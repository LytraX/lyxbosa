# Changelog

Written for people running the scanner: what it detects, what it reports, and what a
configuration or a calling script has to do differently.

This file starts at 2.1.0. For anything earlier, the GitHub release notes carry a
commit list that CI generates per tag. Versions are the git tags described in
[docs/RELEASING.md](docs/RELEASING.md).

---

## Unreleased

### Detection coverage

**Corpus detection is 696 of 1,299 reviewed malicious samples (53.6%), from 172 of 774
(22.2%) — and the denominator is where almost all of that came from.** 525 quarantine rows
were ruled malicious, 524 of which the current binary already detects, so they entered both
sides of the ratio at once. Read as progress it is a mirage: no rule changed, and a figure
that jumps 31 points without a rule change is the §11 shape — a measurement whose
denominator is chosen by the same process that fills the numerator. What it does mean is
that 525 samples now have an expectation the suite can fail on, where before they had none.

The verdict was taken by rule cluster rather than by row: 88 clusters covered all 525 and
the verdict was uniform across every one — split-identifier `gzuncompress`, `goto` mazes,
`require base64_decode(...)`, a file manager whose own banner reads NO LOGIN. Each row's
`expect.must_detect` was then set from a fresh per-sample `check` against the binary rather
than from the rules the collecting scan recorded, and that distinction earned itself
immediately: **one of the 525 no longer fires**, and is recorded as a `known_miss` whose
reason is that a rule narrowed. Taking the recorded rules would have written an expectation
the suite fails on. Known misses 602 → 603, `rule-exact` 98 of 98, technique coverage
unchanged at 90 of 123.

Sensitivity was derived from each sample's bytes rather than asked for, and **28 of the 525
hardcode their victim's identifiers** — `/home/<account>/<domain>/` constants, canonical
URLs, database name and user literals in harvested `wp-config` copies, a support address in
a mailer's `From` header. The malware embeds the customer it was found on. Two of the forty
identifier hits were collisions read in context before being dismissed (a component of an
ordinary PHP superglobal, in 94 files; an ordinary English word in UI text, in 19). 31
credential-bearing rows are tagged `secret` from a content match, so they sit behind two
independent locks rather than one.

### Added

- **The secret gate is armed structurally (`corpus/shard-gate.py`).** A row tagged `secret`
  whose masking is applied must now carry `masking.secret_gate == "PASS"` or it is not
  publishable. Two blockers, not one: a recorded `FAIL` is a measurement that was taken and
  did not pass, an absent result is a row whose masking predates the gate, and the repairs
  differ — re-mask versus re-measure. Collapsing them would let a `--fix` run manufacture the
  field, which is the blind fix the gate exists to prevent.

  The rule sits **inside** the `applied` branch. A `secret`-tagged row with masking not
  applied already carries one blocker for that cause, and §8 counts reasons rather than rows,
  so a second reason for one cause is a double-counted denominator — the shape that left the
  blocker tally 14 out for two rounds. There is a control for exactly that: a fixture with
  `applied: false` and a `not_applicable_reason` must come back **clean**, and would report
  `drift` if the rule fired twice.

  Four control cases added, taking `--inject` from 12 to 16, all 16 passing. Run against the
  pre-change `evaluate()` the same suite fails on exactly the two new positive cases, which
  is the evidence that they test the new rule rather than the old one.

- **`corpus/regen-tiers.py`** — recomputes a map's `mask_tier` and refuses to write unless
  two separate things are provably true. The map is out of repo, cannot be recovered from
  git, and `pre-push-check.py` builds its identifier list from it, so the write is the
  dangerous part and the tier arithmetic is not.

  **Assertion one, contents:** `identifiers()`, `keep_tokens()`, `pairs()`, every top-level
  field but `mask_tier`, and `mask_tier`'s key set, all unchanged — then re-asserted by
  reading the file back. Six mutations must be caught and one honest regeneration allowed;
  a guard that rejects everything is not a guard either.

  **Assertion two, meaning:** coverage per changed name over a real path population, refusing
  a measured loss. This one exists because assertion one passed on a demotion that cost six
  masked occurrences — a tier change moves no identifier, no pseudonym and no key, so a
  contents check is structurally unable to see it. Refused **per name** rather than on the
  net: a net lets one name's gain pay for another name's loss, and "the totals balance" is
  not a statement about the name that stopped being masked. `--allow-coverage-loss` is the
  override and has to be typed. The matchers are built by instantiating a real
  `incident_mask.Masker` over a one-name map rather than by re-deriving the tier regexes, so
  a coverage check cannot measure a width the masker does not use.

### Changed

- **The map's `mask_tier` regeneration was built, run, measured and rolled back.** `tiers()`
  was fixed last round and tiers are stored, so the fix changed nothing until it was run. Of
  134 identifiers exactly one moved, `C → D`: a five-character alphabetic account name that
  *is* a stock-CMS filename token, which `C` rewrote as a whole word wherever it appeared. The
  other 133 reproduce their stored value against the union of both trees, which is how the
  vocabulary was identified — `trail-data/CMS` alone disagrees on a second name, so the stored
  tiers were not generated from it. Every contents assertion passed and `--collisions` read 0.

  **It was reverted on the measurement.** A tier is a substitution width, so the question is
  how many real occurrences each width reaches. Over a census of 247,829 collected paths `C`
  masks **29** occurrences of that name and `D` reaches **23**; over a 366,080-path population
  including directory names, 34 against 30. The six lost are the name as a filename prefix
  before `_` and the name between `-` and `.` — the `<account>_<something>` form that
  incident-response directories and database dumps are named after. The cost in the other
  direction measures **zero**: across 48,256 `origin.path` values the name occurs only as a
  substring of a longer token, which `C`'s leading-boundary rule does not touch, and no
  stock-CMS token was rewritten anywhere in either index. §5.6 holds that leaving a name costs
  everything and over-masking costs nothing; a measured six against a measured zero only goes
  one way. The map is back at `C`, `--collisions` reads **1** again, and the regenerated map
  is kept as `account-mapping.json.20260905-postregen.bak` so the census stands.

  **The 0 it would have read was not the resolution it looks like.** `vocabulary()` yields
  bare tokens with no separator, and every tier-`D` rule requires one, so **no `D`-tier
  identifier can ever be reported by `--collisions`**. The 0 would have meant the name left
  the check's reach, not that the collision was resolved. The positive control on it is the
  same check against the pre-regeneration map, same name and same vocabulary, still reading 1
  — the tier is the only variable. `--collisions` asserts that no `A`/`B`/`C` identifier
  rewrites a stock token, and is not evidence about `D`.

  **The rollback does not reach sample bytes.** `content_mask.ContentMasker` re-derives the
  tier from the vocabulary it is handed, and `mask-samples.py` always hands it one, so the
  byte masker treats that name as `D` either way — masking a sample under both maps gives
  byte-identical output while the masker's own self-demotion count drops 1 → 0. The row masker
  now treats it as `C` and the byte masker as `D`, deliberately: over a row field the wrong
  tier over-masks a path segment, over sample bytes it rewrites a working identifier in code.

- **`--inject` no longer requires `--vocabulary`, in `regen-tiers.py` or in
  `mask-samples.py`.** A control suite that cannot run without pointing at a 158,675-file
  tree is a control that gets skipped, and a skipped control is the state AGENTS.md is about.
  Neither suite's cases depend on what a stock CMS tree contains — they test refusals, the
  contents assertion, the coverage refusal and the file mode, with tiers set by hand so each
  case is about the guard rather than the arithmetic. Both now synthesise a small vocabulary
  and say so in their output. Masking and regeneration still refuse to run without a real
  tree, because there the collision reference is the whole point.

- **13 of the 15 `secret`-tagged rows with no gate result were re-measured** with
  `mask-samples.py`, not fixed. All 13 cleared the secret gate and held detection parity;
  two of the 13 gained a `plaintext gate did not pass` blocker they had not recorded before.
  **Two rows were refused**, each carrying one `wp-credential`-shaped literal that survived
  masking byte-identical to its input, so they keep `applied: true` from a superseded run and
  are now blocked by the new rule — the first time it has been observed to say no.

  Local publishable moves 380 → 378 (the two refusals). `plaintext gate did not pass` 0 → 2
  and `carries secret with masking applied but no secret_gate result was recorded` 0 → 2, in
  `index-summary.json`. The three `no masking has been applied` blockers are unchanged at 31,
  7 and 2, which is the double-counting control holding on real data. **No published figure
  moves**: the published half carries zero `secret`-tagged rows and its gate run is unchanged
  at 44,544 publishable, 0 stale.

### Measured, not changed

- **The stored tier's blast radius was nil, and the places it could have landed were
  checked as censuses rather than samples.** This is what made the rollback cheap: the
  `C` rule that is now back in force has not over-masked anything, anywhere, that can
  still be observed. The `C → D` name is the only
  identifier whose tier moved, so it is the only one that could have over-masked.
  *Published rows*: 0 occurrences of its pseudonym in 44,544 rows. *Local rows*: 27
  occurrences across 25 rows, every one in `origin.path`, and every one a genuine account
  reference — 23 inside a tier-`D` positional slot, 4 outside one. Not a single stock-CMS
  token was rewritten. Both sweeps read every string of every row, so their power to find an
  occurrence is 1, bounded only by the index as it stands today: a row over-masked and later
  overwritten would leave no trace in either.

  *Sample bytes*: none, and for a reason worth stating precisely. Re-masking all 46 sources
  from the round that masked them, with the vocabulary and without it, produced **identical
  output for all 46** — but that comparison had no power as run, because the name does not
  occur in any of the 46 files at all. Its power was established separately on constructed
  inputs, where the same comparison reports a 5-byte difference for a bare token and for a
  path segment. `ContentMasker._demote_stock_words` is why: masking one sample with the
  pre-regeneration map and with the regenerated map gives the byte-identical result, and the
  masker's own count of tiers it had to demote drops 1 → 0. The byte masker was never
  exposed to the stored tier, which is what SOURCES.md claimed and had not shown.

- **Why two rows moved `plaintext_gate` `PASS → FAIL`, which is not what it looks like.**
  The recorded `PASS` was wrong; nothing regressed. Three measurements, in order.

  *It is not the masker.* The old masked bytes differ from the new ones and cannot be
  reproduced by any flag combination of the current masker. The superseded records'
  `change_kinds` read `account, domain, email, hex-secret, ip`; today's read `account,
  account-slot, docroot-slot, domain, email`. The slot maskers cover values no map can name,
  so they mask strictly **more** — a masker that masks more cannot make a new identifier
  survive. `incident_mask.py`'s span selection is also unchanged across the commit that
  produced the old records: the only edits were to `tiers()` and `collisions()`, so `rx_a`,
  `rx_b`, `rx_c`, `positional` and `mask()` are the same rules that were in force then.

  *It is not the tier, and not the second map.* With the stored tier `C` and no vocabulary,
  the current gate still fails both rows with 1 distinct identifier over 3 occurrences; the
  demotion adds a second. Gating against the legacy map alone passes, so the finding comes
  from the incident map.

  *It is a standing boundary asymmetry between masker and gate.* The survivor is an
  eight-character tier-`B` identifier, and all three of its occurrences are preceded by an
  alphanumeric. The masker at `B` requires `(?<![A-Za-z0-9])` and will not substitute after a
  letter or a digit; the gate treats a name of six characters or more as a leak by
  containment at any position. The control is three lines: the same name after a separator is
  masked and the gate passes, after a letter or after a digit it is left and the gate fails.
  So the earlier gate — an uncommitted predecessor of `verify-content-mask.py` — passed bytes
  that the committed predicate reports. **The earlier `PASS` was wrong.**

  *And it is not a wholesale widening.* All 82 remaining residue rows were re-gated against
  their source bytes: **79 still pass, 3 do not.** Those 3 plus the 2 already found make 5 of
  95 residue rows carrying a `plaintext_gate: PASS` the current gate rejects. The 3 were
  measured, not sampled, so the figure is exact for that population and says nothing about
  rows outside it.

  **Neither of the 2 changed a publishable count**, because both were already blocked on an
  unreviewed verdict and a `pii` tag; removing the new blocker leaves three others standing.
  **One of the 3 is not**: a row tagged `c2/identity` with `publishable: true` and no
  blockers at all, whose recorded `PASS` does not survive. Its finding is a single
  three-character identifier, which is exactly the length §5.3 records as producing
  coincidences, so whether it is a real occurrence needs a human — that adjudication is what
  the gate exists to demand. It is in neither the published half nor any shard, so nothing
  has left the machine; it is one concrete instance of the 48 rows that are publishable on a
  superseded gate result.

- **The encoded-layer blocker reads 2 before and 2 after, and it is the same two rows.**
  A count that holds while its membership turns over is the shape the blocker tally already
  drifted on once, so it was established rather than assumed, in three steps. Only the 15
  rows in the re-measure worklist — which is on disk — had their masking records touched, so
  every other row's encoded verdict is unchanged by construction. Of the 24 rows in the index
  carrying a non-`PASS` encoded gate, 22 are outside that worklist and none of them produces
  the blocker, so they contributed 0 before and 0 after. Inside the worklist, a row whose
  encoded verdict flipped in either direction would have changed its blocker set, and that is
  precisely `shard-gate`'s blocker-drift class: it reported exactly 2 rows, and on both the
  encoded blocker was present in the recorded set *and* the computed set, with only the
  plaintext blocker added. Membership did not move.

  The 22 silent rows are worth their own line, because "24 rows fail the encoded gate and 2
  are reported" is not a discrepancy: 16 have `applied: false`, so the gate fields are never
  consulted and the row is blocked once, for one cause, by "no masking has been applied"; the
  other 6 are tagged `clean` alone, so `unmasked` is empty and the masking branch is skipped
  entirely — the same tag arithmetic as the `c2` hole below, in its other tag. Twelve of the
  24 carry `SKIPPED-oversize (>1MB)`, meaning their encoded layer was never gated at all;
  all 12 have `applied: false` and none is publishable.

- **95 local rows carried a masking record no current tool would produce, and 82 still do.**
  Only `mask-samples.py` has ever written `masked_sha256`/`rules_before`, and the committed
  script always writes `secret_gate` and `measured_with` alongside them — so a row carrying
  the first pair without the second was written by a state of that script that no longer
  exists. 89 are missing `secret_gate` entirely and 6 carry an `encoded_layer_gate_uncapped`
  field that appears nowhere in the tree.

  The `index-local.jsonl.pre` snapshot of 2026-09-04 16:33 dates them: it already held **112**
  byte-style records and **0** carrying `secret_gate`, a day before `mask-samples.py` was
  committed. So this is not a legacy population inherited from an older process — the
  description that came with the 15 when they were called 17 — nor is it confined to the
  round that committed the tool. It is residue from `--apply` runs of a script under
  development across at least two days.

  13 were re-measured this round (52 rows now carry a current-form record, 39 + 13), leaving
  **82 superseded, 48 of them `publishable: true` on gate results a superseded gate
  computed**. How wrong that population is no longer needs estimating: all 82 were re-gated
  against their source bytes, and **79 still pass while 3 do not**. With the 2 found among
  the 13, that is **5 of 95** residue rows carrying a `plaintext_gate: PASS` the current gate
  rejects — a census of the population, not a sample, so it is exact for these 95 and says
  nothing about rows outside them. One of the 3 is `publishable: true` today. Separately, 29
  rows carry a `not_applicable_reason` that no script in the repository writes at all — also
  present, at the same count, in the 2026-09-04 snapshot.

- **The `c2`-only hole, measured for a later round's decision.** `ALWAYS_OK` is `clean` and
  `c2`, so a row tagged `c2` and nothing else skips every masking gate. 647 local rows are in
  that state; 637 have no masking record at all, so their bytes have never been read by any
  masking pass — 8.8 MB, median 3.5 KB, largest 1.1 MB. 34 of the 647 are not blocked by the
  gate, all in `quarantine/evidence`, all carrying an `origin` — which the published half's
  own invariant rejects, so none is promotable as it stands. In the published half 30 rows
  are `c2`-only, 2 with no masking record, both `undetected-pool-review` index rows whose
  bytes are not shipped.

  The independent leak predicate finds **0 hits across all 647 rows**, and that is a census
  of row *text*. It says nothing about the bytes, which is exactly the hole: nothing that
  exists today has read them. Closing it means a byte pass over those 637, not a gate edit.

### Fixed

- **`pre-push-check.py` refused `regen-tiers.py` over its own control fixtures.** The
  coverage controls needed a name to build paths out of, and the one reached for was a real
  account name that happens also to be an ordinary English word — the same name the whole
  tier argument is about. It went into a tracked file as a literal, in the fixtures of the
  tool written to protect the map. The check caught it before the commit, which is the
  sixth time this exact shape has occurred here and the third time the tool caught it. The
  fixtures now use a string that is in neither map, fires no leak predicate and appears in
  no stock tree, and the file says why. Controls set the tiers by hand, so the string never
  needed to be a real one; it was reached for because it made the fixture read well.

- **`regen-tiers.py` widened the pseudonym map from `0600` to `0644` when it wrote it.**
  The write used `open(tmp, "w")` and `os.replace`, which takes the umask rather than the
  mode of the file it replaces, so a file holding 232 customer identifiers became
  world-readable on the machine that holds them. Nothing in the tool noticed, because the
  assertion it had compared *contents* and the contents were correct.

  `write_map_atomic()` now mirrors `indexio.write_jsonl_atomic`: read the mode of the file
  being replaced, `chmod` the temp file to it **before** the rename — between `os.replace`
  and a later `chmod` the file is live at the wrong mode, and that window is the bug — then
  `fsync` the file and the directory, so a crash cannot leave the directory entry pointing
  at the old inode. The backup is taken with `shutil.copy2`, which carries the mode across,
  and the mode is re-asserted after the write alongside the contents.

  **The control asserts the mode, not the content**, because a content-only assertion is
  exactly what let this through: a map at `0600`, `0640` and `0644` must each come back at
  the mode it went in with. And there is a control on the control — the pre-fix write is
  reproduced in the suite and must be *seen* to widen `0600`, or "the mode was preserved" is
  not being measured at all. `--inject` is 16 cases, up from 7.

- **The seventeen that were fifteen.** `SOURCES.md`, `CORPUS_PLAN` §7.2 and this file all
  said 17 local rows were tagged `secret` with masking applied and no `secret_gate`. The
  measured count was 15. It was **stale rather than miscounted**, and the two candidate
  explanations separate cleanly.

  *Not a miscount.* Seven natural variants of the predicate were run against the index —
  counting any masking record rather than an applied one, counting both halves, widening to
  `identity`, keying on the row's secret evidence instead of its tag, and so on. They return
  10, 13, 15, 15, 10, 8 and 51. **None returns 17**, so there is no reading of the question
  under which today's index answers seventeen.

  *Stale.* Every other figure in that commit was taken after the write and still reproduces
  exactly: blockers `identity` 169, `path` 3, `identity/secret` 7, `secret` 31, encoded-layer
  gate 2, and 39 rows carrying `masking.measured_with`. The index has not moved since that
  round ended, so a figure from it that does not reproduce was taken when the index was in a
  different state — before that round's own `--apply`. The blocker arithmetic is consistent
  with exactly that: 33 rows gained a current-form record, 31 of them from the not-applied
  population (72 → 40) plus one row that lost the `secret` tag, leaving 2 from the drift set,
  17 → 15.

  That last step is a reconstruction, not a measurement, and it rests on two values the
  commit does not state — that `identity/path/secret` stood at 2 before the round, and that
  the row which lost its `secret` tag was one with no masking applied. Both are forced or
  near-forced (blockers only shrank that round, and the row lost the tag for carrying no
  credential literal), but on the other readings the pre-write count is 16 rather than 17.
  The `index-local.jsonl.pre` snapshot cannot settle it: it predates the round by a day and a
  whole quarantine review, over which the `secret` population went 52 → 88 and its drift set
  43 → 15. **What is measured is that 17 was not the state at the end of that round; the
  mechanism is inference.**

  The lesson is narrower and sharper than "recount": **a figure quoted in a commit that also
  performs a write has to say which side of the write it was taken on.**

  The full measured population is now stated as a breakdown rather than a single number —
  88 rows carry the tag, all local, none published — because the single number is what hid
  the staleness for a round.

### Added

- **Byte-level masking (`corpus/content_mask.py`, `verify-content-mask.py`,
  `mask-samples.py`).** Row masking has existed since §5; this is the same triple for sample
  *bytes* — a masker that needs the map, a gate that shares none of the masker's patterns,
  and a driver that runs all of §5.6's checks rather than the convenient one. Every
  substitution is length-preserving and the masker raises rather than returning a different
  length. Synthetic values carry a `mask…` marker so a reader of shipped bytes can tell a
  masked account from a real one, deliberately **not** in the map's own `acct`/`site`/`srv`
  namespaces — an eight-character name masked to `acct1234` would alias a pseudonym already
  issued to someone else. Three characters of entropy, not two, because at two the
  synthetics collided on the first run and `collisions_between_replacements()` refused to
  run. `mask-samples.py --inject` is the control: parity can report a destroyed detection, an
  unreadable file is refused, bytes that do not hash to their row are refused, an unchanged
  sample keeps its detection.

  **46 rows worked, 39 cleared, 7 held.** The 7 are genuine tar containers (`ustar` at offset
  257, sizes multiples of 512) which §5.5 excludes because byte-masking a container corrupts
  it. All 39 length-preserved exactly — 3,150 bytes changed across 5,395,101 bytes staged —
  and detection parity held 39 of 39, with 36 of those having the power to notice a loss.
  The masking blockers move accordingly: `identity/secret` 36 → 7, `secret` 34 → 31,
  `identity` 172 → 169, `path` 4 → 3, encoded-layer gate 5 → 2. **No published figure moved**:
  detection, known misses, technique coverage and the false-positive rate are all unchanged,
  which is the correct result for a round that changed bytes and no verdicts.

### Changed

- **§5.4 is relaxed for plain base64 and stands for every compressed layer, and the
  difference is arithmetic rather than a measurement.** "Length-preserving masking cannot
  reach an encoded payload" held three samples that each carried a short `/home/<acct>/…`
  constant inside a plain base64 region, 37 to 68 bytes decoded. base64's output length is a
  function of its input's *length* alone, so a length-preserving substitution in the decoded
  bytes yields an encoded region of exactly the same length and nothing after it moves;
  deflate's is a function of its *content*. `content_mask.py` repairs that case and only that
  case, under five conditions checked per region: the region decodes, this encoder reproduces
  it byte for byte, the substitution preserves length in the decoded domain, the spliced file
  has the same total length, detection parity holds. All three cleared.

  Recorded with it, because it nearly went the other way: **deflate can look
  length-preserving on short inputs.** The same substitution held deflate's length at 37 bytes
  (45 → 45) and 68 (76 → 76), and only moved at 400 (366 → 368). Two short samples would have
  "shown" the rule could be relaxed for compressed layers too.

- **§7.2's secret bullet cannot be satisfied as written, and §7.2 is the half that bends.**
  §5.1 requires a masked secret to be replaced by a synthetic of the same *shape*, so a
  correctly masked sample still contains something bcrypt-shaped and an absolute scan of the
  output must report it — 54 such literals remain across the 39 samples, every one synthetic
  by construction. Stripping the shape would destroy the detection the sample exists to
  demonstrate. The rule becomes differential: no credential-shaped literal in the output is
  byte-identical to one in the input, over the plaintext and every decoded layer.
  `verify-content-mask.secret_gate()` implements it per sample and has already failed
  usefully, on an attacker password literal assigned to a `$pass` variable the masker's
  keyword list did not cover. **The structural half is deliberately not done**:
  `shard-gate.py` decides publishability by reading rows, has no field for a secret gate, and
  local rows are tagged `secret` with masking applied and no `secret_gate` result — so
  imposing the rule today would put all of them into blocker drift until re-measured. It
  blocks the first public shard carrying a `secret`-tagged sample; no shard carries one today.

  *(This entry originally said "17 local rows", and 17 was the count on the wrong side of
  this round's own `--apply` — see "the seventeen that were fifteen" below. The figure is
  removed here rather than restated, because the round that arms the gate owns it.)*

### Fixed

- **`incident_mask.py --collisions` could not report the strongest collision it can meet.**
  The attribution loop required `real != token.lower()`, so a token that *is* an identifier —
  an account name that is also an ordinary word used as a stock-CMS filename token — was
  rewritten by `mask()` and then dropped on the way to the report. The check printed **0
  tokens would be rewritten** while the masker rewrote one, and `SOURCES.md`'s claim that
  both maskers rewrite nothing in the 158,675 stock CMS files rested on that zero. It now
  reports an exact hit and an unattributable rewrite instead of dropping either, and
  truthfully reads **1**. Underneath it, `tiers()` gave that same case the *weakest*
  treatment: the length test came first and an exact match fell through to a tier that
  rewrites the whole word. An identifier indistinguishable from stock vocabulary is the most
  colliding case, not a marginal one; it is now positional-only. Tiers are stored in the
  out-of-repo map, so this changes nothing until the map is regenerated — which is why the
  byte masker re-derives the tier from a vocabulary it is handed and treats a missing
  vocabulary as a hard failure rather than running without a collision reference.

- **A slot rule's delimiter list was a positive list, for the third time.** The rules that
  mask a value no map can name — a third party's account written into a sample's own UI —
  ended with a list of the delimiters expected to follow. `/home/<acct>/<domain><br>` ends at
  `<`, which was not on it, so the account was masked and the site name beside it was not.
  The guard is now the negative form. Both occurrences were in one sample and both were
  caught by reading the masker's output, not by the gate: the gate is map-driven and neither
  name is in either map, which is the whole reason the slot rules exist.

- **70 rows carried `identity` evidence that was not evidence, and dropping the tag with it
  would have unblocked two real ones.** The `identity.ips` basis collected 637 distinct
  dotted quads across 225 samples that were Freemius `@since 1.2.2.7` version strings, SVG
  path coordinates (`0l-5.6 5.6c-.7.7-.7 1.8 0 2.5l5.6…`), `127.0.0.1` localhost checks and
  a `1.1.1.1` in a Cloudflare footer template. The evidence is retracted on all 70. The tag
  is dropped on **four** — six rows had `ips` as their only basis, and **two of those six
  genuinely carry identity**, one with 4 and one with 48 real `/home/` paths plus a mapped
  account name. Retracting evidence and dropping a tag are not the same operation; doing them
  as one would have published 52 customer home paths. One row also loses `secret`: it holds
  no credential literal and builds `$new_user = "hacker" . rand(100, 999)` with `md5(rand())`
  — generating a secret is a technique, not a sensitivity.


### Changed

- **The false-positive denominator moved: 8 of 146,712 becomes 44 of 197,559, a rate of
  0.0055% to 0.0223%.** `corpus/benign/sources.jsonl` grew from 86 pinned sources to 136.
  The 50 additions are not a wider sample of what is popular — each version was read off
  the copy actually installed on a collected host (a plugin's main-file `Version:` header,
  a theme's `style.css`, core's `wp-includes/version.php`), so the benign corpus now
  contains the versions the scanner meets rather than the versions upstream ships today.
  **Both halves of the rate grew and the numerator grew faster**, which is the expected
  direction: the previous benign tree could not have produced these findings because it
  did not contain the code. All 44 are upstream library code and all 44 are pinned as
  `known_fp` fixtures in `corpus/expect/benign-false-positives.json` — 24 of them new this
  round, most inside vendored copies of the Freemius SDK. They stay counted inside the 44.
  The figure is quoted in the README, which is updated to match. Anyone regenerating it
  needs `corpus/fetch-benign.sh` again: the lockfile changed.

- **One false positive was found already fixed, and is now pinned as fixed.** Stock
  WordPress core 4.8.3's `wp-admin/includes/class-ftp-sockets.php` was flagged `BD005` by
  the scan that collected it and is not flagged by the current ruleset. Nothing had been
  able to notice, because the file was not in a pinned benign tree until 4.8.3 was pinned
  this round. It carries a plain `must_not_detect` rather than `known_fp`, so the fix is
  now a regression test: if `BD005` returns on stock core, the suite goes red.

### Added

- **`corpus/fetch-benign.sh` accepts `.tar.gz` sources as well as `.zip`.** The archive
  kind is read off the URL and an unrecognised suffix is a hard failure rather than a
  fall-through to `unzip` — CORPUS_PLAN §8's rule that a silent fallback is how two
  artefacts that claim to be the same thing stop being the same thing. Unpacker
  dependencies are now tested one at a time and only for the formats the lockfile actually
  contains, which is the same lesson as the `command -v zstd tar jq` that reported success
  while `zstd` was absent. `corpus/fetch-benign.sh --inject` is the positive control: five
  hermetic cases over `file://` URLs, asserting that a good zip and a good tar.gz verify,
  that a one-byte corruption of either is refused, and that an unknown suffix is refused.

- **`corpus/resolve-benign.py` — the closure mechanism that decided 92% of this corpus now
  exists in the repository.** Rows byte-identical to a file in a pinned source were being
  closed by ad-hoc scripts in collection directories, so the reason code
  `pinned-benign-hash` appeared on 9,168 published rows and nowhere in the tree. It closes
  a row only when the verdict is still `unreviewed`, records superseded sensitivity tags
  rather than overwriting them, builds the published row from a whitelist so it cannot
  carry an `origin`, and prints separately any row whose collecting scan had already
  flagged it — those are false positives on upstream code, not closures to wave through.
  `--inject` is the control, nine cases.

### Not added, and this is the round's main result

- **The rule that would close 82% of the known misses will not be written.** 495 of the 602
  samples this version misses are one 2017 SEO doorway campaign, and the candidate for them
  was `title == meta[keywords] == meta[description]`, exactly. It scored **0 false positives
  over 207,311 files** — and was refused twice, because only 12 of those files carried both
  meta tags, so it had twelve chances to fail and a rule-of-three bound of 25%.

  Round 11 pinned the population it actually needed: three trees of rendered HTML
  documentation. Measured against those, the candidate takes **494 false positives in 506
  at-risk files — 97.6%**. GNU Texinfo writes the node title into `<title>`,
  `meta[description]` and `meta[keywords]` verbatim on every page it generates, so the
  "discriminator" describes a documentation generator rather than a doorway page.

  What that means for the headline: **detection will not rise much from 22.2% soon**, because
  the largest single block of misses is now a family whose rule has been measured and
  rejected rather than merely unwritten. A 495-sample jump was available at any point for the
  price of shipping on twelve files' evidence.


### Fixed

- **The publishability gate was only half a gate, and the half it was missing is the half
  that mattered.** `corpus/shard-gate.py` computes `publishable` from the §4.1 rule and is
  the only thing allowed to write it. It failed when a row *claimed* publishable and was
  not, and it was **silent when a row was publishable and did not claim it**. Two operator
  review passes — six samples in one, eight in another — set `verdict: malicious` and
  `sensitivity: ["c2"]` without re-running it, so fourteen rows kept `publishable: false`
  and kept recording *"verdict is unreviewed"* and *"sensitivity not yet assessed"* as
  their blockers after both statements had stopped being true. Every run recomputed all
  fourteen, printed `publishable flags corrected: 14`, and exited 0. Nothing downstream
  reads the row — `promote-pending.py` defers on the recorded blocker and
  `index-summary.json` counts it — so a stale blocker was a stale denominator, and the two
  blocker tallies sat exactly 14 above the sensitivity and verdict counts they mirror.
  This is the same shape as the regex that matched `/home/` and not `/home2/`: a check
  narrower than the thing it guards, silent in exactly the direction its subject drifted.
  The gate now reports **over-claimed**, **under-claimed** and **blocker drift** — the
  third for a row whose boolean is right and whose recorded reasons are not — and fails on
  any of them. `shard-gate.py --inject <index>` is the positive control; it passes twelve
  of twelve here and fails seven of twelve against the pre-fix gate, which is how the
  green result above is worth reading. A `--fix` run that corrects anything now exits
  non-zero on purpose: the correction is not the result, the result is that something
  upstream changed a verdict without re-running the gate.

- **The suite's headline detection figure could not fail.** `corpus/verify.py` built its
  `Detection` line entirely out of `index-summary.json`, so it printed a recorded number
  regardless of what the binary under test did. Pointed at a build containing none of the
  current rules, the suite reported `shard-run 7/95, 88 missed` and `Regression 7/95` — both
  correctly red — and directly above them `Detection 169/774 (21.8%)`, with the sub-line
  "95 verified by re-running `check`" when 7 had been verified and 88 had just failed. The
  figure a reader sees first was the one that could not deliver bad news about the
  instrument. It now reconciles the recorded count against what the run actually detected,
  says plainly that the number is read from the summary when they disagree, and fails.

### Added

- **`OBF041` (high)** — a file that opens with the ASCII letters `PNG` or `GIF` where a
  real image signature belongs. A real PNG begins with the byte `0x89` precisely so it
  cannot be read as text; a real GIF's version field is `87a` or `89a`. Forty files named
  `.png`/`.gif` in five staged plugin directories are base64 payloads behind a three-byte
  cover word, and the cover does not track the file's own name, so the rule reads content
  only. Plain extension/magic mismatch would take 18 ordinary files — misnamed JPEGs and
  empty test fixtures — to reach samples this already reaches. 0 of 11,522 at-risk files
  in the benign trees.
- **`WS011` (critical)** — a bundled mailer behind a password written into the source. A
  bulk-mailer kit ships a whole copy of PHPMailer with a send UI and a password prompt
  whose secret is a literal on line 3. Bundling PHPMailer alone is *more common in
  ordinary plugin code than in malware* — 225 files in the benign trees do it — so the
  gate is the rule, not the library and not the kit's brand, which one rename defeats.
  0 of the 230 files that bundle the library.
- **`BD018` (critical)** — a `rename()` that undoes a quarantine: a source carrying
  `.suspected` (what cPanel and ImunifyAV append when they quarantine a file) and a
  target with an executable extension. Anti-remediation, and there is no honest reading
  of it — a legitimate program has no reason to know that suffix exists. Renaming *to*
  `.php` is ordinary and wp-super-cache does it; renaming *from* a quarantine suffix
  happens nowhere in 207,311 benign files. 0 of 343 files containing a `rename()`.
- **`PHI009` (critical)** — `mail()` in a file that reads submitted fields out of a
  superglobal and carries the recipient as a literal. Each conjunct is load-bearing:
  without the address literal the shape costs 30 false positives, because WordPress's
  own `wp_mail()` path reaches `mail()` and `$_REQUEST` in one file — but every address
  it sends to arrives as an argument or through a filter; without the superglobal it
  costs 24, on PHPMailer's own docblock example address. A CMS contact form takes its
  recipient from configuration; a drop is written down. 0 of 175 files calling
  `mail()`.
- **`CRED007` (critical)** — a card security code read from the request and reaching a
  remote-fetch sink without leaving the enclosing block. A fake payment gateway packs
  the card number, expiry, CVC and the whole billing and shipping record into one array
  and `file_get_contents` a remote URL with it. The CVC is the discriminator: a real
  gateway tokenises client-side and PCI DSS forbids retaining it, so a server-side
  security code in transit is close to definitionally wrong — while a card *token*
  crossing a server is ordinary, which is why keying on "card" would take two honest
  WooCommerce gateways. 0 of the 465 files carrying a card-code token.

### Detection coverage

**Corpus detection is 169 of 774 reviewed malicious samples (21.8%), up from 128 of 774
(16.5%).** The five rules above measured 75 samples they newly detect; 41 of those were in
published shards and are now promoted from `expect.known_miss` to `expect.must_detect`.

The whole difference is those 41 rows and nothing else. The denominator did not move — 774
reviewed malicious samples before and after — so this is the first round in which the figure
rose rather than falling or holding: promoting a known miss whose rule now fires moves a
sample from the denominator-only side to both sides. Known misses fall 646 → 605, the suite's
executed set goes 54/54 → 95/95 with all 95 matching their expected rule exactly, and the
false-positive rate is unchanged at 8 of 146,713 benign files. Technique coverage is also
unchanged at 80 of 123, which is correct rather than surprising: a `known_miss` sample
already contributed its techniques to both sides of that ratio.

Each row was re-measured with `check` against the bytes the suite runs before being applied,
because `expect.must_detect` is compared to `check`'s output exactly. `corpus/verify.py` now
reports **0 newly detected** — the same figure a scanner built before these rules would
report, so it is worth saying how the two are told apart: the run immediately before the
promotion, using the same binary, reported 41, and running the promoted corpus against a
pre-`OBF041` build turns 88 of the 95 executed samples red instead of printing the same
numbers quietly.

**34 samples are still owed** and stay in `corpus/pending-promotions.jsonl`: 29 blocked on
masking they have not had, 3 on a sensitivity assessment, and 2 on a human verdict that only
the operator can give. Their detection is real; none of those blockers is about whether a
rule fires, which is why the file records the blocker rather than just the hash.

**Corpus detection is now 172 of 774 (22.2%), from 169 of 774 (21.8%).** Two movements, with
separate causes, and only one of them touches that figure:

- *Recomputing fourteen stale rows moved no count at all*, which is the correct result for
  fixing a derived field and is why it is stated rather than omitted. The two blocker
  tallies fell by 14 each — `verdict is unreviewed` 79,595 → 79,581 and `sensitivity not yet
  assessed` 73,797 → 73,783 — and now equal the verdict and sensitivity-tag counts they are
  meant to mirror, which is the arithmetic that had been 14 out for two rounds.
- *Publishing eight of them and promoting three* is the rest. The eight components of one
  2017 SEO doorway kit move from the local half to the published half and ship as
  `malicious-doorway-kit-001` (12 KB, unmasked — the independent gate found nothing to mask
  in the plaintext or the raw bytes, and there is no encoded layer to hide one in). Three of
  the eight are the `BD018` deployers that had been sitting in the handoff blocked on the
  stale state above; they are re-measured against the shipped bytes and promoted, taking
  known misses 605 → 602 and detection 169 → 172. Publishing does not move detection on its
  own — a published row and a held row are both in the denominator — but it moves what a
  stranger can reproduce: the suite's **executed set goes 95 → 98**, all 98 matching their
  expected rule exactly, and the known misses it can re-run go 37 → 42. **Technique coverage
  goes 80 → 90 of 123**, all ten from these rows and none previously covered by any tested
  sample. The false-positive rate is unchanged at 8 of 146,713 benign files: no rule and no
  benign source changed.

`corpus/index-summary.json` gains `local_only_publishable_no_blocker`, which reads **5**.
Those are rows the §7.2 gate does not block that are still held — the five remaining
incident samples from those two reviews, which carry no `family`, `technique` or `reason`
and so cannot be published without a classification nobody has made. Before this round the
key would have read 0 for the wrong reason, because a row that became publishable was never
recorded as having done so. A sixth was **held deliberately**: §7.2's secret scan fires on
its bytes, and the corpus's only other sample carrying that technique is tagged `c2+secret`
and held for masking, so its `sensitivity: ["c2"]` looks under-tagged. Re-tagging axis B is
a human assessment and the row waits for one.

### Added

- **`RCE015` (critical)** — a file written, executed with `include`/`require`, then
  deleted. A remote loader fetches PHP over HTTPS, writes it to a path, includes the
  path and unlinks it, which is `eval` performed through the filesystem: it needs no
  `eval`, no `allow_url_include`, and leaves nothing behind for the next scan. The rule
  is the three-way linkage on one path variable — written, included, unlinked, in that
  order and within 400 bytes. Nine files across 279,337 in the benign trees put one
  variable through both an include and an unlink; in eight the unlink comes *before* the
  include, and the ninth is 10,731 bytes away.
- **`OBF040` (high)** — a URL whose scheme word is cut in half. `'htt'.'ps://c.by'.'a61
  .xy'.'z/'` folds to a C2 address that no search for `https://` will find. Assembling a
  URL from concatenated literals is ordinary and 208 benign files do it; cutting between
  two letters of `http`/`https` rather than at its punctuation is what the rule tests,
  and it is what separates the malware from the one benign file that splits a scheme at
  all (w3-total-cache, wrapping a message at the colon).
- **`WS010` (high)** — a 404 a file tells about itself. The shell answers
  `404 Not Found` and exits unless a magic request parameter is present, so it reads as
  absent to every crawler, uptime probe and operator that fetches the URL. Benign code
  that returns 404 decides on the state of a resource — `! is_file( $file )`,
  `$current_blog->archived`; this decides on whether the caller knows a token.

- **`OBF039` (critical)** — a per-file substitution cipher. A WordPress `db.php` drop-in
  campaign resolved every dangerous identifier at runtime through a table lookup, so nothing
  was written down for a pattern to match and the alphabet differed per file. It matches the
  decoder instead: the position `strpos` finds used as an index into a second alphabet that
  the file assembles from short literals. Closes 46 known misses and takes corpus detection
  from 10.0% to 45.4%.
- **A golden corpus and a reproducible suite** (`corpus/`). The benign half is 86 upstream
  sources pinned by version and sha256 — nothing is committed, `corpus/fetch-benign.sh`
  downloads and hash-verifies — so the false-positive rate regenerates anywhere and yields
  the same number. `corpus/verify.py` runs it. See
  [Detection coverage](README.md#detection-coverage).

### Changed

- **Detection is reported over every reviewed malicious sample.** It previously printed
  `recall 100%`, which was true and meaningless: `must_detect` was populated from a rescan,
  so a sample carried it *because* it had been detected, and anything known not to be
  detected was moved to a `known_miss` column and out of the denominator. The figure could
  only fall if a working detection broke. That measurement is still reported under the name
  of what it is — a regression check — and the coverage figure is now stated over the whole
  reviewed set, where it can deliver bad news.
- **Precision is no longer reported at all.** It had been withheld until the malicious and
  benign sets were "commensurate" in size, which was the worse repair: satisfying that means
  shrinking the benign side until the ratio is near 1:1, tens of thousands of times more
  malicious than a real host, and printing something flattering that means nothing.
  `tp/(tp+fp)` belongs to a field scan, which supplies the real ratio by construction.
- **Known false positives stay counted in the false-positive total.** Pinning a defect
  records it; it does not remove it from the number it belongs to.

## [2.1.0] - 2026-09-03

Archive scanning, and 96% fewer false positives.

### Detection

**False positives down 96% against a live shared host.** A production scan of a
multi-site host produced 1,751 findings, of which 27 were malware, 10 were real
vulnerabilities in third-party code, and 1,714 were false positives. Rescanning the
same 1.3 M-file tree now reports **63** of those false positives, with **all 27 malware
files and all 10 vulnerability findings still detected**, and finds 7 files the earlier
scan missed — every one of them malware. Scan time is unchanged (17.6 min against 19.5).

The precision was concentrated in a handful of rules, and so is the fix. Five clusters
accounted for 88% of the noise:

- `OBF036` matched protobuf-generated PHP, macOS AppleDouble resource forks and iconv
  charset tables. It now rejects the first two on content — the AppleDouble magic
  number and the generated-protobuf header — and requires control bytes to be
  *adjacent*, which is what separates a stored payload from a byte table.
- `DEFC006` matched every module of a webpack development bundle. It now reads the
  bundler's own markers out of the evaluated string.
- `RCE*`, `WS*`, `DRP*`, `EXP*` and `BD*` matched attack URLs quoted inside GoAccess
  analytics reports. Execution evidence inside a serialised field of a file the
  webserver serves as data is a log, not code.
- `DRP002` matched the composer install one-liner wherever it appears as
  documentation, and now carries an installer-domain whitelist like `DRP001` already
  had.
- `BD002` and `BD004` matched a caching plugin's own settings screen. `BD002` keys on
  argument position — only a superglobal in the cron *hook* means the attacker chose
  what runs — and `BD004` requires a consumer that ships the config somewhere.

Two rules were matching things they were never meant to. `EXP009` and `RCE008` used an
unanchored function-name alternation, so any identifier ending in `exec` matched, as did
the English phrase `Booking System (`. `OBF022` fired at critical on WordPress core's
`block-editor.js`, because `${` also opens a JavaScript template literal.

A further sixteen rules were narrowed to the shape they were written for:
`OBF002`, `OBF003`, `OBF005`, `OBF009`, `OBF011`, `OBF016`, `OBF021`, `OBF024`,
`BD001`, `BD008`, `BD013`, `DEFC002`, `DEFC004`, `DRP008`, `DRP010`, `PHI001`,
`RCE011`, `SEO001`.

### Added

- **Archive scanning.** `.zip`, `.tar`, `.tar.gz` and `.gz` are opened and their members
  scanned by the same rules, addressed `backup.zip!wp-content/uploads/shell.php`.
  A container that turns out to be a copy of an installed site raises an exposure
  finding of its own and is never quarantined. Every guard is expressed in decompressed
  bytes or wall-clock time, and nothing is extracted to disk. On the host above this
  found 348 files the loose-file scan could not see, including two obfuscated webshells
  and a JPEG/PHP polyglot uploader inside backups left in web roots.
- **`OBF029` (critical)** — a payload staged as a long run of small uniform `.=` appends.
  One sample was staged as 203,831 appends of four characters each, which every
  length-based and adjacency-based rule walked past.
- **`RCE014` (critical)** — `eval` over a decryption call (`openssl_decrypt`,
  `mcrypt_decrypt`, `sodium_crypto_secretbox_open`, `openssl_open`). Executing
  ciphertext has no honest use.
- **`SEO008` (high)** — PHP user-agent cloaking: crawler names tested against
  `HTTP_USER_AGENT` in a file that fetches a hardcoded remote address and prints it.
  `SEO003` only ever read `.htaccess`, and this is the far more common form.
- **`OBF038` (high)** — generated noise comments, wordless filler wedged between tokens
  to break pattern matching.
- **Skip reasons.** Every file the scanner does not open is counted and named — `size`,
  `excluded` or `unreadable` — and directories it could not list are counted too. See
  [Skipped files](README.md#skipped-files).
- **`scan.report_excluded`** (default `false`) — list every file the include/exclude
  globs rejected, not just count them.
- The eval-family rules now tolerate block comments between a function name and its
  opening parenthesis, which closes `@/***//*!50000*/eval/***/(` for `RCE001`,
  `RCE002`, `RCE004`, `RCE005` and `RCE012` at once.

### Changed

- **`scan.max_file_size` default is 25 MB**, up from 5 MB. On the host above this reads
  230 more files for about 4% more scan time. It buys coverage rather than detections —
  those 230 files matched nothing — the point being that a file the scanner never opened
  should not be counted as clean. See
  [Choosing `scan.max_file_size`](README.md#choosing-scanmax_file_size).
- **`archives.max_member_size` is pinned at 5 MB** and no longer follows
  `scan.max_file_size`. A member is inflated into memory and shares one expansion budget
  with every other member of the same archive, so it wants the tighter bound.
- **The pre-scan confirmation summary is compact.** It was 160 lines with the default
  filter list, which pushed the directories and the quarantine setting off the screen.
  It is now about 18 lines: directories in full, everything else one labelled line each,
  filter lists flowed to the terminal width, and byte counts in human units. `-v` lists
  every pattern.
- **The summary line for unscanned files** reads
  `Files not scanned: 512 (487 over size limit, 18 excluded by filters, 7 unreadable)`,
  and is printed only when something was skipped.

### Removed

- **`BD010`.** It matched `add_filter('auto_update_...')`, the documented WordPress API
  for a plugin managing its own updates, and produced no true positive across 1.3 M
  loose files, 2 M files with archives opened, or the malware corpus. Naming it in
  `builtin_rules.use` or `builtin_rules.disable` is a silent no-op, not an error.

### Fixed

- **A file that could not be read was reported as scanned and clean.** `readFile`
  returned an empty string on a failed open; that string was matched against every rule,
  found nothing, and the file was counted as scanned with no findings. It now fails, and
  the file is reported as `unreadable`.
- **A failed `stat` was reported as an oversize file and then read anyway.** The walker
  tested `ec` and the size cap in one condition, so on failure the size was unspecified
  and the scanner tried the file regardless.
- **Glob-excluded files vanished** — no callback, no count — so there was no way to tell
  whether an exclude pattern did anything.
- **An unreadable directory was indistinguishable from an empty one**, because the
  directory iterator was told not to report permission errors.
- **`check` reported "No matches found" for a file it never read.** An oversize or
  unreadable file now prints `Not scanned (over size limit)` — see *Compatibility*.
- **`-DLYXBOSA_TUI=OFF` did not compile**, though it is the documented switch for the
  minimal and static builds.
- **Configuration warnings were suppressed whenever archives were disabled**, because
  the whole check returned early. It also now warns when e-mail alerts are enabled with
  no recipient — a configuration that would otherwise have failed silently at the end of
  a long scan.
- **The generated configuration documented `alert:` without its `email:` sub-block**,
  where the parser actually reads `to`, `from` and `subject`. Setting `to:` one level up
  silently did nothing.

### Report format

Additive in JSON. `skipped` and `filesSkippedSize` keep their exact meanings, and
`archives.membersSkipped` is byte-identical, so existing consumers are unaffected:

```json
"skipReason": "size",
"filesSkipped": { "total": 208, "size": 183, "excluded": 18, "unreadable": 7 },
"directoriesUnreadable": 2
```

CSV gains `skipped` and `skip_reason` as its **last two** columns, so positional
consumers keep working, and a skipped file now produces a row — it produced none before,
because the writer emitted one row per match.

### Compatibility

- **`check` exit code.** An oversize or unreadable file now exits `1` instead of `0`.
  A script of the form `lyxbosa check "$f" && echo clean` previously treated an unread
  file as clean and no longer does. This is the one change here that can alter the
  behaviour of an existing caller.
- Configuration schema, CLI flags and every other exit code are unchanged.

---

[Unreleased]: https://github.com/LytraX/lyxbosa/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/LytraX/lyxbosa/compare/v2.0.2...v2.1.0
