# Corpus sources and layout

```
corpus/
  index.jsonl                       the published half: one row per unique blob, 44,544 rows
  make-summary.py                   regenerates index-summary.json from the two halves
  expect/                           golden expectations, per shard
  benign/sources.jsonl              pinned benign sources: name, version, url, sha256, size
  fetch-benign.sh                   downloads, verifies hashes, unpacks. Downloads are not committed
  resolve-benign.py                 closes rows byte-identical to a file in a pinned source
  shard-gate.py                     §7.2 over the INDEX — computes `publishable`, fails the build
  shard-census.py                   §7.3 over the ARCHIVES — resolves every packed member to a row
  clearance.py                      the rule for a human-cleared gate finding; a library, no writes
  clear-finding.py                  the only writer of `clearances`; refuses more than it accepts
  adopt-decoded-tags.py             the only writer of `sensitivity` from `decoded_form_tags`
  remeasure-gates.py                writes the verdict a re-measurement produces, one row at a time
  fp-note.txt                       the false-positive note the findings carry; prose, not behaviour
  make-shard-manifest.py            regenerates a shard's MANIFEST.json from the index
  promote-pending.py                applies pending-promotions.jsonl; re-measures every row
  build-shard.sh                    packs a staged shard; requires zstd, fails hard without it
  local/index-local.jsonl           local-only rows (gitignored)
  import-infected-tree.py           imports the legacy trail-data/Infected tree
  infected_mask.py                  path masking for that tree; map is out of repo
  incident_mask.py                  path masking for the current incident; map is out of repo
  verify-infected-mask.py           the independent masking check for ROWS, either tree: --map <path>
  content_mask.py                   §5.1 — masking of sample BYTES, length-preserving
  verify-content-mask.py            the independent check for BYTES: plaintext, encoded layers, secrets
  mask-samples.py                   runs §5.6's three checks over a batch and records the result
  promote-gate.py                   §5.3 — the map-AWARE check, run when a row is promoted
  index-summary.json                the denominator: counts and blockers, tracked
  shards/                           built shards (gitignored; LOCAL ONLY - none has ever been distributed)
```

## `published` is a classification, not a distribution state

**No shard has ever been distributed.** All 24 assets across the 6 releases are scanner
binaries; `corpus/shards/` is gitignored, has zero tracked files, exists only on the machine
that built it, and nothing in this tree references a shard download URL. Every shard is a
local build artefact awaiting a decision to publish.

So `publishable: true` and the `published` half of the index mean **"cleared to be
distributed"**, and `published_shipped_as_bytes: 84` means **"would ship as bytes in a shard
if one were released"**. Neither says anything has left this machine. A blocker on a
`published` row is a *pre-publication* blocker: it costs a rebuild, not a disclosure.

This is written down because the distinction was blurred and it cost real work. This file
called shards "release assets" and `docs/KNOWN_ISSUES.md` said two samples "ship in" one of
them - present tense for an intended state - and a careful reading of both produced a
conclusion that a customer identifier was already public. It was not. Three minutes of
checking `git ls-files` and the release assets settled it, and the wrong conclusion had
already been reasoned three steps forward. **Say which state you mean**: cleared to publish,
built locally, or actually distributed. They are three different things and only the first
two have ever been true here.

## The index

The index is **split in two, and both halves matter**:

| file | rows | tracked? | what it is |
|---|---|---|---|
| `index.jsonl` | 44,544 | yes | published samples — the ones a public suite can verify |
| `local/index-local.jsonl` | 48,256 | no | everything held back, with each row's blockers |
| `index-summary.json` | — | yes | the counts, so the denominator survives without the rows |

"index.jsonl is small and lives in git" and "the index lists every blob including local-only"
were in tension; splitting resolves it without dropping the accounting. **`index-summary.json`
is the part that stops the suite overstating itself** — it lets a run report *"10,018 verified,
50,591 held, of which 380 obfuscated-and-undecodable, 29 archive containers, 3 known misses"*
rather than quietly reporting a percentage of a denominator it chose.

A row can carry several blockers and is counted under each, so the blocker counts sum to more
than the row count. That is deliberate: collapsing to one reason per row hides the specific,
actionable blocker behind the generic one — which is exactly what happened when the gate first
stored only the first reason and the encoded-layer failures disappeared behind "unreviewed".

**`index-summary.json` is generated, not written.** It used to be maintained by hand, which
is how it came to say `shipped-sample: 2353` in its reason codes while also saying
`published_shipped_as_bytes: 6` — two claims that cannot both be true. `make-summary.py`
computes it from the two halves, and `make-summary.py --check` fails non-zero if the file on
disk disagrees with the index. Run it after any change to either half.

`publishable` is **computed by `shard-gate.py`, never asserted by hand**. Running it with
`--fix` recomputes every row; running it without arguments fails non-zero if the stored
answer disagrees with the computed one. It caught 103 rows on its first run — samples that
had been masked and gated but never actually reviewed, and 14 that carried `pii`.

**It only looked one way for its first nine rounds, and that is the direction it did not
need to look.** The gate failed when a row claimed publishable and was not, and was silent
when a row was publishable and did not say so — so two operator review passes, six samples
and eight, could set `verdict: malicious` and `sensitivity: ["c2"]` without re-running it,
and fourteen rows kept `publishable: false` and kept recording *"verdict is unreviewed"* and
*"sensitivity not yet assessed"* as their blockers long after both had stopped being true.
Every run recomputed all fourteen, printed `publishable flags corrected: 14`, and exited 0.
Nothing downstream could see past the record: `promote-pending.py` defers on the stored
blocker and `index-summary.json` counts it, so a stale blocker is a stale denominator — the
two blocker counts stood exactly 14 above the sensitivity and verdict tallies they are meant
to mirror, which was the arithmetic tell nobody read.

The gate now reports three classes and fails on any of them: **over-claimed** (stored true,
computed false — the original rule), **under-claimed** (stored false, computed true — the
fourteen), and **blocker drift** (the boolean agrees and the recorded reasons do not, which
matters because §8's accounting is built out of the reasons). A `--fix` run that corrects
anything exits **non-zero on purpose**: the correction is not the result, the result is that
something upstream changed a verdict or a tag without re-running the gate. The green result
is the plain run afterwards. `shard-gate.py --inject <index>` is the control, and it fails
seven of its twelve cases against the pre-fix gate.

The field stays **stored** rather than computed on read, and the reason is in the code: the
published half is a tracked document a stranger reads without running anything, and
`publish_blockers` has to be materialised anyway because it is where the denominator comes
from. A stored derived value is a cache; the repair is not to stop storing it but to assert
that it still equals its source.

### The suite's binary is overridable, and two build directories are enough

`corpus/verify.py` reads `$LYXBOSA_BIN`, falling back to `build-release/lyxbosa`. Set it when
you are measuring a rule change against a build of your own:

```
LYXBOSA_BIN=$PWD/build/lyxbosa corpus/verify.py
```

This exists because the path used to be hardcoded, and that produced a bad instruction: two
agents working this tree at once were told to use a *third* build directory, when `build`
(debug) and `build-release` were already one each. The count of directories was never the
problem. The problem is that a suite which can only read one path forces anyone measuring a
change to rebuild the very binary the suite is reading, and a rebuild part-way through a run
leaves the per-sample `check` calls straddling two binaries with nothing reporting an error.
Overriding the path removes the conflict without inventing a directory to hold it.

### The legacy `Infected` tree, and why its rows carry `predates_ruleset`

`trail-data/Infected` is not the current incident. It is many older servers and older
incidents, and it is **the material the first version of these rules was written against**.
Detection measured over it is therefore partly a test of the rules against their own source
material — CORPUS_PLAN §11 in a new place.

So every row imported from it carries **`predates_ruleset: true`**, and `index-summary.json`
carries the split:

```
malicious_reviewed        760      malicious_reviewed_excl_predates_ruleset   172
malicious_detected        122      malicious_detected_excl_predates_ruleset    60
        16.1%                                     34.9%
```

Both figures are true and they answer different questions. The field costs nothing to record
now and cannot be reconstructed once the rows are indistinguishable, which is the whole
argument for writing it at import rather than later.

`malicious_known_miss_by_family` is there for the adjacent reason: 495 of the 638 known
misses are a single 2017 doorway campaign, and a per-sample rate lets one family with many
files dominate a figure that reads as capability. A bare total cannot show that.

Three tools support the import, and the split between them is deliberate:

| file | needs the map? | what it does |
|---|---|---|
| `import-infected-tree.py` | yes | reproduces the denominator, refuses to run if it moved, sniffs content, triages media structurally, indexes archive members and never containers, classifies with the evidence recorded |
| `infected_mask.py` | yes | path masking, and `collisions()` — which proves *which* identifiers rewrite something they should not, against a real vocabulary |
| `verify-infected-mask.py` | yes | the independent check. Shares no regex with either masker |
| `gate_provenance.py` | half | stamps and checks what produced a gate verdict: an AST digest of the six deciding modules, and a digest of the maps' behavioural surface |
| `clearance.py` | no | whether a recorded human decision clears a given finding: the digest it is keyed to, the provenance it is pinned to, and the two tags no route may clear. A library — it never writes, and it needs no map, so a stranger can check every clearance in the published half |
| `clear-finding.py` | yes | writes one clearance, additively, under the lock. Needs the maps only to refuse a free-text reason that names a customer |
| `verify-and-stamp.py` | yes | re-verifies a row's recorded verdicts against the bytes it stands behind and stamps provenance only where they still agree; additive, and asserts it |
| `stamp-legacy.py` | no | gives a field written by a tool no longer in the tree an author, a date and a re-checked claim |
| `adopt-decoded-tags.py` | no | makes `sensitivity` describe the decoded form as well as the wrapper. Refuses a row with no `decoded_form_tags` rather than computing one, and prints the denominator it can see on every run |
| `remeasure-gates.py` | yes | writes the verdict the current gate returns where the recorded one disagrees, one row and one author at a time. The act `verify-and-stamp.py` deliberately refuses |
| `regen-tiers.py` | yes | recomputes a map's `mask_tier` against a vocabulary. Two assertions before it writes: the map's **contents** (`identifiers()`, `keep_tokens()`, `pairs()`, every other field, the tier key set) and what the tiers **mean** — coverage per changed name over a real path population, refusing a measured loss. Backs up first, preserves the file mode, re-asserts both after |

`incident_mask.py` is the same pair of jobs for the **current incident**, whose map and
identifiers are different. Its widths are measured rather than chosen: each identifier gets
the widest substitution its own collisions against the stock CMS trees permit, so a name
that is also an English fragment is masked as a whole word while a distinctive one is masked
anywhere in a token.

**That last claim used to read "both maskers rewrite nothing in the 158,675 files of
`trail-data/CMS` and `trail-data/CMS-ext`, which is what `--collisions` asserts", and
`--collisions` did not assert it.** Its attribution loop required `real != token.lower()`,
so the one case where an identifier IS a stock-CMS token was rewritten by `mask()` and then
dropped on the way to the report: the check printed zero while the masker rewrote a stock
token. One name in the current map is an ordinary five-letter English word that stock CMS
trees use as a filename token, and `tiers()` had given it `C` — leading boundary plus a
trailing non-letter — which fires on the whole word. `collisions()` now reports an exact hit
and an unattributable rewrite instead of dropping either, so `incident_mask.py --collisions`
reported **1**, truthfully.

`tiers()` was fixed in the same commit — an identifier that is exactly a stock-CMS token gets
`D`, positional-only, which is §5.3's rule for a colliding name — and that changed nothing on
its own, because tiers are computed once and stored in the map. **The regeneration was built,
run, measured and rolled back**, and the measurement is the reason this section is longer than
either "regenerated" or "not done" would be.

`regen-tiers.py` regenerated the map against the union of both trees. Of 134 identifiers
exactly one moved, `C → D`, and the other 133 reproduced their stored value; `trail-data/CMS`
alone disagrees on a second name, which is how the vocabulary the stored tiers came from was
identified. Every content assertion passed: `identifiers()` 232, `keep_tokens()` 3, `pairs()`
231 and every other field byte-identical. With the regenerated map `--collisions` read **0**.

**And the demotion was the wrong trade, measured.** A tier is a substitution width, so the
question a tier change has to answer is how many real occurrences each width reaches. Over a
census of 247,829 collected paths the `C` rule masks **29** occurrences of that name and the
`D` rule reaches **23**; over a 366,080-path population that also includes directory names,
34 against 30. The six it loses in the first population are the name as a filename prefix
before `_`, and the name between `-` and `.` — the `<account>_<something>` form that
incident-response directories and database dumps are named after, which is the same shape
§5.3 records as having hidden three client names for a year. The cost in the other direction
measures **zero**: over 48,256 `origin.path` values the name appears only as a substring of a
longer token, which `C`'s leading-boundary rule does not touch, and no stock-CMS token was
rewritten anywhere in either index. §5.6 holds that leaving a name costs everything and
over-masking costs nothing, and a measured six against a measured zero only goes one way.

**So the map is back at `C` and `--collisions` reads 1 again.** The regenerated map is kept
as `account-mapping.json.20260905-postregen.bak` so the census does not have to be redone.
The paragraph above it stands unchanged: `--collisions` reports 1 truthfully, and the 1 is a
real rewrite of a real stock token that the `C` rule performs.

**What the 0 would have meant is worth recording, because it is not what it looks like.**
Run against the pre-regeneration map — same name, same vocabulary, only the tier different —
`--collisions` reads 1, which is the positive control on the 0. But `vocabulary()` yields
bare tokens with no separator in them, and every tier-`D` rule requires one (`/home/`,
`_public_html`, `php\d\d-`), so **no `D`-tier identifier can ever be reported by
`--collisions`**. The 0 would not have meant the collision was resolved; it would have meant
the name had moved out of the check's reach. `--collisions` asserts that no `A`/`B`/`C`
identifier rewrites a stock token, and it is not evidence about `D` at all. That is the
second reason the rollback is cheap: the tier that reads clean is the tier nothing measures.

**The byte masker was never exposed to the stored tier**, and this is shown rather than
argued: `content_mask.ContentMasker` re-derives the tier from the vocabulary it is handed, and
masking a sample with the pre-regeneration map and with the regenerated map gives
byte-identical output while the masker's own count of tiers it had to demote drops 1 → 0. The
rollback therefore changes nothing about sample bytes — `mask-samples.py` always passes a
vocabulary, so the byte masker still treats that name as `D` while the row masker treats it as
`C`. **The two maskers disagree on this one name deliberately**, and the disagreement is the
design: over row fields a wrong tier over-masks a path segment, which is untidy, and over
sample bytes it rewrites a working identifier inside code, which is corruption.

**The guard that should have caught it now exists.** `regen-tiers.py` measures coverage per
changed name over a real path population before writing, and refuses a loss rather than
warning about it; `--allow-coverage-loss` is the override and it has to be typed. Re-running
the same regeneration today reports `C -> D masks 23 occurrence(s) where it masked 29 (-6)`
and exits non-zero. Seven content controls caught six mutations and were silent on this one,
because a demotion changes no identifier, no pseudonym and no key — it changes only what the
map *means*, and nothing was asserting that.

## Masking sample bytes

Three tools, mirroring the row-masking triple, and the split is the same one: the masker
needs the map, the check does not share the masker's patterns, and the driver runs all of
§5.6's checks rather than the one that is convenient.

| file | needs the map? | what it does |
|---|---|---|
| `content_mask.py` | yes | length-preserving substitution in sample bytes; **subclasses `incident_mask.Masker`**, so span selection is the same code and cannot drift between the two maskers |
| `verify-content-mask.py` | yes | the independent gate: plaintext, every statically decoded layer, and a differential secret check. Shares nothing with either masker |
| `mask-samples.py` | yes | masks a batch, runs all three gates plus per-sample detection parity, writes `masking` and only `masking` |

Every substitution is length-preserving and the masker raises rather than returning a
different length. A synthetic value carries a `mask…` marker wherever the identifier is long
enough to hold one plus three characters of entropy — the same positive-form discipline
`shard-gate.py` applies to rows, so a reader of shipped bytes can tell a masked account from
a real one. The marker is deliberately **not** `acct`, `site`, `srv` or `demo`: those are the
map's own namespaces, and an eight-character name masked to `acct1234` would alias a
pseudonym the map has already given to someone else. At two characters of entropy the
synthetics collided on the first run — `collisions_between_replacements()` caught it and
refuses to run — which is why the floor is three and not wherever it looked reasonable.

`mask-samples.py` will not record a pass it did not measure. Every `check` is per sample and
carries a **read proof**: an empty rule set is accepted as "scanned and clean" only when the
scanner also said so, and an unproven read raises rather than returning nothing. Parity is
measured between the original and the masked bytes staged under **identical basenames**, so
a filename-dependent rule cannot appear as a masking effect; the original is measured at its
collection path as well, and any disagreement is reported as a filename effect rather than
folded into the parity answer.

### Two things the identifier gates do not answer, and what was done about each

**A hex digest is not a secret just because it is a digest.** `content_mask.py` will mask
one, and does not by default. Every hex digest adjudicated in this collection was something
that must not be rewritten: two attacker file markers in comments, an example value in a
panel's own help text, and a host-binding hash the payload compares against the victim
file's contents at run time. No row's `secret` evidence names a hex digest — the evidence
names bcrypt hashes, literal passwords, wp-config credentials and salts — so masking one
destroys an IOC or a literal the sample's own logic depends on, for nothing. `--mask-hex-digests`
turns it on for a round that has real ones. The same reasoning, and the same default, applies
to `--mask-ipv4`: every dotted quad in these 39 samples was an RFC section number in a
vendored docblock or the unspecified address.

**The identifier gates say nothing about secrets, and a shape test cannot close that.**
§5.1 requires a secret to be replaced by a synthetic of the same shape, so the output still
contains something bcrypt-shaped and no test of the output alone can tell it from the
original. What is checkable is the **difference**: `secret_gate()` asserts that no
credential-shaped literal in the output is byte-identical to one in the input, over the
plaintext and every decoded layer. It needs no knowledge of whose secret it is, and it fails
loudly when a credential form the masker does not cover comes through untouched — which it
did, on an attacker password literal assigned to a `$pass` variable the masker's keyword list
did not have.

### The secret gate now fails in both directions, and the rule is the count

`secret_gate()` asserted that no credential-shaped literal in the output is byte-identical to
one in the input and said nothing about the count going **up**. One row recorded 23
credential-shaped literals after masking where it had 22 before and nothing in the tree asked
about it for a round. A gate that can only fail one way is the shape AGENTS.md opens with.

**The rule that was armed is the count, and the measurement chose it.** Two candidate rules,
both over the 132 masked local rows:

| candidate rule | rows it refuses |
|---|---|
| no literal in the output that was not in the input, excluding the masker's own marked synthetics | **46**, of which **36** are `secret`-tagged and so are hard refusals in `mask-samples.py` |
| more literals after than before | **1** |

The set rule is unusable and the cause is exact rather than statistical. §5.1 makes a
correctly masked credential a *new* credential-shaped literal, so the set grows every time
masking works — eleven wp-config literals go in on one row and eleven different ones come
out. The obvious repair is to exclude the synthetics the masker made, and the marker that
identifies them, `mask`, is only written by `_synthetic()`, which handles **identifiers**.
The masker's credential substitutions — `_value`, `_bcrypt`, `_phpass`, `_hex` — carry no
marker at all by construction, so a masked bcrypt is unattributable however long it is. That
is asserted rather than argued: `verify-content-mask.py --inject` proves `SYNTHETIC_MARKER`
equals the masker's constant and that a masked bcrypt moves and comes back unmarked.

The count rule is immune to all of it, because a replacement is one for one. Over the 132
rows the count rises on exactly one, falls on none, and holds on 131.

**What produced the one increase is not what the hypothesis expected.** Not a synthetic. The
masker changed **four bytes** on that row, inside one base64 region; the region re-encoded,
and the `base64+inflate` layers nested below it decoded differently. `secret_literals()`
counts over the plaintext *and every decoded layer*, and **that layer population is not stable
under masking**: 23 layers became 16, nine disappeared, two appeared, and one of the two
carries a ten-character `$GLOBALS['DB_NAME']['…']` array key that the `wp-credential` pattern
reads as a credential — the same shape false positive as the row's other 22, arriving through
a different door. So `before` and `after` were censuses of two different populations, which is
§11 one level down from where it usually lives.

Over the 132 rows the decoded-layer set moves under masking on **11**, and on ten of those the
literal count is unchanged, so the instability is common and the increase is not.

The two causes therefore get two owners and one reason each:

  * **the gate** fails on a carry-over (unchanged) and on an increase over a decoded-layer
    population that did **not** move — there, both counts speak for the same population;
  * **`shard-gate.py`** raises its own reason for an increase over a population that moved,
    read from the recorded evidence and independent of the tags. It blocks, because a
    "cannot tell" must not read as "fine"; and the gate stays silent on that case, because
    two reasons for one cause is the double-counted denominator that left the blocker tally
    14 out for two rounds.

`secret_literals_added`, `_by_the_masker`, `_unattributed`, `decoded_layers_before/after` and
`literal_population_comparable` are now recorded on every re-measured row: **measured and not
armed**, so the next round can decide the set rule against real numbers rather than against
the argument above. The one row the new reason blocks was already blocked, so no blocker tally
is flooded and no publishability moves.

`mask-samples.py`'s refusal message was fixed in the same change. It quoted
`secret_literals_carried_over` unconditionally, so on the second failure mode it printed
*"0 credential-shaped literal(s) survived masking unchanged"* — a refusal naming a cause that
had not happened, and zero of it.

This closes, for the rows it runs on, the hole recorded above as "the next round's job".
**The structural half is now closed too**: `shard-gate.evaluate()` requires
`masking.secret_gate == "PASS"` on a `secret`-tagged row whose masking is applied, and
records two distinct blockers — one for a gate that ran and failed, one for a row whose
masking predates the gate and carries no result at all. They are separate because the repair
is different: a FAIL is re-masked, an absence is re-measured.

The requirement sits **inside** the `applied` branch. A `secret`-tagged row with no masking
applied already carries "carries secret but no masking has been applied", and §8 counts
reasons rather than rows, so a second reason for the same cause is a double-counted
denominator — the shape that left the blocker tally 14 out for two rounds.

The population it lands on, measured against `index-local.jsonl` rather than assumed
(88 rows carry the tag, every one of them local, none in the published half):

| state | rows |
|---|---|
| masking applied, `secret_gate` records a pass | 46 |
| masking applied, no `secret_gate` — refused by re-measurement | 2 |
| `applied: false` with a `not_applicable_reason`, no gate | 8 |
| no masking record at all | 32 |

**The number this table replaces was 17, and it was stale rather than wrong.** It was written
into this file, into CORPUS_PLAN §7.2 and into CHANGELOG in the round that added
`mask-samples.py`. Two things are measured rather than argued. First, no reading of the
question yields it: seven variants of the predicate — any masking record rather than an
applied one, both halves, widened to `identity`, keyed on the row's secret evidence instead
of its tag — return 10, 13, 15, 15, 10, 8 and 51, and **none returns 17**. Second, every
other figure in that commit reproduces exactly against the index today — blockers `identity`
169, `path` 3, `identity/secret` 7, `secret` 31, encoded-layer gate 2, and 39 rows carrying
`masking.measured_with` — so the index still stands where that round left it, and a figure
from it that does not reproduce was taken when it stood somewhere else: before that round's
own `--apply`.

The mechanism is inference and is labelled as such. The blocker arithmetic closes on
17 → 15 if `identity/path/secret` stood at 2 before the round and the row that lost its
`secret` tag had no masking applied; on the other readings the pre-write count is 16. The
`index-local.jsonl.pre` snapshot cannot arbitrate — it predates the round by a day and a
quarantine review across which the `secret` population went 52 → 88. **A figure quoted in a
commit that also performs a write has to say which side of the write it was taken on**, and
that is the correction worth keeping.

Of the 15, thirteen were re-measured with `mask-samples.py` and cleared the secret gate;
**two did not**, each carrying one `wp-credential`-shaped literal that survived masking
byte-identical to its input. Those two keep `applied: true` from a superseded run and are
now blocked. That is the gate doing the thing it was armed for, on its first run, which is
the only evidence that it is a gate at all.

A shard's `MANIFEST.json` and its tracked copy in `expect/` both carry every sample's
`expect`, which is three places one answer can be written and two of them can be wrong
silently — `verify.py` reads `expect` from the **index**, so a stale manifest changes nothing
the suite prints. `make-shard-manifest.py` regenerates the index-owned half of a manifest
(`verdict`, `family`, `sensitivity`, `expect`, `technique`) and writes both copies from the
one text. The packaging half — which file holds the bytes, what it hashes to after masking,
the entry order, the prose note — is carried over from the stage and *checked*: the bytes are
re-hashed, and `masked: false` must mean the shipped hash equals the source hash. `size` is
the shipped file's size and comes from disk, never from the index row, which is the source
blob's size and differs wherever a payload was extracted onto a generated carrier.

Its control is that it reproduces every already-built manifest byte for byte from the
unmodified index. That is what caught both of the above while they were still wrong, and on
its first real run it also found `expect/malicious-db-dropin-001.json` a full round behind —
still declaring 46 samples undetected after the round that closed them, unnoticed because
nothing reads that file at run time.

`shard-gate.py` is the one that must **not** need the map, and does not: it asserts the
*form* of what is allowed (`acctNN`, `siteNN`, `srvNN`), so a stranger can run it.

**That map-free property leaves one hole, and `promote-gate.py` is where it is closed.**
Incident-response directories are named `<token>-<what was done>-<8 digits>-<6 digits>`, and
the leading token is an account name often enough to matter and an operation verb most of
the time. A published row carrying one leaks a customer, and neither map-free invariant sees
it: it is not an `origin` field and it holds no `/home<digits>/`. A *form* rule cannot close
it either — requiring that leading token to be a pseudonym flags **16,656** of the local
half's rows to reach the **2,425** that actually named a customer, 85.4% false positives, on
`live`, `ir`, `cross`, `renamed`, `post`, `orphaned`, `active`, `core`. The discriminator is
the map and only the map, so the check runs where the map is: at promotion, over the exact
text about to be written, recording category and count and never the identifier.

**Directory names live in the map, not in the tools.** `import-infected-tree.py` is tracked,
and a classification rule spelled `rel.startswith("<client>.gr/page/")` puts a customer's
name in git exactly as surely as an unmasked index row would. The map holds the names; the
tool reads roles. This is §5.3's "a field nobody thought of", one level out — it was not a
field at all, it was the tool's own source.

### A stored gate verdict now says what produced it

`shard-gate.py` read `masking.plaintext_gate == "PASS"` and trusted it, with nothing in the
row recording *when* it was measured or *by what*. A verdict from a version of the gate that
has since been tightened read exactly like one taken a minute ago. Re-gating by hand found
**5 of 95 local rows and 1 of 8 rows in the published half** sitting at `PASS` under a
predicate the current gate rejects — the samples had not changed, the predicate had, and no
field in the index could have shown it.

`measured_with` already existed and answers a different question. It records the scanner
binary, which is the right provenance for `detection_survived` and says nothing about the
masker or the identifier gate. **Provenance for the wrong question reads as provenance**,
which is why 52 rows looked accounted for and 90 looked like the whole problem.

`gate_provenance.py` stamps two digests. The `tools` digest stands at **`6fecbeebbccc`** and
the `map` digest at **`9268d21c394b`** over both maps; every one of the 139 stamped rows
carries that pair. It moved once this round, from `07079af767d4`, and the move is entirely the
note relocation plus the secret gate's second direction — the two changes were made together
precisely so the re-measurement is paid once.


| digest | over what | who can check it |
|---|---|---|
| `tools` | an **AST** of the six modules that decide spans and verdicts, docstrings stripped | anyone: they are tracked |
| `map` | the identifier list, the keep list and the tier table | only a machine holding the maps |

An AST rather than a file hash, because comments and formatting are absent from an AST by
construction: rewriting a docstring does not move it, and changing a regex literal, renaming
a local or adding a branch all do. A git commit was considered and rejected — every record
this round had to repair was written by an *uncommitted* working tree, so a commit id would
have been absent or, worse, confidently wrong.

`verify()` returns **three** answers, never two: `ok`, `absent`, `stale`. The `tools` half is
always required; the `map` half is checked only where the maps exist, and the result says
`map not checked` rather than passing quietly — §7.2's map-free invariants are a floor under
what a stranger can verify, never a licence to report a partial check as a whole one.

In `shard-gate.evaluate()` the question is asked **first** inside the `applied` branch,
because it decides whether the three verdicts below are worth reading. `absent` and `stale`
raise one blocker rather than two: §8 counts reasons and the repair is identical for both —
re-measure. The diagnosis is not identical, so it goes in the gate's own report line
(`masked rows by gate provenance`), which is printed on every run whether or not it is zero.

Two routes write it. `mask-samples.py` stamps it as a side effect of masking, which is right
for a row whose bytes can be re-masked. `verify-and-stamp.py` is for a row whose bytes are
already built — the published half — and it re-runs the gate over the bytes the row actually
stands behind, writing provenance **only where the current verdict equals the recorded one**
and refusing the row where it does not. Its write is additive and asserted to be: only
`provenance` and, where the row records no hash of its own masked bytes, `masked_sha256`.
Its own control caught the first version of that assertion looking only one way — it could
see an overwritten key and not an added one.

**And that assertion refused every row the tool had ever stamped.** `provenance` is a key the
row already has, so the additive check rejected it — which meant the tool written to keep
provenance current could not update it the instant the tools digest moved, and the only route
left was a hand-edit. `provenance` is now the one key that may be **replaced**, under
`--restamp`, and the report prints how many stamps are replacements rather than additions on
every run. The safety property was never the assertion: a stamp is written only where
`reverify()` says the current gate returns what the row records, so a replacement can restate
a verdict and never launder one. The control asserts all four halves — refused without the
flag, replaced with it, no second key allowed to ride along, and a row whose verdict *moved*
still refused.

### The gate is wider than the masker at tiers `B` and `C`, on purpose, and it shows

The masker's tier rules and the gate's leak predicate derive their boundaries independently —
that is the point of the split, and it means the two do not agree everywhere. They disagree in
one direction consistently:

* the masker at `B` and `C` requires `(?<![A-Za-z0-9])` before the name, so it will not
  substitute after a letter **or a digit**;
* the gate treats a name of six characters or more as a leak by containment, at any position
  at all, and a shorter one as a whole **alphabetic** run — which a preceding digit satisfies.

So `<alnum><name>` for a long name and `<digit><name>` for a short one are found by the gate
and cannot be masked at those tiers. A three-line control says it plainly: with the name
after a separator the masker rewrites it and the gate passes; with the same name after a
letter, or after a digit, the masker leaves it and the gate fails.

This is §5.3's "a gate that is stricter than the masker can be is a gate that can never pass",
standing rather than hypothetical, and it is the correct way round — a gate that could only
see what the masker already handles would certify nothing. What it means in practice is that
a `plaintext_gate` FAIL on such a row is a finding for a human, not a masker bug: either the
tier is too narrow for that name or the occurrence is one of the documented short-name
coincidences. It is also why a `plaintext_gate: PASS` recorded by an **earlier** gate is not
evidence: a gate that did not implement this predicate would have passed the same bytes.

### `acct<unmapped:XXXX>` — what it means and why 16 of them stay

A row carries `acct<unmapped:XXXX>` when the collection knew an account by its hash but no
map named it. It is already a pseudonym, so it is not a leak; it is a gap in the map.

The hash is `sha256(account_name)[:4]`, verified against all 85 known name/hash pairs with
zero disagreements — which is what makes the gap closable at all. Feeding it the 76 distinct
`/home*/<name>/` components from the whole-host manifest resolved **7 of 23** markers, every
one of them to an account the map *already* held. Those rows said "unmapped" while the answer
was on disk, so that was a masker gap rather than a map gap, and it is now substituted.

**The remaining 16 are not chaseable from anything this corpus holds.** Their account names do
not appear in the host manifest, which was taken after the incident: an account deleted or
renamed between compromise and collection leaves rows that reference it and a filesystem that
does not. Four hex characters is 65,536 values against 76 candidates, and there were zero
collisions, so this is a genuine absence rather than an ambiguity.

Do not resolve them by guessing. A wrong name attached to a real account's rows is worse than
no name, because it is indistinguishable from a right one afterwards.

### Tag `secret` from the bytes, not from the review

Thirty-one unreviewed rows carry a non-empty `DB_PASSWORD` literal — harvested `wp-config.php`
copies from a cross-account symlink farm, 15 distinct databases, plus auth salts. They were
held by exactly one lock: `verdict: unreviewed`.

One lock is not enough here, and the failure mode is the ordinary one rather than an exotic
one. The operator answers a review queue by setting a verdict and a sensitivity in the same
pass. Get the sensitivity wrong — type `c2` on something that also carries a secret, which
happened on a different row earlier the same day — and the row is publishable, because `c2`
is in `ALWAYS_OK` and buys a free pass through every masking gate.

So `secret` is now set on those 31 rows **from a content match, before any verdict exists**.
That is not the judgement a human owes: whether a sample is malicious is axis A and stays
theirs. Whether the bytes contain a password literal is a fact a tool can read, and it is the
floor under the judgement rather than a substitute for it. `secret` is not in `ALWAYS_OK`, so
it demands the plaintext gate, the encoded-layer gate and detection parity no matter what else
lands on the row.

The general rule this yields: **tag from the bytes wherever the bytes can be read, and reserve
the review for what they cannot settle.** A tag derived mechanically cannot be mistyped in a
hurry, and it survives a review that gets a different axis wrong.

### A `c2`-only row skips every masking gate, and the tag is the only thing stopping it

`evaluate()` computes `unmasked = tags - ALWAYS_OK - …`, and `ALWAYS_OK` is
`{"clean", "c2"}`. So for a row tagged `c2` alone, `unmasked` is empty and the whole masking
branch is skipped: no plaintext gate, no encoded-layer gate, no detection-parity check. A
human typing `["c2"]` is the entire distance between those bytes and a shard cleared for publication.

That is not hypothetical. One row from the 2026-09-05 operator review was tagged `c2` alone
while carrying an attacker password-gate hash — the class §7.2's secret scan must return zero
hits on over a shard cleared for publication. The scan cannot tell whose secret it is, so the tag has to
reflect what the scan will find, and the corpus's only other sample with that technique
already carried `c2+secret`. It has been re-tagged and is now blocked for the honest reason.

**The structural hole is still open and is the next round's job.** `shard-gate.py` reads index
rows, not bytes, so it cannot verify a content claim — the check belongs at publish time,
where the bytes are in hand. Until then: `c2` and `clean` are the two tags that buy a row a
free pass, so they are the two that need reading rather than trusting, and a review that sets
either should say what it read.

**Sized, so the next round can decide rather than guess.** 647 local rows are tagged `c2` and
nothing else. 637 of them carry no masking record at all — 8.8 MB of bytes no masking pass
has ever read, median 3.5 KB, largest 1.1 MB. 34 of the 647 are not blocked by the gate, all
in `quarantine/evidence`, and all 34 carry an `origin`, which the published half's own
invariant rejects — so none is promotable in its present form, and the exposure is a future
promotion that strips `origin` rather than anything standing today. The published half holds
30 `c2`-only rows, 2 of them with no masking record, both `undetected-pool-review` index rows
whose bytes are not shipped.

The independent leak predicate reports **0 hits over all 647**, and the power of that is
exactly what it says: a census of every string in every one of those rows, and *nothing about
their bytes*. Row text is not the hole. Closing it means reading 637 files, not editing a
gate, and the figure to beat is that no tool in this repository has ever opened them.

The general form, which this corpus has now paid for in three places: **a gate that trusts a
field is only as good as whatever wrote the field.** The publishability boolean drifted
because nothing asserted it against its source; the blocker strings drifted the same way; and
the sensitivity tag can drift because nothing asserts it against the bytes.

**The hole had its first concrete consequence, and the repair is not the one this section
proposed.** Five local rows recorded `masking.secret_gate: FAIL` and not one carried the
`secret` tag, so the rule armed the round before — which consults `secret_gate` only on a
`secret`-tagged row — never looked at any of them. Four were `publishable: true` with **zero**
blockers. Three of those four were tagged `clean` alone, which is in `ALWAYS_OK`, so `unmasked`
was empty and the whole masking branch was skipped as well: two independent tag conditions
between a recorded credential failure and a shard.

The fix is not to widen `ALWAYS_OK` or to re-tag the rows. It is that the two questions were
conflated:

  * *Does this row need a masking pass?* is a question about the **tags**, and it stays
    tag-driven, because that is what it asks.
  * *What did the gates that ran actually say?* is a question about the **bytes**, and it is
    now asked of every row that records a result, whatever the tags are.

A gate finding is evidence about the bytes; a tag is a claim about them. Conditioning whether
to read the evidence on the claim it might contradict is backwards, and it is the same shape
as the `c2`-only hole above — which is why widening the tag set would have moved the hole
rather than closed it. `unreadFailures()` asserts the resulting property independently of the
rule that produces it: **publishable, stored or computed, while holding a recorded non-pass
that no clearance covers, is impossible.** It is re-derived from the record and does not call
`evaluate()`, so an edit that reintroduces a tag condition breaks it without touching it.

`ALWAYS_OK` itself is unchanged and the 637 unread `c2`-only files are still unread. What
changed is that a tag can no longer silence a measurement that exists; it can still stop one
being demanded.

#### The five, read one at a time

Only one of the five is under-tagged for the reason the gate gives. Four are shape false
positives — and the brief that framed this round offered two possibilities where the bytes
show three, because a row can be under-tagged for a reason **other** than the finding that
exposed it. The published half holds none of these rows and no shard has ever been
distributed, so nothing here is or was exposed.

| row | carried literal | verdict |
|---|---|---|
| `0effe952c8ef` | a real bcrypt hash | **real credential; row under-tagged** |
| `361693ec4569` | a fragment of a regex literal | shape false positive |
| `b827cdd9d417` | 22 array-key names | shape false positive; **row under-tagged for other reasons** |
| `77fce772f1c6` | 95 bytes of C source | shape false positive |
| `34bba99dae63` | a UI label | shape false positive |

**`0effe952c8ef` — real.** Inside a `base64+inflate` layer, a 60-character `$2y$10$…`
assigned to `$stored_hash` and passed to `password_verify()` against `$_POST['password']`:
the shell's own gate credential. Masking recorded `changes: 0`, so the masked output is the
input and the hash is byte-identical in both — which is exactly what `secret_gate` measures.
The row's own `deobfuscation` block already said so: `decoded_form_tags: ["identity",
"secret"]`, `evidence_decoded.secret: ["bcrypt-hash", …]`. Its `sensitivity` is `["clean"]`
because it was taken from `encoded_form_tags`, which is `["clean"]` — the outer form of a
sample whose whole point is that the outer form carries nothing.

**`361693ec4569` — a shape false positive, on a credential harvester.** The one literal is
ten characters of regex syntax, captured because the `wp-credential` pattern found a
wp-config constant name inside a `preg_match` pattern in the sample's own source and read the
following `['"]` as the opening quote of a value. The sample extracts DB credentials from
`wp-config.php`; it contains the patterns, not the values. Its `sensitivity_evidence.secret`
names two wp-config constants and is the same false positive one level up — `sensitivity.py`
matches those constant names as bare substrings, so any file that *mentions* them is tagged.

**`b827cdd9d417` — a shape false positive, and the most serious row of the five anyway.** All
22 literals are configuration array-key names in an ALFA-family shell that uses a wp-config
constant name as its own `$GLOBALS` namespace; the pattern reads `…']["user"` and captures
`user`. No credential value is present. But the row's decoded layers carry
`decoded_form_tags: ["c2", "identity", "path", "pii", "secret"]` while `sensitivity` is
`["clean"]`, and **`pii` is in `NEVER`** — never publishable by any route — on a row that was
`publishable: true`. The `pii` hit is on `first_name`/`last_name` column names in a SQL insert
the shell uses to create its own admin user, so it is arguably a collision too; that is a
judgement for the operator, and it is recorded rather than made. Also worth noting:
`secret_literals_after` is 23 against `secret_literals_before` 22 — masking *added* a
credential-shaped literal, which no gate currently asks about.

**`77fce772f1c6` — a shape false positive.** A base64 layer holds C source for a bind shell:
`write(c,"Password:",9);`. The `quoted-credential` pattern matched `Password` `:` and then
took the string's **closing** quote as an opening one, so `[^'"]{4,}` ran 95 bytes to the next
quote three statements later. The shell compares the entered password to `argv[2]`; nothing is
stored.

**`34bba99dae63` — a shape false positive.** `password:"password"` in a jQuery-Terminal
string table, beside `login:"login"`. A UI label. The row was already blocked on the plaintext
and encoded-layer gates and is now blocked on this one too.

**The mechanism behind the two under-tagged rows is systemic, not a typo.** Both have a
`deobfuscation` block whose `sensitivity` equals `encoded_form_tags` while `decoded_form_tags`
is strictly larger, and `hidden_by_encoding` names the difference. Tagging a sample by its
outer form is tagging it by the thing the encoder was for.

### Sensitivity now describes the decoded form, and the ruling costs no publishability

`adopt-decoded-tags.py` applies the operator's ruling: **sensitivity describes what the sample
carries, including in its decoded form.** §5.4's premise is that an identifier inside an
encoded layer makes a sample unpublishable, so a sensitivity read off the wrapper is measuring
the wrong object.

Eleven local rows had `decoded_form_tags` the sensitivity did not cover. All eleven were
tagged `clean`, which is also what their `encoded_form_tags` say — so on every one of them the
sensitivity is the wrapper's. They are now `identity` (4), `c2` alone (3), `c2`+`secret`,
`c2`+`path`+`secret`, `identity`+`secret`, and `c2`+`identity`+`path`+`pii`+`secret`. `clean`
is dropped wherever anything else survives, which is `sensitivity.py`'s own contract.

**Nothing's publishability moves, and that is the result rather than a disappointment.** Six of
the eleven already had masking applied with every gate passing, so the tags they gain demand
gates that have already been measured and cleared. Three carry `c2` alone, which is in
`ALWAYS_OK`, so nothing was ever demanded of them and nothing is now — they are not movement
and are not counted as any. The two that are blocked stay blocked. The one substantive change
is on `b827cdd9d417`, which gains **`pii`**: it was blocked only on `secret_gate: FAIL`, which
is a *clearable* finding, and `pii` is in `NEVER` and clearable by no route at all. The row
goes from conditionally blocked to permanently held.

What the bytes say, read one at a time — every one confirmed against the source blob, and the
weak ones said to be weak:

| row | adopted | what the bytes show |
|---|---|---|
| `6c78797b8d1b`, `e194e5dbcadc` | `identity` | a **customer domain the map holds** inside a `base64` layer; the byte masker rewrites it. Supported |
| `fc1508dfb372` | `identity` | the same, a different customer domain. Supported |
| `084018700631` | `identity` | one address at a public webmail provider in a `hex-escape` layer. **The map holds no identifier matching it** — the leak predicate finds nothing — so this is `identity` in the sense of "an address is present", not "a customer is named". The weakest of the four, and it is still the right tag: `content_mask` rewrites every non-reserved address structurally, so there is something to mask |
| `137b7a4c1dea` | `c2`, `path`, `secret` | a whole `wp-config.php` inside nested `base64`: 11 `wp-credential` literals with real values, three `/home*/<acct>/` components, four external hosts. All three supported, strongly |
| `162ccc9adf4e` | `c2`, `secret` | `c2` supported (a raw-paste host). **`secret` is supported by one detector and not the other**: `sensitivity.py`'s `literal-password` matches `$hashed_password = '<32 hex>'`, the shell's own gate credential, while `verify-content-mask`'s `quoted-credential` requires no leading word character and so does not. Its `secret_gate: PASS` therefore means *nothing of my shape was here*, not *the secret was masked* |
| `4ab3e5387a75`, `aff0a5d71411`, `b92405d8ff16` | `c2` | one to three external hosts each in `base64` layers. Supported, and in `ALWAYS_OK` |
| `0effe952c8ef` | `identity`, `secret` | the real bcrypt in `base64+inflate` passed to `password_verify()`. `secret` supported beyond doubt; `identity` is one address at a privacy-mail provider, the attacker's own contact, so it is the `084018700631` case again |
| `b827cdd9d417` | `c2`, `identity`, `path`, `pii`, `secret` | `secret` is 22 array keys (shape FP, already recorded); `pii` is `first_name`/`last_name` **column names** in the SQL insert the shell uses to create its own admin user; `identity` is stock joke addresses at `fbi.gov`/`google.com`; `path` is `/home/alfa/` and `/home/user/`. Every one reads as a collision, and `pii` is unclearable anyway |

**The adopted value is a claim by an earlier pass, and `adopt-decoded-tags.py` cannot check
it** — that is what the table above is for, and it is why the tool refuses to compute
`decoded_form_tags` where a row has none. A `--fix` that writes the field it then trusts is
the tool agreeing with itself.

#### Is the population eleven, or is eleven what the comparison can see?

Measured, and it is the second. §11's rule — a denominator enumerated by the process that
produced the numerator bounds the result and not reality — applies twice over here, because
**both** the numerator and the denominator come from one pass's decoder.

| population | how enumerated | under-covered |
|---|---|---|
| 142 local rows carrying `decoded_form_tags` | the recording pass wrote the field | **11** |
| the same 142, re-derived from the bytes with the **gate's** decoder | this round | **20** |
| every stored-publishable local row (373; 366 resolved, 182 decode) | census | **31** |
| the 282 rows that pass recorded `undecodable` (281 resolved, 56 decode) | census | 2, both `c2`-only and both already blocked |
| the 84 published shipped-as-bytes rows (76 resolved, 14 decode) | census | 2 |

The middle row is the whole answer. Over the *same* 142 rows the gate's decoder yields
**6,120 layers against the recording pass's 318** — 19× — and the re-derived tag set is
**strictly wider on 13 rows and narrower on none**. Two of the thirteen carry more than `c2`:
one gains `c2`+`identity`+`secret` and one gains `identity`, both `publishable: true` today.
So `decoded_form_tags` is not a property of the bytes; it is a property of the decoder that
wrote it, and the eleven is bounded by that decoder rather than by the corpus.

**What would have to be true for the real number to be larger** is exactly what the third row
tests, and it is true: that rows outside the 142 also carry more in their decoded form than
their sensitivity says. A census of every stored-publishable local row finds **31**, and five
of them are worse than anything in the eleven — `1438674b06d8`, `c24465d301e2`,
`e50d85a3a815`, `eba16e1e9159` and `cd98180175a5` are `publishable: true` with **no masking
applied at all**, and the current gate fails their encoded layer with `exact`-position hits on
identifiers of 7, 8, 10, 19 and 23 characters. An `exact` hit on a 19- or 23-character
identifier is not a base64 coincidence. One of them decodes to a WordPress `usermeta` SQL dump
and a contact block carrying a customer domain the map holds and a telephone number.

Those five are **not** re-tagged here. Adopting a tag set this round's own re-derivation
produced would be trusting a field because it is there, one level up, which is the defect the
ruling repairs. What they need is the masking pass none of them has ever had, and that is a
round's work with a scanner in it. The eleven are the operator's ruling applied to what the
record holds; the thirty-one is the size of the question.

**Power.** Every figure above is a census of a stated population, not a sample, so none of them
carries a sampling error — and none of them bounds reality either, because each population is
still one the corpus chose. 7 of the 373 publishable local rows and 8 of the 84 published rows
are excluded: the first seven exceed the 4 MB read cap this census used (6.8 MB to 279 MB),
and the eight have no blob resolvable through `blobmap-all.jsonl`. Those fifteen rows are
unmeasured, not measured clean.

**The two under-covered published rows are collisions, and reading them is what says so.**
Both are `media-polyglot` fixtures tagged `c2`+`path` whose decoded layer yields `identity`,
and in both the whole basis for it is a hardcoded attacker callback address in a URL inside a
`base64+inflate` layer — `sensitivity.py` tags `identity` on any dotted quad, which is the
retracted-IP defect recorded above in its original form. The tag that fits is `c2` and both
rows already carry it. **No published row is under-tagged in a way that matters**, and that is
a census of all 84, not a sample of them.

### Reading a recorded gate verdict: `!= "PASS"` was right by accident

`shard-gate.py` tested every gate field against the string `PASS`. That fails closed on any
other value, which is the correct direction — and it cannot tell a `FAIL` from a value it does
not understand, and cannot say which it saw. Two forms in the index are neither:

  * **six rows store `encoded_layer_gate` as a dict** — `{"result": "FAIL",
    "distinct_identifiers": …, "kinds": …, "occurrences": …}`, between 2 and 64 occurrences of
    `acct` and `dom` identifiers inside encoded layers. This is an older schema: the modern
    finding dict sits in a **sibling** key (`encoded_layer_finding`) and has no `result`.
  * **twelve rows store the string `SKIPPED-oversize (>1MB): held, not published`** — not a
    verdict at all, but a gate that never ran.

**Neither was being read as a pass, and neither was being read at all.** `{"result":"FAIL"} !=
"PASS"` is `True`, so the comparison would have produced the blocker; what stopped it is that
all eighteen rows carry `masking.applied: false`, and the whole masking branch sat inside
`if unmasked: if applied:`. The blindness was the tag/`applied` condition again, not the
comparison. Measured rather than assumed: every one of the four value forms was run through
the real `evaluate()` and every one produced `encoded-layer gate did not pass` when the branch
was reached.

**The dict form predates every tool in this tree.** It is present at 15 rows in
`trail-data/incoming/2026-09-03/index.jsonl` (2026-09-04 11:53) and at 15 in the 2026-09-04
16:33 backup, and at 0 rows in both generations of the published half. It came in with the
2026-09-03 collection import; no surviving tool from that import writes it, and the two that
touch the field (`promote-staging.py`, `derived/promote-round.py`) write the string form. Last
round did not introduce it. **15 → 6 has a cause:** nine of the fifteen were re-masked in the
2026-09-06 re-measurement, and `mask-samples.py` overwrote the field with the string form — 7
to `PASS`, 2 to `FAIL`. The remaining six were never re-masked (`applied: false`,
`local_only: permanent`) and still carry the original.

`gate_result()` now classifies rather than compares, and the fourth class exists so a form
nobody anticipated cannot be silent:

| class | what it is | blocker |
|---|---|---|
| `pass` | the string `PASS`, or a dict whose `result` is | none |
| `fail` | the string `FAIL`, or a dict whose `result` is | *X* gate did not pass |
| `skipped` | a string saying the gate did not run | *X* gate was not run: … |
| `unreadable` | everything else — a bool, a number, a list, a dict with no recognised `result` | *X* gate result is not a recognised verdict and is not read as a pass |

Three classes rather than one because the repair differs: a FAIL is a human decision, a SKIP
is to run the gate, and an unreadable value is to find out what wrote it. `verify-and-stamp.py`
now shares this parser; its own `_norm` read any truthy non-string as `FAIL`, which is
fail-closed and cannot distinguish a dict recording `PASS` from one recording `FAIL`.

**`applied: false` means two different things, and the discriminator is which key is set.**

| form | rows | what the gate fields are |
|---|---|---|
| `reason: "no identifier to mask…"` | 123, all published | measurements. The gate ran over the collected bytes and found nothing, so nothing was changed |
| `not_applicable_reason: …` | 29, all local, all archive containers | a recorded **decision** that masking is impossible |

Only the second disqualifies a field, and only one field: `detection_survived`. All 29 store
it as `false`, which is a placeholder for a measurement nobody took rather than a report that
masking destroyed detection — reading it as the latter would attach 29 rows to a cause that
never happened, which §8 forbids more specifically than it forbids missing one. Their **byte**
gates are still read, and that is where the twelve `SKIPPED` rows now block. Two of those
twelve are tagged `clean` alone and were held by nothing but a `local_only` marker; they are
the "blocked by coincidence" case exactly.

### The human clearance — an escape hatch recorded as a thing, not as a gap

Some gate findings are collisions and no predicate that can see one can decide it. The
encoded-layer predicate produces 127 false positives over 8,000 stock CMS files, and the case
that killed its confidence grade was real. Before this round the only ways to act on that
judgement were to hand-edit `publishable` (which §4.4 forbids and `staleness()` catches), to
edit the tag so the gate stops asking (the defect this round is repairing), or to loosen the
predicate for everybody.

A clearance is a row-level record with `gate`, `finding_digest`, `by`, `at`, `reason` and
`gate_provenance`. `corpus/clear-finding.py` is the only writer; `corpus/clearance.py` holds
the rule, so it is readable by someone not running the writer.

| constraint | how it holds | control |
|---|---|---|
| keyed to the **specific** finding | digest over the gate, its recorded verdict and the evidence beside it | a clearance against a changed profile blocks — **and** re-signed against the changed profile it clears |
| does not carry to another gate on the same row | the gate name is in the digest payload | encoded-gate clearance leaves the plaintext blocker standing; a plaintext one clears it |
| invalidated when the gate provenance moves | the `tools` and `map` digests are pinned by value, compared to the row's | tools moved → blocks; map moved → blocks; re-judged → clears |
| cannot apply to `pii` or `content` | structurally there is no finding to key to, **and** checked outright | a clearance on such a row clears nothing, both tags |
| counted where it can be watched | `index-summary.json` carries `cleared_by_human_rows`, `_findings`, `_by_gate`, `published_…` | `make-summary.py --check` |
| `publishable` stays **computed** | the clearance is an input to `evaluate()`; nothing writes the boolean | a second, uncleared blocker survives the clearance |
| a `--fix` cannot manufacture one | `recompute()` writes three fields | asserted |
| only a **finding** is clearable | `CLEARABLE_GATES` is the four recorded gate results | a verdict, a `local_only` hold or an unapplied masking pass is work to do, not evidence to judge — and the provenance blocker is excluded by the same rule, since clearing it would be circular |

Two failure modes, deliberately not the same: **malformed** (missing author, empty reason, a
gate that is not a finding) exits non-zero, because a clearance nobody can read is a decision
the record has lost; **inert** (the digest matches nothing, or the provenance moved) is the
mechanism working and is printed with a count on every run, because a clearance that has
stopped applying looks from a distance exactly like one that has not.

`clear-finding.py` also refuses a reason that matches an identifier from the maps, reporting
the **length** and never the name. The reason is free text a human types into a file that is
tracked in the published half, and AGENTS.md records five separate occasions in one day where
a client name reached git through prose. It reports lengths because a refusal that quotes the
collision has put the name in a terminal and, if anyone pastes it, in a commit message.

**The first two clearances are recorded, and they are the mechanism's first real run.** Both
are on `34bba99dae63`, both adjudicated by the operator, both entered with a reason written by
shape: the encoded-layer finding is the imagick case — a 6-character label as the middle
syllable of a standard ImageMagick PHP function name inside an alphabetically ordered table of
that extension's functions — and the plaintext finding is three occurrences of one 3-character
label inside base64 ciphertext where the measured null expects 1.08, p about 0.10 under
Poisson. `index-summary.json` reads `cleared_by_human_findings: 2`, `cleared_by_human_rows: 1`,
`cleared_by_human_by_gate: {encoded_layer_gate: 1, plaintext_gate: 1}`, and
`published_cleared_by_human_rows: 0`.

**The row is still not publishable, and that is the point.** It also carries `secret_gate:
FAIL`, which nobody cleared, so a second uncleared blocker survives the clearance exactly as
the design requires. Two of its three blockers went; the third stayed.

#### Re-measured 2026-09-06, and both findings are unchanged in shape

Last round's gate repair moved the tools digest from `6fecbeebbccc` to `83735611dab4` at commit
`194e969`, which made **both clearances inert** — exactly as designed, and confirmed rather than
assumed by re-running `gate_provenance.stamp` at each commit in the range. A clearance is keyed
to one finding measured by one set of tools, and both are allowed to move.

So the findings were re-measured against today's gate rather than the old reason being copied
forward under a new digest. The masked bytes were **regenerated and hash-verified** to the
recorded `masked_sha256` first (the file left on disk from an older pass hashes to something
else), so what was measured is the file the row stands behind:

| | encoded-layer | plaintext |
|---|---|---|
| recorded | 1 identifier, len 6, 1 occurrence, `begins`, segment 25 | 1 identifier, len 3, 3 occurrences, `contains`, segments 19/70/74 |
| today | **identical in every field** | **identical in every field** |

**A clearance that can be transplanted is not a clearance.** These two are re-signable because
a fresh measurement produces the same finding, not because the old reason still reads well.

#### The secret-gate evidence went stale under a current stamp

The row records `secret_literals` 1 / 1 / 1 and `masking.provenance.tools: 83735611dab4`, the
current digest. Today's gate returns **2 / 2 / 2**. Re-running the pre-repair gate from
`d548b3e` over the same two files returns 1 / 1 / 1 — matching the row exactly — so the payload
was produced by the superseded predicate while the stamp beside it is current.

Neither tool is at fault and both would do it again: `verify-and-stamp.py` compares gate
*verdicts* and `FAIL` did not become `PASS`, so it stamped; `remeasure-gates.py` compares
verdict *classes* and refuses where none moved, so it will not rewrite it. **Nothing in the
tree compares the evidence**, and a finding payload can therefore go stale beneath a stamp that
appears to certify it. Recorded as open.

The extra literal is the second `quoted-credential` on the row, found only because `194e969`
removed the pattern's left boundary so `$user_password` would be caught. Both literals sit in
the same 119,508-byte `base64+inflate` layer and both are carried over unchanged: one is the
19-byte jQuery-Terminal UI label already recorded above, and the other is a 15-character
English prompt ending in `!`, under a camelCase key ending in `Password`, between two sibling
message strings of the same form. Neither is a credential; the gate fails on *unchanged*, not
on *present*.

`corpus/secret-fp.py` is the null those readings are weighed against — the tracked
`SECRET_SHAPES` predicate over stock CMS trees, which carry no customer credential by
construction. It is a separate file precisely because `verify-content-mask.py` is inside
`gate_provenance.TOOLS` and a new flag there would move the digest and invalidate every stamp
again. Over **32,000 stock files**: 343 credential-shaped literals, 230 of them
`quoted-credential`; the first literal's class (`kw=password`, 8–15 chars, no space) is **59 of
230 — the largest class in the null** — and the second's (same but containing a space) is **9 of
230**, with 87 of 230 containing a space at any length. **State the power:** at 8,000 files the
second class showed **0 of 109**, which excluded nothing — the expected count there was ~2.8 and
P(zero) ≈ 6%. The 32,000-file figure is the one to cite.

### Three findings recorded for a decision, and not decided here

Three gate findings were on the operator's desk. Each is recorded on its row with the full
profile the gate produces; what follows is the decoded context a person needs to read them,
identifiers replaced by `<id:Nc>` and never spelled out. **None is decided in this file.**

**Two are now cleared and one is now judgeable.** The operator ruled both findings on
`34bba99dae63` collisions and both clearances are entered, taking the count from 0 to 2 on 1
row; the row remains blocked on its uncleared `secret_gate`. `3529f0f6b2cd` was re-measured
first, in that order and for the reason below, and its `FAIL` is now on the row — so it can be
judged, and has not been.

#### `3529f0f6b2cd` — published, and the record and the measurement disagree

The row's stored `masking` says `plaintext_gate: PASS` and `encoded_layer_gate: PASS`. Run
today over **the bytes actually inside `malicious-outside-webroot-001`** (sha `782a8924be8a`,
the masked output the manifest names), the current gate returns `plaintext_gate: PASS` and
`encoded_layer_gate: FAIL`.

**The FAIL was never written to the row, and that is the provenance stamp working exactly as
designed.** `verify-and-stamp.py` writes provenance only where the current verdict equals the
recorded one; here it does not, so the row got no stamp and is blocked on
`gate results have no usable provenance`, not on the finding. A tool that had written the
`FAIL` in would have flipped a `publishable` in the published half on its own authority. The
blocker is honest and the finding still needs recording, which is what this is.

| | |
|---|---|
| gate | `encoded_layer_gate` |
| layer path | `base64`, decode depth 1, 98,473 bytes decoded |
| distinct identifiers | 1, `acct` kind, **3 characters** |
| occurrences | 1 |
| position | `contains` — at offset 63 of a 97-character segment |
| the segment | 97 characters of base64, bounded by `+` on both sides |
| where the segment is | 72,564 characters into a single unbroken 97,600-character base64 run |
| what surrounds it | more of the same run; there is no other structure at that depth |

The segment reads as base64 ciphertext throughout, and the label sits in the middle of it.
The row's own note says the original gate read this same ~98 KB stage, so what moved is the
predicate and not the reach.

**This row could not be cleared, and that was the mechanism being consistent rather than
obstructive.** `clear-finding.py` refused it — `encoded_layer_gate recorded a pass; there is
nothing to clear` — because the row's stored value was `PASS` and a clearance is keyed to a
recorded finding. A clearance signed against a pass would pre-approve whatever the gate said
next. So the order for this row was fixed: **re-measure first**, which writes both the `FAIL`
and the provenance, and only then judge what it says. Judging a finding the record does not
hold is the same defect as trusting a `PASS` nothing measured, one level up.

**The re-measurement is done and the record now holds the FAIL.** `remeasure-gates.py` exists
for exactly this act and is deliberately not part of `verify-and-stamp.py`: stamping says
*these tools produced this verdict* and is additive and safe in batches, while re-measuring
says *the verdict has changed* and rewrites a recorded measurement in a tracked index. It
takes one `--sha`, an author, and the sha256 the bytes must hash to, and it refuses a row
where nothing moved. Run over `782a8924be8a` — the masked output the manifest names — it
reproduces the profile above to the digit: one 3-character `acct` identifier, `contains`, in
a 97-character `base64` segment, with `plaintext_gate` still `PASS`.

#### `34bba99dae63` — local, blocked, two findings of very different shape

`plaintext_gate: FAIL`, three occurrences of one 3-character `acct` identifier:

| occurrence | segment | position | where |
|---|---|---|---|
| 1 | 70 chars, bounded `/` … `+` | `contains`, offset 15 | 41,570 chars into a 44,284-char base64 run |
| 2 | 74 chars, bounded `/` … `/` | `contains`, offset 50 | 63,694 chars into a 158,124-char base64 run |
| 3 | 19 chars, bounded `+` … `+` | `contains`, offset 16 | 101,667 chars into the same 158,124-char run |

All three are the same shape as `3529f0f6b2cd`'s: a short label inside base64 ciphertext,
where the "segment" boundaries are base64's own `+` and `/` characters rather than anything
structural.

`encoded_layer_gate: FAIL`, one occurrence of one **6-character** `acct` identifier — and
this one is a different animal:

| | |
|---|---|
| layer path | `base64+inflate`, 473,603 bytes decoded — **0.0% of it base64**; it is PHP source |
| position | `begins` — offset 0 of a 25-character segment, bounded by `_` on both sides |
| the segment | `<id:6c>tructimages\|imagick` |
| its neighbours | `…\|imagick_cropthumbnailimage\|imagick_current\|imagick_cyclecolormapimage\|imagick_decipherimage\|imagick_<id:6c>tructimages\|imagick_deleteimageartifact\|imagick_despeckleimage\|…` |

**This is the imagick case.** It is the specific hit CHANGELOG records as having killed the
encoded-layer confidence grade — "a six-character account name inside `imagick_…` in a 473 KB
decoded PHP function table" — and the layer size matches to the byte. The entry sits in
alphabetical order between two neighbouring `imagick_` functions, in a table of them.

#### The power of each judgement, and which null belongs to which

Two nulls, and using the wrong one is how the withdrawn confidence grade went wrong in the
first place (§11: a denominator enumerated by a process that does not resemble the population
bounds the result and not reality).

**For a hit inside base64 ciphertext**, the base64 null applies. Regenerated this round with
`verify-content-mask.py --base-rate --trials 660` — 660 trials of 98,473 bytes of random
base64 through the real predicate and the real 288-identifier set:

  * short-name rule fired in **108 of 660 trials (16.4%)**, mean **0.182 hits per trial**
  * the containment rule (6+ characters) fired **once in 660** — 0.0015 per trial, and with a
    single observation the 95% upper bound is about 0.0045

Scaled to the actual layers by base64 bytes:

| finding | comparable bytes | expected by chance | observed |
|---|---|---|---|
| `3529f0f6b2cd` encoded | 98,473 (0.99× the null blob) | **0.18** short-name hits | 1 |
| `34bba99dae63` plaintext | 581,931 across 34 runs (5.91×) | **1.08** short-name hits | 3 |

So neither is far outside what random base64 of that size produces. That is a statement about
surprise and not about truth: the null cannot tell you this particular occurrence is a
coincidence, only that occurrences like it are common at this scale.

**Re-run 2026-09-06 under the moved tools digest, and it reproduces to the digit**: 660 trials,
108 with a hit (16.4%), mean **0.1818** short-name hits, containment **1**, and the length
split 109/6/1 at 3/4/6 characters. This matters because the plaintext clearance entered on
`34bba99dae63` cites those numbers as its reason, and a clearance resting on a figure that had
quietly moved would be a judgement about something else. 0.182 × 5.91 = 1.08, which is the
expectation the reason quotes.

**One figure does not reproduce and its cause is not established.** CHANGELOG records the
short-name arm at 0.23 hits per trial; the same command, same fixed seed, same map digest
(`9268d21c394b`, unmoved since) and the tools digest that round ended at
(`07079af767d4`; it has since moved once, to `6fecbeebbccc`, for the note relocation above)
reads **0.18**
today, and reads 0.18 at 60, 0.13 at 100 and 0.18 at 660 trials, so it is not a trial-count
difference. The containment arm reproduces exactly at 1 in 660. The ratio the argument rested
on survives — about 120:1 rather than 150:1 — and the grade it supported was withdrawn anyway,
so nothing downstream moves; but the 0.23 should be read as unreproduced rather than as
measured.

**For the 6-character `begins` hit, the base64 null does not apply at all** — its layer is
0.0% base64. The right null is the stock-CMS table, regenerated this round with `--stock-fp`
over 8,000 stock CMS files that carry no customer of ours by construction, so every hit is a
false positive:

| | recorded in `FP_NOTE` | regenerated 2026-09-06 |
|---|---|---|
| false positives | 127 | **127** |
| files with a hit | 104 of 8,000 (1.3%) | **104 (1.30%)** |
| position split | 83 `exact` / 20 `begins` / 24 `contains` | **83 / 20 / 24** |
| from identifiers of 6+ characters | 36 | **52** |

**Everything reproduces except the last row, and its cause is exact.** 36 is `begins` (20)
plus `contains` at 6+ (16); it omits the **16 `exact` hits at 6+**, which the summary line
includes, giving 52. Both are true of different questions. The note states the narrower one
without the qualifier its own docstring keeps — and that matters here specifically, because
the finding being weighed *is* a 6-character `begins` hit, and all 20 `begins` false positives
in the table come from identifiers of 6+ characters. The note understates the population this
hit belongs to by 16.

**The constant is corrected, and it has moved out of the behavioural digest.** `FP_NOTE` was
a module-level assignment in `verify-content-mask.py`, one of the six modules in
`gate_provenance.TOOLS`, so every word of it sat inside the AST the `tools` digest is taken
over: correcting four characters of prose moved the digest and put all 139 stamped rows into
re-measurement. That is why a figure known to be wrong stayed wrong for a round. **A
descriptive note is not behaviour and must not be able to do that.**

It now lives in `corpus/fp-note.txt`, which the digest does not read, and the note states the
split it was missing: 52 from identifiers of 6+ characters, of which **16 `exact`, 20 `begins`
and 16 `contains`** — regenerated today with `--stock-fp`, along with every other figure in
the note (127 hits, 104 of 8,000 files, 1.30%, 83/20/24). All 20 `begins` false positives come
from identifiers of 6+ characters, which is the population the finding on the desk belongs to.

Relocating it moves the digest **once** and then never again, which is the whole argument for
paying the re-measurement now. Three assertions in `gate_provenance.py --inject`, and the
obvious one is the weakest of the three:

  * rewriting `fp-note.txt` must not move the digest — true, and it would also be true of a
    module that ignored the file entirely, including the one this replaced;
  * the loader must actually follow the file, proved by pointing `_load_fp_note` at a
    different one;
  * the note's prose must be **absent from the AST the digest reads**, which is the direct
    statement and the one that fails against the pre-change tree.

Run against the pre-change modules the second and third read `IGNORED` and `PRESENT` and the
suite fails; the first reads `held` and passes. That is why there are three.

### The five `clean` rows, ruled on and written — and what each one's evidence actually is

Five local rows sat `publishable: true` with zero blockers, tagged `clean` alone and with no
masking record. The cause is one cause: `sensitivity.classify()` has no decoder and `clean`
is its **default branch** — `if not tags: tags.add("clean")`. Four are gzip streams and the
fifth hides its payload in a base64 literal, so every regex in the rule saw compressed noise.
The tag was not a judgement about these samples; it was the absence of one.

`corpus/tag-sensitivity.py` writes the operator's ruling, and refuses to write one that the
re-derivation over the row's own bytes does not support, or that leaves a re-derived tag
unadjudicated. `publishable` stays computed by `shard-gate.py`. Identifiers below are
described by shape; the evidence is on the rows in `sensitivity_tagged`.

| row | ruling | what decided it |
|---|---|---|
| `cd98180175a5` | `path` | a stock `template-loader.php` (3,143 B) with `@include base64_decode(…)` prepended. The 96-character literal is its only layer and decodes to 72 bytes holding one absolute path of the form `/home/<8-char account>/public_html/…/<16 hex>.ttf`. 0 URLs, 0 e-mail shapes, 0 dotted quads anywhere in the file, so nothing else is proposed. |
| `eba16e1e9159` | `c2`, `identity` | gzip → 118,904-byte posts-table dump. Exact map-identifier hits at lengths 8, 19 and 23, all 0/8000 in the stock null; the database is named after an 11-character token whose first 8 are an exact account identifier; one customer host (2-label). `identity` here rests on the customer host, not on the rule's e-mail branch — there are no e-mail shapes at all. 8 external hosts, none recognisable public infrastructure. |
| `e50d85a3a815` | `c2`, `identity`, `path`, `secret`, `pii` | gzip → 2.78 MB full-site dump, 58 layers. 37 tables including users/usermeta/comments; 415 e-mail occurrences over 13 domains, 2 of them customer domains; one `phpass-hash`; two `/home*/<x>/` slots, one an exact 8-character account identifier. **`pii` is in `NEVER`: this row is permanently unpublishable, index row and hash only.** |
| `c24465d301e2` | `c2`, `identity`; **`pii` rejected** | gzip → 675,278-byte posts table. One customer host (2-label) is what fires `identity`; database named after a 10-character token prefixed by a 7-character account identifier; 52 external hosts, none public infrastructure. `pii` fired on `form-field` alone, 34 times over spam post content — attacker-generated filler, not visitor data. Rejected on that reading; actual submitted values turning up later would be new evidence, not a re-opening. |
| `1438674b06d8` | `identity`; **`pii` rejected**, **`c2` unresolved and left off** | see below. |

**`1438674b06d8` — the account name is in the tar headers and nowhere else.** gzip → 5,027,840-byte
tar, 256 members (222 regular files) under one top-level directory:

```
tar members                         : 256
distinct uname / gname values       : 1 / 1, equal, 8 characters, an exact map identifier
distinct (uid, gid) pairs           : 1
members whose PATH contains it      : 0
members whose BODY contains it      : 0
```

A member-level content scan sees nothing at all; only reading the container's own metadata
finds it. This leak form is one nothing else in the tree looks for, and it is invisible to
content masking by construction — §5.5 forbids touching the container and the identifier is
*in* the container rather than in any member.

**The rule's own evidence for that tag is different, and wrong.** `classify()` fires
`identity` on `cust_hosts or emails or ips`; here that is 81 e-mail shapes across 44 domains,
upstream contributor addresses in a translation-credits file, **0 of them on a customer
domain**. The tag is right and the rule's reason for it is a false positive, which is exactly
why the evidence is written onto the row rather than left implicit in the tag.

`pii` is one occurrence — the word `phone` in a `readme.txt` changelog line, measured across
all 222 regular members. `c2` is **unresolved and the tag is left off**: not one of the five
`C2_HINTS` markers fires anywhere in the archive, so the tag would rest entirely on the
"any external host" branch. 73 external hosts, 0 customer hosts, 17 matching a
public-infrastructure keyword list, and all 73 occur in member bodies belonging to one
upstream file-manager plugin — its cloud-storage volume drivers and its documentation. There
is no separable campaign code to attribute the remaining 56 to. `c2` is in `ALWAYS_OK`, so
leaving it off costs no publishability; adding it wrongly would put a false tag on the row
for nothing.

### The `c2` ruling on `1438674b06d8`, and the rule it generalises to

**Ruled: leave it off.** Recorded in `corpus/taggings/2026-09-06-c2-ruling.json`, written onto
the row, and stated as a rule in CORPUS_PLAN §4.1 — `c2` requires evidence of attacker
control, never the presence of an external host, because the tag is in `ALWAYS_OK` and
therefore buys a free pass through every masking gate rather than merely labelling a sample.
The measurement that decided it is the negative one: **0 of the 5 `C2_HINTS` markers fire
anywhere in the archive**, which is a stronger statement than any argument from the host list.

**Two defects in `tag-sensitivity.py` came out of writing that ruling, and both are repaired
with controls.**

* **A later ruling erased the record it amended.** `build()` wrote a fresh
  `sensitivity_tagged`, so applying the ruling took the tar-header finding — a measurement
  that exists nowhere else — off the row. Prior `evidence` and `human_basis` are now carried
  forward with the new ruling winning per key, the record being replaced is kept whole under
  `supersedes`, `originally` carries the pre-first-ruling tags past a one-level chain, and
  `assert_additive` **refuses any write that drops a recorded evidence key**. That last one is
  the check that would have caught it.
* **A ruling that changes no tag could not be written at all.** The tool refused it as
  "nothing would move", which would have left the row saying `UNRESOLVED` after a person had
  ruled — the stale-record defect this corpus keeps finding, in the one field whose purpose is
  to say what a human decided. A ruling that closes a hold is now a legitimate write, and
  `--restate` re-derives a record from a decision file it *already agrees with* so a gap can
  be filled without editing the row: it may change no ruling and must add something.

**The residual cost is recorded rather than papered over.** The row's top-level record now
reads `was: ["identity"]` and `originally: ["identity"]`; the literal `was: ["clean"]` from
the first write is gone, because it was destroyed before the repair existed. What survives on
the row is the substantive fact — `derived.raw_tags: ["clean"]`, the machine reading over the
bytes — plus the `cause`, the tar-header evidence and the superseded record. The fix stops it
recurring; it does not undo it.

### Four of the five are archives, and `not_applicable_reason` is now written from the repo

§5.5 excludes archives from content masking entirely, so four of the five can never have the
masking pass their tags demand. That decision is `masking.not_applicable_reason`, which 29
rows already carried and **nothing in this tree wrote** — `mask-samples.py` reads it and
refuses a row that has one.

The obvious repair was the one `sensitivity.py` got: find the untracked original and
reproduce it. **It is not available here, and the difference is the finding.** No `.py`
anywhere on this machine writes the string, and `git log --diff-filter=A` puts the first
commit of `mask-samples.py` a day *after* the rows appeared. The writer was never saved.
There is nothing to hash and no behavioural probe that could be run against it, so
`corpus/mark-not-maskable.py` re-derives the *claim* instead: it re-reads the container magic
from the bytes (`gzip` on all four), records what it read and the sha256 it read it from, and
refuses a row whose bytes are not a container — which is what happened to the fifth, a PHP
file, on the live run.

It deliberately does **not** write the seven other masking keys the 29 legacy rows carry
(`plaintext_gate`, `encoded_layer_gate`, `detection_survived`, `changes`, `change_kinds`,
`length_preserved`, `c2_kept`). Those are measurements and this tool takes none of them;
copying them to make the new rows look like the old ones would be manufacturing a measurement.
`--census` prints both populations so the difference is visible rather than discovered. The
reason string is the 29's verbatim except for its final `Held local-only.`, which these rows
have not earned.

**It clears no blocker, and that is correct.** `shard-gate`'s "carries *tag* but no masking
has been applied" is driven by `applied`, so an archive carrying an unmaskable identifier
stays unpublishable permanently. Publishability moved by 0 rows.

### The field census: three orphans were three because nobody had counted

Three fields have been found one at a time, a round apart each, by somebody noticing. The
question *how many more are there* had never been asked of the whole index, and it is
mechanical. `corpus/field-provenance.py` parses every tracked module in `corpus/` and asks,
for every field the rows actually carry, whether any of them can be shown to **write** it —
`r["k"] = v`, a dict literal, `setdefault`, `pop`, or a module-level `KEY = "k"` written
through — as opposed to merely mentioning it in `d.get("k")`.

That distinction is the whole subject: `mask-samples.py` contains the literal
`not_applicable_reason`, so any grep-based census would have called that field covered while
the defect stayed open, and `--inject` asserts exactly that.

```
fields carried by rows        135   (9 value-keyed maps not descended into)
  written by a tracked module  89
  only READ by tracked modules  1
  mentioned nowhere            45
```

**45, not three.** `written` is an over-count — a name in a write position might belong to
some other dictionary — so `ORPHAN` is an under-count: every field it reports is really
unaccounted for and there may be more. Two denominators are bounded by their own process and
both are stated on every run: the fields are enumerated **from the rows**, so a field every
row has since lost is invisible (`masking.encoded_layer_gate_uncapped` was an orphan on 3
rows when `stamp-legacy.py` was written and is on 0 today), and the modules are enumerated
from `corpus/*.py`, so a field written by a tool since deleted reads as an orphan.

Three conditions hide under one phrase, and they need different repairs:

* **the author exists and is untracked** → reproduce it and prove the reproduction
  (`sensitivity.py`, `deobfuscate.py`);
* **the author is gone** → re-derive the claim from the bytes and record who did
  (`stamp-legacy.py`, `mark-not-maskable.py`);
* **the author never existed** → the field is a convention, and the repair is to stop
  treating it as a measurement.

### The gate's two credential narrownesses, repaired, and what it cost

`verify-content-mask.SECRET_SHAPES` had no PEM shape at all, and `quoted-credential` opened
with `(?<![A-Za-z0-9_])` while the tagger's `literal-password` has no left boundary — so a
password on a variable whose name *ends* with the keyword was tagged and never gated, and
`pwd` was not a keyword here at all. §5.6 already rules that a lookaround should err towards
over-matching and records two leaks from one that did not; this was the third. For a
**differential** gate, over-matching is the strict direction: every extra literal is one more
thing masking must have changed, so widening cannot make this gate laxer.

Both are in `gate_provenance.TOOLS`, so the repair moved `tools_digest` from `6fecbeebbccc`
to `83735611dab4` and put all 140 stamped rows into re-measurement. **That bill was paid in
full and it is worth recording what it actually was**, because it is the price of every
future repair to a TOOLS module:

| | |
|---|---|
| stamped rows invalidated | 140 |
| masked bytes on disk | 73 |
| masked bytes **regenerated and hash-verified** from the originals | 132 of 142 (3 mismatched, 7 record no `masked_sha256`) |
| rows re-stamped | 139 (7 published, 132 local) |
| rows left `stale` | 1 published (`3529f0f6b2cd`), no reachable bytes |
| rows that lost `publishable` for the length of a commit | 34 |
| human clearances made inert | 2, both on `34bba99dae63` |

`corpus/restage-masked.py` is what made the middle row possible. `content_mask.mask_sample`
is deterministic in (bytes, map, vocabulary, flags), so the masked form can be regenerated
and then **checked against the `masked_sha256` the row already records** — a regenerated file
that hashes to it is not a plausible reconstruction, it is the same file. One attempt is
made with the driver's own default flags; a mismatch is reported as a finding about the row
rather than retried under other flags, because a tool that searched until something matched
would manufacture the provenance claim it was asked to check.

**Two tools were re-measuring two of the three gates their stamp claims.** `verify-and-stamp`
re-ran `plaintext_gate` and `encoded_layer_gate` and said nothing about `secret_gate`, which
is produced by a `TOOLS` module and was therefore always inside the stamp's claim; the same
hole was in `remeasure-gates`. It mattered the moment the credential shapes moved: the digest
moved for a change to exactly the verdict neither tool could see, and a re-stamp would have
written a fresh stamp over rows whose recorded `secret_gate` the current tools do **not**
produce. Both now take the pre-masking bytes and re-measure the differential, and both return
**three** answers — `agrees`, `disagrees`, `cannot-check` — because a row nobody could measure
and a row that disagrees need different work.

**Six rows go `PASS` → `FAIL`, four of them publishable.** Of the four "real divergences"
recorded last round, two moved, two do not exist, and four more were found outside the
population that was searched:

| row | was | tags | what the repair changed |
|---|---|---|---|
| `162ccc9adf4e` | `publishable: true` | `c2`,`secret` | **verdict.** 0→1 literal, carried over. The one the brief named. |
| `fa4356393880` | `publishable: true` | `clean` | **verdict.** Tagged `clean`, so no rule ever asked it for a secret gate. |
| `b839772db7c7` | `publishable: true` | `c2` | **verdict.** `c2` is in `ALWAYS_OK`; nothing was demanded of this row at all. |
| `91d2ee9cdd6d` | `publishable: true` | `c2`,`identity` | **verdict.** 0→2 literals, both carried over. |
| `e29dba8fde17` | blocked (unreviewed) | `secret` | **verdict**, on a row that was already blocked. |
| `47e9334ce266` | blocked (unreviewed) | `c2`,`secret` | **verdict.** Passed over *two* literals while a third was invisible — outside the "zero literals" predicate entirely. |
| `80d78e0b4ece`, `a0830cd1a181` | blocked | | **evidence only.** Already `FAIL`; carried literals 1 → 6 each. |
| `24d902d48a0d`, `bba931abc09d` | blocked | | **nothing.** These are the two "PEM blocks": 34 `BEGIN … PRIVATE KEY` markers each, **0 `END` markers**, 32 of them inside docblock prose in a vendor crypto library a scan report quotes. No key body, so no value for any gate to compare. The PEM shape requires a complete block precisely so it does not fail them on documentation. |

**The power of that re-measurement.** 132 rows record a `secret_gate`; before/after bytes
exist for **132 of 142 masked rows** after regeneration, so the sweep is near-complete rather
than the 64-of-132 it would have been from the surviving stage directories alone. The 10 rows
outside it (3 regeneration mismatches, 7 with no recorded `masked_sha256`) are unmeasured, and
at the observed rate of 6 movements in 132 rows one further movement among them would not be
surprising.

### The second decoder is now tracked, and the two vocabularies are reconciled

`deobfuscation.decoded_form_tags` on 142 rows was written by
`trail-data/incoming/2026-09-03/deobfuscate.py` — untracked, 3,208 bytes.
`corpus/deobfuscate.py` reproduces it, asserts behavioural equality against the original over
11 probes carrying no customer identifier, and reports `ok`/`moved`/`absent` for the
reference rather than passing quietly where it is missing.

Two vocabularies for one operation is how two artefacts that claim to be the same thing stop
being the same thing, so `METHOD_ALIASES` states the correspondence and `reconcile_methods()`
measures it:

```
hex-escape + octal-escape  ->  escape        two recorder names, one tracked name
rot13                      ->  (none)        a branch the gate's decoder does not have
(none)                     <-  raw-inflate   and the reverse: the tracked decoder finds a
                                             zlib/gzip stream anywhere in the bytes, the
                                             recorder only inflates what base64 produced
```

The names are only half of it. Every threshold differs too — base64 runs `{40,}` against
`{16,}`, hex strings quoted-`{40,}` against unquoted-`{24,}`, `chr()` `{4,}` against `{6,}`,
texty `>0.85` against `>0.80`, depth 6 against 4 — and the recorder does not de-duplicate
layers by content while the tracked decoder does. Measured over the **8 of 142** rows whose
bytes are reachable here: 357 recorder layers against 380 tracked, `hex-escape` 304 +
`octal-escape` 12 against `escape` 337, and the two layer counts agree on **2 of 8** rows. A
sample of 8 in 142 detects a discrepancy present on 10% of rows only 57% of the time; what
these 8 establish is that the disagreement is common, not what its rate is.

**It is kept out of `gate_provenance.TOOLS`, and not for last round's reason.** The argument
for putting it in is real and should be stated: `sensitivity.py` was excluded because "a
tagger produces no gate verdict", and a decoder is not a tagger — the encoded-layer gate *is*
a decoder plus a predicate. Measured, the premise is false for this module: every
`decode_layers` call in the gate path resolves to `verify-content-mask.decode_layers`, which
is already in `TOOLS`, and nothing in `corpus/` reads `deobfuscation` except
`adopt-decoded-tags.py`, which writes `sensitivity` — a publish blocker, not a gate verdict.
`TOOLS` is not a list of important modules; it is the claim that editing a file invalidates
stored gate verdicts, and this round has just measured what that claim costs. Spending it on
a module that cannot alter one of those four verdicts would make the digest the thing people
route around. And `TOOLS` would not address the real hazard anyway: it would say "the decoder
changed", never "the two decoders disagree" — which is what `--reconcile` is for.

### `pending-promotions.jsonl` — measured by one side, applied by the other

A rules round measures which `known_miss` rows its new rules now detect. It does not flip
them: all index writes go through the corpus side, so a rules agent that also wrote the index
would be two hands on one file. The measurement has to survive the gap between the two, and a
number that lives only in a report does not — it is in a session scratchpad that gets cleared.

So the rules side writes `corpus/pending-promotions.jsonl`: one row per sample, its sha256,
the exact rule codes `check` returns for it, which index half it is in, and its publish
blockers if any. The corpus side applies rows from it and **deletes each row as it is
applied**. When the last row goes, so does the file. A non-empty file means work is owed; an
absent file means none is.

Each row's `now_detects` is measured per sample with `check`, never inferred from a batch
scan, because `expect.must_detect` is compared to `check`'s output exactly and a batch scan
does not tell you which rule fired on which file.

Rows in the `local` half usually cannot be promoted immediately even though the detection is
real: their blockers are masking and review, which are independent of whether a rule fires.
That is why the file records the blocker rather than just the sha256 — otherwise the next
reader has to re-derive why 34 of 75 did not move.

`promote-pending.py` is the applier, and it treats the file as a handoff rather than an
authority: every row is re-measured with `check` against the **shipped** bytes in the shard,
and a row whose measurement disagrees with what it recorded is refused rather than written.
An empty measurement on a row the file says now fires is a hard refusal that names the
binary, because that is what a build made before the round's rules looks like — it promotes
nothing and reports zero newly detected, which reads as a result rather than an error. A row
whose `publish_blockers` are non-empty is deferred with the blocker quoted back, never
resolved here; resolving one is masking or review, which is somebody else's job.

A promotion rewrites exactly one field. `expect.known_miss` and `known_miss_reason` become
`expect.closed_known_miss` — date, the rule that closed it, and verbatim the reason the row
used to give — and `must_detect` becomes the measured set. Verdict, publishability,
sensitivity and masking are untouched: a promotion is a statement about detection and about
nothing else.

### Any writer of either half goes through `indexio.py`

`write_jsonl_atomic` for the write, `index_lock` around a read-modify-write. Not a style
preference — both were paid for on 2026-09-04, when two sessions worked this tree at once.

`shard-gate.py --fix` used to `open(path, "w")`, which truncates a 62 MB index before the
first row lands. A concurrent reader measured 48,407 rows, then 14,148, then 79,467 — three
moments of one write, and indistinguishable from corruption from the outside. It also saw
fields that "appear nowhere in my sources" and were gone seconds later: another session's
merge, half-written. The round stopped and reported possible corruption, which was the right
call on the available evidence and cost the round anyway. **The tell is a
`make-summary.py --check` that passes in one instant and fails the next.**

The second failure mode did not fire and is the worse one. Two writers each doing a
read-modify-write of the whole file means the last one silently drops the other's rows, and
**every gate still passes** — a half-merged index is internally consistent, so no integrity
check can catch it. Only the lock can.

`python3 corpus/indexio.py --selftest` reproduces the torn read against the old write and
shows it absent from the new one. It keeps the control on purpose: a test that only proves
the new path is clean cannot tell you the old path was the cause.

`reason` is a short code rather than prose, to keep the file a reasonable size:

| code | meaning |
|---|---|
| `stock-cms-hash` | byte-identical to a file in the pinned stock CMS tree |
| `pinned-benign-hash` | byte-identical to a file in a source pinned in `benign/sources.jsonl` |
| `stock-cms-hash-resolved-prior` | as above, and it resolves a prior corpus row that was tier `unverified` |
| `media-polyglot` | media container carrying executable code |
| `media-clean-not-published` | structurally clean media: no code, so a false positive or customer content |
| `staging-directory-review` | a human opened the whole directory, confirmed it is attacker staging, and the sample passed both gates |
| `doorway-kit-review` | a human read one legacy-tree doorway kit end to end — deployers, generator, installed `.htaccess`, templates — and ruled on the whole kit |

## The benign half is fetched, not shipped

Of the 44,544 published rows, **44,460 are reproducible from a pinned source or from the
stock CMS tree** and are therefore *not* shipped as blobs — they are an index row plus a
lockfile entry. **84** samples *would* ship as bytes if a shard were released: 7 polyglot fixtures, 67 staging samples, 8
doorway-kit samples and 2 outside-webroot wrappers.

That is the point of §6: the benign half is a lockfile and a script, so anyone can
regenerate it and get the same false-positive number, instead of taking ours on trust.

```
corpus/fetch-benign.sh              # download, verify, unpack
VERIFY_ONLY=1 corpus/fetch-benign.sh   # re-check hashes already on disk
corpus/fetch-benign.sh --inject     # the control: prove the hash gate can refuse
```

`benign/sources.jsonl` currently pins **136 sources**: 87 WordPress plugins, 22 themes,
24 WordPress core versions including deliberately old ones because an outdated core is what
a real host looks like, and 3 trees of rendered HTML.

**The versions are derived, not chosen.** The first 86 sources pinned each slug at whatever
upstream shipped that day, which pins the version a host is *least* likely to be running.
The 50 added in round 11 were read off the installed copy on a collected host — a plugin's
main-file `Version:` header, a theme's `style.css` header, core's
`wp-includes/version.php` — and every one of them was confirmed by measurement rather than
by argument: a version derived wrongly resolves nothing, and each of these resolved
between 4 and 3,300 rows. Pinning them mechanically decided a further **32,272 rows**, of
which 7,843 were sitting in quarantine directories while being ordinary stock code.

**Deriving a version is not the same as being able to pin it.** 32 component versions
across 27 slugs were identified on the collected hosts and could not be pinned: premium
plugins and themes never distributed on wordpress.org, agency-built and site-specific
code, one plugin whose directory was closed upstream, and two whose exact installed
version wordpress.org no longer retains. They account for **17,667 blobs that no pinned
source reaches**, and they are the reason this pass closed 32,272 rows rather than 50,000.
Substituting a nearby version for the two that are merely unretained would be a guess that
looks like work — a version pinned on a guess that happens not to match is
indistinguishable from one that was never pinned.

**`kind: rendered-html` exists for one reason and it is a measurement, not a corpus gap.**
The stock trees are almost entirely source, so a discriminator keyed on `<title>` and
`<meta>` had 12 files in 207,311 that could ever have matched it — a 25% rule-of-three
bound dressed up as a zero. Three Texinfo-generated GCC manuals are now pinned, two that
carry the meta tags and one older build that does not, which turned that bound into a
measured 97.6% and closed `docs/RULE_CANDIDATES.md` §4. The third is a **control**: without
a rendered-page tree that is *not* at risk, "rendered pages match" and "all HTML matches"
are indistinguishable.

A hash mismatch in `fetch-benign.sh` is a hard failure, never "probably a new version":
upstream may have been replaced. The archive kind is read off the URL — `.zip` and
`.tar.gz` — and a suffix the script does not recognise is refused rather than passed to
`unzip` on the assumption it is close enough.

### `resolve-benign.py`, and the 92% it implements

92% of everything ever closed in this corpus was closed by exact hash against a pinned
source; 8% by human review. Until round 11 the 92% had **no committed implementation** —
it was done by an ad-hoc script in a collection directory, so `pinned-benign-hash` appeared
as a reason code on thousands of published rows and nowhere in the repository. A mechanism
that decides tens of thousands of rows has to be readable by whoever audits those rows.

What it will and will not do:

  * it closes a row only while the verdict is `unreviewed`. A human verdict is never
    overridden by a hash;
  * it **supersedes** a sensitivity tag rather than overwriting it, and records what the
    tag was. 829 rows carried `content`, `c2`, `identity`, `secret`, `pii` or `undecidable`
    and were byte-identical to a pinned release anyway — vendored SDKs contain API hosts
    and key material, and plugin releases contain images. The tag described the bytes
    correctly and their owner incorrectly, and hash identity is what settles it: the same
    bytes are downloadable by anyone from the same pinned URL;
  * it builds the published row from a **whitelist**, so it cannot carry an `origin`. Four
    rows once did, because a promotion copied the whole local row and removed what it
    remembered to remove;
  * it prints separately every row whose collecting scan had already flagged it. Those are
    **false positives on upstream code**, not closures to wave through — 25 of them this
    round, and they are why the pinned `known_fp` list went from 6 sha256 to 31.

## Shards

`shards/malicious-polyglots-001.tar.zst` — 6 masked polyglot samples and 3 clean-carrier
precision fixtures, 128 KB. Expectations in `expect/malicious-polyglots-001.json`.

`shards/malicious-staging-001.tar.zst` — 67 samples from 14 confirmed attacker-staging
directories, 3.0 MB, in 7 families: a fake-plugin loader that keeps its payload in files
named as images, a WooCommerce card skimmer, a self-hiding fake core plugin, a forged
update-header request gate, a forged-plugin auto-login backdoor, a fake theme of raw zlib
blobs, and a timestamp-named theme stager. Expectations in
`expect/malicious-staging-001.json`.

**Twenty-three of the 67 are `known_miss`** — real malware this scanner does not detect at
the recorded version. It was 64 of 67 when the shard was built, which is the point of
shipping them: the corpus previously measured recall over six samples it already found.
`OBF041` closed 40 of them and `CRED007` one, all promoted in one batch on 2026-09-05 and
recorded per row as `expect.closed_known_miss`. See `docs/RULE_CANDIDATES.md` §2.

`shards/malicious-outside-webroot-001.tar.zst` — the two hex-digest wrappers from `/var/tmp`
that `docs/KNOWN_ISSUES.md` issue 3 rests on. Polymorphic siblings in two different accounts;
each rewrites a plugin inside the webroot while keeping three state files outside it. Both are
`known_miss`. Account paths masked length-preservingly, both gates pass over the plaintext and
the ~98 KB decoded stage, detection parity verified per sample.

These two rows carry a **`placements`** field, which exists because of them. The index is
content-addressed and kept one example path per blob; these blobs have 16 and 14 paths, and the
one shown was an IR quarantine copy. `/var/tmp` — the placement that is the entire finding —
was invisible. `placements` records the count per placement class, so a placement-based claim
has something to rest on.

`shards/malicious-doorway-kit-001.tar.zst` — the eight executable and template components
of one 2017 SEO doorway kit from the legacy `Infected` tree, 12 KB. Three deployers, three
generators and two presentation templates, shipped **as collected**: the independent gate
found nothing to mask in any of them, in the plaintext or in the raw bytes, and the
encoded-layer audit finds no region able to carry an identifier. Five are `known_miss`; the
three deployers are the samples `BD018` closed, promoted in this shard's first round. This
is the corpus's first published material from the legacy tree, so every row carries
`predates_ruleset: true` — detection over them is partly a test of the rules against their
own source material, and the summary reports the figure both ways for exactly that reason.
Expectations in `expect/malicious-doorway-kit-001.json`.

`shards/malicious-polyglots-002.tar.zst` — one fixture plus one clean carrier. A 510-byte
"Priv8 Uploader" PHP block injected straight after a real image's JFIF header and terminated
with `__halt_compiler()` so PHP ignores the ~140 KB of image that follows. The image is
customer content and is **not** shipped: the payload is paired with a generated 166-byte
baseline JPEG. Parity was measured rather than assumed — original `OBF036`; payload alone
nothing; generated carrier alone nothing; generated carrier plus payload `OBF036`.

Nothing in the staging shard was masked, and that is a result rather than an omission: the
independent identifier gate found nothing to mask, in the plaintext or in any of the 40
statically decoded payload layers. Detection parity therefore holds by construction — the
bytes are the bytes that were collected.

Every sample in it is a **generated carrier plus an extracted payload**: no customer image
or document bytes are present, verified by confirming no 64-byte run is shared with the
original outside the payload itself. The clean carriers exist to pin the other direction —
a valid PNG, GIF or PDF must produce no findings at all.

### On the format

`.tar.zst`, per §7. The choice is about **decompression speed for a runner reading one
sample at a time**, which is the property xz is worst at, so the format is not up for
renegotiation because a dependency is missing.

`build-shard.sh` therefore treats a missing `zstd` as a **hard failure** and prints the
install command, exactly as `fetch-benign.sh` does for `jq` and `sha256sum`. It does not
fall back to another compressor: a silent fallback is how two artefacts that claim to be the
same shard stop being the same shard.

### On the password

Every `<shard>.tar.zst` has a `<shard>.tar.zst.zip` beside it: the same archive inside a zip
with the passphrase `infected`. All eight shards are wrapped this way, not just the polyglot
one this section used to name.

The passphrase is deliberately public and documented here, because §7.1 is explicit: **if CI
can open the archive, so can anyone.** It is not a confidentiality control and must never be
treated as one. It buys three real things: GitHub's and AV vendors' scanners stop flagging
the repository as malware-hosting, contributors' endpoint AV stops quarantining files on
clone, and casual scraping and accidental execution get harder.

**Masking is the actual control.** Nothing enters a shard unmasked, which is what
`shard-gate.py` and `shard-census.py` exist to enforce — the first over the index, the second
over the archives themselves.

So the purpose is settled and it is the first of the two readings: **anti-scanner, not
confidential.** The passphrase therefore travels with the shard, in this file, in the release
notes and in the build script's own output. A shard nobody can open is not published either.

#### What a consumer does with one

```
unzip -P infected malicious-polyglots-001.tar.zst.zip   # -> malicious-polyglots-001.tar.zst
sha256sum malicious-polyglots-001.tar.zst               # compare with the release note
tar -I zstd -xf malicious-polyglots-001.tar.zst         # -> MANIFEST.json, samples/, carriers/
```

`MANIFEST.json` is the shard's own copy of every member's `expect`, and
`corpus/expect/<shard>.json` in this repository is the tracked copy of the same thing. They
are byte-identical by intent.

**These are live malware samples.** They extract read-only (mode 0400) for that reason. Do
not place them under a web root or anywhere a PHP handler can reach.

#### Which hash certifies the shard

**The `.tar.zst` hash, never the `.zip` hash.** The tar is reproducible: `build-shard.sh`
pins member order, mtimes, ownership and permissions, and `--selftest` asserts that two
builds of the same content agree through perturbed stage metadata. The zip is not
reproducible and cannot be made so — ZipCrypto prefixes every entry with a randomised
12-byte encryption header, so three wraps of one byte-identical input give three hashes,
measured. A `.zip` hash proves a file arrived intact from one upload; it says nothing about
whether the contents are what was built. Verify by unwrapping and hashing the tar.

## Running the suite, and the review-round workflow

```
corpus/verify.py                      # full run
corpus/verify.py --skip-benign        # fast: skips the 146k-file benign sweep
corpus/verify.py --json               # machine-readable
corpus/verify.py --update-baseline    # re-baseline after a review round
```

**Batch your reviews, then re-baseline.** This is a workflow consequence of the guard in
§8, and it is worth choosing rather than discovering.

Every batch of human review moves samples out of `unreviewed` and into the recall
denominator. The suite correctly refuses to compare recall across a changed denominator — a
figure over a set that grew is not the same measurement — so it withholds the delta and says
why. That is the right behaviour, and it has a consequence: **reviewing in many small
batches means never seeing a comparable recall figure**, because the denominator moves every
run.

So:

- review in **larger, less frequent batches** when a comparable trend matters;
- or run `--update-baseline` **once, deliberately, at the end of a review round**, which
  makes the new set the reference point that subsequent runs compare against.

What not to do is re-baseline on every run to make the withheld delta go away. The
withholding is the signal that the population changed; suppressing it by moving the
reference point each time gives a smooth-looking series that compares nothing.

The same applies to the benign side, though less often: adding sources to
`benign/sources.jsonl` changes the false-positive denominator, so the FP *rate* before and
after a lockfile change are also not directly comparable.

### `make-summary.py --help` used to overwrite the summary

The dispatch was `if "--check" in sys.argv: … else: write`, so `--help`, a typo, or any flag
added later fell through to the **write** path. The one irreversible thing this tool does was
the thing it did when it did not understand you, and the file it writes is the denominator
every suite run quotes. `dispatch()` now returns an error for anything it does not recognise;
`--inject` asserts all nine cases, including `[]` still meaning *write* — a dispatch that
errored on everything would pass a suite made only of negatives.

It is also now on the pre-report list in AGENTS.md. `--check` was the one gate not run before
round 13 was reported green, and it was failing: the round moved 9 rows out of
`local_only_publishable_no_blocker` and 2 clearances out of `cleared_by_human`, and the
summary still asserted the old counts. The two `shard-gate` runs cannot see that, because they
read the index and not the summary.

## What is deliberately not here

- **Archives.** §2.3: not corpus data. Members are collected individually and archive
  fixtures are generated, never harvested. Byte-masking an archive corrupts it — see §5.5.
- **`pii` and `content` samples.** Not maskable, so never published; index row and hash only.
- **Samples that did not decode.** Held permanently: absence of a plaintext identifier in an
  obfuscated file is evidence the encoder worked, not evidence the file is clean.
