# Corpus changelog

Written for people **using the published malware corpus**: what is in a shard, what the index
records, how a figure was measured, and what changed about any of it.

Versions here are the **corpus tags**, `corpus-YYYY.MM.N`, cut per review round — not the `v*`
scanner tags in [`../docs/RELEASING.md`](../docs/RELEASING.md). The two series move on
different cadences on purpose: the scanner versions on rules, the corpus on review rounds, and
a round that rules 525 samples malicious without touching a rule is a corpus release and not a
scanner one.

**Which file covers what**

| this file — `corpus/CHANGELOG.md` | [`../CHANGELOG.md`](../CHANGELOG.md) |
|---|---|
| the index, both halves, and its denominators | detection rules, by rule code |
| shards: what ships, masking, publication gates | the CLI, its flags and exit codes |
| tooling under `corpus/` | report and output formats |
| corpus-wide measurement rounds and detection coverage | binary releases, tagged `v*` |
| corpus documentation (`SOURCES.md`, `CORPUS_PLAN.md`) | anything that changes how you invoke the scanner |

A rule's own entry — what it matches, what it measured — is in the scanner changelog. The
corpus-wide coverage figure that moved when it landed is here, because that denominator is the
corpus's and moves without any rule changing.

This file starts at `corpus-2026.09.1`, the first corpus release. Everything before it lived in
`../CHANGELOG.md` under `Unreleased`, which meant that file was asserting *unreleased* about
work that had shipped. Those entries were **moved here, not copied**: two changelogs describing
one round is the same problem one level up.

Figures quoted in `README.md` and `corpus/SOURCES.md` are generated from
`corpus/index-summary.json` by `corpus/doc-figures.py`. Figures in *this* file are history: they
are correct as of the round that recorded them and are deliberately never regenerated.

---

## Unreleased

### Fixed

- **`corpus/verify.py` reported a false-positive rate over whatever the host let the scanner
  open, and counted what it could not open as clean.** The denominator was `totalFilesScanned`,
  which counts a file the scanner reached and could not read; the clean count was that minus
  the matches. A file the host withheld was therefore in the denominator with no finding
  against it — clean without a byte read. A directory the walk could not list, a root gone
  mid-scan and an interrupted walk were recorded and asserted nothing, and a scan refused
  before it started for a missing root was read as zero samples and `n/a` with no failure.
  Harmless on Linux today — zero unreadable entries under the pinned trees, by `find` — and
  not on Windows, where Defender withholds files during the scan and chooses which.

  The suite now **refuses the figure** and records a failure when the report carries any
  unreadable file, any unlistable directory, a missing root, an interruption, or when there is
  no report; and discloses, without refusing, what the scanner's own policy declined — over
  the size cap, excluded — which leaves the denominator. The rule is who chose the shortfall:
  policy is reproducible and part of the figure's definition, a host's refusal is neither.
  **The denominator is now files read**, so the next measurement will be smaller than the
  197,559 in `README.md` by the count of files over the size cap; that difference is
  attributed here in advance and is not a change in the scanner.

  The malicious half had the same defect one level down: `check` exits 1 for a file it cannot
  read, and the suite read only the rule list off stdout, so an unreadable sample was an empty
  list — a miss on a `must_detect` row, *still missed* on a `known_miss` row, clean on a
  `must_not_detect` row and *newly fixed* on a known false positive, three of the four green.
  The exit code is read first now; an error is counted under `unscanned`, listed under
  failures, and is never a verdict. `--inject` (41 cases) asserts every refusing channel
  refuses, every policy channel does not, and — with the real scanner over a real tree — that a
  file the user cannot read refuses the figure and the same tree with access restored reports
  again. `control-suites.py` discovers it on its own: 42 suites, from 41. CORPUS_PLAN §11
  records this as the fourteenth instance.

  **A report that lacks a channel is refused too, and the control found why that matters.**
  Run against `build-release/`, the first end-to-end case took a path the rule had not covered:
  that binary predates `rootsMissing`, steps over a root that is not there, exits 0 and writes
  a report indistinguishable from a clean scan of a tree that was there. Absence of the channel
  is not evidence of coverage, so a report missing `interrupted`, `filesSkipped`,
  `directoriesUnreadable` or `rootsMissing` is refused by name, and the control fails loudly —
  naming the binary and the channel it lacks — rather than skipping, until the scanner under
  test is one that reports them. So the control takes `build/` when `LYXBOSA_BIN` is unset,
  and an explicit `LYXBOSA_BIN` still wins, because naming a binary means that binary. A
  control is not a measurement and the two want different defaults: a published figure has to
  come from `build-release/`, which `AGENTS.md` forbids rebuilding mid-round, so a control
  insisting on it would report the age of a build as a failure of whatever round was being
  checked — and a gate people have to work around is one they learn to skip. This does not
  merely turn the result green: the end-to-end section was being abandoned rather than
  executed, **30 cases ran before and 41 run now**, and the eleven recovered are the ones
  asserting the rule against a real scanner over a real tree rather than against reports the
  control wrote itself.

- **Three control suites had never been run by anything, because the runner only read
  `.py`.** `control-suites.py` is the one command `AGENTS.md` puts on the pre-report list so
  that coverage stops depending on anybody's memory, and its own docstring argues that a
  hardcoded list would be that memory dependency one level up. It discovered by suffix, and
  `build-shard.sh --selftest`, `fetch-benign.sh --inject` and `release-assets.sh --selftest`
  fell outside it — not failing and not skipped, simply never asked. All three pass, and all
  three together cost about a second: **45 suites, from 42.**

  The shell half is read by a different means, for the same reason the Python half is parsed
  rather than grepped. There is no AST to ask, so the question put to a shell script is
  whether the flag stands in a **dispatch position** — a `case` pattern, or compared against
  a positional — rather than whether it appears. That distinction is load-bearing here rather
  than theoretical: all three of those tools name their own flag in a comment or a usage
  string as well as dispatching on it, so *appears in the file* would have been true of the
  prose in every one of them.

  Six new cases, both directions: a `case` pattern is discovered, a comparison against `$1`
  is discovered, a script naming the flag only in a comment and a usage line is **not**, a
  failing shell suite is reported `FAILED` rather than skipped, a passing one reads ok, and
  the three real shell suites are asserted present **by name** — because a discovery that
  quietly stopped opening `.sh` would satisfy every case that compares the parser only to
  itself, which is the shape §11 keeps recording. 24 cases, from 18.

### Added

- **`corpus/release-assets.sh` refuses to print the commands that cut a corpus tag while
  the changelog still says `Unreleased` about what that tag would publish.** A corpus tag
  publishes shards a stranger downloads and re-runs, and its changelog section is where the
  counts those shards assert are written down — which shard is new, which figure moved and
  what moved it. Push the tag first and that section can only be written as history about
  something already public, by somebody reconstructing which side of the tag each entry fell
  on. `--print-upload <tag>` is where the refusal belongs: printing is as far as this script
  goes by design, the commands to tag and to publish come out of there, and refusing to
  print them is refusing to cut the release.

  **Closed out is four things, each refused by name**, because a heading with nothing under
  it satisfies a check for the heading and ships a release whose section says nothing.
  `## [<tag>] - <date>` exists, exactly once; it carries at least one entry; `## Unreleased`
  is still above it, or the next round writes into a released section and this recurs one
  round later; and a `[<tag>]:` definition exists at the foot, or the bracketed heading
  renders as brackets.

- **Seven controls, both directions — and the good case had to be run against real data
  before it was worth anything.** Five planted defects, one per rule plus the shape this
  gate exists for: the *previous* tag closed out and the one being cut not, which is what
  the file looks like every time this has gone wrong and which a check asking only "is any
  section closed" would pass. Each refusal is asserted to name its own rule, since a
  function returning 1 unconditionally catches all five and refuses every real release.

  The seventh is the one that earned its place. The emptiness test was
  `printf '%s\n' "$body" | grep -q '^- '`, and under `set -o pipefail` that pipeline reports
  the **left** side: `grep -q` exits on the first match and closes the pipe, `printf` takes
  SIGPIPE and exits 141, and pipefail hands back the 141. Every real section read as empty.
  The twenty-line fixture passed throughout, because it is small enough that `printf`
  finishes before `grep` can close the pipe — so the good case is now asserted against
  **`corpus/CHANGELOG.md` itself**, at the size the sections actually are, with the tag read
  out of the file rather than named in the control so it needs no editing per release. A
  good case small enough to win a race has not been observed. Two further instances of the
  same pipeline shape were repaired beside it; neither fires today, one match each, which is
  the version of this that gets found much later.

## [corpus-2026.09.2] - 2026-09-08

### Added

- **29 samples that the scanner already detected can now be re-run by a stranger, and the
  headline moves because of that and not because of a rule.** `leaf-php-mailer-2.8` — Leaf
  PHP Mailer 2.8, a public bulk-spam mailer with an embedded PHPMailer — was 29 rows held in
  the local half. The scanner returned `PHI009,WS011` on every one of them at the previous
  tag and returns the same today; nothing about the rules changed in this round. What they
  lacked was a shard: `expect.must_detect` is compared to `check`'s output over the **shipped**
  bytes, so a row nothing ships cannot carry an assertion, and all 29 sat under
  `expect.known_miss` beside genuine rule gaps. Publishing the bytes lets the corpus assert
  what the scanner was already doing.

  | figure | before | after | cause |
  |---|---|---|---|
  | `published_shipped_as_bytes` | 140 | **169** | the 29, in one new shard |
  | `malicious_detected` | 701 | **730** | the same 29, now assertable |
  | sample-weighted detection | 54.0% | **56.2%** | arithmetic on the line above; no rule changed |
  | `malicious_detected_runnable` | 102 | **131** | 29 from this round, 5 from an earlier `OBF042` promotion whose manifest was stale |
  | `known_miss` | 598 | **569** | the 29 promoted out of the marker |
  | known misses of kind `detected-not-shippable` | 32 | **3** | the same 29 |
  | ...of them in scope | 29 | **0** | all 29 were the in-scope ones |
  | `published` / `local_only` | 44,544 / 48,256 | **44,573 / 48,227** | 29 rows moved between halves; `total_blobs` unchanged at 92,800 |
  | false-positive rate | 0.0223% | **0.0223%** | unchanged, and it could not have moved: no scanner source, no `corpus/benign/sources.jsonl` entry and no recorded false positive was touched. Re-measured anyway — 44 of 197,559, the same 44 rules |

  Every promotion was re-measured with `check` against the bytes in the stage that became the
  shard, one file at a time, never from the handoff's record: a census over all 29, not a
  sample, returning `PHI009,WS011` on 29 of 29 with `build/lyxbosa` at `eb611749bd80`.

  **They are 29 rows and close to one file, and the corpus should say so.** 28 of the 29 are
  the same length and differ from one another in nine to eleven byte positions — the embedded
  password literal — and the twenty-ninth differs only in line endings. Published as 29 rows
  because per-deployment literal substitution is the technique under test
  (`polymorphic-literal`), but the 4.9 MB of samples compress to a 44 KB shard, which is the
  measurement of how much new material this actually is. A reader counting *distinct
  artefacts* gained one.

- **A new shard, not an extension of an existing one, and the reason is the consumer's.**
  Appending to `malicious-db-dropin-001` would change that shard's bytes and therefore its
  sha256, so anyone holding `corpus-2026.09.1` would find a file of the same name hashing
  differently under the next tag with nothing in the name to say so.
  `malicious-bulk-mailer-001` leaves the other eight untouched by the addition — verified by
  `sha256sum -c` against the list as it stood, all eight OK. Seven of them are still
  byte-identical in the finished release, checked against the `SHA256SUMS` that
  `corpus-2026.09.1` actually published rather than against the local copy. The eighth,
  `malicious-staging-001`, changed for an unrelated reason recorded under *Fixed*, and its
  66 sample files did not.

- **`corpus/publish-rows.py`, because publication had no tool.** Every previous round that
  moved rows from the local half to the published half wrote a script for that round and threw
  it away, which is how four published rows came to carry `origin` — a path on a customer
  host. `shard-gate.py` catches that after the fact; this refuses it before. It drops the
  fields the published half may not carry, re-asks the published-half form rules over the row
  **as it will land**, takes both index locks for the whole read-modify-write and writes the
  published half first, so the only reachable interruption leaves a row in both halves rather
  than in neither.

  It refuses rather than performing anybody else's act: a row carrying `local_only` is
  refused rather than released, a row tagged `pii`/`content` is refused, and publishability is
  taken from `shard-gate.evaluate()` **today** rather than from the row's stored flag.
  `--inject` (19 cases) asserts every refusal is reachable and that a clean row still moves —
  a mover whose checks all passed vacuously would publish everything and report success.

### Fixed

- **A promotion wrote "no rule fired" onto 29 rows the scanner detects.**
  `promote-pending.closed_expect()` recorded `closed_known_miss.was` from the row's prose
  `known_miss_reason`, falling back to the literal string `"no rule fired"` when there was
  none. The 29 rows published this round carried no prose reason — they carried
  `known_miss_kind: detected-not-shippable`, which means the opposite: rules fired and nothing
  shipped the bytes. The first run of the promotion put that sentence on all 29 and the
  published index would have asserted it. `KIND_WAS` now maps each kind
  `classify-known-miss.py` can assign to what it actually means, prose still wins where a row
  has it, and an unrecognised kind falls back rather than raising.

  The same promotion left `known_miss_kind` and `known_miss_kind_measured` on the closed row,
  including `ships_as_bytes: false` — which the promotion had just made false. Both are now
  dropped with the marker they describe. Seven `--inject` cases, including the one that failed
  in anger: a `detected-not-shippable` row must not close as "no rule fired".

- **`malicious-staging-001` was shipping a manifest that contradicted the index, and no
  pre-report command could see it.** Five of its members were promoted to
  `must_detect: ["OBF042"]` in an earlier round; the shipped `MANIFEST.json` and the tracked
  `corpus/expect/malicious-staging-001.json` still said `known_miss: true`. `shard-census.py`
  reported all ten disagreements and `REFUSE TO PUBLISH`, correctly — it is the only check
  that opens the archives — while both `shard-gate` runs, `make-summary --check` and
  `doc-figures --check` passed, because none of them is asked about a shard. Regenerated from
  the index. **All 66 sample files are byte-for-byte unchanged**, measured before and after:
  only `MANIFEST.json` moved, so the shard's sha256 changed and its contents did not.

  This is not this round's defect and it is this round's to report: the repair was found by
  running the census the publication path requires, and the gap is that the five pre-report
  commands do not include it. A round that publishes nothing never opens a shard.

- **`doc-figures.py --inject` was reading the day's data instead of the rule.** One case
  asserted that quoting `known_miss_mixed_in_scope` beside "known misses" is refused. It was
  built from the live summary, and publishing the 29 took the in-scope
  `detected-not-shippable` count to zero — at which point the in-scope union *equals* the
  in-scope rule-gap figure and `miss_violations` stands down, exactly as its own docstring
  says it should. The tool was right and the case was wrong. It now builds a summary that
  genuinely mixes, and a second case asserts the stand-down in the other direction: a union
  that is not mixed must be **accepted**, because a guard that refuses a correct document gets
  switched off rather than fixed. This is the same shape as the four family-rate cases
  `AGENTS.md` records as red for six rounds. 60 cases, all pass.

- **The rules/corpus handoff kept asserting a state the corpus had left.**
  `corpus/pending-promotions.jsonl` records each row's `half` and `publish_blockers` as the
  rules side saw them at measurement time, and `promote-pending.py` defers on that snapshot.
  After publication the 29 rows still read `half: local` and "no shard carries these bytes",
  so the applier would have deferred work that was finished. `--refresh` re-derives both
  fields **from the index** and prints every change. It is a separate run and never a side
  effect of `--apply`, because having `adjudicate()` read the index directly would delete the
  gate rather than refresh it — the handoff disagreeing with the index is itself a finding.
  It cannot invent a clearance: five `--inject` cases, including one asserting that a blocker
  the index still records survives the refresh, and one that a sha in neither half keeps
  exactly what it recorded.

- **`expect.known_miss` carried two claims and the published figure reported only one of
  them.** The marker means *the published suite asserts no rule for this row*. Two unrelated
  facts put a row there: the scanner reads the bytes and nothing fires — a miss — or the
  scanner reads the bytes, rules **do** fire, and no shard carries them, so there is nothing
  for the suite to run an assertion against. Published as a single number under the heading
  "Recorded known misses", glossed in `README.md` as *recorded malware this version does not
  catch*, the second population was reported to a stranger as the first.

  `corpus/classify-known-miss.py` measures which, per file, and records
  `expect.known_miss_kind` plus `expect.known_miss_kind_measured` — the rules that fired, the
  binary they fired under by `sha256_12`, and whether any shard ships the bytes. Applied to
  all 598 rows through `indexio.py` with the lock held across the whole read-modify-write.

  | figure | before | after | cause |
  |---|---|---|---|
  | Recorded known misses | 598 | **558** | 32 rows re-measured as detected, 8 as unmeasurable |
  | ...of them in scope | 67 | **38** | 29 of those 32 are in scope |
  | Recorded, detected, nothing ships the bytes | — | **32** | new state, measured per file |
  | ...of them in scope | — | **29** | all 29 are `leaf-php-mailer-2.8` |
  | Recorded, bytes not on this machine | — | **8** | new state; 0 in scope |

  **No detection figure moves, and that is also attributed.** Detection stays 701 of 1,299
  and 90.5% (636 of 703); `malicious_detected_runnable` stays 102; technique coverage stays
  90 of 123. Reclassifying why a row is unasserted touches neither `must_detect` nor
  `verdict`, so it cannot move a figure computed from them. Measured rather than assumed:
  regenerating the summary added three keys — `malicious_known_miss_by_kind`, its in-scope
  twin and the note — and **changed no existing key**. `known_miss` itself is deliberately
  still 598: it is the union, and every consumer that reads it keeps seeing every row.

  The count falls in the flattering direction, so the rows are named rather than inferred
  from the handoff file. All 32 are local-half, none ships as bytes — checked against every
  unpacked shard manifest, not against `publishable` — and each was run individually through
  `check` with a locally built binary: 29 `leaf-php-mailer-2.8` returning `PHI009,WS011`, 2
  `webmail-phish-harvester` and 1 `phish-kit-verified-by-visa-2012` returning `PHI009`.

- **`corpus/verify.py` prints the same three counts, from the same source.** The suite's
  *Known misses* line read the union under the word "misses". It now reads `rule-gap` on that
  line and prints the other two states beneath it, **every run, including at zero** — a line
  that appeared only when non-zero would let the suite and the README drift apart in the one
  state nobody would look at. All three are read from `index-summary.json` rather than
  recomputed, so the two cannot disagree without `doc-figures.py --check` saying so.

- **Controls, in both directions, in the same commit.** A split whose effect is to lower a
  published miss count needs its controls pointed at the flattering direction, so every case
  asserts both what a row counts as and what it does not.
  `classify-known-miss.py --inject` (16 cases) asserts that a row with no rule firing is a
  miss and specifically not `detected-not-shippable`; that a detected unshipped row is
  specifically **not** a miss; that an unreachable row is **neither**, because an empty rule
  list and absent bytes are the same input to a naive check and different facts; that the
  kind vocabulary is closed and every value in it reachable; and that a detected row whose
  bytes **do** ship is refused rather than classified — that is a promotion for
  `promote-pending.py`, and calling it `detected-not-shippable` would assert that nothing
  ships a file that ships. No row is in that state today, which is exactly why the control
  is there. `make-summary.py --inject` gains 7 cases on the partition (52 total, all pass),
  and `doc-figures.py --inject` gains 15 (drifting each of the three states separately,
  refusing a split that does not add up, refusing an `<unclassified>` row rather than
  rendering it as a zero, and both directions on the new guard).

- **A guard on the mixed total, modelled on the one that refuses a family rate over a
  population nobody drew.** `known_miss_mixed_total` and `known_miss_mixed_in_scope` are
  computed and rendered nowhere; `doc-figures.py --check` refuses any generated-region
  document that prints either in a paragraph talking about known *misses*. It stands down
  when the union genuinely equals the miss count, matches `known miss`/`known-miss` but not
  the field name `known_miss` — "598 rows are `known_miss`" is true, "598 known misses" is
  not — and will not fire on a small integer inside a longer number. Measured against the
  documents as they stood: it refused the old `README.md` table on both figures and reported
  nothing in `corpus/SOURCES.md`, whose unrelated "Twenty-three of the 67" is a shard's
  sample count.

### Fixed

- **The previous round reported 531 known misses as unreachable. 523 of them are on this
  machine.** That round wrote, in this file and in its commit message, that every
  `predates_ruleset` row's bytes are absent "exactly as `family_evidence.SampleStore`'s
  docstring says of all 531", and made no claim about whether any rule now reaches the
  doorway campaign.

  `SampleStore` resolves through one collection blobmap. Measured: that blobmap contains **0
  of those 531** and **67 of the 67** others, so it returns the docstring's number and would
  do so however many of the files were on disk. A fresh hash over the trees — 511,554 files
  examined, 19,821 hashed on a size match, every hit verified against the row's own `sha256`
  — resolves **590 of the 598**, the missing 523 sitting in `trail-data/Infected/`, the tree
  those rows were collected from and one the blobmap never indexed. **The resolver's index
  bounded the answer and the answer was read as the world**: CORPUS_PLAN §11 in a new place,
  and the fourteenth instance it tells you to assume.

  So the campaign *was* measurable. Measured: all 495 doorway rows are `rule-gap`, no rule
  fires on any of them. The previous round's conclusion was right and its stated reason was
  not, which is the worse of the two ways to be right.

  `classify-known-miss.py` therefore enumerates by hashing rather than by reading any
  pre-written map, and reports what it genuinely could not reach — 8 rows, all
  `predates_ruleset`, 0 in scope — as `unverified` rather than as undetected.

- **The new resolver had the same shape of blind spot, found before it mattered.** It walked
  `corpus/shards`, where the bytes live *inside* `.tar.zst` archives, so it saw the archives
  and never their members: a row shipping only from a shard would have been recorded "not on
  this machine" while the corpus was handing it to strangers. The shards are now unpacked
  before the scan and their members hashed with everything else. **It changes no number
  today** — files examined 511,402 → 511,554, resolved 590 → 590 — because all 36 known-miss
  rows that ship are also loose in the collection trees. A blind spot that is currently empty
  is still a blind spot, and this one was one reordering away from repeating the defect in
  the bullet above. `--inject` asserts a file reachable only under an extra root is found by
  content, and that a decoy of exactly the right size is not mistaken for it.

- **`pending-promotions.jsonl` was not the population.** The handoff holds 31 rows and is
  written by the rules side for the corpus side to apply, so it contains what a round
  remembered to write. Measured against it: 30 agree exactly, including the rule sets; **2
  `webmail-phish-harvester` rows are detected and absent from it**; and **1
  `phish-kit-verified-by-visa-2012` row it lists as detected could not be re-measured**,
  because its bytes are not on this machine. That last row is recorded `unverified` and is
  **not** counted as detected — a handoff file is a claim, and this round's rule was that the
  falling number has to be defended row by row from a measurement taken here.

- **Two hand-written figures in prose had gone stale, and nothing compares them.**
  `README.md` said 602 of the 707 rows in the unrecorded sampling frame are recorded known
  misses; measured now, 597 carry the marker and 565 are misses no rule fires on. Cause of
  the 602 → 597: the five `OBF042` promotions in the round above. `corpus/SOURCES.md` said
  495 of "the 638 known misses" are the doorway campaign; 638 has not been the total for
  several rounds. Its denominator is now removed rather than corrected — a figure written by
  hand into prose that nothing checks will go stale again, and `README.md`'s generated table
  already carries the current numbers.

- **`OBF042` closes 5 known misses, and every published detection figure moves — the first
  round in twelve where that is a result rather than a defect.** Five second-stage files in
  `fake-plugin-image-payload-loader` were promoted from `expect.known_miss` to
  `expect.must_detect: ["OBF042"]` through `pending-promotions.jsonl` and
  `promote-pending.py --apply`, which re-measured each one with `check` against the **shipped
  shard bytes** rather than the source blob. The rule itself is in
  [`../CHANGELOG.md`](../CHANGELOG.md); what is here is what it did to the denominators.

  | figure | before | after | cause |
  |---|---|---|---|
  | Detection, whole reviewed set | 53.6% (696/1,299) | **54.0% (701/1,299)** | the 5 promotions |
  | Detection excluding the rules' source material | 89.8% (631/703) | **90.5% (636/703)** | the same 5 |
  | Recorded known misses | 603 | **598** | the same 5 |
  | ...of them in scope | 72 | **67** | the same 5 |
  | Samples a stranger can re-run | 97 | **102** | the same 5 |
  | Family macro, frame unrecorded | 29.9% | **30.2%** | the same 5, in one family |
  | Family micro, frame unrecorded | 14.9% (105/707) | **15.6% (110/707)** | the same 5 |

  Every one of those seven differences is the same five rows. Nothing else moved: `detected`,
  `rule_exact` and `missed` over the non-known-miss samples are **97 → 97, 97 → 97, 0 → 0**,
  measured by running the suite against a binary built without the rule and then with it, so
  the rule is additive and drifted nothing. **Technique coverage did not move — 90 of 123 —
  and that is also attributed: `custom-alphabet-strtr` was already recorded on those rows, and
  `verify.py` counts the techniques of every *tested* sample whether or not it is a known
  miss, so a promotion cannot move that number.**

### Measured, not changed

- **The 29 `leaf-php-mailer-2.8` rows are not a rule gap, and `WS011` was never narrower than
  its description.** The round opened on the question of why 29 rows sit as known misses when
  `WS011` is already "a bundled mailer library behind a hardcoded password gate". Neither
  available explanation was the answer. Re-measured with a locally built binary against **both**
  the masked bytes and the pre-mask originals, all hash-verified against the digests the rows
  record: **29 of 29 fire `PHI009,WS011`**, on both. It is the kit `WS011` was written for —
  28 blobs at exactly 170,139 bytes and one at 165,629, matching the rule's own note.

  They read as misses because `expect.known_miss` is a claim about the *published* suite and
  these are local-half rows. Their detection was already recorded in `pending-promotions.jsonl`,
  and `promote-pending.py` correctly refuses to promote a row with no shipped bytes. What was
  actually wrong was the blocker those handoff rows carried: **"carries identity/secret but no
  masking has been applied", which the masking pass resolved on 2026-09-07.** All 29 now read
  `masking.applied: true` with four gates PASS and `publish_blockers` empty. The blocker string
  is corrected to the real one — held under `local_only_publishable_no_blocker` because **no
  shard carries their bytes**, verified against every unpacked shard manifest, with family and
  technique present on all 29 so the other cause that category admits is excluded. Shipping
  them is a corpus task and not a rules one; the handoff now says so.

  **This makes the in-scope known-miss figure a conflation.** Of the 72, 29 were detected
  already and 43 were genuinely undetected. A round aimed at "72 in-scope misses" would have
  spent its effort on the largest of them for no gain.

- **All 603 known misses were re-measured, and 531 of them cannot be measured here at all.**
  Not just the in-scope 72: every `known_miss` row was resolved to bytes and run through
  `check`. 29 detected, 43 missed, and **531 unreachable — every one of the
  `predates_ruleset` rows, including all 495 of the doorway campaign.** Their `origin.path` is
  the path the file had on the customer's machine and the collection blobmap does not carry
  them, exactly as `family_evidence.SampleStore`'s docstring says of all 531. So no claim is
  made here about whether any rule now reaches that campaign: the population that would answer
  it is not on this machine, and reporting a zero from a set of files that were never opened
  is the failure mode this repository keeps a control for.

### Known, and left standing

- **`fake-plugin-image-payload-loader` is now named by `family_bucket_suspects`, and it is a
  false positive of that heuristic.** Before this round all 45 detected members of the family
  expected `OBF041` alone, so the members shared a rule and the check passed over it. Now 40
  expect `OBF041` and 5 expect `OBF042`, the intersection across detected members is empty, and
  the family matches the shape the check looks for.

  The heuristic is doing what it says — it reports and does not exclude, and its own docstring
  calls the output "evidence for a person to rule on". Here the adjudication is that this is one
  campaign, not a pile: five staged plugin directories, each holding a `.php` loader, a `.txt`
  second stage and seven or eight payload blobs (39 in all, two of the five also carrying a
  `README.txt`), and the tiers legitimately fire different rules because they *are* different
  code. **The heuristic is deliberately not changed.** "Detected members
  share no expected rule" cannot distinguish a pile of unrelated files given one label from a
  real multi-stage kit, and the cheap repair — excluding families whose members split cleanly by
  rule — would blind it to the pile it exists to find. Recorded here instead, which is what a
  reporting check is for.

### Added

- **The 180 rows are applied, and the family rate is published once per sampling frame with
  neither called the headline.** The seven families from the pilot session are recorded on 180
  of the 531 unfamilied rows. **Sample-weighted detection does not move: 696 of 1,299, 53.6%,
  before and after** — assigning a family changes no verdict and no expectation. The published
  family figures do not move either, and that is the point of the round: the rows they moved
  into are a second column, not the same one.

  **A clean definition drawn out of a contaminated pool is a second failure, and it is not the
  one `families_detection_conditioned` records.** That key names a label whose *membership* is
  conditioned on detection — `if hit`, visible in the assigning code. The seven new families
  have none of that shape: each is defined by a literal shared across its members, every marker
  is re-read from the sample bytes by the writer, and a member carrying none of them is
  refused. But all seven were drawn from one pool, and when they were assigned that pool held
  **530 detected rows out of 531** against 696 of 1,299 across the reviewed set. Exactly one
  row in it was undetected, so at most one family drawn from it could ever have scored below
  100%. All seven came out fully detected.

  The frame is now measured at write time by `family_evidence.frame_detail()` and recorded on
  every row as `family_evidence.sampling_frame`, because by the time anything re-derives it the
  pool has shrunk by everything labelled since. `index-summary.json` gains
  **`families_sampling_frame_conditioned`** — its own key, deliberately not folded into
  `families_detection_conditioned`, because the two are found by different means and a reader
  who has seen one will not look for the other.

- **`family_detection_by_frame`, and no rate across the two frames anywhere.** Had the old
  single rate survived this write it would have read **micro 32.1% and macro 40.8%**, up from
  14.9% and 29.9%, with every new family fully detected and not one verdict changed. A reader
  would have seen the scanner improve by seventeen points because somebody worked through a
  queue.

  **Excluding the new families and keeping 14.9% was refused, and the measurement is why.**
  That population is not a clean control either: **602 of its 707 rows are recorded known
  misses**, because a mass miss is what gets investigated and labelled, and a single 2017
  doorway campaign supplies 495 of them. Drop that one family and the same micro average reads
  **49.5%**. Both frames are contaminated, in opposite directions, and nothing in this corpus
  establishes that either is a fair draw — so both are published, each under its own frame, and
  neither is the headline. The sample-weighted figure over the whole reviewed set stays the one
  number with a denominator nobody chose.

- **`corpus/doc-figures.py --check` now refuses a document that publishes a family rate without
  its population.** Two rules: a per-frame rate must appear with that frame's integer pair
  *and* that frame's label, and a rate computed across both frames must not appear at all —
  there is no denominator that makes it mean anything. The combined rule stands down while the
  union equals one frame's own rate, which is the state the guard was committed in.

  The sweep is whole-document rather than per-region, because the region check compares only
  the generated block and prose around it is a person's by design — so a rate loose in the
  prose is exactly what nothing was watching. **17 controls in both directions**, including one
  that asserts the region check *alone* passes the document the guard rejects: a guard whose
  positive case is already caught by the check beside it has not been shown to do anything.

### Fixed

- **Three `doc-figures.py` controls were defending a figure no document renders.** The
  three-state family counts moved into the per-frame blocks, and the drift controls still
  drifted `family_detection`, whose three-state cells nothing quotes any more. They passed
  while blind. Repointed at the block the documents render.

- **The reachability ceiling was standing on prose, and is re-derived.** *428 of 531 reachable,
  103 not* came from a scratch script lost to a crash. Re-run over all 95 clusters and all 531
  rows it reproduces exactly — 378 rows in 38 clusters with a distinctive shared literal, 50 of
  53 singletons, 87 in three clusters whose only cluster-wide literal is carried by roughly a
  fifth of the pool, 13 in one cluster sharing nothing — and it is stable for any rarity
  threshold between 93 and 193 rows, a two-to-one range on the only free parameter. It is a
  **floor, not a ceiling**: the pilot labelled **16 of those 103** by splitting a cluster on a
  literal a minority of its members carry. **87 rows remain out of reach** and stay counted in
  `malicious_family_population`, which still partitions the reviewed malicious set exactly.

### Added

- **A local cluster-review tool for the 531 unfamilied rows, and the finding that labelling
  them raises the family-weighted rate mechanically.** `corpus/review-app.py` (a loopback
  server), `corpus/assign-family.py` (the tracked writer) and `corpus/family_evidence.py` (the
  rule that a family is defined by bytes). None of them is published and the app is never an
  artifact or a hosted page: it renders `origin.path`, account names and live malware bytes on
  screen by design, which is why it binds `127.0.0.1`, checks the `Host` header, escapes every
  byte it renders and serves `default-src 'none'` so nothing a sample references is fetched.

  **The headline does not move and the family figures move a great deal.** A pilot session
  labelled 180 of the 531 rows as 7 families. Sample-weighted detection is **696 of 1,299,
  53.6%, before and after** — assigning a family changes no verdict and no expectation.
  Family-weighted detection would go from **micro 14.9% to 32.1% and macro 29.9% to 40.8%**,
  and every one of the 7 new families is *fully detected*.

  That movement is a property of which rows were left unlabelled, not of the scanner. **530 of
  the 531 unfamilied rows carry an expected rule (99.8%); 105 of the 707 already-labelled rows
  do (14.9%).** So any family drawn from the unfamilied population is fully detected before
  anybody looks at it, and a family-weighted figure computed after labelling them measures the
  labelling backlog. The session was validated and held for one round; **it is applied in the
  round above**, with the frame it was drawn under recorded on every row and the published rate
  split by frame so that applying it could not move one.

- **`ruleset_determined()` — the refusal `family_bucket_suspects` structurally cannot make.**
  The 531 collapse into 95 clusters keyed on `expect.must_detect`, which is the scanner's
  output, so a family lifted whole from a cluster is conditioned on detection exactly as
  `legacy-infected-tree-sample` was. The dispersion test cannot see it: that test names a
  family whose members share *no* rule, and a cluster-lifted family shares *every* rule, so it
  passes trivially. The writer refuses a session in which every family is a function of the
  recorded rule-set, and records `ruleset_determined` on each row. A family escapes by
  splitting a cluster or taking part of one — which is what the byte markers are for.

- **Dispersion is now a share, not a boolean, because the boolean refused two real families.**
  `family_bucket_suspects` asks whether the intersection of a family's rule-sets is empty, and
  **one outlier member empties an intersection.** Run over the pilot it named two families of
  seven: a file-manager shell where **16 of 17** members share one rule, and a doorway set
  where **24 of 26** do. The shape it was built to catch sits at **15%** — 39 distinct
  rule-sets over 61 members — and every other labelled family in the index today sits at
  **100%**. The boolean cannot tell 15% from 94%.

  `family_evidence.DISPERSION_FLOOR` is 50%, and the calibration is **one positive and six
  negatives, which is not a calibration**: it is a floor at 15% and a ceiling at 92% with
  nothing observed between. The boolean is still computed and still reported, because the
  census applies it. What actually stops a pile from being recorded is `verify_markers`: every
  member must carry a literal re-read from its own bytes by the writer, and five unrelated
  malware classes have no such literal to share. That refusal does not consult the scanner.

- **What one screen can and cannot decide, censused over all 95 clusters and all 531 rows.**
  38 clusters (378 rows) carry a literal shared by two or more members and distinctive enough
  to rule on. 53 clusters are singletons with no second member on the screen, but **50 of the
  53 carry a literal some other row also carries** and are reachable from the marker view. 3
  clusters (87 rows) share only corpus-generic literals and 1 cluster (13 rows) shares nothing
  at all. **428 of 531 rows are reachable from a screen; 103 are not** and need the decoded
  payload rather than the bytes as stored. Not a sample — every cluster was measured.

- **Family-weighted detection, published beside the sample-weighted figure, with the
  population it is silent about named in the same table.** The sample figure is dominated by
  whichever campaign was collected most heavily: one 2017 doorway campaign supplies **495 of
  the 1,299** reviewed malicious samples, so it is one missed family and 495 missed samples at
  once. Sample weighting says the scanner misses a great deal; family weighting says it misses
  one thing prolifically. Both are now generated from `index-summary.json`.

  Over **38 campaign families: 9 fully detected, 5 partially, 24 completely missed.** Three
  states, never two — collapsing partial into either neighbour discards which campaigns the
  scanner catches most of. **Macro average 29.9%** (every family weighted equally) against
  **micro 14.9%** (every sample, over the identical 707 rows); the gap is the measurement, and
  a macro average that tracked the micro average on every input would not be one.

  Detection uses the **same predicate as `malicious_detected`** — a row carries an expected
  rule — written once and called from both, so the family figures and the headline cannot drift
  apart. The three populations sum to `malicious_reviewed` and `--inject` asserts they do.

- **`legacy-infected-tree-sample` is not counted as a family, and its 61 rows are not dropped.**
  `import-infected-tree.py` assigns that label under `if hit`: a sample is in it *because the
  scanner flagged it*, recorded on the row as `reason: detected-and-read`. It reads 61 of 61
  detected and could not read anything else. Counted as a family it made coverage read **10 of
  39** rather than **9 of 38**, in the flattering direction, with a tautology in the numerator.
  Its rows move to a named third population, `provenance_bucketed`, and stay in every total.

  A census over **all 39** labelled families — not a sample — found it is the only one, on
  three independent properties: its 61 members carry **39 distinct expected rule-sets with no
  rule shared by all of them** across eight rule prefixes, where every other multi-member
  family shares a rule or fires one set; its single technique is the most generic in the
  vocabulary; its `verdict_reason` is a five-way disjunction of unrelated malware classes.
  `family_bucket_suspects` recomputes that dispersion every run, independently of the reason
  code, so a second bucket arriving later is named rather than counted.

- **The denominator gap is stated wherever the figure appears.** **531 of the 1,299** reviewed
  malicious rows carry no family at all, so a family figure describes 768 rows and is bounded
  by who did the labelling. They are not a random 531: **530 are detected**, so excluding them
  silently takes sample-weighted detection over what remains from **53.6% to 21.6%**. The
  **same 531 rows** — the identical set, not merely the same count — carry no `technique`, so
  technique coverage (**90 of 123**) is silent about exactly the same population. The two
  coverage figures do not corroborate each other.

- **`family_rerun_power`, because the family census is mostly recorded rather than re-run.**
  Of the 38 campaign families, **23** have every member re-executable by `verify.py`, 4 some,
  and **11 none — and those 11 hold 561 of the 707 rows**, because the largest families are
  among them.

### Fixed

- **A published percentage was rounded twice and read 14.8% where the ratio is 14.9%.**
  `micro_rate` was stored to 4 decimal places and rendered as a percentage by rounding again:
  105/707 is 14.8515%, which reads **14.9%** from the integer pair and **14.8%** from the
  stored `0.1485`. The generated table said 14.8% while the prose beside it said 14.9%, both
  derived from the one key. Rates are now stored to 6 places, the rendered micro average is
  taken from the published integer pair, and a control asserts the two agree to the printed
  decimal. Caught by the region's first regeneration, before the round was reported.

- **`corpus/doc-figures.py` — the figures a document quotes are written from
  `index-summary.json`, and `--check` fails naming the figure that drifted.** `README.md` said
  detection was **22.2%, 172 of 774, with 602 recorded misses** and that the corpus held
  **91,669 blobs, 12,249 classified and 79,420 unreviewed**. The index said 53.6% (696 of
  1,299), 603, and 92,800 blobs of which 46,016 are classified and 46,784 unreviewed. Both
  claims were live on `master`, not only at the tag, and an outside reviewer reading the
  published release found them before anybody here did.

  **The repair is generation, not correction.** Correcting these by hand is exactly how they
  went stale, so a fresh set of hand-written numbers would be the same defect with a newer
  date on it. Figures now live in delimited regions a tool writes; the prose that interprets
  them sits outside the markers and survives regeneration untouched. Every region is a table
  and nothing else — a renderer that emitted a sentence would eventually eat an argument.

  **It reads the summary and never the index**, which is the design rather than an
  implementation detail. If it counted rows, a document could agree with `index.jsonl` while
  disagreeing with `index-summary.json`, and the project would hold two denominators that
  nothing compares — the defect `make-summary.py` exists to end, one level out. The chain is
  single-file and transitive: index → (`make-summary.py --check`) → summary →
  (`doc-figures.py --check`) → `README.md` and `SOURCES.md`, and both links run in
  `pre-push-check.py`.

  **16 controls, both directions.** A document that agrees passes; a summary figure drifted by
  one is refused *and the refusal names `detection_pct`*; regenerating against that drifted
  summary passes again, so the refusal is not vacuous. A missing region fails rather than
  silently generating nothing — that is the merge failure mode, where the markers go, the
  numbers stay, and a skip reports green over a document nothing defends any more. Also
  refused: a BEGIN with no END, two BEGINs, a hand-written row inside a region, and a summary
  missing a key the documents quote, which raises rather than rendering `None` into a
  published table. Asserted in the other direction: prose edited *outside* a region survives
  regeneration untouched.

- **`make-summary.py` gains `published_shipped_by_reason`.** `published_reason_codes` counts
  every published row under its reason, so its shipping codes sum to 142 and include the two
  rows whose files were dropped from the archives. A document wanting to say *which* samples
  ship was left computing the breakdown by hand — and `SOURCES.md` did, naming four reason
  codes at their pre-drop counts and omitting `undetected-pool-review` entirely. That is the
  stale-set defect this file's own comment predicted, reproduced one level out in prose, where
  no `--check` could see it. It can see it now.

- **`pre-push-check.py` delegates `doc-figures.py --check`, and its docstring says why this
  one belongs in a leak gate where the derived database did not.** The test is not *is it a
  leak*; it is *does pushing make it public, under this project's name, in a form a stranger
  will act on*. `corpus/local/index.db` is gitignored, derived and never pushed, so a
  `--check` for it here would gate an event that cannot happen — it is guarded instead by
  `derived_db.open_ro()` refusing at the moment of use. `README.md` ships and is read first, so
  a wrong figure in it is a false public claim, which is the other thing a push makes
  permanent. Three controls, both directions: agreeing documents accepted, a README stale by
  one detection sample refused *with the figure named*, and a document whose region is gone
  refused rather than skipped.

- **`corpus/CHANGELOG.md` — this file, split out of the root changelog.** That file says in its
  own header that it is written for people running the scanner and that its versions are the
  `v*` tags in `docs/RELEASING.md`, and it was then asserting `Unreleased` about work that had
  shipped in `corpus-2026.09.1`. The two series move on different cadences on purpose: the
  scanner versions on rules, the corpus on review rounds. Entries were **moved, not copied** —
  two changelogs describing one round is the same problem one level up — and a control asserts
  the partition is lossless: **1,949 non-blank lines in, 1,949 out, none gained**. The first
  attempt lost the `Known before publication` block, because its heading carried prose and no
  bullets and the emitter only flushed headings that had bullets under them; the line-multiset
  check is what caught it, and it is why the check is a multiset rather than a line count.

### Fixed

- **Four more stale figures and eight release-state assertions, found by sweeping the class
  rather than the two reported instances.** The reviewer found one of each; a fix sized to that
  report would have been sized to the report rather than to the problem. Every tracked document
  was swept with `command grep` over `git ls-files` — not the shell's `grep` wrapper, which
  cannot see gitignored trees and would not have been trustworthy for the question either way.
  **Every figure below is the document being wrong, not the corpus changing. No detection
  figure moved and none needed measuring.**

  | document | claimed | the index says | cause |
  |---|---|---|---|
  | `README.md` | detection 22.2%, 172 of 774 | 53.6%, 696 of 1,299 | reported; stale since round 12 |
  | `README.md` | 602 known misses | 603 | reported |
  | `README.md` | 91,669 blobs, 12,249 / 79,420 | 92,800, 46,016 / 46,784 | reported |
  | `README.md` | regression 98 of 98 | 97 of 97 | **not reported**; round 15's two dropped members |
  | `SOURCES.md` | `published_shipped_as_bytes: 84` | 140 | **not reported**; two rounds stale |
  | `SOURCES.md` | 44,460 reproducible | 44,404 | **not reported**; the same 58 rows, then the two drops |
  | `SOURCES.md` | ships 7 + 67 + 8 + 2 | 66 + 58 + 8 + 7 + 1 | **not reported**; `undetected-pool-review` never listed |
  | `CORPUS_PLAN` §7.3 | 140 malicious members, 98 executed, 98 rule-exact, 42 known misses, 146 of 146 | 138, 97, 97, 41, 144 of 144 | **not reported**; five figures inside a statement about the check's own power |

  The `SOURCES.md` and `CORPUS_PLAN` entries are the sharper finding. `84 → 142 → 140` and
  `44,460 → 44,402 → 44,404` were each *recorded in this changelog on the round they moved*.
  The changelog got the correction and the document carrying the number did not — which is the
  precise shape a `--check` exists to make impossible, and the reason this round's answer is a
  gate rather than an edit. All of them are now generated or dated;
  `QUARANTINE_REVIEW_QUEUE.md`'s second copy of the technique-coverage figure was **deleted
  rather than generated**, because removing a duplicate beats checking one.

- **Eight sentences asserted a release state that the 2026-09-07 release falsified**, and the
  right repair differs per sentence — generate it, date it, or rewrite it as history. Three are
  in `SOURCES.md`, one in `KNOWN_ISSUES.md`, and four are in changelog entries that this round
  moved, where the released section they now sit in makes them history by position and they are
  dated in place besides.

  *The count was first reported as five, in this entry and in the commit message that landed
  it.* A line-based `command grep` matched seven; the eighth is the `SOURCES.md` five-row
  finding, whose sentence **wraps** — the line ends at `no shard has ever been` and the next
  begins `distributed,` — so the pattern could not see it, and it was found separately by
  reading. Recounting over unwrapped prose gives eight. The lesson is the one §11 keeps
  recording: a population enumerated by a line-based sweep is bounded by the sweep's line
  model, not by the prose. It is left corrected here rather than quietly, because a count that
  moved is not a result until it says why.
  `SOURCES.md`'s tree listing and its *`published` is a classification* section both said no
  shard had ever been distributed, in the present tense; both are rewritten as history with the
  current state beside them, because the distinction they draw is now load-bearing rather than
  merely tidy. `SOURCES.md`'s five-row finding said "no shard has ever been distributed, so
  nothing here is or was exposed" — the conclusion survives and was **re-checked rather than
  inherited**: all five rows are local-only, and none of their digests is among the 149 distinct
  hashes in the eight shipped manifests. That is a complete enumeration of every member of every
  shard against every one of the five, so a hit would have been found with certainty rather than
  with a sampling power that would need quoting. `KNOWN_ISSUES.md` issue 3 said both
  outside-webroot samples were staged in a shard that had not been distributed; neither half is
  true — the shard shipped, and only the `-b` sibling is in it, the `-a` having been adjudicated
  unpublishable and dropped while keeping the reason code that records how it was *found*. The
  two instances inside changelog entries are dated in place in the released section below.

### Measured, not changed

- **No detection figure moved and none needed measuring.** This round writes no index row and
  rebuilds nothing. `index-summary.json` gains exactly one key, `published_shipped_by_reason`;
  a before/after diff over every key shows **one added, none removed, none changed**.
  `make-summary.py --check` was failing until the summary was regenerated in the commit that
  added the key, and it passes now.

- **The release's malicious/benign split, measured here rather than inherited from the
  review.** The review said the release "contains 140 samples of which 138 are malicious and two
  are deliberately benign attacker artefacts", while `benign-attacker-artefacts-001` ships one
  sample file. Both statements are right, and the trap is a third number: the eight manifests
  carry **144 members — 138 malicious and 6 benign**, of which 4 are generated clean carriers
  with no index row. Samples are 140. The two benign *samples* are the `failed-fetch-404-artefact`
  in the benign shard and an `orphaned-upload-stub` inside `malicious-uploaders-001`, which the
  release notes already say. Reconciled three ways that agree: 140 shipped index rows = 138
  malicious + 2 benign; 144 manifest members = those 140 + 4 carriers; and
  `published_fetched_not_shipped` = 44,544 − 140.

- **The review's "41(?) released known misses" against the census's 42 — both correct, for
  different questions.** 41 known misses ship as bytes; 42 are in the published index. The
  difference is exactly one row, `hex-digest-wrapper-outside-webroot-a`, adjudicated
  unpublishable and dropped from `malicious-outside-webroot-001` in round 15 while keeping its
  `outside-webroot-sweep` reason code, because a discovery route is not a publication decision.
  Measured two independent ways that agree: the index predicate `ships_as_bytes`, and opening
  all eight shard manifests. A flattering review is still a source whose numbers were not
  measured here.


### Added

- **`corpus/derived_db.py` and `corpus/derive-index-db.py` — a derived SQLite read index over
  both halves, whose freshness guarantee is refusal at read time.** The JSONL stays the source
  of truth; the database is one-way, gitignored, rebuildable in 2.16 s, and never authoritative
  about anything. It exists because every tool re-parses 61.4 MB — 92,800 rows, about 0.77 s of
  `json.loads` — on every invocation, dozens of times a round, and because nothing could ask for
  the rows in one cluster, carrying one tag, or under one path prefix without scanning all of
  them.

  **The check is not a `--check`.** `derived_db.open_ro()` verifies freshness as part of opening
  the file and raises if it cannot, so a stale read is unperformable rather than merely
  detectable, and there is no flag to skip it. That shape is chosen against this repository's
  record: `index-summary.json` could sit stale until a human ran `--check` and it did, twice;
  `make-summary.SHIPPED` carried the comment *"nothing catches a stale set"* and nothing did, so
  58 samples were reported as reproducible from upstream when they exist nowhere but inside a
  shard. Both are one defect — the detector separate from the use. `--check` exists and is
  useful; it is not the mechanism.

  **What freshness means is stored, not assumed.** A `source` table records each JSONL's
  sha256, row count and a cheap fingerprint; a `meta` table records the schema version and the
  build time. On open, the schema version must match exactly, the *set* of sources must match
  the machine, every sha256 must be recomputed and equal, and the rows the database holds per
  half must equal the count it recorded. The refusal names which source moved. Hashing costs
  0.055 s, about 7% of the parse it replaces, and is paid every open. The fingerprint may only
  ever say *definitely stale* and is never consulted by `open_ro`: both halves are written by
  `write_jsonl_atomic`, so a fast path that can wrongly answer "fresh" is the failure mode
  restated.

  **Three structural rules.** The builder reads under `indexio.index_lock`, both halves,
  published first — held 0.17 s of a 2.16 s build and released before the SQLite work, so a
  concurrent write makes the result *stale* rather than *wrong*. The database is assembled in a
  sibling temp file and `os.replace()`d in, so a reader never sees a partial build. Consumers
  open `file:...?mode=ro`, and the file is left in `DELETE` journal mode and never WAL, because
  a WAL database cannot be opened read-only without writing a `-shm` beside it.

  **The whole row is kept as JSON** beside the extracted columns, which is why the database is
  169.8 MB from 61.4 MB (277%). The census reports 326 dotted fields carried by rows and 53
  orphans, and its standing caution is that a field every row has lost is invisible to a census
  enumerated from the rows; a normalised schema that dropped unmodelled fields would make that
  worse and would do it quietly.

  **56 controls, both directions**, since a refusal that always fires and one that never fires
  look identical from a green run. The one that matters: an index edited **in place** with its
  size, mtime and inode restored to exactly what the database recorded — the fingerprint cannot
  prove it stale, and `open_ro` refuses it anyway. Beside it, the controls that stop the refusal
  from being vacuous: an index atomically rewritten to identical bytes still opens, an index
  touched but not changed still opens, and a published-only database is legitimate where there
  is no local half.

- **`corpus/derive-index-db.py --bench`** — measured rather than asserted, freshness check
  charged to every query because a consumer pays it every invocation:

  | query | rows | scan | db open | db rows | db keys | speed-up |
  |---|---|---|---|---|---|---|
  | cluster: one `family` | 495 | 0.77 s | 0.069 s | 0.007 s | 0.001 s | **10.1×** |
  | tag: `sensitivity` contains `c2` | 791 | 0.77 s | 0.053 s | 0.011 s | 0.002 s | **11.9×** |
  | path prefix: one 3-segment masked prefix | 10,254 | 0.77 s | 0.053 s | 0.245 s | 0.043 s | **2.6×** |

  `db rows` materialises every match through `json.loads`; `db keys` answers the same query
  without doing so, which is what a result list needs — the gap between those two columns is
  row materialisation, not index cost, and it is the whole of the third row's weaker figure.
  The speed-up quotes the pessimistic column. Every result set is reconciled against the scan
  in the same run, and a difference is reported as a failure rather than as a speed-up.

### Measured, not changed

- **No detection figure moved and none needed measuring.** This round adds a reader over the
  index and changes no row, no rule and no binary; `build-release/` was not rebuilt.
  `shard-gate.py` passes on both halves and `make-summary.py --check` agrees, all three
  unchanged from before the round.

- **The field census reads 326 fields carried and 53 orphans, against the 316 and 54 that
  CORPUS_PLAN §11 records for 2026-09-06.** The cause is the two rounds merged since
  (`corpus/clear-for-publication`, `corpus/release-flags`). Measured from git on the half that
  has history: the published index carried 158 dotted keys at `7f38f1f` and carries 202 today,
  **+44 and none removed**, almost all of them the `masking.secret_literals.*`,
  `masking.plaintext_finding.*` and `masking.remeasured.*` blocks those rounds wrote. The union
  over both halves moved only +10, so 34 of the 44 were already carried by the local half — and
  the orphan count fell by one because `origin.incident` was removed outright, which
  `field-provenance.py` reports under *fields REMOVED from the index*. **The local half's
  contribution to this delta is not measurable**: it is gitignored and has no history, so the
  +10 and the −1 are attributed to the published side plus a bound, not decomposed.

## [corpus-2026.09.1] - 2026-09-07

**Erratum, recorded after the release.** The `README.md` at this tag carried stale detection
and corpus figures. The tag is not moved and the release is not re-cut — re-tagging a published
artefact is the one thing this project refuses on principle, and a tag is history rather than a
mistake to erase — so the correction is recorded here instead:

| `README.md` at `corpus-2026.09.1` said | the index at that tag said |
|---|---|
| Detection: 22.2% — 172 of 774 confirmed-malicious samples | **53.6% — 696 of 1,299** |
| The other 602 are recorded known misses | **603** |
| Regression: 98 of 98 expected detections still firing | **97 of 97** |
| The corpus holds 91,669 blobs, 12,249 classified, 79,420 unreviewed | **92,800 blobs, 46,016 classified, 46,784 unreviewed** |

`docs/corpus-release-notes.md` — which is what a consumer of the shards actually reads, and
which ships with the release — carried the correct figures throughout and is unchanged. The
defect was confined to the repository front page, where it was found by an outside reviewer
rather than by anything here. Fixed on `master` by generating them; see `corpus/doc-figures.py`
under Unreleased.

### Fixed

- **`published_shipped_as_bytes` was never a count of shipped bytes, and 58 samples were
  reported as the opposite of what they are.** It counts published rows whose reason code
  appears in a hand-maintained `SHIPPED` set in `make-summary.py`. `undetected-pool-review`
  was added as a reason code and never added to that set, so its 58 rows were counted under
  `published_fetched_not_shipped` — which asserts they are reproducible from a pinned source.
  They are not: nothing outside the shard has them. The 58 are 46 in
  `malicious-db-dropin-001`, 11 in `malicious-uploaders-001`, 1 in
  `benign-attacker-artefacts-001`, each resolved individually by hash. **The file's own
  comment predicted it** — *"`--check` catches a stale summary; nothing catches a stale set"* —
  and nothing did, because `--check` compares the summary to the index and both `shard-gate`
  runs read the index, which was never asked about the archives. The count moves 84 → 142 and
  44,460 → 44,402, two numbers by 58 in opposite directions.

- **No shard rebuilt to its own bytes.** Same content, same mtimes, same ownership, same
  permissions, different member order, because `tar -cf - .` emits readdir order. Permissions
  were also inconsistent across shards from the same script — 117 of 142 samples at `0400`, 25
  at `0644`. `build-shard.sh` now pins order, mtime, ownership and permissions, and
  `--selftest` builds the same content twice through perturbed stage metadata and requires one
  hash. All eight `.tar.zst` now reproduce. The `.zip` wrappers **cannot**: ZipCrypto prefixes
  each entry with a randomised 12-byte header, so three wraps of one input give three hashes.
  The selftest asserts that too, so a future reproducible zip flags the comment rather than
  quietly falsifying it.

### Added

- **`corpus/shard-census.py`** — the §7.2 gate run over the archives as they are rather than
  over the index that describes them: publishability, `pii`/`content` absence, the differential
  secret check, detection survival, and three-way agreement between each shard's
  `MANIFEST.json`, its tracked copy in `corpus/expect/` and the index row. 16 controls, each
  catching its planted defect. Census over all 142 samples and 146 members, so a discrepancy on
  any single member is detected with certainty rather than with a power figure.

- **CORPUS_PLAN §7.4 — how a consumer opens a shard.** The passphrase is `infected`, public by
  design and identical on all eight; `SOURCES.md` had named it for one. The purpose is
  anti-scanner, not confidentiality — it stops drive-by antivirus pickup and casual scraping of
  live malware, and a password published beside the file would be theatre if it claimed
  anything more. Samples extract read-only at `0400` and are live malware.

### Known before publication — all five closed

Three staleness findings stopped the upload and were recorded rather than worked around: one
blocked row sitting inside a built shard, one row recording `plaintext_gate: PASS` that the
current gate refuses on the shipped bytes, and four fixtures whose recorded gate evidence was
computed over the collected original rather than the generated carrier that ships (all four
pass when re-run over the shipped bytes — the row simply did not say so). **134 of the 142
shipped rows carried no `masking.provenance`**, so nothing dated a recorded result against the
predicate that produced it.

All of it is closed below. `corpus/shard-census.py --regate` now reports zero findings where
it reported five, over 140 samples rather than 142. **When this was written nothing had been
uploaded and no release existed**; `corpus/release-assets.sh --print-upload corpus-2026.09.1`
emitted the command and had no code path that published. The upload happened later the same
day — 2026-09-07 — which is what makes this section a release note rather than a plan.

### Added

- **Two ambiguous findings were put to the masker before being adjudicated, and it refused
  both — so both files are dropped rather than cleared.** The ruling was *do not adjudicate
  what you can mask*, and §5.4's relaxation covers a short identifier inside a plain base64
  region. Neither region qualified, for two different reasons, and both were measured rather
  than argued.

  **`a3edd57e2ceb` (`otykhyc.gif`, `malicious-staging-001`)** — the 4-character `contains` hit
  at offset 20,902 sits inside a 66-character run that `content_mask.B64_RUN` matches, so the
  masker reaches it in the only sense its regex can. The run ends in a single `=` and so has
  **65 data characters**, which is not a valid base64 length; `b64decode(validate=True)` raises
  and `mask_encoded_layers` takes the bare `except: continue` without even a report entry.
  §5.4's *first* per-region condition is that the region decodes. It is not an encoded layer at
  all. The full masker run confirms it: **0 changes, output byte-identical to input, 0 of 4,089
  encoded regions acted on**, and `plaintext_gate` still FAIL.

  **`3529f0f6b2cd` (`malicious-outside-webroot-001`)** is the opposite shape and the more
  interesting refusal. Its 131,300-character outer region **passes every §5.4 condition** — it
  decodes, and this encoder reproduces it byte for byte — so the masker reaches it in full,
  decodes 98,473 bytes and applies the plaintext masker. Nothing changes, because the hit is a
  3-character token inside a 97-character mixed-case run with a **digit on each side**, and
  `incident_mask.tiers()` demotes a name that short to positional masking (unrestricted
  containment reports one such name 49,292 times across this corpus). The gate, deliberately
  wider, counts a short identifier when neither neighbour is *alphabetic* — a digit is not.
  **The region is maskable and the finding is not reachable by masking**, and the reason it is
  not reachable is the same measurement that makes the finding a probable coincidence. Widening
  the masker is the repair that must not be made: §5.6 forbids it in sample bytes, and
  `content_mask.py` is in `gate_provenance.TOOLS`, so the edit would invalidate all 142 stamps.

  **What the shards lose.** `malicious-staging-001` 67 → 66 members: the dropped sample is one
  of **40** carrying `must_detect: ["OBF041"]` in a 52-member family, **39 remain**, and the set
  of its techniques that no remaining member carries is **empty**.
  `malicious-outside-webroot-001` 2 → 1: the survivor is the polymorphic sibling `37927df458e5`
  with an **identical eight-technique list**, all gates PASS and `publishable: true`. Both are
  `known_miss` with `must_detect: []`, so the shard's detection content is unchanged and
  KNOWN_ISSUES issue 3 now rests on one sample rather than two.

  The applicable statistic is the corpus-wide **P ≈ 21%**; the per-file 2.5% is not quoted,
  because it was computed for the most extreme of 142 files after seeing it, which is §11's
  denominator-chosen-by-the-numerator in its purest form. Both readings stand and neither
  decided anything: the mask was attempted first and failed, and a region that cannot be masked
  costs one sample out of 142 against an irreversible publication.

- **`verify-and-stamp.py` skipped every row it was written to stamp, and the stamp now names
  its bytes.** The loop opened `if not m.get("applied"): continue` — a claim about whether the
  *masker changed bytes* — while a stamp certifies a *gate verdict*. **123 published rows record
  both identifier gates with `applied: false`** and the reason "no identifier to mask: the
  independent gate found none": a gate that ran, over bytes that ship, producing a published
  claim nothing dated. That is §7.2's own correction — *whether the evidence is READ must not
  depend on the claim it might contradict* — in the tool that **writes** the record. Not
  hypothetical: `a3edd57e2ceb` is in that population and its recorded PASS is a FAIL on the
  bytes in the tar.

  The 134 are two populations, not one: **123 record gate results and owe a stamp; 11 record an
  empty `masking: {}`** — tagged `clean` or `c2`, both in `ALWAYS_OK` — and owe nothing, which
  is reported rather than silently skipped. **131 rows stamped** (122 added, 9 replaced under
  `--restamp`), **0 refused, 0 not-checkable**.

  `masking.provenance` gains `bytes_sha256`, the digest of what the gate was re-run over: both
  halves are needed to re-derive a published result, the predicate and the input. Written here
  and **not** in `gate_provenance.stamp()`, because that file is in `TOOLS` and the digest must
  not move for a field that is not part of the predicate — **`tools` stayed
  `c5c21c570397`**. Safe against clearances by construction rather than by luck:
  `clearance._prov_key` reads `tools` and `map` only, asserted in both directions by a control.
  `masked_sha256` is no longer added where masking was not applied, which would have stated a
  masking that did not happen on 122 rows.

- **`shard-census.py` reads the stamp's bytes, which closes the four fixture findings.** The
  four generated carriers re-measure **PASS on both gates over the bytes that ship**, and
  `remeasure-gates.py` correctly **refuses** to rewrite a record that did not move. What was
  missing was never the measurement but the statement of which bytes it was about, so the census
  accepts a fixture-resolved member only where `masking.provenance.bytes_sha256` **equals** the
  member's own hash. The field is evidence, not an assertion: a stamp naming other bytes leaves
  the finding standing, asserted in both directions.

- **A credential kept on purpose now says so (`corpus/keep-credential.py`,
  `corpus/credential_disposition.py`).** The two `pdf-magic-fake-supercache` rows each carry one
  `quoted-credential` literal and neither carries the `secret` tag, so `evaluate()` demanded no
  `secret_gate`, none ran, no finding existed, and **the rule passed in silence** — the eighth
  form of this defect.

  **The literal is not a password value, and reading it makes the keep stronger.** The captured
  group is `.$<var>.` — PHP string-concatenation syntax between two delimiters, from the
  backdoor generating `<a href="?pass='.$var.'&…">`. The access password is a runtime variable
  and **is not in these bytes**. Kept for the same reason the campaign hosts on those rows are
  kept (§4.1).

  The gate is now run and its answer recorded: **FAIL on both**, correctly — `secret_gate` is a
  differential and `changes: 0` means every literal is carried over by construction. The FAIL
  **blocks**, and the keep is a `clear-finding.py` clearance signed by a person and keyed to the
  finding digest. `keep-credential.py` can only ever make a row *less* publishable: the
  disposition is the argument, the clearance is the authorisation, written by different tools on
  purpose. A disposition records shape, keyword, value length and character-class form and
  **never a value**; there is deliberately no digest, because the shape key already ties the
  record to the bytes and a truncated digest of a short word is dictionary-recoverable.
  `shard-gate` checks the record against itself (a row may not keep more literals than the gate
  says survived); `shard-census --regate` checks it against the tar, in both directions.

  **The null is reported and deliberately not relied on.** Over 12,000 stock CMS PHP files: 73
  `quoted-credential` literals in 68 files (0.57%), 3 containing a variable sigil, and 0 of this
  exact form. **State the power:** 0 of 73 excludes a class rate above roughly 4% by the rule of
  three and says nothing below it — the trap round 14 recorded when a class read 0 of 109 and
  was 3.9% at four times the sample. The argument rests on reading the match.

- **`corpus/release-assets.sh` — the checksum list is derived in the run that verifies it.**
  There is no stored list: `--verify` recomputes each inner `.tar.zst` hash from disk, unwraps
  each `.zip` and asserts the tar inside is that same file, rebuilds each shard from its own
  contents and asserts byte-identity, and only then writes `SHA256SUMS`; on any failure it
  writes nothing. `--print-upload` emits the tag and `gh release create` command and has **no
  code path that publishes**. Six controls. One of them failed usefully: every case printed
  `caught` while the script exited 1, because `scratch()` appended to an array inside `$( )` —
  a subshell — so the cleanup list stayed empty, the `EXIT` trap returned 1 on the empty
  expansion, and every temp directory was being left on disk. Found only because the exit status
  was checked and not just the output.

### Fixed

- **No shard had ever been rebuilt with the reproducibility repair, so none of the eight
  reproduced.** The previous round fixed `build-shard.sh` and its `--selftest`; the eight
  artefacts on disk were never rebuilt through it. Measured before anything changed, by
  extracting each shipped shard and repacking it: **all eight DIFFER**, and the archives say why
  — `lytrax/lytrax` ownership, real mtimes, `MANIFEST.json` at `0644`, readdir order. All eight
  were rebuilt through the tracked script and **all eight now reproduce from an extraction**.
  Six changed by rebuild alone and two by rebuild plus a dropped member; the six were predicted
  from the pre-change extraction and came out identical, which is what makes the other two
  attributable to the drop. A checksum list written before this round would have been internally
  consistent and wrong about every one of the eight files.

- **Two predicates said "ships" and tested "published", and a dropped member separated them.**
  `make-summary.SHIPPED` counts a reason code, which records how a sample was *found* and not
  that its bytes are in a shard; rewriting a discovery route to fix arithmetic would destroy the
  provenance instead. The count gains the condition the archives already enforce — the census
  fails the build on "shipped row is not publishable today" — hoisted to `ships_as_bytes()` so
  it can carry a control. `published_shipped_as_bytes` **142 → 140**.
  `malicious_detected_runnable`'s own comment already said *"how many **ship** and can therefore
  actually be re-run"* while the predicate said "published": it read 98 where `verify.py`
  executed 97 and printed **NOT RECONCILED**. **98 → 97**, and the figure now reconciles.

- **`verify.py` reported two families as "not present in any shard"** — the right check asking
  the wrong question, since an unpublishable row is not in a public shard by design. It skips
  rows that are not `publishable` and **prints the count**, because a family disappearing from
  the suite must be visible as a number rather than as nothing.

- **`a3edd57e2ceb`'s `plaintext_gate` was a stale PASS**, re-measured against the file in the
  tar: **verdict-moved to FAIL**, finding recorded, `publishable` recomputed by
  `shard-gate.py --fix`, which is the only writer of that field. **Published `publishable`
  44,543 → 44,542**, that row alone. Left standing and stated rather than repaired: the row
  still carries `masking.reason: "no identifier to mask…"` beside the FAIL that contradicts it —
  true on the other 122 rows that share the sentence, false on this one, and a one-invariant
  repair for the next round.

- **`docs/corpus-release-notes.md`** — written for a stranger rather than for us: what the eight
  shards are, that the samples are live malware extracting read-only at `0400`, the passphrase
  and the §7.4 open procedure, how to verify an asset and why the `.tar.zst` hash is the one
  that certifies it, and what the figures mean — **including that the headline 53.6% mixes in
  1,131 samples of the rules' own source material while the in-scope figure is 631 of 703**.
  With an explicit section on what a consumer may and may not conclude: not precision, which is
  a field-scan measurement; not a false-positive rate transferable off pinned upstream CMS
  source; and not a detection rate for their own server, over a corpus 48% of which is still
  unreviewed.

### Added

- **The prose a gate finding carries is out of the AST, and the price was paid once
  (`corpus/finding-note.txt`, `corpus/finding_notes.py`).** Two sentences generated onto
  findings were string literals inside `verify-content-mask.py`, one of the six modules in
  `gate_provenance.TOOLS`, so correcting either cost a re-measurement of every stamped row —
  which is why the identifier note's second clause, *"they are the thing being masked"*, was
  known-wrong for two rounds and stayed. It presumes the outcome the two adjudicated
  polyglots exist to overturn: an identifier this gate finds may equally be attacker
  infrastructure that is deliberately kept. The corrected note now says that what a matched
  name is, is an adjudication and not something the field decides.

  **All six copies read from one source.** Five modules — `clearance.py`, `gate_evidence.py`,
  `lift-adjudication.py`, `remeasure-gates.py`, `shard-gate.py` — hard-coded the note in
  their own finding fixtures, and every one of them carried `identifier names deliberately
  not recorded here` while the generator wrote `… here; they are the thing being masked`.
  **Five controls had been asserting text the generator has never produced**, invisibly,
  because each agreed with itself. They now take it from `finding_notes.IDENTIFIER_NOTE`,
  and `finding_notes.py --inject` reads the five modules' own syntax trees and reports any
  finding-shaped dict that has gone back to a literal — with the planted-note positive
  control, and with `shard-gate.FINDING_SHAPE` excluded for being a table of type tags
  rather than by name, so a shape table that ever gained real prose would be reported.

  **`secret_gate`'s note is deleted rather than relocated, and that closes a live schema
  fork.** No writer recorded it — `mask-samples.py` writes twelve named fields and
  `remeasure-gates.recorded_form` narrows to the same twelve — so it survived only on 8 rows
  from an earlier build that recorded thirteen keys where 124 recorded twelve.
  `gate_evidence.compare_gate` compares the keys the *row* holds, so those two schemas could
  answer differently the moment the text moved, and the only thing making that harmless was
  that the text was pinned inside a `TOOLS` module. Removing the key made all 8 read
  `evidence-moved` once and reconcile to twelve. **Forked rows: 8 → 0**, now asserted by
  `gate_evidence.forked_secret_rows` over both halves rather than guarded by a coupling —
  and `digest-controls.py`'s case on that note is kept under its old subject with its answer
  reversed, because a control that disappears when its answer changes is how a repository
  forgets what it decided.

  **Reachability, measured before anything moved.** Two figures were in circulation and both
  are superseded. The "69 of 140" is real and lives in `shard-gate.findingShapeViolations`
  (`restage-masked.py` states it as "73 had reachable bytes and 69 did not"); it predates
  regeneration, and it does not add up — 73 + 69 is 142 masked rows, not the 140 stamped at
  that moment. Regeneration answers **132 of 142**, reproduced exactly on 2026-09-07. The
  reachable set is **142 of 142**, because regeneration is one of three ways to *prove* a
  row's masked bytes and `restage-masked.py` implemented one. It now implements all three:
  `regenerated-unchanged` (6 rows recording `changes: 0` — the row saying its masked form
  *is* its input, whose sha256 it records; a rebuild that touches a byte still returns
  `mismatch`), and `--found` (4 rows whose masked bytes were already on disk and hash to
  what the row records, via `masked_sha256` or a `remeasured.bytes_sha256` fallback that is
  named in the report rather than passed off as the field). Nothing was stranded.

  **Counts, each with its cause.** `tools_digest` 83735611dab4 → c5c21c570397; all **142**
  stamped rows re-measured — 129 by `verify-and-stamp.py --restamp`, 13 by
  `remeasure-gates.py` where the note change made the recorded evidence move.
  **Published `publishable` did not move: 44,543 → 44,543.** The estimate recorded in
  `shard-gate.py` was 44,536, written off seven rows that turned out to be reachable, six of
  them by the `changes: 0` proof. `3529f0f6b2cd` shed its stale-provenance blocker — it was
  the row left stale for want of bytes last round — and stays unpublishable for its real
  encoded-layer `FAIL`. **Local `publishable` 365 → 364, and the missing row is the round's
  result**: `34bba99dae63`'s five clearances are keyed to finding digests
  (`35c1c513eafa → 97b08efeb965`, `410ecb66d940 → e10eaf8d5831`, `b79b479b3940 →
  411e0ef0c067`) *and* to gate provenance, and both moved. It is over-determined — the
  provenance half alone inerts them, so the row would have lost `publishable` this round
  even had the note not changed a character. Re-signing is the operator's act and no tool's,
  so the row is `publishable: false` with its three real gate failures recorded as blockers.
  `index-summary.json` was regenerated: `--check` was failing until it was, and every
  difference it reported was that one row. **No detection figure moved**: nothing here ran
  the scanner, both writers assert detection parity is outside their scope, and a field-level
  diff of all 44,544 published rows against `HEAD` shows `detection_survived`, `rules_*`,
  `measured_with` and `detection_after_masking` unchanged on every one.

- **The orphan census can say which verdicts rest on a shared leaf, and one orphan is
  resolved by reading the table it is named in (`corpus/field-provenance.py`).** 43% of
  non-orphan classifications sat on a leaf shared with another field and the figure appeared
  once, in the header, so no individual verdict said whether it was one of them. It is now on
  the verdict — and only where it can change the reading, because the bound is
  one-directional: matching by leaf can only *add* matches, so a `written` or `read-only`
  verdict on a shared leaf is weaker, while an `ORPHAN` is unaffected. A leaf no module names
  at all is named for none of the fields on it.

  `named_field_tables` reads a declared constant out of a module's syntax tree, so
  `campaign_marker` — listed in `make-shard-manifest.INDEX_OWNED`, a bare string in a table
  that `key_positions`' subscript-and-`.get()` sweep cannot see — is classified `read-only`
  from the source rather than by a hand-written override. **Orphans 54 → 53**, `read-only`
  23 → 24. The list of tables is named rather than pattern-matched: crediting every uppercase
  tuple of strings would inflate `read-only` the way `written` is already inflated.

  Ten more orphans are triaged into `KNOWN` with their causes, searched with `command grep`
  over the 276 python files under `corpus/`, `trail-data/`, `docs/` and `tests/` found by
  `find` — the shell's `grep` respects `.gitignore` and cannot see `trail-data`, which is
  where every untracked writer named actually lives. Two are near-misses worth recording
  because the next sweep would otherwise resolve them by accident: `fp_fixture` against
  `verify.py`'s own `fp_fixtures`, `observed_by` against its `observed_by_rerun`, and the
  `basis` leaf against `tag-sensitivity.py`'s `human_basis` and `make-summary.py`'s
  `<no basis recorded>` placeholder — three substring collisions in a triage of eleven
  fields, which is the rate to expect rather than a run of bad luck.
  `prior_corpus` (2,494 rows) has no writer and no reader anywhere on this machine — its only
  mentions are two docstrings citing `prior_corpus.family`, a field neither half carries.

- **`corpus/lift-adjudication.py` — a human adjudication is no longer squatting in a gate's
  evidence key.** Two published rows, the polyglot siblings of §5.4, recorded
  `classification / decision / resolution / value / why_it_matters` under
  `masking.encoded_layer_finding`. Not one of those is a key the encoded-layer gate produces,
  and `clearance.finding_digest` is taken over exactly that key — so on those two rows the
  finding digest for the encoded-layer gate was computed **over prose and an address**, and
  rewording the argument would have moved it.

  Measured before the move rather than argued. Run against both pseudonym maps (288
  identifiers, 64 keep tokens) over the exact fixture bytes the shard ships and whose sha256
  the rows record, the current tools return `PASS` for both and emit **no
  `encoded_layer_finding` at all**. The block was never a gate finding. And the damage was
  already live: `verify-and-stamp.reverify` reported **`disagrees` / `evidence-moved` on both
  rows before the move and `agrees` on both after**, so each was unrepairable by
  `verify-and-stamp.py` and refused outright by `remeasure-gates.py`'s human-decision rule.

  Moved to `masking.human_adjudication`, additive except for the vacated key, with `about`
  added to name the gate the old key said structurally. Digest `663ee3e0cf71 →
  ebddfbf1d6ed` on both; **no clearance was keyed to either**, checked over every clearance
  object on this machine rather than assumed; `publishable` stayed `true` with zero blockers
  on both, before and after. The leaf is `human_adjudication` and not `adjudication` because
  `field-provenance.classify` matches on the leaf — see §11's eleventh instance below.

- **`shard-gate.py` — four blocks of published content that nothing read now have readers.**
  Ten of the 64 orphan fields, all on published rows, all describing either an identifier
  kept on purpose or the identity of a shipped fixture. All map-free.

  * **a gate finding records shapes and counts, and nothing else.** Every finding carries a
    generated note saying *"identifier names deliberately not recorded here"* — a claim about
    the field, published in the tracked index, with nothing checking it, while two other
    published rows used that same field to record an address. A finding may now carry only
    the keys `_profile` emits, at the types it emits them. Run against the two rows **as they
    were**, it fires on both; against the index as it stands, it is clean.
  * **an adjudication must be one somebody else could audit** — every required key present,
    `about` naming a gate the row records, and **an address in its resolution must be one the
    row declares in `ioc.campaign_hosts`**. That is the c2-versus-customer distinction made
    structural instead of assumed: this block may name an identifier only because the
    identifier is attacker infrastructure kept under §4.1, and an adjudication resolving to
    an address the row never declared would be a decision to publish one on no stated ground.
  * **the kept-indicator block keeps saying only what it is for** — `c2_fallback_ip` among
    `campaign_hosts`, every entry host-shaped, and the block, `masking.c2_kept` and the `c2`
    tag agreeing. Three records of one decision that could disagree, and nothing asked.
  * **a fixture describes the bytes it ships** — payload smaller than fixture, two distinct
    64-hex hashes, `name == family`, and `sha256 == fixture_sha256` **iff**
    `size == fixture_size` (7 of 7 agree in both directions; three rows are their own fixture
    and four are not, and a row that is one by hash and not by size is half-updated).

- **`clearances` record `reasoned_by`.** `by` is the authorising human and stays that —
  accountability for a publication decision belongs with a person. But all three live
  clearances read `by: cl` while the argument in each was drafted by an assistant, presented
  and authorised, so the record read as though the signer had done the reading. The second
  question now has its own field: `clear-finding.py` refuses to write a clearance without it,
  and the three applying clearances were backfilled. `by` was not rewritten on any of them —
  the authorisation was real, and rewriting it is the laundering this mechanism exists to
  prevent. The field is deliberately **not** in `clearance.REQUIRED`: `malformed()` is the
  hard-failure path and the two superseded records predate the field, so `shard-gate` prints
  the count of clearances carrying none instead of destroying them.

- **`corpus/gate_evidence.py` — the stamp now compares the whole finding, not the verdict
  class.** A provenance stamp asserts that *these tools produced these verdicts*, and both
  tools that write one compared the verdict class and stopped there. So a finding payload
  could go stale beneath a stamp that appears to certify it, and the two tools then disagreed
  in a way that left the row unrepairable by either: `verify-and-stamp.py` stamps where the
  verdicts agree, so `FAIL` still being `FAIL` meant it stamped; `remeasure-gates.py` refuses
  where no verdict moved, so it would not write the fresh payload. Neither was wrong about the
  verdict.

  **This is worse than the two blind spots closed before it, and specifically rather than
  rhetorically: those blocked rows and this one authorises.** The evidence is what a person
  reads when they judge a finding, and `clearance.finding_digest` is taken over exactly that
  evidence, so a payload moving under a current stamp un-anchors a human decision instead of
  raising a blocker. There is a second route to the same place and it was opened deliberately:
  `FP_NOTE` moved out of `verify-content-mask.py` last round so that correcting a
  false-positive figure would stop invalidating 140 stamps — which means the note can now be
  rewritten with `provenance.tools` unmoved while `false_positive_note` inside every stored
  finding, and every clearance digest keyed to it, moves.

  Both tools now compare through this module, so they cannot go back to disagreeing about what
  "the row records this" means. The evidence is read through `clearance.evidence_for` rather
  than a second lookup table — a stamp has to certify exactly what a clearance keys to — and
  `same_finding()` asserts that tie in both directions. Out of `gate_provenance.TOOLS` on the
  same ground `shard-gate.py` is out: it decides no gate verdict, and including it would
  invalidate all 142 stamps on every edit to a comparator.

  **The rule was measured before it was armed.** Requiring the recorded block to carry every
  key the current tools emit would put **126 of the 132** measurable rows into re-measurement
  for `note`, a constant string of prose that neither writer disagrees about. So the armed rule
  is the keys the row records; a key the tools emit and the row does not is reported as
  `unrecorded_fields` and is not a difference, and the opposite direction — a key the row
  records that the tools no longer emit — is. 27 control cases, and against the superseded
  verdict-only comparison **6 of the 27 fail**.

- **`shard-gate.py`: a recorded `decision` must carry its `resolution`.** A block reading
  `decision: held for human confirmation; not published until resolved` with no `resolution`
  beside it is, to every tracked consumer of this index, identical to a row with nothing wrong:
  `publishable` is computed from gate verdicts and tags, none of which the decision touches.
  The sentence says the row is held and nothing holds it.

  **The population is zero and the controls are therefore the whole of the check, which is
  written into its docstring.** Two rows in the corpus carry a `decision`, both published, both
  `publishable: true`, both carrying a `resolution`; nothing tracked read either field. So this
  rule has never fired, cannot be validated against real data, and is exactly what AGENTS.md
  means by "not yet a check". Ten control cases in both directions, including a decision under
  `gate_categories` (the second place findings live), a resolution recorded as empty, a
  resolution with no decision, §8's one-cause-one-reason on a row already blocked elsewhere,
  and the assertion that it is not clearable. The live run prints the census — 2 carriers, 0
  unresolved — as a statement about the population, never as evidence the rule works.

- **Two orphan fields given a tracked reader in `shard-gate.py`, both invariants that have
  never fired.**

  `masking.detection_after_masking` (6 published rows) looks redundant beside `rules_after` and
  is not: **no published row carries `rules_after` at all**, so on those six rows it is the
  published half's only record of what the scanner matched after masking — and it is the
  measurement `expect.must_detect` was taken from. The reader is the relationship it stands in:
  `set(expect.must_detect) <= set(detection_after_masking)`, a floor rather than an equality,
  because the recorded scan may legitimately have seen more but may not have failed to see
  something the row asserts. It holds on 6 of 6, with equality on all six. 7 controls.

  `staging_dir` (75 rows, **67 of them published**) is a directory name, and the positive form
  of that is what is asserted — one path component from `[A-Za-z0-9._-]` — the same discipline
  as `HOME_RE`/`ACCT_RE` and map-free for the same reason. Measured before arming: 13 distinct
  values, 7 to 32 characters, every one a single component, and **none matching an identifier in
  either pseudonym map**. They are attacker-created directory names. The rule's value is not
  today's population; it is that the field can never come to hold `/home/<x>/…` without
  something saying so. 11 controls.

- **`pre-push-check.py` now delegates `make-summary.py --check`, so a stale denominator
  refuses a push.** The rule that it must be run was already in AGENTS.md, already annotated
  with the note that it exists because a round was reported green while it was failing — and a
  round was then reported green while it was failing. A written rule missed twice wants a gate,
  not stronger wording, so the summary is enforced beside the index question
  (`verify-infected-mask`) and the gate invariants (`shard-gate`).

  **Controls run in both directions**, because a delegation that always refuses and one that
  never fires look identical from a green run: a fresh summary must be accepted and a summary
  **stale by one** must be refused, with the refusal asserted to name the field that drifted.
  The stale case is a valid, plausible summary wrong by one rather than malformed JSON — a
  broken file would prove only that broken files are caught. The control builds a temp
  directory of symlinks to the real index halves with its own copy of the summary, so nothing
  in the repository is written.

- **`corpus/secret-fp.py` — the stock-CMS null for the secret gate's shapes, per class.**
  `--stock-fp` and `--base-rate` are both nulls for the *identifier* gates; the secret gate had
  none, so a row could record `secret_literals_carried_over: 2` with nothing to say whether two
  credential-shaped literals in a megabyte of vendored library code is a lot or the number you
  get for free. It imports the tracked `SECRET_SHAPES` predicate rather than restating it, and
  it is a separate file **because `verify-content-mask.py` is inside `gate_provenance.TOOLS`**:
  adding a mode there would move the digest and invalidate every stamp and both clearances
  again, and a null is a measurement *about* a gate rather than part of it.

  Over 32,000 stock files: 161 (0.50%) carry a credential-shaped literal, 343 literals, 230
  `quoted-credential`. Broken down by keyword, value length and **whether the value contains a
  space** — the discriminator that actually separates a credential from a UI message, reported
  rather than assumed. 14 controls, including that a planted credential is counted, that a file
  with none contributes zero *and is still counted as scanned*, that the space classes are
  distinct, and that the keyword list has not drifted from the tracked pattern.

- **`shard-gate.py` asserts `sum(placements.values()) == count`.** `placements` was an orphan on
  33,555 rows, **15,674 of them published**, and no tracked module mentioned it. It is not dead
  — it is a histogram of where on a real server the copies of a blob were found, over a closed
  vocabulary of 11 labels — so it gets a reader rather than a deletion. The invariant holds on
  **33,555 of 33,555**: 33,553 against `count`, and 2 against `copies_on_disk`, an older name
  for the same quantity that was itself an orphan on exactly those two rows. Two orphans
  resolved by one invariant.

  Nine controls, both directions. **The invariant has never fired in anger** — it was written
  over a population that already satisfies it, which is the condition AGENTS.md names as "not
  yet a check", and that is why there are nine controls rather than a green run.

- **`corpus/drop-field.py` — remove a dead field from an index, and refuse to do it blind.**
  Removing a field from 47,133 rows is three lines of Python, and that is the problem: every
  orphan this corpus has found was written by a script somebody ran once and never committed,
  and a round that deletes one with an untracked one-liner has done the same thing in the other
  direction. It refuses any field a tracked module writes or reads (delegated to
  `field-provenance.py`, so the guard cannot drift from the census that justified the removal),
  refuses `publishable` and anything under `masking`, refuses a deletion that would remove
  nothing, and asserts after the edit that the row count, the row order and every other field
  are unchanged. 19 controls.

### Changed

- **The `secret_literals` schema fork is closed at the writer, and the reason the remaining
  eight rows are not rewritten is priced rather than asserted.** Re-derived over both halves:
  **124 rows record twelve keys and 8 record thirteen** — not the 126 and 6 recorded when the
  comparison rule was armed, and the difference has a cause. All 8 of the thirteens are rows
  `remeasure-gates.py` rewrote, and the two rewritten at the end of last round moved from
  twelve keys to thirteen as a side effect: arming the rule created two more instances of
  the case it had been measured against. The extra key is `note`, a constant string of prose
  that carries no measurement, and it is an artefact of one writer emitting whatever the gate
  returned where `mask-samples.py` records a named subset.

  `remeasure-gates.py` now records the same twelve, taken from
  `gate_evidence.RECORDED_SECRET_KEYS` and asserted equal to `mask-samples.py`'s own tuple by
  reading it out of that module's syntax tree — the constant cannot live in `mask-samples.py`
  itself, which is in `gate_provenance.TOOLS`, without moving the digest to install a name.

  **The eight existing rows are left, and why:** dropping `note` moves
  `clearance.finding_digest` for `secret_gate`, and `34bba99dae63` carries a live human
  clearance keyed to that digest. Rewriting the record would inert an authorisation entered a
  round ago over a constant string, and re-signing is the operator's act, not a tool's. The
  schema converges by attrition instead — no new row can fork, and each of the eight collapses
  to twelve the next time it is legitimately re-measured.

  **And the divergence being harmless today is now checked instead of relied on.** The two
  schemas can only answer differently if the note's *text* moves, and that string is a literal
  inside `verify-content-mask.py`, so moving it moves the `tools` digest and every stamped row
  goes stale in the same instant. `digest-controls.py` asserts that coupling — and asserts its
  opposite for `fp-note.txt`, which was deliberately moved out of the AST for exactly the
  reason that would make this fork live.

- **`verify-and-stamp.py` and `remeasure-gates.py` compare the finding, and
  `remeasure-gates.py` now writes only what moved.** The stamper refuses a row whose payload
  the current tools would not produce even where `FAIL` is still `FAIL`, and says which cause —
  a moved verdict needs a decision, a moved payload needs a re-measurement, and §8 counts
  causes. The re-measurer treats a moved payload as a reason to run.

  Arming that made two previously harmless rewrites harmful, so the write is now scoped to the
  keys `moved()` reports. Normalising a recorded `{"result": "FAIL"}` into the string `"FAIL"`
  moves `clearance.finding_digest` and takes a human clearance with it, for a verdict whose
  class never changed; and the finding-removal branch — correct when a gate goes back to
  `PASS` — would have **deleted a human decision record** sitting under `encoded_layer_finding`
  on a published row whose gate already passes. A block carrying a `decision` is now refused
  outright rather than rewritten or removed. A finding is also written to whichever block holds
  it, `masking` or `gate_categories`, so a row cannot end up with two copies of one finding and
  one of them superseded; `assert_scoped` checks inside `gate_categories` rather than waving the
  block through. `remeasure-gates --inject` 26 → **44** cases, `verify-and-stamp --inject` →
  **25** with a counted total (it was the literal 14), and 4 of the 25 fail against the
  superseded comparison.

- **The drift was measured across every stamped row, and it is two.** 142 rows carry a
  provenance stamp — 141 current, 1 published stamp left `stale` for want of bytes.
  `restage-masked.py` regenerated and hash-verified the masked bytes for **132** of the 142
  from their originals, which is every row that records a `masked_sha256` the regeneration
  reproduces; the other 10 are 7 published rows recording no `masked_sha256` at all (6 shipped
  fixtures and the stale one) and 3 whose regeneration hashes to something this tree no longer
  reproduces. Of the 132, **2 carry a current stamp over evidence the current tools would not
  produce**, and in both the verdict class is unmoved.

  **State the power, not just the outcome.** The drift found is entirely in `secret_literals`,
  which is recorded on **132 of 142** masked rows — and every one of those 132 is measured, so
  for that field this is a census and not a sample. `plaintext_finding` is 5 of 5 measured.
  `encoded_layer_finding` is 3 of 5: the two unmeasured are the published rows in *Measured, and
  open* below. 138 of the 140 recorded evidence blocks were re-measured; the two that were not
  could not be, and are named.

  Cause, attributed rather than assumed: re-running the gate from `d548b3e` over the same
  before/after pairs reproduces both recorded payloads exactly, and today's gate reproduces
  neither. The payloads were produced by the predicate superseded in `194e969` — the PEM shape
  and the widened `quoted-credential` keyword — while the stamp beside them is the one that
  repair created. `34bba99dae63`: 1 / 1 / 1 recorded, **2 / 2 / 2** today. `b827cdd9d417`:
  22 / 23 / 22 recorded, **27 / 25 / 23** today, with `shapes_carried_over` gaining
  `quoted-credential`.

  Both re-measured with `remeasure-gates.py --by cl`. `b827cdd9d417` loses a blocker as a
  result — *"masking left more credential-shaped literals than it found (22 → 23) over a
  decoded-layer population that moved"* — because the widened pattern sees 27 literals in the
  input where the old one saw 22, so the apparent increase was an artefact of a pattern that
  could see fewer literals before masking than after. It stays unpublishable on `pii`.

- **Three clearances on `34bba99dae63`, and the row becomes `publishable: true` — read this
  one.** The two identifier clearances were re-signed against a fresh measurement rather than
  carried forward: both findings were re-derived from the bytes today and both digests are
  unchanged (`35c1c513eafa`, `410ecb66d940`), so what had lapsed was only the provenance pin.
  The plaintext reason is re-derived — three `contains` hits of one 3-character label in base64
  ciphertext runs, each bounded by digits, at offsets 15 / 50 / 16 of segments of 70 / 74 / 19;
  the base64 null regenerated today at 660 trials × 98,473 bytes gives 0.182 hits per trial, the
  masked bytes carry **585,252 bytes of base64 run over 211 runs**, so the null expects 1.08 and
  three is p ≈ 0.10 under Poisson. (The previous signature cited 581,931 bytes over 34 runs; the
  byte total agrees to 0.6% and the run count was taken over a different definition of a run.)
  The encoded-layer reason is sharper than the one it replaces: the 25-character segment is not
  a name at all — the splitter treats `_` as a separator and `|` as an ordinary character, so it
  is the tail of one pipe-delimited function name plus the extension prefix of the next, and the
  `begins` position is an artefact of where that prefix ends.

  The third is a ruling: **both carried-over secret literals are collisions.** They are UI
  strings in a vendored browser-terminal widget, in one `strings` message table inside a
  119,508-byte `base64+inflate` layer. Neither was changed by masking, which is the gate working
  — it measures whether masking altered a credential-shaped literal — on two strings that are
  not secrets.

  **The trade is recorded with the ruling, because it is a real cost and not a defect.** The
  second literal is visible only because the pattern's left boundary was dropped last round so a
  password on a variable whose name *ends* with the keyword would be caught. Priced by running
  the same 32,000-file stock null through the pre-repair pattern: `quoted-credential` false
  positives **116 → 230**, of which **113 are the dropped left boundary**, 1 the added `pwd`
  keyword and 0 the new PEM shape; space-containing ones **42 → 87**; and that literal's own
  class — keyword `password`, 8–15 characters, *with* a space — goes from **0 to 9**. The first
  literal's class is the largest in the null at **59 of 230**. No shape refinement is proposed:
  "contains a space" would be a guess of the same kind as the last one and has not survived a
  null of its own.

  **Consequence, stated plainly:** all three of this row's blockers now carry an applicable
  clearance, so `shard-gate.py --fix` computes `publishable: true` and local publishable goes
  **364 → 365**. That is the escape hatch doing exactly what it is for, and it is also the first
  time it has opened. The row is in the local half and nothing promotes it; promotion remains a
  separate act.

- **`clear-finding.py` refused the one act the clearance design demands.** Its duplicate test
  compared the gate and the finding digest and stopped there, so a clearance that had gone
  **inert** because the tools digest moved — the state this design deliberately produces, and
  the state both clearances on `34bba99dae63` were in — could never be re-signed. The refusal
  even named the case (*"an inert one being papered over"*) while being unable to tell it from a
  genuine duplicate: the finding is the same and what has changed is the pin, which the test did
  not read.

  The comparison is now (gate, finding, **pin**). Same finding under the same pin is a duplicate
  and stays refused; same finding under a pin that has since moved is appended, never edited
  over the old record, and carries `supersedes` naming what it re-signs — the record of who
  judged what under which gate is a history, not a slot. 8 new controls in both directions,
  including that the re-signed clearance actually applies and the superseded one is still inert
  and unedited. The suite's hardcoded total said 19 while it ran 18; it is counted now, and 26.

- **`corpus/field-provenance.py`: a control fixture is not a writer.** The same bound the
  previous entry repaired, one module along. Every tool here carries an `inject()`, and a
  control fixture is a dict literal — which the parser reads as a write position exactly like a
  real one. Measured over both halves, **nine fields carried by rows have no write position
  anywhere in `corpus/` outside a control suite**, including `account_hash` on 67,985 rows and
  `origin.account_hash` on 47,133, whose only mention in this repository is a fixture in
  `regen-tiers.py --inject`. All nine were reported as covered.

  Write positions inside `inject()` and `_selftest()` stop counting; **read** positions still
  do, because a control that reads a field is a tracked reader in the only sense this census
  measures — and without that asymmetry the repair would throw away real coverage. Eight of the
  nine have a genuine reader elsewhere and move to `read-only`; exactly one,
  `deobfuscation.status` on **645 rows**, was a true orphan the census had been hiding. A second
  instance came with it: `tracked modules parsed` was computed as the number of modules with at
  least one *write* position — the same number by coincidence until fixtures stopped counting,
  after which it read **30** over a directory of 34.

  | | before | after | cause |
  |---|---|---|---|
  | fields carried by rows | 311 | 314 | three `masking.remeasured.*` keys this round writes |
  | written by a tracked module | 241 | 237 | −9 fixture-only, +5 genuinely written |
  | read-only | 3 | 13 | 8 fixture-only fields that do have readers, plus the two given one below |
  | **ORPHAN** | **67** | **64** | see below |

  Orphans, cause by cause, against the same rows: 69 with the pre-round modules and the old
  rule; −2 for the `masking.remeasured` keys this round genuinely writes; −2 for
  `encoded_layer_finding.decision` / `.resolution`, which gained a tracked reader in the
  decision invariant; **+1** for `deobfuscation.status`, revealed by the fixture rule; −2 for
  `detection_after_masking` and `staging_dir`, given readers above. Recorded as `CORPUS_PLAN.md`
  §11's **tenth** appearance, and the sharper lesson of the ten: a bound repaired in one place
  has not been repaired, because the property that produced it is still in the tool.

- **Counts that moved this round, each with its cause, and the ones that did not.**
  **No detection figure moves**: all 40 detection-bearing fields in `index-summary.json` are
  byte-identical before and after, which is a census of both halves rather than a sample. No
  scanner was run, nothing was rebuilt, `measured_with` is untouched at `4c3e0af08988` on every
  row, and no sample's bytes changed. `gate_provenance.tools_digest()` is **`83735611dab4`
  before and after** — nothing this round touches is inside `TOOLS` — so **0 rows were
  re-stamped** and the stamp census is unchanged at 7 `ok` + 1 `stale` published, 134 `ok` local.

  Exactly **10** fields in the summary moved, and every one traces to one of the two rows:
  `cleared_by_human_rows` 0 → 1, `_findings` 0 → 3, `_by_gate` gaining one per gate (the three
  clearances); `local_only_blockers` losing one each of *plaintext gate did not pass* (5 → 4),
  *encoded-layer gate did not pass* (9 → 8) and *secret gate did not pass* (11 → 10) (the same
  three); the *22 → 23 over a decoded-layer population that moved* blocker going to zero (the
  `b827cdd9d417` re-measurement); and `local_only_publishable_no_blocker` 364 → 365. Published
  publishable is **44,543 → 44,543**. `index-summary.json` is regenerated in this round, and
  `make-summary.py --check` was failing until it was.

- **`corpus/field-provenance.py` no longer parses itself, and its map test is no longer a
  count.** Both were making the orphan census report fewer orphans than there are, and one of
  them was hiding fields the census had itself recorded as orphans.

  `KNOWN` and `REMOVED` are dict literals keyed by field name, and a dict-literal key is a
  write position, so the census was the sole claimed writer of six real index fields — and
  `main()` prints only the states that are **not** `written`. `evidence_decoded`,
  `evidence_encoded` and `hidden_by_encoding`, 142 rows each and listed in `KNOWN` *because* an
  untracked decoder wrote them, were classified covered and never printed. **The note recording
  them as orphans is what stopped them being reported.**

  The map heuristic — "more than eight distinct children" — classified **ten** parents as
  value-keyed maps. **One was.** The nine schema blocks it swallowed include `masking` (26
  children): every gate verdict, every finding, `provenance`, `secret_literals`, the block a
  human clearance is keyed to. An orphan anywhere under it was invisible to the tool whose
  entire job is finding orphans. It ran the other way too — three value *keys* under
  `sensitivity_review.adjudication` were reported as orphan fields because that parent had only
  four children. The old docstring had predicted this in words ("a schema block with nine keys
  would be misread as a map") and then nine were.

  The test is now what actually distinguishes the two: **schema keys are written by a programmer
  and are identifiers; value keys are data labels and are not.** Over both halves exactly four
  parents have any non-identifier child and all four are real maps; every other parent's
  children are identifiers without exception.

  | | before | after | cause |
  |---|---|---|---|
  | fields carried by rows | 135 | 311 | nine schema blocks descended into for the first time, less the field removed below |
  | value-keyed maps | 10 | 4 | the identifier test |
  | written by a tracked module | 90 | 241 | the schema-block children, most of which do have writers |
  | read-only | 1 | 3 | `placements` and `copies_on_disk` gained a tracked reader |
  | **ORPHAN** | **44** | **67** | the census could finally see — not a change in the corpus |

  Recorded as `CORPUS_PLAN.md` §11's **ninth** appearance, and the first that a check had
  declared about itself before anyone asked: the docstring stated the row-side bound correctly
  and in advance, and the two bounds it did not state were the larger ones. Writing a bound
  down is cheap and it is not the check; sizing it is.

### Measured, and open

- **Two published rows record a human adjudication inside a gate-finding key.**
  `9437f7423b83` and `9bbe4a34dc6b` put `decision` / `resolution` / `classification` / `value` /
  `why_it_matters` under `masking.encoded_layer_finding`, on rows whose encoded-layer gate reads
  `PASS`. The gate produces no finding on a pass, so the key holds something the tools would
  never write, and `gate_evidence.compare` reads that as a payload the current tools would not
  produce — correctly, and for a reason no re-measurement can repair. Neither row has bytes to
  measure (both record no `masked_sha256`), so nothing acts on it today. The repair is to give
  the adjudication its own key rather than to borrow the gate's; not done, and recorded rather
  than done quietly.

- **The two writers of `masking.secret_literals` disagree about its schema.**
  `mask-samples.py` writes a named 12-key subset; `remeasure-gates.py` writes everything
  `secret_gate()` returns bar the verdict, which is 13. The odd key is `note`, a constant string
  of prose. 126 rows carry 12 keys and **8** carry 13 — the six re-measured last round and the
  two re-measured this one. Measured and not armed: it is why `gate_evidence` compares the keys
  the row records, and reconciling it would rewrite 126 rows for a prose key and move every
  `finding_digest` keyed to one.

### Removed

- **`origin.incident`, from 47,133 local rows and 0 published ones.** Flagged for review
  because a field naming an incident is the shape that has caught this repository out before.
  It is the opposite of that: **one distinct value across every row that carried it** — the
  8-character constant `INCIDENT`, a hardcoded string literal in an untracked merge pass, with
  no data path reaching it and no entry in either pseudonym map. Zero entropy, so it cannot
  carry a customer identifier by construction. **No reader anywhere in 272 Python files.**
  Completely redundant: `incident` was present *iff* `account_hash` was, so the `origin`
  key-shape already separates the incident tree (47,133) from the legacy tree (1,123).

  git cannot name the commit that last wrote it — the local half is gitignored and the writer
  is untracked. A before/after census of every counted quantity in both halves is
  byte-identical; 47,133 rows lost exactly that key and nothing else moved. **The untracked
  writer still emits it**, so a future merge pass will put it back; that is a property of an
  untracked writer, not of this removal, and it is why the removal is recorded in
  `field-provenance.REMOVED`, which the census now prints.

  **The reader search had to be redone.** The first sweep reported "nothing reads it" while
  unable to see 237 of the 272 Python files: `grep` in this environment is a shell function
  wrapping `ugrep --ignore-files`, which respects `.gitignore`, and `trail-data/` is gitignored
  — so a recursive search from the repository root silently skipped every untracked script,
  which is exactly where every orphan field's writer has turned out to live. The same shape as
  the `/home/`-not-`/home2/` regex: a search whose blindness is invisible from its output.

- **The five unmasked-publishable rows are tagged, and the reason they read `clean` is on
  the rows (`corpus/tag-sensitivity.py`, `corpus/taggings/2026-09-06-five-clean-rows.json`).**
  `cd98180175a5` → `path`; `eba16e1e9159` → `c2`,`identity`; `e50d85a3a815` →
  `c2`,`identity`,`path`,`secret`,`pii`, which puts it in `NEVER` and makes it permanently
  unpublishable; `c24465d301e2` → `c2`,`identity` with `pii` **rejected** (form-field shape
  over spam post content is attacker-generated filler); `1438674b06d8` → `identity` with
  `pii` rejected and **`c2` left off and recorded as unresolved**.

  The tool writes a *ruling*, not a re-derivation and not an adoption. A tag may not be added
  unless `sensitivity.classify_deep` over the row's own hash-verified bytes also produces it,
  every tag the re-derivation *does* produce must be adjudicated — added, rejected or held,
  with a reason — and a silent pass over one is refused, because silence is what put these
  rows at `clean` in the first place. The bytes question has **three** answers and
  `unavailable` refuses the write. `publishable` stays computed by `shard-gate.py`.

  **The evidence is on the row, because some of it exists nowhere else.** On `1438674b06d8`
  the account name is in the `uname` and `gname` field of **all 256 tar member headers** and
  in **0 member paths and 0 member bodies**; a member-level content scan sees nothing and only
  the container's own metadata carries it. The row also records that the *rule's* reason for
  its `identity` tag is different and wrong — 81 e-mail shapes over 44 domains, none on a
  customer domain. And the cause is recorded on every one of the five: `classify()` has no
  decoder and `clean` is its **default branch**.

  **`1438674b06d8`'s `c2` is now ruled: left off** (`corpus/taggings/2026-09-06-c2-ruling.json`).
  The decisive measurement is a negative one — **0 of the 5 `C2_HINTS` markers fire anywhere in
  the archive** — and the ruling is recorded as a rule in CORPUS_PLAN §4.1, not only as a row
  decision: **`c2` requires evidence of attacker control, never the presence of an external
  host**, because the tag is in `ALWAYS_OK` and buys a free pass through every masking gate
  rather than merely labelling a sample. "An external host inside a malicious archive" is guilt
  by containment — the reasoning that produced the retracted `identity` on a Cloudflare footer
  template's resolver address. `sensitivity.classify()` still emits `c2` on any external host
  and is unchanged; that output is now explicitly a *proposal* a person must add, reject or
  hold.

  Movement, all attributed: local `publishable` 373 → 368; `clean` −5, `identity` +4, `c2`
  +3, `path` +2, `pii` +1, `secret` +1; new blockers `carries identity but no masking has
  been applied` ×3, `carries path…` ×1, `carries identity/path/secret…` ×1, `carries pii,
  which is not maskable and is never published` ×1. No published row moved and no detection
  figure was measured.

- **`corpus/mark-not-maskable.py` — `masking.not_applicable_reason` is written from the
  repository for the first time.** Four of the five are archive containers, which §5.5
  excludes from content masking entirely, so what they need is the decision the 29 existing
  rows carry — a field nothing in this tree writes and `mask-samples.py` only reads.

  **The writer could not be brought in, and that is the finding.** No `.py` anywhere on this
  machine writes the string, and `git log --diff-filter=A` puts `mask-samples.py`'s first
  commit a day *after* the rows appeared: the author was never saved, so unlike
  `sensitivity.py` there is nothing to hash and no behavioural probe to run. The tool
  re-derives the *claim* instead — container magic re-read from the bytes, `gzip` on all four,
  recorded with the sha256 it read — and refuses a row whose bytes are not a container, which
  is what it did to the fifth (a PHP file) on the live run. It deliberately writes none of the
  seven other masking keys the legacy rows carry: those are measurements it did not take.
  Publishability moved by **0 rows**, and that is correct — `applied: false` still blocks.

- **`corpus/field-provenance.py` — 45 fields in the index have no writer in this repository,
  not three.** Three had been found one at a time, a round apart each, by somebody noticing.
  This parses every tracked module and asks, per field the rows carry, whether anything can be
  shown to **write** it rather than merely mention it — the distinction that matters, since
  `mask-samples.py` contains the literal `not_applicable_reason` and any grep would have
  called that field covered. 135 fields, 89 written, 1 read-only, **45 mentioned nowhere**.
  `written` is an over-count so `ORPHAN` is an under-count, and both denominators are
  enumerated by their own process and say so on every run.

- **`corpus/sensitivity.py` — the rule that assigns every sensitivity tag is now in the
  repository.** It was `trail-data/incoming/2026-09-03/sensitivity.py`: gitignored, untracked,
  not covered by `gate_provenance.TOOLS`. Anyone cloning this repository could read the rows
  and not the rule that made them — could not re-run it, review it, or tell whether it had
  changed since the rows were written. **It was never only the `secret` tag.** `classify()`
  returns one set covering `content`, `path`, `identity`, `secret`, `c2`, `pii` and `clean`,
  and all six modules that call it take the whole set; only `unreviewed` and `undecidable` are
  outside its vocabulary. The unreviewable surface was 92 `secret` rows plus 45,242 `clean`,
  4,277 `content`, 788 `c2`, 287 `identity`, 178 `pii` and 46 `path`. 235 rows carry a
  `sensitivity_evidence` block that is this function's `ev` dict verbatim, which is what
  attributes them to the rule rather than to a convention.

  It **reproduces** the original rather than improving it — a tracked module whose behaviour
  differs from the one that ran cannot be used to review the rows it produced.
  `--verify-reference` reports `ok`/`moved`/`absent` (three answers, never two, so a stranger
  without the gitignored file gets *cannot check* rather than a quiet pass) and `--inject`
  asserts behavioural equality over 16 probes carrying no customer identifier. Two known
  defects are **reported and deliberately not fixed**, because either would move tag counts on
  rows nobody has re-read: `identity` fires on any e-mail or IP (81 upstream contributor
  addresses on one sample, none on a customer domain), and `c2` fires on any external host
  (20 of 73 on that sample are php.net, wordpress.org, github.com, MDN and two CDNs — and `c2`
  is in `ALWAYS_OK`, so a wrong `c2` never blocks).

  `classify_deep()` adds what the rule never had: a decoder, and specifically
  `verify-content-mask.decode_layers` — the gate's own, so a tag and a gate that disagree are
  disagreeing about a rule and never about which bytes each read. **This is the cause of all
  five local rows that sit `publishable: true` with zero blockers, tagged `clean` alone.**
  `classify()` has no decoder; four of the five are gzip streams and the fifth hides its
  payload in a base64 literal, so every regex sees compressed noise and falls through to
  `if not tags: tags.add("clean")`. `clean` is the **default branch of a function that cannot
  read its input**, and it is the tag that means publish as-is. §5.4 already says the absence
  of a plaintext hit is evidence the encoder worked, not evidence the sample is clean.

  `reconcile()` states the two credential definitions together. They may legitimately differ,
  and the boundary is a property of the pattern: the tagger asks *is a credential present* and
  should over-match, the gate asks *did masking change every credential-shaped literal* and
  needs a value it can capture — **a shape with no capturable value can only be tagged, never
  gated**, which `SHAPE_KIND` records. Two ways they are wrongly narrower, both measured:
  `verify-content-mask.SECRET_SHAPES` has **no PEM shape at all**, and its `quoted-credential`
  lookbehind `(?<![A-Za-z0-9_])` blocks a password assigned to a variable whose name ends with
  the keyword — `$user_password`, `$adminpassword`, `$pwd`. §5.6 already rules that lookarounds
  should err towards over-matching and records two leaks from one that did not; this is the
  third, on credentials. The nine rows that pass `secret_gate` over zero literals then
  decompose without a rule of their own: **five are name-only** (a bare constant, nothing to
  compare, the zero is correct) and **four are a real divergence** — two PEM blocks, two
  blocked passwords, one of them on a `publishable: true` row inside a `base64` layer.

  Kept **out of `gate_provenance.TOOLS`** deliberately: `TOOLS` is the modules that decide a
  stored *gate verdict*, and a tagger produces none. `sensitivity.digest()` gives a
  sensitivity claim its own provenance instead. `gate_provenance.tools_digest()` is
  `6fecbeebbccc` before and after, **0 rows re-stamped**.

- **`corpus/digest-controls.py`** — the control `verify-content-mask.py` named and nobody
  wrote. That file's comment says "`--assert-note-is-not-behaviour` is the control that says
  so"; the flag existed nowhere in the tree. The property is true, but a true property with no
  check is one edit from being a false property with no check. It cannot live where it was
  promised — `verify-content-mask.py` is in `TOOLS`, so an argparse branch there moves the
  digest and re-measures 140 stamped rows *to install a check whose subject is that prose edits
  do not do that*. A comment is absent from the AST, so repointing the line costs nothing.
  Eight cases in four pairs, each an edit that must not move a digest beside one that must:
  prose, a comment, a docstring and a tagging-rule change leave `tools` at `6fecbeebbccc`; a
  constant and a regex literal move it; and the tagging-rule change moves the tagger's own
  digest, or the tagger would have provenance in name only. It also answers to
  `--assert-note-is-not-behaviour`.

- **`corpus/adopt-decoded-tags.py` — `sensitivity` now describes the sample's decoded form,
  not its wrapper.** A `deobfuscation` block records `encoded_form_tags` for the bytes as
  collected and `decoded_form_tags` for everything a static decoder gets out of them. On
  **11 local rows** the sensitivity equalled the *encoded* tags while the decoded tags were
  strictly larger — tagging a sample by the thing the encoder was for, on rows whose whole
  point is that the outer form carries nothing. §5.4's premise is that an identifier inside
  an encoded layer makes a sample unpublishable, so a sensitivity taken from the wrapper is
  measuring the wrong object.

  All 11 are adopted, `clean` dropped wherever anything else survives. **No publishability
  moves**, and the reason is the result rather than a disappointment: six of the eleven had
  already been masked with every gate passing, so the tags they gain demand measurements
  that exist; three carry `c2` alone, which is in `ALWAYS_OK`, so nothing was demanded of
  them before or after and they are not counted as movement. The one substantive change is
  `b827cdd9d417` gaining **`pii`** — it was blocked only on `secret_gate: FAIL`, which is
  *clearable*, and `pii` is in `NEVER` and clearable by no route.

  The tool refuses a row with no `decoded_form_tags` rather than computing one: a `--fix`
  that writes the field it then trusts is the tool agreeing with itself, and this field is
  an input to the publish gate. What the bytes actually say on each of the eleven is written
  up per row in `corpus/SOURCES.md`, including the two weak ones — `identity` resting on an
  address at a public mail provider that no map identifier matches — and the one where
  `sensitivity.py` and `verify-content-mask.py` disagree about what a secret is.

- **`corpus/remeasure-gates.py`** — writes the verdict a re-measurement produces onto a row
  whose record disagrees with it. Deliberately not part of `verify-and-stamp.py`, whose whole
  contract is that it stamps *only* where the current gate returns what the row records:
  stamping says "these tools produced this verdict" and is additive and safe in batches, while
  re-measuring rewrites a recorded measurement in a tracked index and can flip a `publishable`
  in the published half. One `--sha`, one author, and the sha256 the bytes must hash to; it
  refuses a row where nothing moved, and a verdict that goes back to `PASS` takes its finding
  with it.

- **A human can clear one gate finding, and the decision is a record rather than a gap
  (`corpus/clearance.py`, `corpus/clear-finding.py`).** Some findings are collisions and no
  predicate that can see one can decide it — the encoded-layer predicate produces 127 false
  positives over 8,000 stock CMS files. Before this the only ways to act on that judgement
  were to hand-edit `publishable` (§4.4 forbids it and `staleness()` catches it), to edit the
  tag so the gate stops asking (the defect this round repairs), or to loosen the predicate for
  everybody.

  A clearance carries `gate`, `finding_digest`, `by`, `at`, `reason` and `gate_provenance`.
  **`publishable` stays computed**: the clearance is an input to `evaluate()`, never a value
  written over the boolean, and a second uncleared blocker still blocks. It is keyed to the
  **specific finding** by a digest over the gate, its recorded verdict and the evidence beside
  it, so a judgement about a 3-character identifier in a 97-character segment cannot carry to
  whatever the next re-measurement finds — nor to a different gate on the same row. It is
  **invalidated when the gate provenance moves**, pinned by the `tools` and `map` digests by
  value, because a clearance is a judgement about what a particular gate said and a changed
  gate has not been judged. It **cannot apply to `pii` or `content`** — structurally, since
  those produce no finding to key to, and checked outright as well. And it is **counted in
  `index-summary.json`** (`cleared_by_human_rows`, `_findings`, `_by_gate`, and the published
  subset), because the one route by which a recorded FAIL becomes a publishable row must not
  be a number nobody watches.

  Malformed and inert are deliberately different: a clearance nobody can read exits non-zero,
  a clearance that has stopped applying is printed with a count on every run.
  `clear-finding.py` refuses a reason that matches a map identifier and reports the **length**,
  never the name. Only recorded gate results are clearable — a verdict, a `local_only` hold, an
  unapplied masking pass and the provenance blocker are work to do rather than evidence to
  judge.

  **Zero clearances exist.** The mechanism ships with its controls and no entries. 20 control
  cases in `shard-gate --inject`, each negative paired with the positive that re-signs the same
  judgement against the new state — without the pair, "blocks" only proves something blocked,
  and a hatch that never opens would pass every one. 19 in `clear-finding --inject`, 31 in
  `clearance.py --selftest`.

- **Gate provenance (`corpus/gate_provenance.py`), and `shard-gate.py` requires it.** A
  stored `plaintext_gate: PASS` was a claim about what *some* version of the gate said, and
  nothing in the index recorded which. Re-gating by hand found **5 of 95 local rows and 1 of
  8 rows in the published half** at `PASS` under a predicate the current gate rejects; in
  every case the sample was unchanged and the predicate had moved.

  The stamp is an **AST digest** of the six modules that decide spans and verdicts,
  docstrings stripped, plus a digest of the maps' behavioural surface (identifiers, keep
  list, tier table). An AST because comments and formatting are absent from one by
  construction — a docstring rewrite must not move it and a changed regex literal must. A
  git commit was rejected: every record this round had to repair was written by an
  *uncommitted* tree, so a commit id would have been absent or confidently wrong.

  `verify()` returns three answers, never two — `ok`, `absent`, `stale`. The `tools` half is
  always checkable because those modules are tracked; the `map` half only where the maps
  exist, and it reports `map not checked` rather than passing quietly. In the gate the
  question is asked first inside the `applied` branch, and `absent`/`stale` raise **one**
  blocker because §8 counts reasons and the repair is the same for both; the diagnosis goes
  in a report line printed on every run.

  16 control cases. Five logic changes must move the digest — including the slot-rule
  delimiter guard reversed to the positive-list form, which is the exact change that turned
  two recorded passes into failures with no field in the index moving — and three prose
  changes must not. `shard-gate --inject` goes from 16 to 20 and fails against the
  pre-change gate on exactly the two new positive cases.

- **`corpus/verify-and-stamp.py`** — provenance for a row whose bytes are already built.
  Re-runs the gate over the bytes the row stands behind and stamps **only where the current
  verdict equals the recorded one**, refusing the row where it does not: a stamp asserts
  that these tools produced these verdicts, and writing one over a verdict they would not
  produce is the lie the field exists to prevent. Additive, and asserted to be — its own
  control caught the first version of that assertion seeing an overwritten key but not an
  added one.

- **`corpus/stamp-legacy.py`** — an author, a date and a re-checked claim for a field no
  tool in the tree writes.

### Changed

- **A later ruling no longer erases the record it amends
  (`corpus/tag-sensitivity.py`).** Writing the `c2` ruling exposed it: `build()` wrote a fresh
  `sensitivity_tagged`, so the ruling took the tar-header finding — a measurement that exists
  nowhere else — off the row. Prior `evidence` and `human_basis` are carried forward with the
  new ruling winning per key, the superseded record is kept whole under `supersedes`,
  `originally` carries the pre-first-ruling tags past a one-level chain, and `assert_additive`
  now **refuses any write that drops a recorded evidence key**. A ruling that changes no tag is
  also writable now — it used to be refused as "nothing would move", which would have left the
  row reading `UNRESOLVED` after a person had ruled — and `--restate` re-derives a record from
  a decision file it already agrees with, changing no ruling and required to add something.
  Controls: 32 → 56 cases.

- **`make-summary.py --help` used to overwrite `index-summary.json`.** The dispatch was
  `if "--check" in sys.argv: … else: write`, so `--help`, a typo or any flag added later
  reached the **write** path: the one irreversible thing this tool does was what it did when it
  did not understand you, and it writes the denominator every suite run quotes. `dispatch()`
  now errors on anything unrecognised, and `--inject` asserts all nine cases including `[]`
  still meaning *write*.

  **`--check` is now on a pre-report list in AGENTS.md**, alongside the two `shard-gate` runs.
  It was the one gate not run before this round was reported green, and it was failing: the
  round moved 9 rows out of `local_only_publishable_no_blocker` and 2 clearances out of
  `cleared_by_human`, and the summary still asserted the old counts. Neither gate run can see
  that — they read the index, not the summary. `index-summary.json` is regenerated in this
  round.

- **The secret gate can now see two credential forms it was blind to
  (`corpus/verify-content-mask.py`).** `SECRET_SHAPES` had **no PEM shape at all**, and
  `quoted-credential`'s `(?<![A-Za-z0-9_])` lookbehind blocked a password on a variable whose
  name *ends* with the keyword — `$user_password`, `$adminpassword` — with no `pwd` keyword
  either. The lookbehind is gone, `pwd` is in the list, and `pem-private-key` requires a
  **complete** block: 32 of the 34 `BEGIN … PRIVATE KEY` markers on the rows this was written
  for sit inside docblock prose, and a header-only shape would fail them on documentation.

  Both files are in `gate_provenance.TOOLS`, so `tools_digest` moved `6fecbeebbccc` →
  `83735611dab4` and all **140** stamped rows went into re-measurement. Paid deliberately and
  measured: 73 rows had masked bytes on disk, `corpus/restage-masked.py` **regenerated and
  hash-verified** 132 of 142 more from their originals (`content_mask.mask_sample` is
  deterministic, and a regenerated file that hashes to the row's recorded `masked_sha256` *is*
  that file), 139 rows were re-stamped, 1 published row is left `stale` for want of bytes, 34
  rows lost `publishable` for the length of a commit, and 2 human clearances on
  `34bba99dae63` went inert exactly as designed.

  **Six rows go `PASS` → `FAIL`, four of them `publishable: true`** — `162ccc9adf4e`,
  `fa4356393880` (tagged `clean`), `b839772db7c7` (tagged `c2`, which demands nothing) and
  `91d2ee9cdd6d`. Only one of the four carries `secret`, which is why the nine "vacuous
  passes" could see one of them: that population was selected by the tag written by the rule
  whose blindness was the subject. Of the four divergences recorded last round, two moved
  their verdict, two (`24d902d48a0d`, `bba931abc09d`) are not divergences at all — 34 PEM
  headers and **zero** `END` markers between them — and four more were outside the search.
  Local `publishable` 368 → 364; the published half is unchanged at 44,543.

- **`verify-and-stamp.py` and `remeasure-gates.py` were asking a three-gate question about
  two gates.** Both re-measured `plaintext_gate` and `encoded_layer_gate` and said nothing
  about `secret_gate`, which a `TOOLS` module produces and the stamp therefore always claimed.
  Both now take the pre-masking bytes and re-measure the differential, and both answer
  **`agrees` / `disagrees` / `cannot-check`** — a row nobody could measure and a row that
  disagrees need different work. Without this, the re-stamp after the gate repair would have
  written fresh stamps over six rows whose recorded verdict the current tools do not produce.

- **`corpus/deobfuscate.py` — the second decoder is tracked, and the two vocabularies are
  reconciled.** It reproduces the untracked `trail-data/incoming/2026-09-03/deobfuscate.py`
  that wrote `decoded_form_tags` on 142 rows, with behavioural equality asserted over 11
  probes. `METHOD_ALIASES` states the correspondence: `hex-escape` + `octal-escape` **merge**
  into the tracked `escape`, `rot13` is recorder-only, `raw-inflate` is tracked-only — so
  every gzip container in the corpus is a layer to one decoder and nothing to the other. Every
  threshold differs too, and the recorder does not de-duplicate layers. Measured on the 8 of
  142 rows whose bytes are reachable: 357 recorder layers against 380 tracked, agreeing on
  the count for 2 of 8.

  **Kept out of `gate_provenance.TOOLS`, and not by inheriting last round's reasoning.** The
  case for including a decoder is real — the encoded-layer gate *is* a decoder plus a
  predicate — but measured, every `decode_layers` call in the gate path resolves to
  `verify-content-mask.decode_layers`, which is already in `TOOLS`. This module decides no
  gate verdict; `TOOLS` membership would invalidate 140 of them on every edit, which this
  round has just priced. And it would not detect the actual hazard: it would say "the decoder
  changed", never "the two decoders disagree" — which is what `--reconcile` measures.

- **CORPUS_PLAN §11 gains an eighth appearance** and the heading moves from seven to eight.
  The nine vacuous passes were nine because the predicate began *carries the `secret` tag*,
  and the report that found them explicitly dismissed the other 69 rows recording
  `before == after == 0` as owing nothing. Four publishable rows carrying an invisible
  credential were in that dismissed set. **A reconciliation between two rules must be run
  over the rows that record the measurement, never over the rows one of the rules labelled.**

- **`FP_NOTE` is corrected and has moved out of the behavioural digest.** It said 36 hits
  come from identifiers of 6+ characters where `--stock-fp` prints **52**; 36 was `begins`
  (20) plus `contains` at 6+ (16) and omitted the 16 `exact` hits at 6+. It now says 52 and
  carries the split it was missing — **16 `exact`, 20 `begins`, 16 `contains`** — regenerated
  today along with every other figure in it: 127 false positives across 104 of 8,000 stock
  CMS files (1.30%), 83/20/24 by position. All 20 `begins` false positives come from
  identifiers of 6+ characters, which is the population the finding on the desk belongs to.

  It could not be corrected before because it was a module-level assignment in
  `verify-content-mask.py`, one of the six modules in `gate_provenance.TOOLS`: four
  characters of prose moved the `tools` digest and put all 139 stamped rows into
  re-measurement. **A descriptive note is not behaviour and must not be able to do that.** It
  now lives in `corpus/fp-note.txt`, which the digest does not read, so the relocation costs
  that re-measurement **once** and then never again.

  Three assertions in `gate_provenance.py --inject`, and the obvious one is the weakest:
  rewriting the note must not move the digest (true of a module that ignores the file
  entirely, including the one this replaced); the loader must actually follow the file; and
  **the note's prose must be absent from the AST the digest reads**. Against the pre-change
  modules the second and third read `IGNORED` and `PRESENT` and the suite fails, while the
  first passes — which is why there are three.

- **The differential secret gate now fails in both directions, and the measurement chose the
  rule.** It asserted that no credential-shaped literal in the output is byte-identical to
  one in the input and said nothing about the count going **up**; one row recorded 23 after
  masking where it had 22 before, for a round, with nothing asking.

  Two candidate rules, measured over the 132 masked local rows before either was armed. "No
  literal in the output that was not in the input, less the masker's marked synthetics"
  refuses **46 rows, 36 of them hard refusals** — because §5.1 makes every correctly masked
  credential a *new* credential-shaped literal, and the synthetic marker is written only by
  the identifier substitution: the masker's credential replacements (`_value`, `_bcrypt`,
  `_phpass`, `_hex`) carry none at all by construction, so a masked bcrypt is unattributable
  however long it is. "More literals after than before" fires on **one** row. The count is
  what was armed, and `verify-content-mask.py --inject` now asserts both that
  `SYNTHETIC_MARKER` equals the masker's constant and that a masked bcrypt moves and comes
  back unmarked — the premise the choice rests on.

  **What produced the one increase is not the hypothesis it was written against.** Not a
  synthetic. `secret_literals()` counts over the plaintext *and every decoded layer*, and
  that layer population **is not stable under masking**: four masked bytes inside one base64
  region re-encoded, the `base64+inflate` layers nested below decoded differently, and 23
  layers became 16 — nine gone, two new, one of the two carrying a ten-character
  `$GLOBALS['DB_NAME']['…']` array key the `wp-credential` pattern reads as a credential.
  `before` and `after` were censuses of two different populations. Over the 132 rows the
  layer set moves on **11** and the count moves on **1**, so the instability is common and
  the increase is not.

  Two causes, two owners, one reason each: the gate fails on a carry-over and on an increase
  over an *unchanged* layer population; `shard-gate.py` raises its own blocker for an
  increase over a population that moved, read from the recorded evidence regardless of tags.
  `secret_literals_added`, `_by_the_masker`, `_unattributed`, `decoded_layers_before/after`
  and `literal_population_comparable` are now recorded — measured and not armed, so the next
  round can decide the set rule against numbers. `mask-samples.py`'s refusal message was
  fixed in the same change: it quoted `secret_literals_carried_over` unconditionally and so
  printed *"0 credential-shaped literal(s) survived masking unchanged"* on the second failure
  mode — a refusal naming a cause that had not happened, and zero of it.

- **`verify-and-stamp.py` could not re-stamp anything it had ever stamped.** Its additive
  assertion refused every row already carrying a `provenance`, which is every row it had
  written — so the tool that exists to keep provenance current could not update it the moment
  the tools digest moved. `provenance` is now the one key that may be replaced, and only
  under `--restamp`, with the report always printing how many stamps are replacements rather
  than additions. The safety property is unchanged and is not the assertion: a stamp is
  written only where the current gate returns what the row records, so a replacement can
  restate a verdict and never launder one. Four new control cases, including a stale stamp on
  a verdict that moved, which must still be refused.

- **Counts that moved this round, each with its cause, and the ones that did not.**
  **No detection figure moves**: all nine `malicious_detected` / `malicious_known_miss` /
  `malicious_reviewed` figures and their `_excl_predates_ruleset` variants are byte-identical
  in `index-summary.json` before and after, which is a census of both halves rather than a
  sample. The mechanism is stronger than the coincidence: over the 132 re-measured local rows
  **not one** of `masked_sha256`, `plaintext_gate`, `encoded_layer_gate`, `secret_gate`,
  `detection_survived`, `rules_before`, `rules_after`, `changes`, `change_kinds` or
  `measured_with` moved on any row — the masker is unchanged, the scanner binary is unchanged
  at `4c3e0af08988` (read, never rebuilt), and the only fields that moved are
  `provenance.at`/`provenance.tools` on all 132, the eight new `secret_literals` keys on all
  132, and `false_positive_note` on the 8 stored findings that carry one.

  Publishable is **373 → 373** local and **44,543 → 44,543** published. Blockers:

  | blocker | before → after | cause |
  |---|---|---|
  | `plaintext gate did not pass` (local) | 5 → 4 | the human clearance on `34bba99dae63` |
  | `encoded-layer gate did not pass` (local) | 9 → 8 | the same row's second clearance |
  | `carries pii …` (local) | 24 → 25 | `b827cdd9d417` adopting its decoded `pii` |
  | `masking left more credential-shaped literals …` | 0 → 1 | the new rule, on the same row |
  | sensitivity tags | `clean` −11, `c2` +6, `identity` +6, `secret` +4, `path` +2, `pii` +1 | the 11 adopted rows, and the arithmetic closes exactly |
  | `cleared_by_human_findings` / `_rows` / `_by_gate` | 0 → 2 / 0 → 1 / `{}` → `{encoded_layer_gate: 1, plaintext_gate: 1}` | the first two clearances ever recorded |

  **The two clearances do not make `34bba99dae63` publishable**, and that is the mechanism
  working: it still carries `secret_gate: FAIL`, which nobody cleared, so a second uncleared
  blocker survives the clearance exactly as the design says it must.

  In the published half the one blocked row's blocker changes rather than its boolean:
  `3529f0f6b2cd` goes from `gate results have no usable provenance` to `encoded-layer gate did
  not pass`. Gate provenance reads `ok: 8` of 8 published and `ok: 132, absent: 2` local — the
  two absent are last round's secret-gate refusals, unchanged.

  **The `tools` digest moved once, `07079af767d4 → 6fecbeebbccc`**, and every one of the 139
  stamped rows was re-measured under it: 132 local re-masked and re-stamped, 7 published
  re-verified against the bytes inside the shard tarballs and re-stamped. The map digest is
  unmoved at `9268d21c394b`. **Asserted afterwards, directly:** appending a sentence to
  `fp-note.txt` changes `FP_NOTE` and leaves the digest at `6fecbeebbccc`, while changing the
  loader's filename constant moves it to `805aeb091b0c`. A prose edit can no longer invalidate
  the index.

  Control suites: `clearance` 31, `clear-finding` 19, `gate_provenance` **16 → 20**,
  `verify-and-stamp` **10 → 14**, `shard-gate` **56 → 61**, `adopt-decoded-tags` 19 (new),
  `remeasure-gates` 18 (new), plus three new secret-gate cases and two marker assertions in
  `verify-content-mask --inject`. All green, and the three new `gate_provenance` assertions
  were run against the pre-change modules first: two of them fail there.

- **Counts that moved in the clearance round.** Local publishable **377 → 373**: the four rows
  described under Fixed, all `secret_gate: FAIL`. Local blockers: `secret gate did not pass`
  **0 → 5** (the five rows, now read regardless of tag), `encoded-layer gate did not pass`
  **3 → 9** (the six dict-form rows, now parsed), `encoded-layer gate was not run:
  SKIPPED-oversize` **0 → 12** (a skip is not a pass). 23 rows recomputed by `--fix`: 4
  over-claimed and 19 blocker drift. **The published half does not move at all** — 44,543
  publishable before and after, no blocker changed, no row flipped. **No detection figure
  moves**, and the mechanism is that nothing changed this round reads bytes or runs the
  scanner: `malicious_reviewed`, `malicious_detected`, `malicious_known_miss` and every
  `_excl_predates_ruleset` variant are byte-identical in `index-summary.json` before and after,
  which is a census of both halves rather than a sample. The `gate_provenance` tools digest is
  unmoved at `07079af767d4`: none of its six modules changed behaviourally, so no provenance
  stamp is invalidated.

- **`shard-gate --inject` goes from 20 cases to 56, and its case total is now counted rather
  than quoted.** The printed number had been hardcoded at 20 while the suite grew, which is a
  count that cannot report a case being dropped; `clearance.py --selftest` was written with the
  same defect and fixed in the same commit. Against the pre-change `evaluate()` the new suite
  **fails 19 of 56** — the three tag-conditioned FAIL cases, all six gate-value forms, both
  detection-parity cases, the SKIPPED-on-a-container case, and all seven clearance cases that
  require the hatch to open. Run before trusting the green.

- **The whole masked population is re-measured and stamped.** All 134 local rows with
  `masking.applied` were resolved to their source bytes (134 of 134) and re-masked; 132
  cleared and now carry provenance, 2 were refused by the secret gate and keep their
  superseded records, which the new rule now blocks. In the published half 7 of 8 rows were
  re-verified against **the bytes actually inside the shard tarballs** and stamped; the
  eighth is reported below.

  Every movement has a cause. `masked_sha256` moved on **74 of 132** rows and every one of
  them carried a superseded record — zero of the 52 rows measured in the last two rounds
  moved, which dates the masker change precisely. `plaintext_gate` `PASS → FAIL` on 3 and
  `encoded_layer_gate` `FAIL → PASS` on 4, all superseded, all with moved bytes: the slot
  maskers now fire where they did not, so four rows stopped leaking into a decoded layer.
  One row gained an encoded `FAIL`. Local publishable **378 → 377**, that one row.

  The encoded-layer blocker reads **2 → 3**, and the four rows that stopped failing did not
  reduce it: all four are tagged `clean` alone, so `unmasked` is empty, the masking branch is
  skipped and they never contributed to it. A blocker count is a count of rows the gate
  *reached*.

- **The two legacy fields have authors.** `encoded_layer_gate_uncapped` (3 rows) is gone,
  regenerated away by the re-measurement. `not_applicable_reason` (29 rows) is stamped
  `legacy` with the author — an uncommitted state of `mask-samples.py`, which the current
  driver still *reads* and never writes — and the date it first appears, 2026-09-04 16:33, at
  the same count. The stamp carries a **re-verification** rather than a label: each row's
  claim to be an archive container was re-read from the source bytes, 27 tar (`ustar` at 257)
  and 2 gzip, and the tool refuses to stamp a claim it cannot confirm, because a legacy
  marker on an unverified claim launders it.

### Measured, not changed

- **The base-rate null reproduces under the moved digest.** 660 trials, 108 with a hit
  (16.4%), mean **0.1818** short-name hits per 98,473 bytes of random base64, containment
  **1** — identical to last round's regeneration. Checked because the plaintext clearance
  entered this round quotes those figures as its reason, and a clearance resting on a number
  that had quietly moved would be a judgement about something else.

- **Is the under-covered population eleven, or is eleven what the comparison can see?**
  Measured, and it is the second — and it is a **sixth** appearance of §11's rule, the first
  where the numerator and the denominator come from the same *decoder*.

  | population | how enumerated | under-covered |
  |---|---|---|
  | 142 local rows carrying `decoded_form_tags` | the pass that wrote the field | **11** |
  | the same 142, re-derived from the bytes with the **gate's** decoder | this round | **20** |
  | every stored-publishable local row (373; 366 resolved, 182 decode) | census | **31** |
  | the 282 rows that pass recorded `undecodable` (281 resolved, 56 decode) | census | 2, both `c2`-only, both already blocked |
  | the 84 published shipped-as-bytes rows (76 resolved, 14 decode) | census | 2 |

  Over the *same* 142 rows the gate's decoder yields **6,120 layers against that pass's 318**
  — 19× — and the re-derived tag set is **strictly wider on 13 rows and narrower on none**.
  So `decoded_form_tags` is not a property of the bytes; it is a property of the decoder that
  wrote it. Widening the population finds **31**, and five of those are `publishable: true`
  with **no masking applied at all** while the current gate fails their encoded layer on
  `exact`-position hits at 7, 8, 10, 19 and 23 characters — one decodes to a WordPress
  `usermeta` SQL dump and a contact block carrying a customer domain the map holds.

  **Those five are not re-tagged.** Adopting a tag set this round's own re-derivation
  produced would be trusting a field because it is there, one level up, which is the defect
  the ruling repairs. They need the masking pass none of them has ever had, which is a round's
  work with a scanner in it. The eleven is the operator's ruling applied to what the record
  holds; the thirty-one is the size of the question.

  Every figure is a census of a stated population rather than a sample, so none carries a
  sampling error and none bounds reality either. 7 of the 373 local rows exceed the 4 MB read
  cap (6.8 MB to 279 MB) and 8 of the 84 published rows have no resolvable blob; those fifteen
  are unmeasured, not measured clean.

  **The two under-covered published rows are collisions**, and reading them is what says so:
  both are `media-polyglot` fixtures tagged `c2`+`path` whose decoded `identity` rests
  entirely on a hardcoded attacker callback address in a URL — `sensitivity.py` tags
  `identity` on any dotted quad, the retracted-IP defect in its original form. The tag that
  fits is `c2` and both rows carry it. **No published row is under-tagged in a way that
  matters**, over a census of all 84.

- **Three findings are recorded with their full profiles and their decoded context, and none
  is decided.** `3529f0f6b2cd` (published) still stores `encoded_layer_gate: PASS` while the
  current gate returns `FAIL` on the bytes in the shard. **The FAIL was never written, and that
  is the provenance stamp doing its job**: `verify-and-stamp.py` writes a stamp only where the
  current verdict equals the recorded one, so the row is blocked on missing provenance rather
  than on the finding, and no tool flipped a `publishable` in the published half on its own
  authority. The finding still needed recording.

  Its context: a 3-character identifier at offset 63 of a 97-character segment, 72,564
  characters into a single unbroken 97,600-character base64 run. `34bba99dae63`'s two: three
  occurrences of one 3-character identifier inside base64 runs of 44,284 and 158,124
  characters, and — separately — a **6-character** identifier at offset 0 of a 25-character
  segment in a 473,603-byte decoded PHP function table, sitting in alphabetical order between
  two neighbouring `imagick_` entries. **That last one is the imagick case itself**, the hit
  this file records as having killed the encoded-layer confidence grade.

  **Two nulls, and using the wrong one is how the grade went wrong.** Re-running
  `--base-rate --trials 660`: the short-name rule fires in 108 of 660 trials (16.4%), mean
  0.182 hits per 98,473 bytes of random base64; the containment rule fires **once** in 660, and
  one observation puts the 95% upper bound near 0.0045. Scaled by actual base64 bytes,
  `3529f0f6b2cd`'s layer (98,473, 0.99×) expects 0.18 short-name hits and shows 1;
  `34bba99dae63`'s plaintext (581,931 across 34 runs, 5.91×) expects 1.08 and shows 3. For the
  6-character hit the base64 null does not apply at all — its layer is **0.0%** base64 — and
  the right null is the stock-CMS table.

- **Two published figures were re-run and one and a half of them do not reproduce.**
  `--stock-fp` over 8,000 stock CMS files reproduces the headline exactly: 127 false positives
  across 104 files, 1.30%, and the position split 83 `exact` / 20 `begins` / 24 `contains`.
  **The "6+ characters" figure does not**: the tool prints **52**, and 36 is what is written
  into `FP_NOTE`, into `_profile`'s docstring, into this file and into every stored finding
  dict. The cause is attributable exactly — 36 is `begins` (20) plus `contains` at 6+ (16) and
  omits the 16 `exact` hits at 6+ — and it matters for the finding actually on the desk,
  because the omitted qualifier makes the note understate the population that the
  6-character `begins` hit belongs to.

  **`FP_NOTE` is deliberately not corrected in this commit.** It is a module-level assignment
  in `verify-content-mask.py`, which is one of the six modules in the provenance digest, so
  editing the string moves `tools` and re-measures all 139 stamped rows. That is a round's
  work and must not be a side effect of a documentation fix. The docstring, which the AST
  digest strips, is corrected in place and the tools digest is asserted unmoved at
  `07079af767d4`.

  The base-rate short-name arm also does not reproduce: recorded 0.23 per trial, reads 0.18
  today at the same fixed seed, the same map digest `9268d21c394b` and the same tools digest,
  and at 60/100/660 trials, so it is not a trial-count effect. The containment arm reproduces
  exactly at 1 in 660. The ratio the argument rested on survives at about 120:1 rather than
  150:1, and the grade it supported was withdrawn anyway, so nothing downstream moves — but
  0.23 should be read as unreproduced, cause not established.

- **Two things are sized and deliberately not armed, per measure-before-arming.** 123 published
  rows record `plaintext_gate`/`encoded_layer_gate` `PASS` with `applied: false` and carry **no
  provenance**; the gate asks for provenance only where masking was applied, so arming it would
  block 123 published rows in one commit. And 8 published rows have masking applied with **no
  `secret_gate` result at all**; the field is demanded only on a `secret`-tagged row and none of
  the 8 is tagged `secret`, so no credential differential has ever been run over the bytes in
  the published half. Both are recorded for a decision rather than taken.

- **The five known gate failures are recorded on their rows rather than in a report.** All
  five now carry the blocker and the finding. Four were already blocked for other reasons —
  an unreviewed verdict and a `pii` tag — and their findings are strong: `exact`-position
  hits at lengths 8 and 12, which the stock-CMS null produces rarely and never in that
  combination. The fifth, `34bba99dae63`, was `publishable: true` with no blockers and is now
  blocked. Both of its findings read as collisions against the profile: a **3-character**
  identifier in `contains` position inside 19-, 70- and 74-character segments (base64), and a
  **6-character** identifier in `begins` position inside a 25-character segment of a decoded
  PHP function table. The verdict on whether either is real is a human's; what changed is
  that the row states the evidence instead of a bare `PASS`.

- **One published row is left for a decision rather than written.** `3529f0f6b2cd` records
  `encoded_layer_gate: PASS` and the current gate returns `FAIL` on the bytes in the shard: a
  3-character identifier, `contains` position, inside a 97-character base64 segment, at
  decode layer 0 — the same ~98 KB stage the row's own note says the original gate read, so
  the change is the predicate and not the reach. `verify-and-stamp.py` refused it, the other
  seven are stamped, and the published half therefore reports one over-claimed row until
  someone decides. Writing it either way flips a `publishable` in the published half, which
  is not this round's call to make.

### Fixed

- **`3529f0f6b2cd`'s record now holds the finding, in the order the mechanism requires.** The
  row stored `encoded_layer_gate: PASS` while the current gate returns `FAIL` over the exact
  bytes the shard holds (`782a8924be8a`), and `clear-finding.py` refused to clear it — *"a
  clearance signed against a pass would pre-approve whatever the gate says next"*. So the
  order was fixed: re-measure first, judge second. `remeasure-gates.py` reproduces the profile
  to the digit — one 3-character `acct` identifier, `contains`, in a 97-character `base64`
  segment, `plaintext_gate` still `PASS` — and writes it with its provenance. The row is now
  blocked on the finding rather than on missing provenance, which is a different and honest
  reason.

- **The gate read the tag before it read the evidence, and four rows were publishable with a
  recorded credential failure on them.** Five local rows record `masking.secret_gate: FAIL`
  and **none carries the `secret` tag**, so the rule armed last round — which consults
  `secret_gate` only on a `secret`-tagged row — never looked at one of them. Four were
  `publishable: true` with **zero** blockers; three of those were tagged `clean` alone, which
  is in `ALWAYS_OK`, so `unmasked` was empty and the entire masking branch was skipped too.
  Two independent tag conditions stood between a recorded credential failure and a shard.

  A gate finding is evidence about the bytes and a tag is a claim about them, so `evaluate()`
  now separates the two questions. *Does this row need a masking pass?* stays tag-driven,
  because that is what it asks. *What did the gates that ran actually say?* is asked of every
  row that records a result, whatever the tags are. `unreadFailures()` asserts the resulting
  property **independently of the rule that produces it** — publishable, stored or computed,
  while holding a recorded non-pass no clearance covers, is impossible — re-derived from the
  record without calling `evaluate()`, so an edit that reintroduces a tag condition breaks it
  without touching it. It was observed firing on the four real rows before the fix.

  `ALWAYS_OK` is unchanged and the 637 unread `c2`-only files are still unread. What changed
  is that a tag can no longer silence a measurement that exists; it can still stop one being
  demanded.

  **Read one at a time, four of the five are shape false positives and one is real.** A
  genuine bcrypt hash assigned to `$stored_hash` and passed to `password_verify()` inside a
  `base64+inflate` layer, on a row whose own `decoded_form_tags` already said `secret` while
  its `sensitivity` was taken from `encoded_form_tags` and read `clean`. The other four: a
  regex fragment captured from a wp-config **harvester**'s own pattern; 22 configuration
  array-key names in a shell that uses a wp-config constant as its `$GLOBALS` namespace; 95
  bytes of C source captured because `write(c,"Password:",9)` puts a closing quote where the
  pattern expects an opening one; and `password:"password"` in a jQuery-Terminal string table.
  There is a third possibility the two-way framing misses and one row is in it —
  `b827cdd9d417`'s finding is a collision **and** the row is under-tagged, carrying `pii` in
  its decoded layers while tagged `clean` and marked publishable. `pii` is never publishable by
  any route. No shard had been distributed when this was written, so none of it was exposed
  then; re-checked after the 2026-09-07 release, none of the five rows' digests appears in any
  shipped manifest either, so none of it is exposed now.

- **An unrecognised or absent gate value is now a failure by construction rather than by
  accident.** `!= "PASS"` fails closed on everything that is not the string, which is the right
  direction — and it cannot tell a `FAIL` from a value it does not understand, or say which it
  saw. Six rows store `encoded_layer_gate` as a **dict** carrying `result: FAIL` (2 to 64
  occurrences of `acct` and `dom` identifiers inside encoded layers) and twelve store the
  string `SKIPPED-oversize (>1MB)`, which is a gate that never ran.

  **Neither was being read as a pass; neither was being read at all.** Measured, not assumed:
  every value form was run through the real `evaluate()` and each produced the blocker once the
  branch was reached. What stopped it is that all eighteen rows carry `applied: false` and the
  branch sat behind `if unmasked: if applied:` — the same tag condition again. `gate_result()`
  now returns one of `pass`/`fail`/`skipped`/`unreadable`, three blockers rather than one,
  because the repair differs: a FAIL is a human decision, a SKIP is to run the gate, an
  unreadable value is to find out what wrote it. `detection_survived` is compared strictly to
  `True`, so a recorded `"no"` cannot read as a pass. `verify-and-stamp.py` shares the parser;
  its own `_norm` read every truthy non-string as `FAIL` and could not tell a dict-form `PASS`
  from a dict-form `FAIL`.

  **The dict form predates every tool in this tree** — 15 rows in the 2026-09-03 collection
  index and 15 in the 2026-09-04 backup, 0 in both generations of the published half. No
  surviving tool from that import writes it; the two that touch the field write the string
  form. Last round did not introduce it. **15 → 6** because nine of the fifteen were re-masked
  in last round's re-measurement and `mask-samples.py` overwrote the field with the string form
  (7 `PASS`, 2 `FAIL`); the six that remain were never re-masked.

  **`applied: false` means two different things and the discriminator is which key is set.**
  `reason: "no identifier to mask"` (123 rows, all published) is a gate that ran and found
  nothing, and its fields are measurements. `not_applicable_reason` (29 rows, all local archive
  containers) is a recorded decision that masking is impossible, and its
  `detection_survived: false` is a placeholder for a measurement nobody took. Only the second
  disqualifies a field and only that one field — reading it as "masking destroyed detection"
  would attach 29 rows to a cause that never happened. Their byte gates are still read, which
  is where the twelve `SKIPPED` rows now block; two of those are tagged `clean` alone and were
  held by nothing but a `local_only` marker.

- **The docs conflated "published" with "distributed", and it produced a wrong conclusion
  about public exposure.** `SOURCES.md` called shards "release assets" and
  `KNOWN_ISSUES.md` said two samples "ship in" one — present tense for an intended state.
  Reading both, a gate failure on a published row looked like a statement about bytes already
  in public. **No shard had been distributed at the time**: every release asset then published
  was a scanner binary, `corpus/shards/` had zero tracked files and no download URL was
  referenced anywhere in the tree. `published` is a classification meaning *cleared to be
  distributed*, and `published_shipped_as_bytes: 84` — its value on this round — means *would
  ship if a shard were released*. Both are now stated where they are used, and the three places
  that implied otherwise are corrected.

  *Eight shards were distributed on 2026-09-07, which makes the distinction this entry draws
  load-bearing rather than merely tidy: `published` still does not mean "distributed", and now
  the difference is a set of bytes a stranger actually holds. See the `SOURCES.md` section
  "`published` is a classification, not a distribution state".*

- **A confidence grade was written for the encoded-layer gate, measured, and withdrawn.**
  The plan was to call a hit from a 6+ character identifier high confidence — it comes from
  the containment rule — and a shorter one low, since the short rule is a whole-alphabetic-run
  test. A null model supported it: 660 trials of 98,473 bytes of random base64 gave 0.23
  short-name hits per trial against 0.0015 containment hits, about 150 to 1.

  **Random base64 was the wrong null.** Decoded layers are frequently code, and code is
  exactly where an account name that is also an English fragment collides. Re-run against
  8,000 stock CMS files — which carry no customer of ours, so every hit is a false positive —
  the predicate produces **127 false positives across 104 files (1.3%), and 36 of them come
  from identifiers of 6 or more characters**. The case that caught it was real: a
  six-character account name inside `imagick_…` in a 473 KB decoded PHP function table, which
  the length rule would have labelled high confidence.

  That is §11 — a denominator enumerated by a process that does not resemble the population
  bounds the result and not reality — so no grade is emitted and the gate verdict is
  unchanged. What a finding now records instead is the evidence: identifier lengths,
  positions (`exact`/`begins`/`contains`), the size of the segment the identifier sits in,
  the layer that carried it, and the measured false-positive rate. A 3-character identifier
  *contained* in a 97-character segment reads differently from an exact match on its own, and
  the row now says which without ever naming anything. `--stock-fp` regenerates the table and
  `--base-rate` regenerates the base64 null that misled it, both from the real predicate.

  An earlier report of this measurement said containment fired **zero** times in 5.9 MB. That
  was one 60-trial sample read as a property; a different seed produces one, reproducibly.
  A base rate of zero means "not observed yet" until it has been looked for at scale.

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
  blocks the first public shard carrying a `secret`-tagged sample. Measured against the eight
  shards actually distributed on 2026-09-07: none carries one — the 144 shipped members are
  tagged `clean` (107), `c2` (34) and `path` (7), and `secret` does not appear.

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

---

[Unreleased]: https://github.com/LytraX/lyxbosa/compare/corpus-2026.09.2...HEAD
[corpus-2026.09.2]: https://github.com/LytraX/lyxbosa/compare/corpus-2026.09.1...corpus-2026.09.2
[corpus-2026.09.1]: https://github.com/LytraX/lyxbosa/releases/tag/corpus-2026.09.1
