# Corpus review round 17 — 180 rows gain a family, and the family rate stops being one number

**Date:** 2026-09-08
**Branch:** `corpus/apply-and-guard` (from `master` at `03dd84f`)
**Scanner:** run, read-only. `LYXBOSA_BIN=build/lyxbosa`, sha256 `50666ef95a9b`, built
2026-09-05 13:33 — the same binary round 16 measured with. **`build-release` was not rebuilt
and not read.**
**Index:** written. 180 rows in the local half gain exactly two keys, `family` and
`family_evidence`. Nothing else moved, on any row, in either half.
**Summary:** regenerated. `make-summary.py --check` **was failing until it was.**
**Pre-report:** all five commands run. See §9.

**Status: no detection figure moved and the published family rate did not rise. The rate is
now reported once per sampling frame, with neither called the headline.**

---

## Headline

> **The acceptance criterion for this round was that the headline must not improve, and it did
> not.** 180 rows gained a family. Every one of the seven new families is fully detected.
> Sample-weighted detection is 696 of 1,299 before and after. And the family figure a reader
> sees did not move, because the 180 rows landed in a second column rather than in the
> existing one.
>
> Had the single family rate survived this write it would have read **micro 32.1% and macro
> 40.8%**, up from 14.9% and 29.9%, with not one verdict changed and not one expectation
> touched. That movement is entirely a property of the pool the seven families were drawn
> from: when they were assigned it held **530 detected rows out of 531**, and *exactly one*
> undetected row, so at most one family drawn from it could ever have scored below 100%.
>
> **A family definition can be clean while its sampling frame is contaminated.** That is a
> different failure from the one round 16 found, and it is recorded under its own key.

---

## 1. The two failures, and why they are two keys

Round 16 found a label whose **membership** is conditioned on detection.
`import-infected-tree.py` assigns `legacy-infected-tree-sample` under `if hit`: a sample is in
it because the scanner flagged it, and the row records that as `reason: detected-and-read`. It
reads 61 of 61 detected and could not read anything else. **You find that failure by reading
the code that assigns the label.**

`corpus/assign-family.py` has none of that shape, and looking for it there finds nothing:

| property of the seven new families | measured |
|---|---|
| membership decided by | a literal shared across the members, re-read from the sample bytes by the writer |
| a member carrying no marker | refused |
| a marker present in fewer than two members | refused |
| a session in which every family is a function of `expect.must_detect` | refused outright |
| refusals that fired on real input during the pilot | 2 |
| membership decisions that any rule change would move | **0** |

Every label is defensible and would survive any rule change. **What is not clean is the pool
they were selected out of.** At the moment of assignment:

| population | rows | carrying an expected rule | recorded known misses |
|---|---|---|---|
| the pool: reviewed malicious rows with no family | 531 | **530 — 99.8%** | 1 — 0.2% |
| the whole reviewed malicious set | 1,299 | 696 — 53.6% | 603 |

Both are censuses — every row counted, nothing sampled — so the comparison carries no sampling
error and needs no significance test. It needs to be **recorded**, which is what this round
adds: `family_evidence.frame_detail()` measures it at write time and the writer puts it on
every row as `family_evidence.sampling_frame`. Re-deriving it later would measure a pool that
has shrunk by everything labelled since, and would answer a question about a population those
rows were never drawn from.

The summary gains **`families_sampling_frame_conditioned`**, its own key beside
`families_detection_conditioned` rather than folded into it. The two are found by different
means — one by reading the assigning code, one only by counting the pool — and a reader who has
met the first will not go looking for the second.

## 2. Which way the guard should cut, and the measurement that decided it

Two defensible answers were on the table: exclude the contaminated families from the headline
and report them separately, or report the rate over both populations with neither called the
headline. **The second, and the reason is that the first population is not a clean control
either.**

| the 707 rows labelled before this writer | |
|---|---|
| rows | 707 |
| carrying an expected rule | 105 — 14.9% |
| **recorded known misses** | **602 — 85.1%** |
| largest single family | `seo-doorway-madxtube-2017`, 495 rows — **70% of the population** |
| micro average with that one family removed | **49.5%** (105 of 212) |

A mass miss is what gets investigated and labelled. That population is 85% known-miss because
of how it was assembled, and 70% of it is a single campaign somebody labelled *because* it was
a 495-sample miss. Drop that family and the same micro average moves from 14.9% to 49.5% —
within four points of the 53.6% whole-set figure.

So **both frames are contaminated, in opposite directions**, and no measurement in this corpus
establishes that either is a fair draw. Excluding the new families and keeping 14.9% would
promote a figure that can only ever deliver bad news, and would freeze it: every family this
method can ever add is frame-conditioned, so under that scheme the headline is immovable by
construction, which is not a measurement of the scanner either.

§11's property is a metric that cannot deliver bad news. **A metric that cannot deliver good
news is the same property with the sign flipped**, and choosing between them is choosing a
direction to be wrong in. Hence: one column per frame, no number spanning them, and the
sample-weighted figure over the whole reviewed set left as the one rate whose denominator
nobody chose.

## 3. What the documents now say, and what refuses to let them say anything else

`README.md`'s family region is two tables. The first has a column per sampling frame with the
frame stated in its header row; the second carries the whole-set context — sample-weighted
detection, the rows still carrying no family, the provenance bucket, technique coverage and
re-run power.

**`doc-figures.py --check` gained a guard with two rules:**

- **companions** — a per-frame rate appearing anywhere in a tracked document must appear with
  that frame's integer pair *and* that frame's label. `14.9%` alone is not a claim anybody can
  check; `14.9% (105 of 707), sampling frame not recorded` is.
- **combined** — a rate computed across both frames must not appear at all. It is not merely
  unaccompanied: there is no population to accompany it with. `32.1%` is over the union of a
  pool that is 530-of-531 detected and a pool that is 602-of-707 missed, and no denominator
  rescues that, so the repair is to refuse it rather than to caption it.

The combined rule stands down while the union *equals* a rendered per-frame rate — the state
before any frame-conditioned family exists, where the union is one frame's own population.
Without that exemption the guard would have refused the correct document it was committed
alongside.

**The sweep is whole-document, not per-region, and that is the whole point.** `drift()`
compares the generated block against what the generator would write and says nothing about the
prose around it, by design — prose is a person's and survives regeneration. A family rate that
escaped into that prose is a published figure with no denominator, and the region check reports
`agrees` over it.

## 4. The seven families, and the frame recorded on each

All seven names are **attacker-campaign labels** — descriptions of malware kits given during
review. None is a customer or site identifier, and `assign-family.py` sweeps every recorded
name, basis and marker with the same predicate `pre-push-check.py` uses, refusing any that
carries one. That sweep is not decorative: malware hardcodes its victim, so a marker lifted
from a sample can be a customer's own host.

| family | rows | detected | sampling frame |
|---|---|---|---|
| `goto-flattened-metaphone-curl-fetcher` | 59 | 59 | detection-conditioned |
| `aes-cbc-cache-loader` | 26 | 26 | detection-conditioned |
| `seo-doorway-casino-content-template` | 26 | 26 | detection-conditioned |
| `tiny-upload-rename-write-shell` | 23 | 23 | detection-conditioned |
| `browser-file-manager-shell` | 17 | 17 | detection-conditioned |
| `self-append-gzip-dropper-common-payload` | 16 | 16 | detection-conditioned |
| `search-engine-cloaking-doorway` | 13 | 13 | detection-conditioned |
| **total** | **180** | **180** | |

**All seven, not six, and that is the answer the frame predicts rather than a coincidence.**
One row in the pool of 531 is undetected; it is not among these 180. The frame is recorded on
each of the 180 rows individually, so a later reader meeting one row does not have to re-derive
it from population counts that will have moved.

Two of the seven are named by `family_bucket_suspects`, the boolean dispersion census, exactly
as round 16 predicted they would be: it asks whether the intersection of the members' rule-sets
is empty and **one outlier member empties an intersection**. The writer's own test is a share
and both sit far above the floor. Reported, not refused — which is what round 16 built it to
do.

## 5. The 103, which do not quietly disappear

`unfamilied` falls from **531 to 351**. That is not the gap closing, and the summary note now
says so where the count lives.

The census behind the *428 reachable / 103 not* figure was run in a scratch script that a crash
took, so the number was standing on prose in a commit message. **Re-derived over all 95
clusters and all 531 rows it reproduces exactly:**

| | clusters | rows |
|---|---|---|
| multi-member, carrying a distinctive shared literal | 38 | 378 |
| singletons sharing a literal some other row carries | 50 | 50 |
| multi-member, only a cluster-wide literal a fifth of the pool carries | 3 | 87 |
| multi-member, sharing no literal at all | 1 | 13 |
| singletons sharing nothing | 3 | 3 |
| **reachable / not** | | **428 / 103** |

The one free parameter is where a literal stops being distinctive. The answer is **stable for
any threshold between 93 and 193 rows** — a two-to-one range — and moves outside it, which is
worth stating rather than quoting a single point estimate. Not a sample: every cluster and
every row.

**It is a floor rather than a ceiling, and the pilot already beat it.** The census asks whether
a cluster's top-ranked marker is distinctive. A reviewer can instead take *part* of a cluster
on a rarer literal only a minority of members carry — which is the same move `ruleset_determined`
rewards, because it is how a family stops being a function of the rule-set. **16 of the 103
were labelled that way in the pilot session**, all of them inside the two large clusters whose
cluster-wide literal is generic. So **87 rows remain out of reach of this method**, and those
need the decoded payload rather than the stored bytes.

All 103 — now 87 — stay inside `malicious_family_population`. The three populations still sum
to `malicious_reviewed` exactly: **351 + 887 + 61 = 1,299**.

## 6. The write, audited by something that is not the writer

`assign-family.py` asserts per row that the keys it changed are exactly `family` and
`family_evidence`, holds `indexio.index_lock` across the whole read-modify-write, re-reads the
index inside the lock immediately before writing, writes through `write_jsonl_atomic`, and
re-reads from disk afterwards to re-audit. **All of that is the writer checking its own
arithmetic.**

So the file on disk was also compared, key by key, against a copy taken before the write — a
census over all 48,256 rows of the local half, not a sample:

| check | result |
|---|---|
| row count | 48,256 → 48,256 |
| row order (sha256 sequence) | identical |
| rows changed | **180** |
| keys that changed, anywhere | **`family` and `family_evidence`, and nothing else** |
| rows gaining one without the other | 0 |
| `publishable` changed | **0 rows** |
| rows that already carried a family and were touched | 0 |
| the 180 changed rows vs the 180 proposed | identical sets |
| detected malicious rows in this half | unchanged |
| recorded known misses | unchanged |
| verdict distribution | unchanged |

The published half was not opened for writing and its sha256 is unchanged.

## 7. What did not move, and the attributed cause for each

**Every count difference carries an attributed cause, and a count that does not change carries
one too.**

| figure | before | after | cause |
|---|---|---|---|
| `malicious_detected` | 696 | 696 | a family is a classification of material already ruled on; the write touches no `expect` and no `verdict` |
| `malicious_reviewed` | 1,299 | 1,299 | no row was added or removed |
| `malicious_known_miss` | 603 | 603 | same |
| `publishable`, any row | — | — | computed by the gates; the writer asserts per row that it did not touch it, and the diff above confirms it over all 48,256 |
| `families_published` | 30 labels | 30 labels | all 180 rows are in the local half; nothing published gained a label |
| `malicious_rows_without_technique` | 531 | 531 | this writer records `family` and `family_evidence` and nothing else — the technique gap is untouched |
| `family_detection_by_frame.sampling_frame_not_recorded` | 38 families, 105 of 707 | 38 families, 105 of 707 | the 180 rows landed in the other frame; **this is the acceptance criterion for the round** |
| `malicious_family_population.unfamilied` | 531 | 351 | 180 rows moved to `campaign_familied` |
| `malicious_family_population.campaign_familied` | 707 | 887 | the same 180 |
| `family_detection` (the union, rendered nowhere) | 105 of 707 | 285 of 887 | the union across both frames; it is why it is rendered nowhere |
| `family_rerun_power.no_member_rerun` | 11 | 18 | the 7 new families ship no bytes in a public shard, so nothing re-runs any member |

## 8. Controls, both directions, shipped in the same commit

| suite | cases | new this round |
|---|---|---|
| `corpus/assign-family.py --inject` | 50 | 10 |
| `corpus/make-summary.py --inject` | 45 | 13 |
| `corpus/doc-figures.py --inject` | 41 | 17 |
| `corpus/pre-push-check.py --inject` | run | — |

**The frame test is asserted in the accepting direction as often as the refusing one**, because
a frame test that called every pool contaminated would satisfy every positive case and measure
nothing:

- a pool detected far above the set it came from → conditioned
- a pool detected at the same rate as its set → **not** conditioned
- a pool detected far *below* its set → conditioned, so the test is two-sided rather than a
  one-way "is this flattering" check
- a frame that was measured and found unconditioned reads `not_recorded`, so recording a frame
  at all is not what gets a family excluded
- one conditioned member is enough to name a family, so a single row assigned by another route
  cannot launder one back into the unmarked column
- the two frames **partition** the campaign families, the campaign rows and the detected rows —
  asserted equal to the union on all three
- the union rate is asserted to be neither frame's rate, which is the number the split exists
  to keep out of a document
- a proposal reaching the writer with no measured frame is a `KeyError`, not a null field on a
  published row

**The guard is asserted not to be redundant.** `run()` takes a `guard=False` for exactly one
purpose: the suite doctors a document by putting a union rate loose in its prose, asserts the
guard refuses it, and then asserts **the region check alone passes the same file**. A guard
whose positive case is already caught by the check standing beside it has not been shown to do
anything. The same pair runs for the companion rule using `corpus/SOURCES.md`, which carries no
family table at all, so nothing in the file can satisfy the companion by accident.

Every guard case runs against a summary the suite **builds** with both frames populated, so the
controls behave identically whether or not any frame-conditioned family exists in the real
index. A control that only worked after a particular write would be a control nobody could run
first — and this round needed to run it first.

## 9. Pre-report

All five commands, run after the write and after every document was regenerated.

| command | result |
|---|---|
| `corpus/shard-gate.py corpus/index.jsonl` | exit 0 |
| `corpus/shard-gate.py corpus/local/index-local.jsonl` | exit 0 |
| `corpus/make-summary.py --check` | exit 0 — **it was failing until the summary was regenerated**, on the family blocks, the two population keys, `family_rerun_power` and three notes, and on nothing else |
| `corpus/doc-figures.py --check` | exit 0 |
| `corpus/pre-push-check.py` | SAFE TO PUSH — run after staging, so it swept every changed file |

**The detection figure, measured across an index that did not change under it.**
`LYXBOSA_BIN=build/lyxbosa` (`50666ef95a9b`), the same binary round 16 used; `build-release`
was neither rebuilt nor read. `verify.py` was run once before the write and once after, and its
**output is byte-identical line for line**:

```
  shard-run        97 / 97     detected   0 missed
  Detection       696 / 1299  reviewed malicious samples detected   (53.6%)
  Regression       97 / 97    expected detections still firing
  False-positive rate 0.0223%  (44 of 197559 benign files)
  Known misses    603 recorded · 41 of them re-run here · 0 newly detected
  Techniques       90 of 123 known techniques covered by a tested sample
  Regressions      +0 failures
```

**Power, stated rather than implied.** 97 of the 1,299 reviewed malicious rows were
re-executed — **7.5%** — and the other 599 malicious local rows stand on the recorded result of
the last rescan. None of the 180 rows labelled this round is among the 97: they are local-half
rows whose bytes ship in no public shard, which is also why `family_rerun_power` now reports 18
families with no re-runnable member rather than 11. So the claim "these seven families are
fully detected" rests entirely on recorded rescan results, and that is exactly why it is
reported as a property of the pool rather than as a result about the scanner.

The census work in this round was **not sampled**: all 95 rule-set clusters, all 531 pool rows,
all 45 campaign families, and all 48,256 rows of the local half in the write audit.

**`index-summary.json` diff.** Against `master` at `03dd84f`: **95 insertions, 23 deletions**.
Against the summary as it stood after the guard landed but before the rows did: **65
insertions, 30 deletions**. Every deletion is accounted for — the union `family_detection`
cells and their `excl_predates_ruleset` twin (180 rows joined the union), `family_rerun_power`
(7 families with nothing re-runnable), the two `malicious_family_population` blocks (180 rows
moved from `unfamilied` to `campaign_familied`), and two notes rewritten this round. **No other
key changed**, which is the attributed cause for every figure that did not move.


## 10. Three controls that were passing while blind

The three-state family drift cases in `doc-figures.py` — fully / partially / completely — were
drifting `family_detection` and asserting the refusal named `family_fully_detected` and its
siblings. Those figure names stopped existing when the three-state counts moved into the
per-frame blocks. **The cases would have gone on passing against a figure no document
renders**, which is the shape this repository keeps finding. They failed loudly on the first
run after the renderer changed, and are repointed at the block the documents actually ship.

A fourth case failed for a smaller reason worth recording: the companion refusal printed the
missing companion's *value* and not its *name*, so a control asking "which companion is
missing" could not tell. The message now names the figure, which is also what a person reading
the failure needs.

## 11. A field census that had to be told about the new field, and one control failing on `master`

`field-provenance.py` classifies `family_evidence` as **read-only — 180 rows, read by
`family_evidence.py` and `make-summary.py`**, and it is right that it cannot see the writer:
`assign-family.py` assigns through the constant `fe.EVIDENCE_FIELD` rather than through a
literal, and the census matches subscripts and `.get()` calls by name. That is the same shape
as `campaign_marker`, already triaged there, and it is the **opposite** of a missing writer —
so it is now named in `KNOWN`, because `read-only` read casually means *nobody writes this*.

Adding that entry also cleared six control failures the write had introduced: run against the
post-write index, `master`'s copy of `field-provenance.py --inject` fails **7 of 57** and this
round's copy fails **1**. The six were all the arrival of an unclassified field.

**The seventh is failing on `master` and this round did not cause it and does not fix it.**
`account_hash has no real write position in corpus/` has been false since round 14:
`derive-index-db.py` builds a synthetic row carrying `origin.account_hash` inside `_loc()`, a
fixture helper. The census excludes write positions inside `inject()` and `_selftest()` —
`CONTROL_SUITES` — but `_loc` is defined at module level, so a control-suite *helper* counts as
a real writer. Fixing it needs the census to know which module-level helpers are only ever
called from a control suite, which is call-graph work with its own controls, and it is not this
round's. **`field-provenance.py` is not in the pre-report five, which is why a control inside
it has been failing for three rounds with nobody looking.**

## 12. What is not in this round

- **Nothing new was decided about the seven families.** The pilot's decisions are accepted as
  they stood: defined by bytes rather than by rule-sets, verified by re-reading the bytes, and
  with two refusals having fired on real input during that session. This round applies them and
  records the frame they were drawn under; it does not re-review them.
- **The 87 rows still out of reach were not attacked.** They need a decoded payload rather than
  stored bytes, and that is a different tool.
- **`family_detection_excl_predates_ruleset` carries the same contamination and is not split by
  frame.** It moves from micro 58.7% to 79.8% on this write. No document renders it, so nothing
  publishes that movement — but a future round that starts rendering it must split it first.
- **`legacy-infected-tree-sample` was not reclassified.** Reclassifying 61 rows is a human
  judgement, and this round touched no row that already carried a label.
- **The decider for the seven families was an agent, not an operator.** Every row records that
  in `family_evidence.decided_by`, unchanged from the pilot. The frame record does not make the
  labels more authoritative; it makes what they measure legible.
