# Corpus review round 10 — a gate that could only fail one way

**Date:** 2026-09-05
**Branch:** `corpus/stale-publishable`
**Scanner:** `build-release/lyxbosa`, unchanged throughout. No rule was touched this round.
**Pool:** the fourteen rows whose stored `publishable` disagreed with the computed one.

**Status: the gate was made symmetric, fourteen rows were recomputed, eight were published
and three of those promoted. The baseline was not updated.**

---

## Headline

> **`shard-gate.py` had never been observed to fail in one of its two directions, because
> it could not.** It failed when a row claimed publishable and was not, and returned zero
> when a row was publishable and did not say so. Fourteen rows had drifted in the second
> direction and every run recomputed them, printed `publishable flags corrected: 14`, and
> exited 0.

The round is that lesson rather than merely subject to it. What follows separates the
repair from the movement, because only one of them changes a number.

---

## Why nobody noticed

Two operator review passes on 2026-09-05 — six samples in one, eight in another — set
`verdict: malicious`, `sensitivity: ["c2"]` and `review.human_confirmed: true`. Neither
re-ran the gate that computes `publishable` from those very fields. So the rows kept
`publishable: false` and kept recording two blockers that had stopped being true.

Three properties combined to keep it invisible, and each is worth naming separately:

1. **The check was one-directional.** `main()` counted a violation only under
   `if r.get("publishable") and not ok`. The other branch incremented a counter called
   `changed` and nothing else. `changed` was printed; the exit code ignored it.
2. **`--fix` normalised it away on every run and reported that as routine.** A line reading
   `publishable flags corrected: 14` above a zero exit is indistinguishable from tidying.
3. **Nothing downstream reads the row; everything reads the record.**
   `promote-pending.py` defers on the stored `publish_blockers`, and
   `index-summary.json`'s `local_only_blockers` is a count of them. A stale blocker is
   therefore a stale denominator, and it propagated into the tracked summary.

**There was an arithmetic tell and it had been on the page for two rounds.** A row's
`sensitivity not yet assessed` blocker exists exactly when its sensitivity carries the
`unreviewed` tag, and its `verdict is unreviewed` blocker exactly when the verdict is
`unreviewed`. So the blocker counts should equal the tag and verdict counts. They did not:

| | blocker count | the tally it mirrors | gap |
|---|---|---|---|
| `sensitivity not yet assessed` | 73,797 | `sensitivity_tags.unreviewed` 73,783 | **14** |
| `verdict is unreviewed` | 79,595 | `verdicts.unreviewed` 79,581 | **14** |

Both gaps are the same fourteen rows, and both are now zero. Nothing computed that
comparison, which is why a number that was 14 out sat in a tracked file across two rounds.

---

## The repair

`staleness()` reports three classes and the gate fails on any of them:

| class | meaning | had it ever fired? |
|---|---|---|
| **over-claimed** | stored true, computed false | yes — 103 rows on the gate's first run |
| **under-claimed** | stored false, computed true | **never, and could not** — the fourteen |
| **blocker drift** | the boolean agrees, the recorded reasons do not | **never, and could not** |

The third exists because the boolean is one bit and the accounting is built out of the
reasons: a row can be unpublishable for a different reason than the one it records, and no
comparison of booleans can see that. It is narrower than the other two and it fired for
real this round, on the one row held below.

A `--fix` run that corrects anything now **exits non-zero on purpose**. The correction is
not the result; the result is that something upstream changed a verdict or a tag without
re-running the gate. The green result is the plain run afterwards.

### The field is still stored, and the code says why

A stored derived value can drift and a computed-on-read one cannot, so dropping it was the
first thing considered. It loses to the published half being a **tracked document**: a
stranger who clones this repository reads `index.jsonl` without running anything, and a row
that says `publishable: true` states its own status. `publish_blockers` has to be
materialised for the same reason and a stronger one — it is where §8's denominator comes
from, and it carries every blocker rather than the boolean's one bit.

So the repair is not to stop storing it. **A stored derived value is a cache, and a cache
with nothing asserting it equals its source is just a copy.** `staleness()` is that
assertion.

### The control, and the proof that the control can fail

`shard-gate.py --inject <index>` constructs eight stale rows and three consistent ones,
runs them through the real `staleness()`, and asserts the class each lands in — including
three negative controls that must stay silent, one of them a real untouched row from the
index being checked.

Twelve of twelve pass. **That is worth nothing until the control is shown to fail**, so the
pre-fix gate was reconstructed by reverting `staleness()` to its one-directional form and
the same control run against it:

```
cases: 12 · passed: 5 · failed: 7
FAIL: reviewed c2 row still stored false (the fourteen)
FAIL: stored false with no blocker recorded at all
FAIL: field absent entirely: the gate has never run on this row
FAIL: unpublishable for a reason other than the one recorded
FAIL: second blocker appeared and was never recorded
FAIL: publishable but still carrying a cleared blocker
FAIL: recompute does not clear staleness
```

The blind gate also printed, over the real 80,536-row index, `over=0 under=0 drift=0`. That
line is the whole defect: a silent, green, exhaustive-looking result.

---

## Every count difference, with its cause

§8 requires an attributed cause rather than a bare delta. There are three causes here and
they are kept apart deliberately, because two of them are commonly conflated.

| figure | before | after | cause |
|---|---|---|---|
| `local_only_blockers["verdict is unreviewed…"]` | 79,595 | 79,581 | **recompute.** −14, the stale rows |
| `local_only_blockers["sensitivity not yet assessed"]` | 73,797 | 73,783 | **recompute.** −14, the same rows |
| total blobs | 92,800 | 92,800 | **recompute moves nothing.** No row was created or destroyed |
| Detection | 169 / 774 | 169 / 774 | **recompute moves nothing.** A publishability field is not a detection claim |
| published rows | 12,264 | 12,272 | **publication.** +8, the doorway-kit components |
| local-only rows | 80,536 | 80,528 | **publication.** the same 8, moved not copied |
| `published_shipped_as_bytes` | 76 | 84 | **publication.** the same 8, shipped as bytes |
| Detection | 169 / 774 | **172 / 774** | **promotion.** +3, the `BD018` deployers |
| known misses | 605 | 602 | **promotion.** the same 3 |
| executed set (`shard-run`) | 95 / 95 | **98 / 98** | **promotion.** the 3, now published *and* runnable |
| known misses re-run by the suite | 37 | 42 | **publication.** +8 shipped, −3 promoted out |
| technique coverage | 80 / 123 | **90 / 123** | **publication.** 10 techniques, all previously uncovered |
| false-positive rate | 8 / 146,713 | 8 / 146,713 | **unchanged.** No rule and no benign source moved |
| `local_only_publishable_no_blocker` | — | 5 | **new key.** See below |

**Recomputing a stale field moved no count, and that is the expected result.** It is stated
rather than omitted because a difference here would have been the finding.

**Publishing does not move detection either** — a published row and a held row are both in
the denominator. What it moves is how much of the figure a stranger can reproduce, and that
is the executed set: 95 → 98, with the eight new samples also adding five re-runnable known
misses.

---

## What was published, and what was verified before it was

`corpus/shards/malicious-doorway-kit-001.tar.zst` — eight components of one 2017 SEO doorway
kit from the legacy `Infected` tree: three deployers, three generators, two presentation
templates. 12 KB. The corpus's **first published material from the legacy tree**, so every
row carries `predates_ruleset: true` and the summary reports detection both with and without
them.

§4.1 says a `c2`-only sample is publishable because an indicator is a property of the
sample. That was verified rather than assumed, in four passes:

| check | what it examined | result |
|---|---|---|
| plaintext identifier gate | raw bytes of all 14 candidates, both pseudonym maps, 290 identifiers, 218,696 bytes | **0 occurrences** |
| encoded-layer audit | all 14 | 8 have **no region able to carry an identifier**; the other 6 do |
| decoded layers | every base64 run ≥ 24 chars in all 14, decoded and re-checked | 25 layers, **0 carrying an identifier** |
| §7.2 generic secret scan | 8 detectors × 14 files | **1 hit**, on a sample that is now held |
| `promote-gate.py` | the exact rows about to be written, both maps | PASS on the legacy map; PASS on the incident map after adjudicating 4 short-name residues |
| detection parity | per sample, source bytes vs staged bytes, `check` not a batch scan | identical on all 8 |

The identifier sweep is **exhaustive, not a sample**, so no power statement is owed: it
compares every identifier in both maps against every byte of every candidate. The
encoded-layer audit is the part with a stated limit — it is a conservative classifier, not a
decoder, and it reports "carries a region large enough to hide an identifier", which is why
the base64 layers were decoded and re-checked separately rather than trusted to it.

### A collision the incident map produced, described rather than quoted

`promote-gate.py` reported **four occurrences of a short-account-name residue** and refused.
Read: all four are the same **two-character token**, and in all four it is the CMS prefix in
a technique tag naming a login-page injection and in the prose of a verdict reason. The
incident map holds exactly one account name of that length, and it collides with a prefix
that appears in half the paths of any WordPress tree — which is the collision
`promote-gate.py`'s own docstring predicts for names below its floor. Adjudicated as CMS
vocabulary and re-run with `--allow-short-residue`, which records the decision rather than
suppressing the finding.

### The encoded-layer audit calls valid UTF-8 an encoded layer

Three of the six incident candidates report `printable_ratio 0.6381` and
`non-printable-bulk`. They are not obfuscated: they are PHP whose comments and variable
names are **Japanese**, and the audit's `printable_ratio < 0.90` test cannot tell multi-byte
UTF-8 from a binary blob. All fourteen files decode as UTF-8 except three legacy templates,
which are Latin-1 doorway content.

This errs in the safe direction — it holds a file that need not be held — so it is recorded
rather than repaired here. It is worth repairing, because a classifier that reports
"encoded layer" for every non-English source file will eventually be believed.

---

## What was held, and why each hold is a finding rather than a shortfall

**Six of the fourteen were not published.** All six are publishable under §4.1's literal
rule; none of them can ship yet.

**One is held deliberately, with `local_only` set.** §7.2 requires that a secret scan over
an unpacked public shard return zero hits, and it fires on this sample's bytes: an attacker
password-gate hash of exactly the class §7.2 names, in the first four lines. The corpus's
only other sample carrying the same technique is tagged `c2` **and** `secret` and is held
for masking — so this row's `sensitivity: ["c2"]` looks under-tagged by the same review that
set it. Adding a sensitivity tag is a human assessment under §4.1's axis B and is not a
tool's to make, so the row is held and the operator has two ways to clear it: re-tag and
mask, or rule that an attacker's own gate hash is an IOC like a `c2` host and the §7.2
detector needs the same carve-out `c2` already has.

That hold is itself an instance of this round's theme: **`evaluate()` never asks the masking
questions for a `c2`-only row.** The `unmasked` set is empty, so the plaintext gate, the
encoded-layer gate and the detection-parity check are all skipped, and the row is publishable
on the strength of a tag a human typed. The tag is the only thing standing between those
bytes and a public shard.

**Five are held for a mechanical reason.** They carry no `family`, no `technique` and no
`reason` — three fields all 132 published malicious rows carry. The two operator reviews
covered verdict and sensitivity and did not extend to classification. Publishing them would
also break the suite's own reconciliation: `verify.py`'s shipped-sample loop skips a row
with no `family`, so the row would count in `malicious_detected_runnable` while never being
executed, and `detection.reconciles` would go false. They are now visible in the summary as
`local_only_publishable_no_blocker: 5`, because five rows sitting in the local half with no
recorded blocker is an unattributed count.

---

## Two findings recorded for a later round, not repaired here

- **`verify.py` selects shipped samples on `r.get("family")` being truthy.** A published
  malicious row without a family is skipped in silence — not even reported as "not present
  in any shard", which is the failure mode §8 names. The consequence is caught downstream by
  the reconciliation check, and no published row is currently in that state, so this is
  latent rather than live. It is the same absent-versus-tested confusion one level along.
- **`promote-pending.py` re-measures the one field it distrusts and trusts the two it could
  also derive.** Its docstring is explicit that the handoff is not an authority, and it
  re-measures `now_detects` per sample against the shipped bytes for exactly that reason —
  but it takes `half` and `publish_blockers` from the handoff at face value, and those are
  the same kind of stored snapshot of derivable state that this round's fourteen rows were.
  Three rows in the file were stale in precisely that way. They were **re-derived from the
  index** rather than edited, and the derivation printed its before and after; the other 31
  snapshots were re-derived too and were already correct, which is the control on that step.
  The repair is for the applier to derive both fields itself.

---

## Commands

```
python3 corpus/shard-gate.py --inject corpus/local/index-local.jsonl   # 12/12
python3 corpus/shard-gate.py corpus/local/index-local.jsonl --fix      # exits 1, prints what it corrected
python3 corpus/shard-gate.py corpus/local/index-local.jsonl            # the green result
python3 corpus/promote-gate.py <rows> --map <map> [--allow-short-residue]
python3 corpus/make-shard-manifest.py <stage> --write --write-expect
corpus/build-shard.sh <stage> malicious-doorway-kit-001
python3 corpus/promote-pending.py --stage-root <parent> --apply
python3 corpus/make-summary.py && python3 corpus/make-summary.py --check
corpus/verify.py
python3 corpus/pre-push-check.py
```
