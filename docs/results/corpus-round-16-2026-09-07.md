# Corpus review round 16 — a family label whose membership is conditioned on detection, and 531 rows that every family figure is silent about

**Date:** 2026-09-07
**Branch:** `corpus/family-detection` (from `master` at `7a7d508`)
**Scanner:** run, read-only. `LYXBOSA_BIN=build/lyxbosa`, sha256 `50666ef95a9b`, built
2026-09-05 13:33. **`build-release` was not rebuilt and not read** — it is sha256
`4c3e0af08988` and another session is measuring with it. The two binaries carry the same
rules: this one reconciles at 97/97, which is the check that says so.
**Index:** **not written.** No row was added, moved or corrected. Every figure here is derived
from the rows as they already stand, and `corpus/indexio.py` was not needed.
**Summary:** regenerated. `make-summary.py --check` **was failing until it was** — on twelve
new keys and **on nothing else**, which is the evidence that no existing figure moved.
**Pre-report:** all four commands run, all four green. See §8.

**Status: no detection figure moved. The sample-weighted figures were not recomputed; they
were joined. `README.md` gains a second generated table and no hand-written number.**

---

## Headline

> **`legacy-infected-tree-sample` is not a family, and counting it as one made family coverage
> flatter by construction.** `import-infected-tree.py` assigns that label under
> `if hit and not chk["container_scoped"]` — a sample is in it **because the scanner flagged
> it** — and the row records the fact plainly as `reason: detected-and-read`. Its 61 members
> read **61 of 61 detected**, and no rule change in either direction could move that: a sample
> the rules stopped catching would never have been given the label.
>
> That is §11 arriving in the **numerator's own selection rule** rather than in a denominator,
> which is why nothing watching denominators saw it. `malicious_reviewed` is right,
> `malicious_detected` is right, and the defect is entirely in how the rows are grouped.
> Recorded as §11's twelfth appearance.

---

## 1. First result: the brief's premise about the source, and the brief's numbers

The brief asked me not to inherit **10 fully detected, 5 partial, 24 missed**, on the grounds
that they were proxied from `expect.must_detect` and `expect.known_miss`, "which is not the
source `verify.py` uses for the headline".

**The premise is wrong, and that is a reassuring result rather than an alarming one.**
`verify.py` does not compute its Detection line at all. It reads it out of
`index-summary.json`:

```python
res["detection"] = {"detected": summary.get("malicious_detected", 0),
                    "reviewed": summary.get("malicious_reviewed", 0), ...}
```

and `make-summary.py` builds that key as

```python
"malicious_detected": sum(1 for r in allr if r.get("verdict") == "malicious"
                          and (r.get("expect") or {}).get("must_detect")),
```

So `expect.must_detect` **is** the source of the headline. The shard re-run inside `verify.py`
is not the headline — it is the reconciliation against it, and it covers 97 rows of 1,299.

Derived from the authority rather than from the proxy, the figures come out **identical**:
10 fully detected, 5 partial, 24 missed over 39 labelled families. The two agree because they
are the same predicate. To keep them that way it is now written once — `is_detected()` — and
called from both the sample-weighted and the family-weighted counts, because two predicates
meant to be one predicate are how a family figure comes to disagree with the headline printed
beside it.

**The brief's numbers are right and are still not the ones this round publishes**, for the
reason in §2.

## 2. One of the 39 is not a family

`legacy-infected-tree-sample`, 61 rows, apparently fully detected. The brief suspected a
catch-all named after its provenance. It is worse than that: it is a catch-all named after
**detection**.

```python
    if hit and not chk["container_scoped"]:
        d["family"] = "legacy-infected-tree-sample"
        d["technique"] = ["obfuscated-php-payload"]
        d["reason"] = "detected-and-read"
```

A catch-all by provenance inflates coverage if its members happen to be easy. A catch-all by
**detection** cannot do anything else. Its fully-detected cell is a tautology.

### The sweep of the other 38 — a census, not a sample

39 families and 1,299 rows is small enough to enumerate, so nothing here is sampled and no
power statement is owed on the sweep itself. Three properties, each computed over every one of
the 39:

| property | `legacy-infected-tree-sample` | every other multi-member family |
|---|---|---|
| expected rule-sets among detected members | **39 distinct, no rule shared by all**, across 8 unrelated rule prefixes | shares a rule across all detected members, or fires a single set |
| techniques | one, the most generic in the vocabulary, carried by no other family | 2–9, specific, several carrying a `campaign-marker` |
| `verdict_reason` | a **five-way disjunction** of unrelated malware classes | one campaign, described |

The `reason` field is the decisive one and the rule-set dispersion is the corroboration —
deliberately, because the dispersion test **does not read the reason code**. It is now
`family_bucket_suspects` in `make-summary.py`, recomputed every run, so a bucket arriving later
under a new reason code is *named* rather than silently counted as a campaign. Run over the
index today it names exactly one family and no others: one true positive, thirty-eight true
negatives.

It reports and never excludes. Reclassifying a label is a judgement, and the brief reserved
that judgement; no family was assigned or corrected this round.

### What happens to its 61 rows

They stay. A sample that was reviewed does not stop having been reviewed, and dropping them
would be the same defect with the sign flipped. They move into a named third population,
`provenance_bucketed`, which is counted, published, and inside every total.

**Attributed cause for the count that changed:** family census **39 → 38**, campaign-familied
rows **768 → 707**, fully detected **10 → 9**. One label reclassified as a provenance bucket
because its membership predicate reads the scanner's output. No row was edited.

## 3. The denominator, which is the weakest part and now says so

**531 of the 1,299 reviewed malicious rows carry no family at all.** A family-weighted figure
describes the other 768 and is silent about them, and that silence is bounded by who bothered
to assign a label rather than by the corpus.

They are **not a random 531**:

| population | rows | detected | rate |
|---|---|---|---|
| campaign-familied | 707 | 105 | 14.9% |
| provenance-bucketed | 61 | 61 | 100% by construction |
| **unfamilied** | **531** | **530** | **99.8%** |
| all reviewed malicious | 1,299 | 696 | 53.6% |

They hold **530 of the 696 recorded detections**. Excluding them silently takes sample-weighted
detection over what remains from **53.6% to 21.6%** — a family metric that quietly dropped them
would be reporting the labelling effort in the *unflattering* direction, which is no better for
being unflattering.

**The honest presentation, and why it is neither of the two the brief offered.** Not "a family
figure over 768 rows with the gap named", because 61 of those 768 are not a family. Not "a
third category for unfamilied samples", because that leaves the bucket inside the family count.
Three populations, which partition the reviewed set exactly:

```
campaign_familied 707 + provenance_bucketed 61 + unfamilied 531 = 1,299 = malicious_reviewed
```

The sum is asserted in `--inject`, and the detected split sums to `malicious_detected` (696)
independently — so the family metric and the headline reconcile on both the numerator and the
denominator, not merely on the rate.

## 4. Technique coverage is the same question a third way, and shares the same blind spot

123 techniques known, 90 with a runnable published sample. Checked rather than assumed: the
published set and the ships-as-bytes set are **the same 90 techniques**, not two sets that
happen to be the same size, so "90 with a runnable test" is accurate.

The finding is what carries no technique. **531 reviewed malicious rows carry none — and it is
the identical set to the 531 carrying no family, not merely the same count** (symmetric
difference: 0). So technique coverage and family coverage are silent about exactly the same
part of the corpus. They do not corroborate each other, and a reader who takes 90-of-123 as
independent confirmation of the family split is double-counting one blind spot.

Excluding the provenance bucket costs technique coverage exactly one technique — the generic
one, carried by no other family.

## 5. Macro, micro, and the gap as the point

| figure | value | what it weights |
|---|---|---|
| macro average, 38 campaign families | **29.9%** | every family equally |
| micro average, same 707 rows | **14.9%** | every sample equally |
| sample-weighted, whole reviewed set | **53.6%** | every reviewed malicious sample |
| sample-weighted, excluding the rules' own source material | **89.8%** | 631 of 703 |

Macro and micro differ by a factor of two **on the real index**, so the divergence needed no
constructing — but it is constructed in the controls anyway, in both directions (§7), because a
macro average that tracked the micro average on every input would not be measuring what it
claims.

The 495-sample campaign is the whole story of the gap: one missed family, 495 missed samples.
Sample weighting says the scanner misses a great deal. Family weighting says it misses one
thing prolifically. Neither is wrong; a reader needs both to know which.

**Three states are reported separately** — 9 fully detected, 5 partially, 24 completely missed
— because collapsing partial into either neighbour loses the same information as collapsing a
row's several publish blockers into one reason. Four of the 29 not-fully-detected families are
ones the scanner catches most of.

## 6. The power of the family census, which is mostly recorded rather than re-run

A family's verdict is read from `expect.must_detect`, a **recorded** result. `verify.py`
re-executes only members whose bytes ship in a public shard: 138 rows of 1,299 (**10.6%**), of
which 97 are expected detections and 41 are known misses. All 138 agreed with the record this
round — 97/97 still firing, 0 of 41 newly detected.

Over the 38 campaign families:

| | families | rows |
|---|---|---|
| every member re-runnable | 23 | 77 |
| some members re-runnable | 4 | 69 |
| **no member re-runnable** | **11** | **561** |

**The 11 families nothing re-runs hold 561 of the 707 rows (79%)**, while the 23 fully
re-runnable ones hold 77 — the re-runnable families are the small ones, and the largest
families are among the eleven — the 495-sample campaign is re-run zero times. So the three-state
split is a census of the *record*, and a stranger can reproduce 23 of its 38 cells in full.
Published as `family_rerun_power` rather than left implicit: the cell nobody checked is §11's
habitual home.

## 7. Controls, both directions, shipped in the same commit

`make-summary.py --inject` — **32 cases, 32 pass** (13 pre-existing, 19 new):

- a family whose every sample is detected reads `fully_detected`
- a family with a single miss reads `partially_detected` **and specifically not `fully_detected`**
- a family with no detections reads `completely_missed`; one detected of ten reads partial, not missed
- lopsided families: macro **0.75** against micro **0.0291** — they disagree
- equal-sized families at equal rates: macro **==** micro. Without this pair the divergence
  could be the arithmetic rather than the data
- the three populations partition a constructed set; 7 unfamilied rows are counted, not dropped;
  none of them reaches the family rate
- a detection-conditioned label is not a family, **its rows are still in the partition total**,
  and it cannot inflate the family counts
- the dispersion detector fires on members sharing no rule, stays silent on members sharing one,
  stays silent below its three-member floor, and needs no reason code to fire

`doc-figures.py --inject` — **24 cases, 24 pass** (14 pre-existing, 10 new): each of the three
family states drifted by one is refused **and named**; the unfamilied count and the bucket count
drifted are each refused and named; the family region with no BEGIN marker is refused; and the
rendered micro average is asserted to agree with the stored rate to the printed decimal.

**The controls were then shown to fail.** A green control that has never said no is not yet a
control, so four mutations were applied to a scratch copy:

| mutation | cases that caught it |
|---|---|
| partial folded into `fully_detected` | 4 |
| macro computed as micro | 2 |
| the detection-conditioned label counted as a family | 5 |
| unfamilied rows swept into the family metric | 3 |

`pre-push-check.py --inject` also passes, including its doc-figures delegation in both
directions.

## 8. Pre-report

All four, all green, after the summary and the documents were regenerated:

```
corpus/shard-gate.py corpus/index.jsonl               PASS
corpus/shard-gate.py corpus/local/index-local.jsonl   PASS
corpus/make-summary.py --check                        PASS  (failing until regenerated)
corpus/doc-figures.py --check                         PASS  (4 regions, incl. family-detection)
```

`make-summary.py --check` failed on **twelve new keys and nothing else** — no existing value
appeared in the drift report, and the regenerated `index-summary.json` is **61 insertions, 0
deletions**. That is the attributed cause for every unmoved figure: nothing moved because
nothing but additions was written.

`verify.py` against `build/lyxbosa`, before and after, identical:

```
Detection    696 / 1299   (53.6%)     shard-run 97/97      Techniques 90 of 123
Regression    97 / 97                 Known misses 603, 0 newly detected
```

`pre-push-check.py` reports SAFE TO PUSH. **Nothing was pushed and no pull request was opened.**

## 9. A figure that was wrong for one regeneration, and how it was caught

The first render of the family region printed the micro average as **14.8%**. The ratio is
105/707 = 14.8515%, which is **14.9%**.

`micro_rate` was stored rounded to 4 places (`0.1485`) and the renderer rounded it again.
Double rounding is a silent one-digit lie, and it had already produced a document disagreeing
with its own prose: the generated table said 14.8% while the paragraph beside it said 14.9%,
both derived from the same key.

Repaired in both places rather than by adjusting the prose: rates are stored to 6 places, and
the rendered micro average is taken from the published integer pair — for which no second
rounding exists — with a control asserting the pair and the stored rate agree to the printed
decimal. The control fails on the old 4-place storage, which is how it is known to be a
control.

The macro average has no integer pair, being a mean of per-family rates, so it is formatted
from the stored value; six places is enough that a second rounding cannot move it.

## 10. What is not in this round

- **No index write.** No family assigned, none corrected. The one label ruled a bucket is
  excluded by a computation over its existing `reason`, not by editing a row; that judgement
  is the operator's and is put to them in the report rather than taken here.
- **No rule change, and no rebuild of `build-release`.**
- **No hand-written figure in any document.** Every family number in `README.md` is inside the
  `family-detection` generated region and defended by `doc-figures.py --check`. The prose
  around it — including the note that family names are **attacker-campaign labels and not
  customer or site identifiers** — is written by a person and survives regeneration.
