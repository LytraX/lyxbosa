# Corpus review round 14 — a fresh measurement for two rulings, a gate for a rule missed twice, and a census that could not see

**Date:** 2026-09-06
**Branch:** `corpus/resign-and-gate` (from `master` at `812fcd6`)
**Scanner:** not run. `LYXBOSA_BIN` was never invoked, `build-release` was not rebuilt, and no
`detection_survived`, `rules_before`, `rules_after` or `measured_with` field moved — censused
before and after every write and byte-identical (134 / 134 / 437 / 8 local-masked).
**Index:** written — local half only, one field removed from 47,133 rows, through
`corpus/indexio.py` under the lock with the re-read inside it.
**Summary:** `make-summary.py --check` passes and never failed this round; no counted quantity
moved, which is asserted by a before/after census diff rather than assumed.
**Pre-report:** all three commands run, all three green. See the end.

**Status: both findings re-measured and unchanged in shape, so the two rulings stand and can be
re-signed against today's digest. The secret-gate finding is presented for ruling, with a
per-shape null that did not exist before. `make-summary --check` is now a gate. The orphan
census was itself blind in two more ways than it declared, and the corrected population is 67,
not 44.**

---

## Headline

> **The census that finds fields nobody writes was the sole claimed writer of three fields it
> had itself recorded as orphans — and it does not print fields it thinks are written.**
>
> `KNOWN` is a dict literal keyed by field name. A dict-literal key is a write position. So
> `evidence_decoded`, `evidence_encoded` and `hidden_by_encoding` — 142 rows each, listed in
> `KNOWN` precisely because an untracked decoder wrote them — were classified `written`, and
> `main()` prints only the states that are not `written`. **The note recording them as orphans
> is what stopped them being reported as orphans.**
>
> Separately, the map heuristic ("more than eight children") classified ten parents as
> value-keyed maps. One was. The nine schema blocks it swallowed include `masking`.

---

## 1. `34bba99dae63` — the two inert clearances, re-measured

### The state, read before acting

Confirmed exactly as briefed, and worth restating because it is the design working:

| | |
|---|---|
| clearance `gate_provenance.tools` | `6fecbeebbccc` (both) |
| current tools digest | `83735611dab4` |
| both clearances | **inert** — the row is not standing on either |
| `publish_blockers` | **three**, not two |

The third blocker is `secret gate did not pass`, added by last round's repair. The digest moved
at `194e969` and nowhere else — measured, not inferred:

```
812fcd6 83735611dab4    d548b3e 6fecbeebbccc
a6ab94e 83735611dab4    fb44507 6fecbeebbccc
194e969 83735611dab4 <- the secret-gate repair    bb1e9f4 6fecbeebbccc
```

**Re-signing the two will not make the row publishable, and that is the correct outcome.** The
third blocker is unruled, and a row with an unruled blocker is not publishable however many of
the other two are cleared.

### The bytes

The staged masked file on disk hashes to `49e5a443f209`, **not** the recorded
`masked_sha256` `6de0931bc28f` — it is from an older masking pass. `restage-masked.py`
regenerated the masked form from the original and it hashes to `6de0931bc28f` exactly, so what
was measured is the file the row stands behind rather than a reconstruction of it. The original
hashes to the row's own `sha256`.

### Both findings, re-measured against today's gate

`remeasure-gates.py` **refuses** the row — "every recorded verdict already agrees with the
current gate" — which is the right refusal and is why the finding profiles are quoted from the
gate directly:

| | recorded on the row | today | |
|---|---|---|---|
| `plaintext_gate` | FAIL | FAIL | agrees |
| `encoded_layer_gate` | FAIL | FAIL | agrees |
| `secret_gate` | FAIL | FAIL | agrees |

**encoded-layer finding — identical in every field:**

| field | recorded | today |
|---|---|---|
| `distinct_identifiers` | 1 | 1 |
| `identifier_lengths` | `[6]` | `[6]` |
| `occurrences` | 1 | 1 |
| `positions` | `["begins"]` | `["begins"]` |
| `segment_lengths` | `[25]` | `[25]` |
| `methods` | `["base64+inflate"]` | `["base64+inflate"]` |

Still the same six-character label at offset 0 of the same 25-character underscore-bounded
segment, in the same decoded layer.

**plaintext finding — identical in every field:**

| field | recorded | today |
|---|---|---|
| `distinct_identifiers` | 1 | 1 |
| `identifier_lengths` | `[3]` | `[3]` |
| `occurrences` | 3 | 3 |
| `positions` | `["contains"]` | `["contains"]` |
| `segment_lengths` | `[19, 70, 74]` | `[19, 70, 74]` |

Still three occurrences of the same three-character identifier.

**Neither finding has changed shape. The rulings transfer on their merits, not by
transplantation** — the reasons were re-derived from a measurement taken today, and this
document is that measurement.

### What DID move, and nothing asked

The secret-gate **evidence** is stale under a **current** stamp:

| | recorded on the row | today |
|---|---|---|
| `secret_literals_before` | 1 | **2** |
| `secret_literals_after` | 1 | **2** |
| `secret_literals_carried_over` | 1 | **2** |
| `masking.provenance.tools` | `83735611dab4` | `83735611dab4` |

Cause, attributed by measurement rather than inference: the pre-repair gate at `d548b3e` was
re-run over the same two files and returns **1 / 1 / 1**, matching the row exactly; the current
gate returns **2 / 2 / 2**. The extra literal is found by `194e969`'s widened
`quoted-credential` keyword alternation.

**Why nothing caught it:** `verify-and-stamp.py` compares gate **verdicts** and stamps
provenance where they agree. `FAIL` did not become `PASS`, so it stamped. `remeasure-gates.py`
compares verdict **classes** and refuses where none moved, so it will not rewrite it. Between
them, a finding payload can go stale under a stamp that certifies it. Neither tool is wrong;
the gap is that no tool compares the *evidence*. Sized below, not repaired this round.

### The new secret-gate finding, for ruling

Both literals are `quoted-credential`, both inside the **same** 119,508-byte `base64+inflate`
layer, both **carried over** (byte-identical before and after masking — the gate fails on
*unchanged*, not on *present*):

| | literal A | literal B |
|---|---|---|
| keyword that fired | `password` | `Password` |
| value length | 8 | 15 |
| value character classes | `aaaaaaaa` | `Aaaaa aaaaaaaa!` |
| contains a space | no | **yes** |
| in the census under | old gate **and** new | **new gate only** |
| surrounding form | `<key>:"<value>"`, unquoted JS object key | same |

Literal A's whole match is 19 bytes in the form `password:"password"` — the jQuery-Terminal UI
label already recorded for this row in `SOURCES.md`. Literal B's neighbours in the same object
are `"Aaaaa aaaaaaaa aaa aaaaa!"` and `"Aaaaa aaaaa aaaaaaaa aaaa aaaa!"`: it is a **message
table**, the key is `<5 lowercase>Password`, and the value is an English prompt ending in `!`.

Literal B exists in the census **only because of the repair**, and specifically because the
repair removed the left boundary so that `$user_password` would be caught. The cost of that
widening is that a camelCase JSON key ending in `Password` now matches too.

### The per-identifier null, which did not exist until this round

`--stock-fp` and `--base-rate` are both nulls for the *identifier* gates. The secret gate had
none, so a row could record `secret_literals_carried_over: 2` with nothing to say whether two
credential-shaped literals in a megabyte of vendored library code is a lot or the number you
get for free. `corpus/secret-fp.py` is that null: the tracked `SECRET_SHAPES` predicate over
stock CMS trees, which carry no customer credential by construction.

It is **not** a flag on `verify-content-mask.py` deliberately — that file is in
`gate_provenance.TOOLS`, and adding a mode to it would move the digest and invalidate every
stamp and both clearances again. A null is a measurement *about* a gate, not part of it.

**32,000 stock files; 161 (0.50%) carry a credential-shaped literal; 343 literals, 230 of them
`quoted-credential`.** Per class:

| class | count | share of the shape |
|---|---|---|
| **literal A** — `kw=password len=8-15 space=no` | **59** | **25.7%** — the single largest class in the null |
| **literal B** — `kw=password len=8-15 space=yes` | **9** | **3.9%** |
| *marginal:* any `quoted-credential` whose value contains a space | 87 | 37.8% |

**State the power.** At 8,000 files this null showed literal B's class at **0 of 109** — which
would have read as the strongest possible evidence and was nothing of the kind. Its 230-literal
population at 32,000 files puts the class at 3.9%, so the expected count at 8,000 files was
~2.8 and P(observing zero) ≈ 6%. A 0 there excluded nothing. **The 8,000-file run had
insufficient power to see this class at all**, and the figure above is quoted from 32,000.

**Both rulings are yours to make.** The measurement says: same shape class as the two you
already ruled on, in the same decoded layer, in a message table, one of them visible only
because the repair widened the keyword — and a stock-CMS null in which that widened class is
25.7% and 3.9% of the shape respectively.

---

## 2. `make-summary.py --check` is now a gate

The rule was in AGENTS.md, annotated with the note that it exists because a round was reported
green while it was failing, and a round was then reported green while it was failing.

`pre-push-check.py` now delegates it the same way it delegates the index question to
`verify-infected-mask` and the gate invariants to `shard-gate`:

```
=== published index, delegated to the tools that own the question ===
  verify-infected-mask x account-mapping.json       PASS
  verify-infected-mask x infected-tree-mapping.json PASS
  shard-gate on the published half              PASS
  make-summary --check on the denominator      PASS
```

**Controls in both directions**, because a delegation that always refuses and one that never
fires look identical from a green run:

```
=== the make-summary delegation, in both directions ===
  a summary that agrees with the index           accepted
  a summary stale by one in cleared_by_human_findings refused
```

The stale case is a **valid, plausible summary wrong by one**, not a malformed file — a broken
JSON would prove only that broken JSON is caught. The control runs against a temp directory of
symlinks to the real index halves with its own copy of the summary, so nothing in the
repository is written; `make-summary.py` locates what it reads from its own `__file__` and
`abspath` does not resolve symlinks, which is what makes that work. The refusal is also
asserted to *name the field that drifted*.

---

## 3. The orphan fields

### The census was blind in two more ways than it declared

The brief said 44 fields and that the tool states the limit that matters. It states one limit;
there are three, and the two it did not state are larger.

**(a) It parsed itself.** `KNOWN` and `REMOVED` are dict literals keyed by field name; a
dict-literal key is a write position. The census was the sole claimed writer of six real index
fields, and `main()` prints only states that are not `written`. Three fields `KNOWN` recorded
**as orphans** were therefore classified covered and never printed:

| field | rows | why it was invisible |
|---|---|---|
| `deobfuscation.evidence_decoded` | 142 | listed in `KNOWN` as a known orphan |
| `deobfuscation.evidence_encoded` | 142 | same |
| `deobfuscation.hidden_by_encoding` | 142 | same |

**(b) The map heuristic was wrong in both directions.** "More than eight distinct children"
classified **ten** parents as value-keyed maps. **One of them was.**

| parent | children | actually |
|---|---|---|
| `masking` | 26 | **schema** — every gate verdict, every finding, `provenance`, `secret_literals` |
| `sensitivity_tagged` | 15 | schema |
| `masking.encoded_layer_finding` | 14 | schema |
| `masking.secret_literals` | 13 | schema |
| `sensitivity_tagged.supersedes` | 13 | schema |
| `deobfuscation` | 12 | schema |
| `fixture` | 12 | schema |
| `media_triage` | 9 | schema |
| `observed_detection` | 9 | schema |
| `placements` | 11 | **a real value-keyed map** |

An orphan anywhere under `masking` was invisible to the tool whose job is finding orphans. It
also over-counted: three value *keys* under `sensitivity_review.adjudication` were reported as
orphan fields because that parent had only four children.

The docstring had **predicted this in words** — "a schema block with nine keys would be misread
as a map" — and then nine were. A declared bound nobody sizes is a bound being carried, not
checked.

**Repaired.** The census excludes itself, and the map test is now what actually separates the
two kinds: schema keys are written by a programmer and are identifiers; value keys are data
labels and are not. Over both halves exactly four parents have any non-identifier child and all
four are real maps (`placements` 10/11, `masking.encoded_regions` 3/3, `masking.not_masked`
2/2, `sensitivity_review.adjudication` 3/4); every other parent's children are identifiers
without exception. Recorded as §11's ninth instance.

| | before | after | cause |
|---|---|---|---|
| fields carried by rows | 135 | **311** | nine schema blocks descended into for the first time; −1 for the field removed below |
| value-keyed maps | 10 | **4** | the identifier test |
| written by a tracked module | 90 | **241** | the schema-block children, most of which do have writers |
| read-only | 1 | **3** | `placements` and `copies_on_disk` gained a tracked reader |
| **ORPHAN** | **44** | **67** | the census could finally see; not a change in the corpus |

### `origin.incident` — 47,133 rows — **dead, and removed**

The field a brief flagged because "a field naming an incident is exactly the shape that has
caught this repository out before." It is the opposite:

| question | answer |
|---|---|
| rows | 47,133 local, **0 published** (`shard-gate` forbids `origin` on a published row) |
| distinct values | **1** — the 8-character constant `INCIDENT`. Zero entropy. |
| what writes it | `trail-data/incoming/2026-09-04/merge-context.py`, untracked, as a **hardcoded string literal**. No data path reaches it. |
| in either pseudonym map? | **no** — neither as a name to mask nor as a replacement |
| a customer identifier by construction? | **no**, and provably: a compile-time literal identical on every row cannot carry one |
| what reads it | **nothing**, across 272 Python files |
| what git can say | **nothing** — the local half is gitignored and the writer is untracked |
| redundant? | completely: `incident` is present *iff* `account_hash` is, so the `origin` key-shape already discriminates the incident tree (47,133) from the legacy tree (1,123) |

Removed with `corpus/drop-field.py --by cl`. Before/after census of every counted quantity in
both halves — rows, `publishable`, verdicts, `detection_survived`, `masking.applied`,
`rules_after`, clearances — is **byte-identical**. 47,133 rows lost exactly that key and nothing
else moved.

**Caveat that belongs on the record:** the untracked writer still emits it, so a future merge
pass will put it back. That is a property of an untracked writer, not of this removal, and it
is why the removal is recorded in `field-provenance.REMOVED` where the next census prints it.

#### The reader search was blind, and had to be redone

The first reader sweep reported "nothing reads it" while unable to see 237 of the 272 Python
files. `grep` in this environment is a shell function wrapping `ugrep --ignore-files`, which
**respects `.gitignore`** — and `trail-data/` is gitignored, so a recursive search from `.`
silently skipped every untracked script, which is exactly where every orphan field's writer has
turned out to live. Redone with `command grep`. The same shape as the `/home/`-not-`/home2/`
regex: a search whose blindness is invisible from its output.

### `placements` — 33,555 rows, 15,674 of them published — **alive, and now has a reader**

Not dead: a histogram of where on a real server the copies of a blob were found, over a closed
vocabulary of 11 English placement labels. No customer identifier — the labels are categories
(`live webroot: plugin or theme directory`, `IR quarantine copy`, …) and the values are counts.

It stands in a checkable relationship to a field that *is* tracked:

```
sum(placements.values()) == count
```

**33,553 of 33,555.** The other two carry `copies_on_disk` instead — an older name for the same
quantity, itself an orphan on exactly those two rows — and it agrees there too, so the
invariant is **33,555 of 33,555 with both names allowed and neither assumed.**

`shard-gate.placementViolations` now asserts it, plus the closed label vocabulary and integer
counts. Nine controls, both directions:

```
  placements summing to count                              clean  ok
  the same total under the older copies_on_disk name       clean  ok
  no placements at all: not this check's business          clean  ok
  placements summing to one less than count                hit    ok
  placements summing to one more than count                hit    ok
  a histogram with no total recorded anywhere              hit    ok
  a label outside the closed vocabulary                    hit    ok
  placements recorded as a list                            hit    ok
  a count that is a bool rather than an int                hit    ok
```

**State the power:** this invariant has never fired in anger. It was written over a population
that already satisfies it on all 33,555 rows, which is exactly the condition AGENTS.md calls
"not yet a check" — hence nine controls rather than a green run.

Two orphans resolved for one invariant: `placements` and `copies_on_disk`.

### The remaining 65, sized rather than triaged

Deliberately not a shallow pass. Grouped by writer, largest first:

| group | fields | rows | what is known |
|---|---|---|---|
| `triage.*` | 10 | 161 | one untracked triage pass; `upstream_differential` is a 4-field sub-block |
| `deobfuscation.*` | 8 | 46–229 | the second untracked decoder; 3 of these were the ones `KNOWN` hid |
| `fixture.*` | 10 | 7 (**published**) | published-shard fixture provenance; `fixture` itself is already read-only |
| `sensitivity_evidence.*` | 10 | 1–685 | `home_paths` and `mapped_name` **checked: booleans, not content** |
| `sensitivity_review.*` | 3 | 68–82 | the adjudication map is now correctly a map, not 3 fields |
| `prior_corpus{,.tier}` | 2 | 2,494 | the largest untriaged pair |
| `masking.encoded_layer_finding.*` | 5 | 2 (**published**) | see below |
| singletons | 17 | 1–46 | `ioc`, `campaign_marker`, `staging_dir`, `expect_provenance`, … |

**One of these was checked immediately because it is published and looked like a leak.**
`masking.encoded_layer_finding.value` is a 58-character string on two `publishable: true` rows,
inside a finding whose own note says *"identifier names deliberately not recorded here; they are
the thing being masked"*. Measured: it is **English prose**, 56 characters, word-shaped, and the
leak predicate returns **no hit** against either pseudonym map. Not a leak.

But those two rows carry `decision: "held for human confirmation; not published until
resolved"` **while `publishable: true`**. That reads as an open blocker and is not one — the
sibling `resolution` records the human confirmation (address adjudicated attacker-owned, kept
as an IOC per §4.1, `c2` is never masked). **Sized, not fixed:** nothing tracked reads either
field, so a row carrying `decision` *without* `resolution` would look identical and nothing
would notice. That is a one-invariant repair for next round.

**Not touched, by decision:** `c24465d301e2`'s `pii` and `1438674b06d8`'s `c2` remain open and
unresolved. Neither was read, written, or closed by this pass.

---

## 4. Controls

Every check added this round ships its control in the same commit.

| tool | controls | result |
|---|---|---|
| `corpus/secret-fp.py` (new) | 14 | all pass |
| `corpus/drop-field.py` (new) | 19 | all pass |
| `corpus/field-provenance.py` | 21 → **32** | all pass |
| `corpus/shard-gate.py` | +9 for `placements` | all pass |
| `corpus/pre-push-check.py` | +2, both directions | all pass |

**One control failed usefully and is worth recording.** `drop-field.py`'s first fixture used
`origin.incident` — the field it was written to remove — as a dict key. `field-provenance`
promptly reported that field as **written, by `drop-field.py`**, and the tool's own guard then
refused to remove it. The control poisoned the census its guard consults. That is the same
defect as (a) above, arriving from the other side within the same round, and the fixture now
uses a name no row carries.

---

## 5. Pre-report

```
python3 corpus/shard-gate.py corpus/index.jsonl               exit 0
python3 corpus/shard-gate.py corpus/local/index-local.jsonl   exit 0
python3 corpus/make-summary.py --check                        exit 0  "agrees with the index"
python3 corpus/pre-push-check.py                              exit 0  SAFE TO PUSH
```

`make-summary --check` did **not** fail at any point this round: the only index write removed a
field that no summary quantity counts, and the before/after census diff is empty.

**No detection figure moved.** None was measured — the scanner was never invoked.
