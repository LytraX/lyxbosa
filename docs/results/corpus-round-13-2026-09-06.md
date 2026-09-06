# Corpus review round 13 — the five taggings, and two tools that asked a three-gate question about two gates

**Date:** 2026-09-06
**Branch:** `corpus/tag-the-five` (from `master` at `bb1e9f4`)
**Scanner:** not run. `LYXBOSA_BIN` was never invoked, `build-release` was not rebuilt, and no
`detection_survived`, `rules_before`, `rules_after` or `measured_with` field moved — counts
re-censused after every write and identical to before (294 / 134 / 134 / 132).
**Index:** written. Both halves, and every write went through `corpus/indexio.py` under the lock.
**Summary:** `corpus/index-summary.json` regenerated; `make-summary.py --check` was **failing**
until it was, and is now on the pre-report list in AGENTS.md alongside the two `shard-gate` runs.

**Status: all five taggings written with their evidence and their cause on the rows; the four
archives carry `not_applicable_reason` from a tracked tool; the gate's two credential
narrownesses are repaired and the 140-stamp bill paid in full; the second decoder is tracked
and reconciled. Three things in the brief were wrong and the measurements are below.**

---

## Headline

> **The gate repair found four more publishable rows carrying a credential, and only one of
> them was in the population that was searched for them.**
>
> Last round decomposed nine rows into "five name-only, four a real divergence". The nine were
> selected by a predicate beginning *carries the `secret` tag* — written by the rule whose
> blindness was that round's subject. Repaired and re-measured over 132 rows: **six** move
> `PASS` → `FAIL`, **four were `publishable: true`**, and three of those four are tagged
> `clean`, `c2` and `c2,identity` — none of which demands a secret gate at all.

---

## What the brief got wrong, with the measurements

### 1. Two of the "four real divergences" are not divergences

> "Expect the four real divergences among the nine vacuous passes to move."

Two moved. Two cannot, and the reason is that there is nothing there:

```
24d902d48a0d and bba931abc09d
  -----BEGIN [A-Z ]*PRIVATE KEY-----  occurrences : 34   (33 RSA, 1 unqualified)
  -----END   [A-Z ]*PRIVATE KEY-----  occurrences :  0
  line prefix before the marker, by count:
     "the headers, e.g. `"   16
     "key. For example, `"   16
     "$privateKey = '"        1
     (indent only)            1
```

Both files are ~8–12 MB scan reports quoting a vendor crypto library's docblocks. 32 of the 34
markers are documentation prose; there is no `END` marker and no key body anywhere in either
file. **`private-key` on those rows is a name-only match in fact**, whatever `SHAPE_KIND` says
about the pattern. The PEM shape added this round therefore requires a *complete* block —
opening marker, at least one base64 body line, closing marker — precisely so it does not fail
two rows on their own documentation. A header-only shape would have been a flood, not a gate.

The nine decompose **5 name-only / 2 real / 2 documentation**, not 5 / 4.

### 2. Four movers were outside the population, and the population was the defect

The brief inherits "the four real divergences among the nine". Measured over every row whose
before/after bytes could be produced (132 of 142):

| row | `publishable` before | tags | recorded | today |
|---|---|---|---|---|
| `162ccc9adf4e` | **true** | `c2`,`secret` | PASS 0/0 | **FAIL** 1/1, 1 carried |
| `fa4356393880` | **true** | `clean` | PASS 0/0 | **FAIL** 1/1, 1 carried |
| `b839772db7c7` | **true** | `c2` | PASS 2/2 | **FAIL** 3/3, 1 carried |
| `91d2ee9cdd6d` | **true** | `c2`,`identity` | PASS 0/0 | **FAIL** 2/2, 2 carried |
| `e29dba8fde17` | false | `secret` | PASS 0/0 | **FAIL** 1/1, 1 carried |
| `47e9334ce266` | false | `c2`,`secret` | PASS **2/2** | **FAIL** 3/3, 1 carried |

`47e9334ce266` never had zero literals — it passed over two while a third was invisible — so
the "zero literals" half of the predicate could not see it either. `fa4356393880` is tagged
`clean` and is a same-size sibling of `e29dba8fde17`, which is tagged `secret`: the same
credential, on two rows, one of which the search could see.

This is CORPUS_PLAN §11's **eighth appearance**, and the sharpest: the enumerating process and
the defective process are the same function. Recorded there.

### 3. The `not_applicable_reason` writer cannot be brought in — it was never saved

> "Bring the writer in the way `sensitivity.py` was brought in last round, or write the four
> with a tracked tool."

There is one arm to that choice, and the difference between this case and `sensitivity.py` is
worth more than either case:

```
grep -rl not_applicable --include=*.py <the whole tree>   -> only corpus/, all readers
git log --diff-filter=A -- corpus/mask-samples.py         -> 9e0914e, 2026-09-05
the 29 rows first appear in                                  the 2026-09-04 snapshot
```

`sensitivity.py` and `deobfuscate.py` are untracked *files that still exist* — readable,
hashable, runnable, and both are now reproduced with behavioural-equality controls. This
field's author is not a file at all: it was an uncommitted state of `mask-samples.py` a day
before that file's first commit, and nothing kept it. So `corpus/mark-not-maskable.py`
re-derives the **claim** — container magic from the bytes — rather than the writer.

**Three conditions hide under "the author is not in the repository", and they need different
repairs.** That is the generalisation the brief asked for, and `corpus/field-provenance.py` is
what tells them apart mechanically.

---

## Job 1 — the five taggings

Written by `corpus/tag-sensitivity.py` from a signed decision file, with the bytes hash-verified
against each row's `sha256` before anything was read.

```
row            was      becomes                       adds                         held/rejected
cd98180175a5   clean    path                          path                         -
eba16e1e9159   clean    c2,identity                   c2,identity                  -
e50d85a3a815   clean    c2,identity,path,pii,secret   c2,identity,path,pii,secret  -
c24465d301e2   clean    c2,identity                   c2,identity                  rejected=pii
1438674b06d8   clean    identity                      identity                     held=c2 rejected=pii
```

The tool writes a **ruling**, and the three refusals are what make it one:

* a tag may not be added unless `classify_deep` over the row's own bytes also produces it,
  unless the ruling names a `human` basis;
* every tag the re-derivation *does* produce must be adjudicated — added, rejected or held —
  and a silent pass over one is refused. Silence is what put these rows at `clean`;
* the bytes question has three answers, and `unavailable` refuses the write rather than
  passing quietly.

32 control cases, and it refused the fifth row on the live archive run because a PHP file is
not a container — a positive control that fired on real data rather than a fixture.

### The evidence that exists nowhere else

`1438674b06d8` is a 5,027,840-byte tar inside a gzip, 256 members:

```
distinct uname / gname          : 1 / 1, equal, 8 characters, an exact map identifier
distinct (uid, gid) pairs       : 1
members whose PATH contains it  : 0
members whose BODY contains it  : 0
```

**A member-level content scan sees nothing.** Only the container's own metadata carries the
account name, and §5.5 forbids touching the container, so this is invisible to masking by
construction. It is now on the row.

The same row records that the *rule's* reason for its `identity` tag is a different one and is
wrong: `classify()` fires on 81 e-mail shapes across 44 domains, **0 on a customer domain**.
Right tag, false evidence — which is exactly why the evidence is written down.

### `1438674b06d8`'s `c2`: unresolved, tag left off, evidence brought

Measured rather than deferred a second time:

```
C2_HINTS markers firing anywhere in the archive : 0 of 5
  telegram 0 · gsocket 0 · raw-paste-host 0 · tor 0 · tunnel 0
external hosts : 73        customer hosts : 0
matching a public-infrastructure keyword list : 17
   php.net, bugs.php.net, wordpress.org, github.com, developer.mozilla.org, www.w3.org,
   httpd.apache.org, www.gnu.org, opensource.org, cdnjs.cloudflare.com, cdn.jsdelivr.net,
   docs.google.com, drive.google.com, maps.googleapis.com, www.googleapis.com, …
all 73 occur in member bodies of one upstream file-manager plugin (elFinder volume drivers
for Dropbox / Google Drive / OneDrive / Box / FTP, and its documentation)
members containing eval / base64_decode / a superglobal read : 14, every one an upstream
   cloud-storage driver
```

**Ruled 2026-09-06: leave it off**, and recorded as a rule rather than a row decision.

> **`c2` requires evidence of attacker control, never the presence of an external host.**
> The tag is in `shard-gate.ALWAYS_OK`, so applying it is not a description of the sample — it
> buys a free pass through every masking gate. A tag that grants an exemption has to be earned
> by positive evidence. "An external host inside a malicious archive" is guilt by containment,
> the same reasoning that produced the retracted `identity` on a Cloudflare footer template's
> resolver address.

In CORPUS_PLAN §4.1, on the row (`corpus/taggings/2026-09-06-c2-ruling.json`), and in
`sensitivity.py`'s docstring, which now says its `external-host` branch produces a *proposal* a
person must add, reject or hold. `classify()` itself is unchanged — repairing it would move tag
counts on 791 rows nobody has re-read.

*(Last round's report said 20 of 73 were public infrastructure; this run's keyword list matches
17. The difference is the list, not the data — a judgement list either way, which is why the
hosts are named rather than only counted.)*

### One correction to last round's write-up

`c24465d301e2` was recorded as carrying "one customer-domain e-mail". Re-measured: 1 distinct
e-mail shape, 2 occurrences, and its domain is **not** a customer domain. `identity` stands on
the customer host, which is unaffected.

### Writing that ruling broke two things, and both are repaired with controls

**A later ruling erased the record it amended.** `build()` wrote a fresh `sensitivity_tagged`,
so applying the ruling took the tar-header finding — the measurement that exists nowhere else,
and the one this brief specifically asked to be put on the row — straight back off it. Repaired:
prior `evidence` and `human_basis` carry forward with the new ruling winning per key, the
superseded record is kept whole under `supersedes`, `originally` carries the pre-first-ruling
tags past a one-level chain, and **`assert_additive` refuses any write that drops a recorded
evidence key** — the check that would have caught it.

**A ruling that changes no tag could not be written at all.** The tool refused it as "nothing
would move", which would have left the row reading `UNRESOLVED` after a person had ruled — the
stale-record defect this corpus keeps finding, in the one field whose whole purpose is to say
what a human decided. Closing a hold is now a legitimate write, and `--restate` re-derives a
record from a decision file it *already agrees with*: it may change no ruling and must add
something.

**The residual is recorded, not papered over.** The row's top record now reads
`was: ["identity"]` / `originally: ["identity"]`; the literal `was: ["clean"]` from the first
write is gone, destroyed before the repair existed. What survives is the substantive fact —
`derived.raw_tags: ["clean"]`, the machine reading over the bytes — plus the `cause`, the
tar-header evidence and the superseded record. The fix stops it recurring; it does not undo it.

Controls on `tag-sensitivity.py`: **32 → 56 cases.**

---

## Job 2 — the four archives, and the pattern behind them

`corpus/mark-not-maskable.py` wrote `applied: false` + `not_applicable_reason` + a
`not_applicable` block naming the author, the moment, the container magic re-read from the
bytes (`gzip` ×4) and the sha256 it read them from. It writes **none** of the seven other
masking keys the 29 legacy rows carry — those are measurements it did not take, and copying
them to make the populations look alike would be manufacturing one. `--census` prints both
shapes on every run.

**It cleared no blocker, and 0 rows moved.** `shard-gate`'s "carries *tag* but no masking has
been applied" is driven by `applied`, so an archive carrying an unmaskable identifier is
permanently unpublishable. That is the correct end state, not outstanding work.

### The census that generalises it

`corpus/field-provenance.py`, over both halves and every tracked module:

```
fields carried by rows        135   (9 value-keyed maps not descended into)
  written by a tracked module  89
  only READ by tracked modules  1
  mentioned nowhere            45
```

**45, not three.** The check parses rather than greps, because the distinction *is* the
subject: `mask-samples.py` contains the literal `not_applicable_reason` on line 393, so a grep
census would have reported that field covered while the defect stayed open — asserted in
`--inject`. `written` over-counts, so `ORPHAN` under-counts: every field it names is really
unaccounted for and there may be more.

Both denominators are bounded by their own process and both are printed: fields are enumerated
**from the rows**, so a field every row has lost is invisible — `masking.encoded_layer_gate_uncapped`
was an orphan on 3 rows when `stamp-legacy.py` was written and is on **0** today.

---

## Job 3 — the gate's two narrownesses, and what the digest movement cost

Measured before arming, as required. The repair, both in `verify-content-mask.SECRET_SHAPES`:

* `quoted-credential` loses its left lookbehind and gains `pwd`. For a **differential** gate
  over-matching is the strict direction, so widening cannot make it laxer.
* `pem-private-key` is added and requires a complete block (see §1 above).

`gate_provenance.tools_digest()` **`6fecbeebbccc` → `83735611dab4`**; only
`verify-content-mask.py`'s module digest moved (`ab45036412ff` → `c3c76c82735c`).

### The bill, itemised

| | |
|---|---|
| stamped rows invalidated | 140 |
| masked bytes surviving on disk | 73 |
| masked bytes **regenerated and hash-verified** from originals | 132 of 142 |
| ↳ regeneration mismatches (not staged, reported) | 3 |
| ↳ rows recording no `masked_sha256` to check against | 7 |
| rows re-stamped | 139 (7 published, 132 local) |
| rows left `stale` | 1 published (`3529f0f6b2cd`), no reachable bytes; already blocked |
| rows that lost `publishable` for the length of a commit | 34 |
| human clearances made inert | 2, both on `34bba99dae63`, exactly as designed |

`corpus/restage-masked.py` is what kept this from being a 69-row regression.
`content_mask.mask_sample` is deterministic in (bytes, map, vocabulary, flags), so the masked
form can be regenerated and then **checked against the `masked_sha256` the row already
records**: a regenerated file that hashes to it is not a plausible reconstruction, it is the
same file. One attempt with the driver's default flags; a mismatch is a finding about the row,
never retried under other flags — a tool that searched until something matched would
manufacture the provenance claim it was asked to check.

### The defect the repair exposed in the stamping tools

`verify-and-stamp.reverify()` re-ran **two** of the three gates its stamp claims.
`secret_gate` is produced by `verify-content-mask.secret_gate`, a `TOOLS` module, so the stamp
always covered it — and the digest moved for a change to exactly the verdict the tool could not
see. Without repairing this first, the re-stamp would have written a fresh stamp over six rows
whose recorded `secret_gate` the current tools do **not** produce. `remeasure-gates.py` had the
same hole and its comment said so out loud ("the secret gate is a differential over bytes this
tool is not given").

Both now take the pre-masking bytes and answer **`agrees` / `disagrees` / `cannot-check`**. The
third state is not decoration: a row nobody could measure and a row that disagrees need
different work, and it refuses rather than stamping on two thirds of a record.

### Verdict or evidence, per row

| row | the repair changes |
|---|---|
| `162ccc9adf4e` | **the verdict.** `PASS` → `FAIL`, and it was `publishable: true`. |
| `fa4356393880` | **the verdict.** `publishable: true`, tagged `clean`. |
| `b839772db7c7` | **the verdict.** `publishable: true`, tagged `c2` — a tag that demands nothing. |
| `91d2ee9cdd6d` | **the verdict.** Was publishable until the digest moved. |
| `e29dba8fde17` | **the verdict**, on a row already blocked as unreviewed. |
| `47e9334ce266` | **the verdict**, on a row already blocked. |
| `80d78e0b4ece`, `a0830cd1a181` | **evidence only.** Already `FAIL`; carried literals 1 → 6. |
| `24d902d48a0d`, `bba931abc09d` | **nothing.** No key body to see — §1. |

**Power.** 132 rows record a `secret_gate`; after regeneration, before/after bytes exist for
132 of the 142 masked rows, so this is a near-census rather than the 64-of-132 the surviving
stage directories alone would have allowed. Ten rows are outside it. At the observed rate — 6
movements in 132 — one further movement among those ten would not be surprising.

---

## Job 4 — the second decoder, tracked and reconciled

`corpus/deobfuscate.py` reproduces the untracked recorder that wrote `decoded_form_tags` on 142
rows. `--inject` asserts **behavioural equality over 11 probes** carrying no customer
identifier, plus the negative half (the probes are not all empty, which a do-nothing
reproduction would satisfy). `--verify-reference` reports `ok` / `moved` / `absent`.

`METHOD_ALIASES` states the vocabulary correspondence, and the disagreement is not only naming:

```
hex-escape + octal-escape  ->  escape        two recorder names, one tracked name
rot13                      ->  (none)        a branch the gate's decoder does not have
(none)                     <-  raw-inflate   the tracked decoder finds a zlib/gzip stream
                                             anywhere; the recorder only inflates what
                                             base64 produced - so every gzip container in
                                             the corpus is a layer to one and nothing to
                                             the other

thresholds:  base64 {40,} vs {16,} · hex-string quoted {40,} vs unquoted {24,}
             chr() {4,} vs {6,} · texty >0.85 vs >0.80 · depth 6 vs 4
             the recorder does not de-duplicate layers by content; the tracked one does
```

Measured on the **8 of 142** rows whose bytes are reachable here: 357 recorder layers against
380 tracked; `hex-escape` 304 + `octal-escape` 12 against `escape` 337; the two layer counts
agree on **2 of 8**. A sample of 8 in 142 detects a discrepancy present on 10% of rows only
57% of the time — what these 8 establish is that the disagreement is common, not what its rate
is.

### The `TOOLS` question, argued rather than inherited

**The case for including it is real and is not last round's case.** `sensitivity.py` was kept
out because "a tagger produces no gate verdict"; a decoder is not a tagger. The encoded-layer
gate *is* a decoder plus a predicate, `secret_gate` counts literals over decoded layers, and
§5.4 exists because an identifier inside an encoded layer is what makes a sample unpublishable.

**Measured, the premise is false for this module.** Every `decode_layers` call in the gate path
resolves to `verify-content-mask.decode_layers`, which is *already* in `TOOLS`. Nothing in
`corpus/` reads `deobfuscation` except `adopt-decoded-tags.py`, which writes `sensitivity` — a
publish blocker, not a gate verdict.

`TOOLS` is not a list of important modules; it is the claim that editing a file invalidates
stored gate verdicts. This round priced that claim: 140 stamps, 132 regenerated files, 34 rows
briefly unpublishable, two clearances inert. Spending it on a module that cannot alter one of
those four verdicts would make the digest the thing people route around, which is how a check
stops being a check.

And `TOOLS` would not detect the actual hazard. It would say *the decoder changed*; it would
never say *the two decoders disagree*. That is what `--reconcile` measures, and it is the check
this module needed.

**Kept out, with its own `digest()`, an explicit alias table, and a divergence check that runs.**

---

## Every count difference, with its cause

| figure | before | after | cause |
|---|---|---|---|
| local `publishable` | 373 | **364** | −5 the five taggings (each row now carries a tag outside `ALWAYS_OK` with no masking possible or applied); −4 the secret-gate re-measurement (`162ccc9adf4e`, `fa4356393880`, `b839772db7c7`, `91d2ee9cdd6d`) |
| published `publishable` | 44,543 | 44,543 | **unchanged, and it carries a cause**: the seven published rows whose bytes were reachable were re-stamped, and the eighth (`3529f0f6b2cd`) was already blocked on `encoded-layer gate did not pass`, so its new provenance blocker adds a reason and not a status |
| `sensitivity` `clean` | 45,242 | 45,237 | −5, the five rows |
| `identity` / `c2` / `path` / `pii` / `secret` | 287 / 788 / 46 / 178 / 92 | 291 / 791 / 48 / 179 / 93 | +4 / +3 / +2 / +1 / +1 from the taggings, per the table above |
| `masking.applied` | 294 | 298 | +4, the four archives at `applied: false` |
| `masking.not_applicable_reason` | 29 | 33 | +4, same rows |
| `masking.not_applicable` | 0 | 4 | new key, written only by `mark-not-maskable.py` |
| `masking.provenance` | 140 | 142 | +2, the two rows that had `absent` provenance were stamped for the first time |
| `masking.remeasured` | 1 | 7 | +6, the six moved secret verdicts |
| `gate_provenance.tools_digest()` | `6fecbeebbccc` | `83735611dab4` | the PEM shape and the widened `quoted-credential`, both in `verify-content-mask.py` |
| masked rows by provenance, local | ok 132 / absent 2 | **ok 134** | regeneration + re-stamp |
| masked rows by provenance, published | ok 8 | ok 7 / stale 1 | `3529f0f6b2cd` has no reachable bytes |
| human clearances applying | 2 | **0** | the digest moved; a clearance is pinned to the tools that produced the finding it judges, and both went inert exactly as the mechanism requires. Reported on every run, not failed on |
| rows blocked on `secret gate did not pass` | 5 | 11 | +6, the re-measurement |
| `detection_survived` / `rules_before` / `rules_after` / `measured_with` | 294 / 134 / 134 / 132 | 294 / 134 / 134 / 132 | **unchanged.** No scanner ran; every write asserted its own scope and the census was retaken afterwards |
| index rows, either half | 44,544 / 48,256 | 44,544 / 48,256 | no row added or removed; every writer asserts the count |
| `index-summary.json` vs the index | **disagreeing** | agreeing | regenerated. `local_only_publishable_no_blocker` 373 → 364, `cleared_by_human_rows` 1 → 0, `cleared_by_human_findings` 2 → 0, `sensitivity_tags` per the rows above. `make-summary.py --check` exits 0 |
| tracked files scanned by `pre-push-check.py` | 187 | **196** | 5 new modules, 2 decision files, 1 report. All PASS |
| stale rows (over / under / drift), both halves | 0 / 0 / 0 | 0 / 0 / 0 | `shard-gate --fix` run after every write, then a plain run for the green result |

**A count that did not change and carries a cause:** the 29 legacy `not_applicable_reason` rows
are untouched. `mark-not-maskable.py` refuses a row that already has a masking block, so it
cannot rewrite them, and `stamp-legacy.py`'s re-verification of those 29 still stands.

---

## Controls, all run before the green results were trusted

```
corpus/tag-sensitivity.py    --inject   56 cases    corpus/gate_provenance.py --inject   20
corpus/mark-not-maskable.py  --inject   24          corpus/digest-controls.py --inject    8
corpus/field-provenance.py   --inject   21          corpus/remeasure-gates.py --inject   26
corpus/restage-masked.py     --inject   10          corpus/verify-and-stamp.py --inject  14
corpus/deobfuscate.py        --inject   24          corpus/clearance.py    --selftest    31
corpus/sensitivity.py        --inject   all passed  corpus/clear-finding.py --inject     19
corpus/shard-gate.py         --inject   61          corpus/adopt-decoded-tags.py --inject 19
corpus/verify-content-mask.py --inject  rc=0        corpus/stamp-legacy.py --inject       4
corpus/make-summary.py       --inject    9          corpus/make-summary.py --check   exit 0
corpus/pre-push-check.py                SAFE TO PUSH · --inject: plant caught, English silent
```

Every new check ships with its control in the same commit. The ones that matter most are the
negative halves: `pem-private-key` must **not** fire on a documentation marker;
`field-provenance` must **not** count a `.get()` as a write; `restage-masked` must **not**
retry under other flags; `tag-sensitivity` must **not** write a tag the bytes do not support.

---

## A process failure worth naming

`make-summary.py --check` was the one gate not run before this round was first reported green,
and it was failing. It is the authority on whether the summary still describes the index, and
the summary is the denominator every suite run quotes — so a round that moves rows and does not
regenerate it leaves a published file asserting counts that no longer exist. Neither
`shard-gate` run can see that: they read the index, not the summary. It is now on a **Before you
report a round green** list in AGENTS.md with the two gate runs.

Separately, `make-summary.py --help` performed a write. The dispatch was
`if "--check" in sys.argv: … else: write`, so any argument it did not recognise reached the
write path — the one irreversible thing the tool does was what it did when asked a question.
Repaired with a nine-case control, including `[]` still meaning *write*, because a dispatch that
errored on everything would pass a suite made only of negatives.

## What is deliberately not done

* **`cd98180175a5` is not masked.** It is the one of the five §5.5 does not exclude, so a
  masking pass is genuinely owed and it keeps `carries path but no masking has been applied`.
* **`3529f0f6b2cd` keeps a stale stamp.** Its bytes are not on this machine in any form that
  hashes to what it records. It was already unpublishable.
* **`34bba99dae63`'s two clearances are inert and were not re-signed.** Re-signing is a human
  judgement about findings measured by the new tools, not a repair.
* **`identity`-on-any-email and `c2`-on-any-external-host are still not fixed.** Both would
  move tag counts on thousands of rows nobody has re-read. `1438674b06d8` is now a worked
  example of the first on the row itself.
* **The 45 orphan fields are counted, not adopted.** The census is the deliverable; deciding
  each one is a round of its own.
* **`decoded_form_tags` is not re-derived.** 8 of 142 rows have reachable bytes; a
  re-derivation from that sample would replace a decoder-bounded figure with a
  sample-bounded one.
