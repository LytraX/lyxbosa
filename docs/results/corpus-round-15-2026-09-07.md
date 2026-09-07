# Corpus review round 15 — two masks attempted and both refused, a stamp that could not reach the rows it was written for, and eight archives that never rebuilt to themselves

**Date:** 2026-09-07
**Branch:** `corpus/clear-for-publication` (from `master` at `871de14`)
**Scanner:** run, read-only. `LYXBOSA_BIN=build-release/lyxbosa`, sha256 `4c3e0af08988`,
unchanged on disk since 2026-09-05 14:52. `build-release` was **not** rebuilt.
**Index:** written — published half only, 134 rows touched across four passes, every write
through `corpus/indexio.py` under the lock with the re-read inside it.
**Summary:** regenerated. `make-summary.py --check` **was failing until it was**; six figures
moved and each has a cause below.
**Shards:** all eight rebuilt. All eight hashes changed.
**Pre-report:** all four commands run, all four green. See §9.

**Status: both ambiguous findings were put to the masker and the masker refused both, for two
different reasons — so both files are dropped rather than cleared, and no probability decided
anything. The census that printed five findings prints zero. Nothing was uploaded and no
release was created; the upload command is at §8 and is the operator's act.**

---

## Headline

> **`verify-and-stamp.py` skipped every row it was written to stamp.** Its loop opened with
> `if not m.get("applied"): continue` — a claim about whether the *masker changed bytes* —
> while a stamp certifies a *gate verdict*. 123 published rows record `plaintext_gate: PASS`
> and `encoded_layer_gate: PASS` with `applied: false` and the reason *"no identifier to mask:
> the independent gate found none"*. A gate that ran, over bytes that ship, producing a
> published claim nothing dated. The tool could not see one of them.
>
> That is §7.2's own correction — *whether the evidence is READ must not depend on the claim it
> might contradict* — arriving in the tool that **writes** the record rather than the one that
> reads it. And it is not hypothetical: `a3edd57e2ceb` is in that population, it is the one row
> anybody re-measured by hand, and its recorded PASS is a **FAIL** on the bytes in the tar.

---

## 1. The two adjudications: attempted, refused, dropped

The ruling was *do not adjudicate what you can mask*, so the mask was attempted first, with
`corpus/mask-samples.py` against both pseudonym maps and the stock-CMS collision vocabulary.
**Both were refused, and the two refusals are not the same refusal.**

### `a3edd57e2ceb` — `otykhyc.gif`, `malicious-staging-001` — **DROPPED**

The 4-character `contains` hit inside the 16-character segment at offset 20,902.

The segment sits inside a 66-character run at `[20853, 20919)` that `content_mask.B64_RUN`
(`[A-Za-z0-9+/]{24,}={0,2}`) **does** match. So the masker reaches the region in the only sense
its regex can. Then:

```
region length 66, ending in a single '='  ->  65 data characters
base64.b64decode(region + '==', validate=True)
  ValueError: number of data characters (65) cannot be 1 more than a multiple of 4
```

65 is not a valid base64 payload length. `mask_encoded_layers` takes the bare
`except Exception: continue` — the branch commented *"not base64 at all; an ordinary
alphanumeric run"* — and does not even emit a report entry. **This is not an encoded layer.**
It is a run of characters that happen to be in the base64 alphabet, inside a file whose real
payload is `strtr+base64` elsewhere.

§5.4's relaxation does not apply, and not marginally: the relaxation's *first* per-region
condition is that the region decodes, and the second is that this encoder reproduces it byte
for byte. Condition one fails outright.

The full masker run confirms it end to end rather than by reading the source:

| | |
|---|---|
| `changes` | **0** |
| output sha256 | `a3edd57e2ceb…` — byte-identical to the input |
| encoded regions acted on | **0** |
| encoded regions reported | 4,089, every one `alphanumeric-run-not-a-layer: left-unmasked` |
| `plaintext_gate` after | **FAIL**, same finding: 1 identifier, length 4, `contains`, 16-character segment |
| detection parity | held — `OBF041` before and after (of a mask that changed nothing) |

**What the shard loses.** `malicious-staging-001` goes from 67 members to 66. The dropped
sample is one of **40** members carrying `must_detect: ["OBF041"]`, all of the same family
`fake-plugin-image-payload-loader`, which has 52 members in the shard; **39 remain**. Measured
against the rest of the shard, the set of techniques the dropped sample carries that no
remaining member carries is **empty**. A polymorphic sibling does not merely cover the
technique — thirty-nine of them do, in the same shard, asserting the same rule.

### `3529f0f6b2cd` — `hex-digest-wrapper-outside-webroot-a`, `malicious-outside-webroot-001` — **DROPPED**

The 3-character `contains` hit inside the 97-character segment.

This one is the opposite shape, and it is worth stating precisely because it is the more
interesting refusal. The outer region is `[5751, 137051)` — 131,300 base64 characters — and it
**passes every condition §5.4 names**: it decodes, and `base64.b64encode(decode(r)) == r`
exactly, padded. The masker reaches this region in full. It decodes it to 98,473 bytes, applies
the plaintext masker to the decoded text, and gets back exactly what it put in — so
`masked == decoded`, the region is passed over, and nothing is spliced.

The reason it gets back what it put in is the same measurement that makes the finding a
probable coincidence. The hit is at offset 73,227 of the decoded layer, inside a 97-character
mixed-case alphanumeric run, with a **digit on each side**. `incident_mask.tiers()` demotes a
three-character name to positional masking, because unrestricted containment on names that
short reports one of them 49,292 times and another 31,089 times across this corpus. The gate,
which is deliberately wider than the masker, counts a short identifier as a hit when neither
neighbour is *alphabetic* — a digit is not — and so it fires where the masker will not
substitute.

**So the region is maskable and the finding is not reachable by masking.** Not for want of a
decoder: for want of anything the masker is willing to call an occurrence.

The obvious repair is the one that must not be made. Widening `content_mask.py` to substitute a
3-character token inside a random 97-character run is exactly the over-matching §5.6 forbids in
sample bytes — *"an unrelated token rewritten inside working code is a corrupted sample, and a
corrupted sample that still detects passes every gate"* — and `content_mask.py` is one of the
six modules in `gate_provenance.TOOLS`, so the edit would also invalidate all 142 provenance
stamps and every clearance keyed to them.

Masker run: `changes: 8`, `encoded_layer_gate: FAIL`, finding identical in every field
(1 identifier, length 3, `contains`, 97-character segment, method `base64`).

**What the shard loses.** `malicious-outside-webroot-001` goes from **2 members to 1**. The
survivor is the polymorphic sibling `37927df458e5` (`-b`), and the comparison is exact: the two
carry **identical technique lists** — all eight, including `polymorphic-sibling` itself — and
the set of techniques lost is **empty**. Both are `known_miss: true` with `must_detect: []`; no
rule fires on either, which is what KNOWN_ISSUES issue 3 rests on. So the shard's *detection*
content is unchanged and the issue now rests on one sample rather than two. `-b` is
`publishable: true` with `plaintext_gate: PASS` and `encoded_layer_gate: PASS`.

### The statistics, and why they decided nothing

The applicable figure is the **corpus-wide P ≈ 21%**. The per-file 2.5% is not quoted anywhere
in this round and is not quoted here: 142 files were scanned and the probability was computed
for the most extreme one *after* seeing it, which is §11 in its purest form — a denominator
chosen by the process that produced the numerator, turning a one-in-five coincidence into an
apparent one-in-forty.

At 21% under the null, a 4-character token carrying no identifying information is a collision,
and the 3-character one has been ruled a collision twice. **Both readings still stand and
neither was acted on.** The mask was attempted first; it failed; the ruling on a region that
cannot be masked is to drop the file. Two samples out of 142 is a cost of 1.4%, it costs zero
technique coverage and one of forty OBF041 assertions, and publication cannot be undone. The
probability is recorded because it is the honest reading of the finding, not because anything
was decided on it.

### Not a byte was reachable by regeneration, and that is already known

Worth recording so the next round does not rediscover it as news. `3529f0f6b2cd`'s shipped
masked bytes (`782a8924be8a`, `changes: 4`) are **not regenerable** by today's masker, which
returns `b2609ff65bd1` with `changes: 8`. That is not new drift: `restage-masked.regenerate`'s
own docstring records it — *"the two rows recording `changes: 4` that also lack a hash produce
8 changes today and are refused here exactly as they should be"* — and the row was resolved by
`--found` rather than by regeneration. The sibling `-b` behaves identically (`f0c984de49e8`
recorded, `7f120df62f92` today). Measured under three vocabularies and all four flag
combinations; none reproduces.

---

## 2. The 134 rows with no `masking.provenance` — 123 stamped, 11 owed nothing

The brief said 134 and 134 is right. It is **not one population**:

| | rows | what they record | owes a stamp? |
|---|---:|---|---|
| gate results, no stamp | **123** | `plaintext_gate` + `encoded_layer_gate` + `detection_survived`, `applied: false` | **yes** |
| an empty `masking: {}` | **11** | nothing at all — no verdict, no parity, no reason | **no** |

The 11 are tagged `clean` (9) or `c2` (2), both in `ALWAYS_OK`, so no masking was ever owed and
no gate ever ran. A row that records no gate result owes no provenance for one — the same
absence/FAIL separation `shard-gate.evaluate()` keeps, one layer down. They are reported rather
than quietly skipped.

**Why none of the 134 had been stamped.** `verify-and-stamp.py` gated its loop on
`masking.applied`, and all 134 are `applied: false`. The tool written to stamp these rows could
not see any of them. Repaired to gate on *"does this row record a gate this stamp would
certify"* (`gate_evidence.STAMPED_GATES`), which is the question a stamp is about.

**The stamp now names its bytes.** `masking.provenance` gains `bytes_sha256`, the sha256 of the
bytes the gate was re-run over. Both halves are needed for a stranger to re-derive a published
result: the predicate and the input. It is written by `verify-and-stamp.py` and **not** by
`gate_provenance.stamp()`, because `gate_provenance.py` is in `TOOLS` and adding a key there
would move the digest and put every stamped row back into re-measurement for a field that is
not part of the predicate.

It is safe against the clearance machinery **by construction rather than by luck**:
`clearance._prov_key` reads `tools` and `map` and nothing else. A control asserts it in both
directions — a clearance pinned before the key was added still applies; one pinned to a
different tools digest still does not.

**Result:** 131 rows stamped — 122 gaining a stamp, 9 replaced under `--restamp` — **0 refused,
0 not-checkable.** 131 = the 123 above plus the 8 that already carried one. `tools` digest
`c5c21c570397`, **unchanged**: no file in `TOOLS` was edited this round.

`masked_sha256` is no longer added where masking was not applied. It used to be added wherever
a row had no hash of its own, which was harmless while the tool could only see applied rows and
would have been wrong on 122 of these: their masked form *is* their input, whose hash the row
already records as `sha256`, and a second field saying so would state a masking that did not
happen.

---

## 3. Three record corrections

### 3a. `a3edd57e2ceb` recorded `plaintext_gate: PASS` and the gate refuses the shipped bytes

Re-measured with `remeasure-gates.py` against the file in the tar (`--expect-sha256` matching,
so the bytes are identified rather than assumed):

| | recorded | today |
|---|---|---|
| `plaintext_gate` | PASS | **FAIL** — verdict-moved |
| `encoded_layer_gate` | PASS | PASS — agrees |

The finding is now on the row: 1 identifier, length 4, `contains`, 16-character segment.
`publishable` recomputed by `shard-gate.py --fix`, which is the only writer of that field.

> **Published `publishable` 44543 → 44542.** Cause: this row alone. `shard-gate` reported
> `stale: over-claimed 1` before the fix and 0 after, and `publishable rows holding an unread
> FAIL` went 1 → 0.

**One thing is left standing and is stated rather than repaired.** The row still carries
`masking.reason: "no identifier to mask: the independent gate found none in the plaintext or in
any decoded layer…"` beside a recorded `plaintext_gate: FAIL` that the same tools produced.
That sentence is now false on this row and true on the other 122 that share it.
`remeasure-gates.py` writes gate results and deliberately does not edit prose, and the row is
unpublishable and out of the shard either way, so nothing turns on it — but it is a claim
contradicted by evidence on the same row, which is the shape this repository keeps finding, and
it is a one-invariant repair for the next round.

### 3b. Four fixtures whose gate evidence was computed over the collected original

`pdf-header-uploader-ui`, `pdf-object-file-manager`, `png-text-chunk-curl-stager`,
`jpeg-injected-priv8-uploader`. Each ships a **generated carrier** whose sha256 differs from the
row's `sha256`, so the census resolved them by `fixture.fixture_sha256` and reported *"gate
result describes bytes other than the ones shipped"*.

Re-measured against what ships. **All four return PASS on both identifier gates**, and
`remeasure-gates.py` **refuses all four** — *"every recorded verdict and every recorded finding
already agrees with the current gate; rewriting the record here would move a measurement that
did not change"*. That refusal is correct and it is the reason the repair is not a re-write.

§7.2 says a gate's finding is evidence about the bytes. What was missing was not the
measurement but the *statement of which bytes it was about* — so the repair is the stamp of §2,
and `shard-census.py` now accepts a fixture-resolved member **only where
`masking.provenance.bytes_sha256` equals the member's own hash**. The field is evidence, not an
assertion: a stamp naming other bytes leaves the finding standing, and a control asserts exactly
that in both directions.

| row | `provenance.bytes_sha256` | shipped member |
|---|---|---|
| `64672979265d` | `01fca3142a7a` | `01fca3142a7a` |
| `bb420f3a4a1e` | `bb33af9d2ec2` | `bb33af9d2ec2` |
| `aa746073f3a2` | `b75d14e5c40e` | `b75d14e5c40e` |
| `5ef0a7068883` | `087700635e83` | `087700635e83` |

### 3c. The two credential literals in `pdf-magic-fake-supercache-a` / `-b`

**They are kept, and the premise needs one correction that makes the keep stronger.**

The brief describes them as *a backdoor's own access password in its own query-string link*.
Read from the match, they are **not a password value at all**. Both are the same shape, once per
row, inside the `base64+inflate` layer:

```
match  (class form) : aaaa='.$aaaa.'
value  (class form) : .$aaaa.        length 7
keyword that fired  : pass
```

`SECRET_SHAPES`' `quoted-credential` pattern is `keyword \W{1,12} ['"] ([^'"]{2,}) ['"]`. Here
the quote it opened on is a **PHP string terminator** and the captured group is the
**concatenation fragment between two string delimiters** — the backdoor generating
`<a href="?pass='.$var.'&...">`. The access password is a runtime variable. **It is not in these
bytes.** So the literal is neither the customer's secret nor the attacker's; it is source code,
and it is kept for the same reason the campaign hosts on these rows are kept.

**The defect was never that they were kept. It was that nothing said so.** Neither row carries
the `secret` tag, and `evaluate()` demanded a `secret_gate` result only from a `secret`-tagged
row, so the gate never ran, no finding existed, and the rule passed in silence — a rule passing
for the wrong reason, in the eighth form this project has found it.

Repaired by running the gate and recording what it says:

- **`corpus/keep-credential.py`** (new) measures `secret_gate` over the shipped bytes and writes
  the keep as `masking.credential_dispositions`. It records shape, keyword, value length and
  character-class form, and **never a value**. There is deliberately no digest of the literal:
  its only job would be to tie the record to the bytes, `matches()` already does that on the
  shape key, and a truncated digest of a short word is recoverable from a dictionary.
- The verdict is **FAIL on both**, and that is correct rather than a problem: `secret_gate` is a
  differential and fails on a literal that is byte-identical before and after. `changes: 0`
  means *every* literal is carried over, by construction. 1 before / 1 after / 1 carried on each.
- The FAIL then **blocks** the row, and the keep is authorised by a `clear-finding.py` clearance
  signed `by: cl`, `reasoned_by:` the assistant, keyed to finding digest `f22ae03c8c8f` and
  pinned to `tools c5c21c570397 / map 9268d21c394b`. **`keep-credential.py` can only ever make a
  row less publishable** — the disposition is the argument, the clearance is the authorisation,
  and they are written by different tools on purpose.

> **Published `publishable` 44542 → 44542.** Cause is not "nothing happened": two rows gained a
> blocker and two clearances covered it in the same round. `cleared_by_human_rows` 0 → 2 and
> `cleared_by_human_by_gate` `{}` → `{"secret_gate": 2}` are where that shows.

**The null is reported and deliberately not relied on.** Over 12,000 stock CMS PHP files: 73
`quoted-credential` literals across 68 files (0.57%), 3 of them (4.1%) containing a variable
sigil, and **0** of the exact concatenation-fragment form. **State the power:** 0 of 73 excludes,
by the rule of three, a class rate above roughly 4% and says nothing at all below it — the same
trap round 14 recorded when a class read 0 of 109 at 8,000 files and was 3.9% at 32,000. The
argument here rests on reading the match, which is a determination from the bytes, not on a null
that cannot carry it.

---

## 4. Eight archives, none of which rebuilt to itself

Round 15's `build-shard.sh` repair pinned member order, mtime, ownership and permissions, and
its `--selftest` passes. **The eight artefacts on disk were never rebuilt with it.** Measured
before anything was changed, by extracting each shipped shard and repacking it:

```
benign-attacker-artefacts-001   DIFFERS    malicious-polyglots-001    DIFFERS
malicious-db-dropin-001         DIFFERS    malicious-polyglots-002    DIFFERS
malicious-doorway-kit-001       DIFFERS    malicious-staging-001      DIFFERS
malicious-outside-webroot-001   DIFFERS    malicious-uploaders-001    DIFFERS
```

Cause, read off the archives rather than inferred: the shipped members carry `lytrax/lytrax`
ownership, real 2026-09-04 mtimes, `MANIFEST.json` at `0644`, and readdir order (`samples/`
before `MANIFEST.json`). That is the pre-repair script's output. The repair was made to the
script and never applied to the artefacts.

All eight were rebuilt from their extracted contents through the tracked
`corpus/build-shard.sh`, and all eight now reproduce:

| shard | sha256 | note |
|---|---|---|
| `benign-attacker-artefacts-001` | `ad57ad98d932` | rebuild only |
| `malicious-db-dropin-001` | `d216c69f1a41` | rebuild only |
| `malicious-doorway-kit-001` | `1b8065bec8c7` | rebuild only |
| `malicious-outside-webroot-001` | `b42218888ff9` | **rebuild + one member dropped** |
| `malicious-polyglots-001` | `b6f08b364f59` | rebuild only |
| `malicious-polyglots-002` | `e4164a52adf5` | rebuild only |
| `malicious-staging-001` | `af01239ec59e` | **rebuild + one member dropped** |
| `malicious-uploaders-001` | `5529ed57a033` | rebuild only |

The six "rebuild only" hashes were predicted from the pre-change extraction and came out
identical, which is what makes the two changed ones attributable to the drop rather than to the
rebuild.

**The brief expected two hashes to change. Eight did**, and the extra six are this finding. It
strengthens rather than weakens the brief's own point: a checksum list written before this round
would have been internally consistent and wrong about every one of the eight files.

---

## 5. The census

| | before | after | cause |
|---|---:|---:|---|
| findings | **5** | **0** | 4 fixture gate-bindings resolved by the stamp; 1 unpublishable member dropped |
| `--regate` failing the gate | 2 | **0** | both files dropped |
| `--regate` recorded ≠ current | 1 | **0** | `a3edd57e2ceb` re-measured |
| kept credentials unmatched in the bytes | — | **0** | new check, over 2 rows recording a keep |
| samples | 142 | **140** | the two drops |
| carriers | 4 | 4 | untouched |

```
=== identifier gates RE-RUN over the shipped bytes (144 members) ===
  failing the gate now                              : 0
  recorded result disagrees with the current gate   : 0
  kept credentials not matched in the shipped bytes : 0   (over 2 row(s) recording a keep)
```

---

## 6. Counts, each with its cause

| quantity | before | after | cause |
|---|---:|---:|---|
| shipped samples | 142 | 140 | the two drops |
| published `publishable` | 44,543 | 44,542 | `a3edd57e2ceb`'s corrected `plaintext_gate` |
| `published_shipped_as_bytes` | 142 | 140 | predicate gained `publishable` — see below |
| `published_fetched_not_shipped` | 44,402 | 44,404 | the same two rows, other side |
| `cleared_by_human_rows` | 0 | 2 | the two credential clearances |
| `cleared_by_human_findings` | 0 | 2 | one finding each |
| `malicious_detected_runnable` | 98 | 97 | predicate gained `ships_as_bytes` — see below |
| rows carrying `masking.provenance` (shipped) | 8 | 131 | §2 |
| `tools` digest | `c5c21c570397` | `c5c21c570397` | **no `TOOLS` file was edited** |
| orphan fields | 53 | 53 | both new fields have readers; no new orphan |
| shard-run executed | 98 | 97 | `a3edd57e2ceb` carried `must_detect: ["OBF041"]` and is dropped |
| `known_miss` re-run | 42 | 41 | `3529f0f6b2cd` is a `known_miss` and is dropped |
| Detection | 696 / 1,299 (53.6%) | 696 / 1,299 (53.6%) | unmoved: neither drop is a *reviewed-set* change |
| Detection excl. source tree | 631 / 703 (89.8%) | 631 / 703 | unmoved, same reason |
| false-positive rate | 0.0223% (44/197,559) | 0.0223% | the benign half was not touched |
| techniques covered | 90 / 123 | 90 / 123 | neither drop was the last sample of any technique |

**Two predicates said "ships" and tested "published", and the drop is what separated them.**

- `make-summary.SHIPPED` counts a reason code, which records how a sample was *found*. It does
  not record that its bytes are in a shard, and rewriting a discovery route to fix arithmetic
  would destroy provenance. The count gains the condition the archives already enforce —
  `shard-census.py` fails the build on "shipped row is not publishable today" — so a row that is
  not publishable is not in a public shard. Hoisted to `ships_as_bytes()` so it can carry a
  control; four cases, both directions.
- `malicious_detected_runnable`'s comment already said *"how many **ship** and can therefore
  actually be re-run"* and the predicate said "published". It read 98 while `verify.py` executed
  97 and printed **NOT RECONCILED** — a real failure caused by the drop and repaired by making
  the predicate match its own comment.

**`verify.py` reported two families as "not present in any shard"**, which was the right check
asking the wrong question: an unpublishable row is not in a public shard by design. It now skips
rows that are not `publishable` and **prints the count** rather than passing over them —

```
  not shipped       2          reviewed malicious row(s) adjudicated unpublishable,
                              so their bytes are in no shard and this run could not execute them
```

— because a family disappearing from the suite must be visible as a number. `verify.py` now
exits 0 with no failures and the detection figure reconciles: **97 verified by re-running
`check`, 599 held local-only.**

---

## 7. Controls

Every check added or changed this round ships its control in the same commit.

| tool | controls | result |
|---|---:|---|
| `corpus/verify-and-stamp.py` | 25 → **34** | all pass |
| `corpus/keep-credential.py` (new) | **25** | all pass |
| `corpus/credential_disposition.py` (new) | covered by the two above | — |
| `corpus/shard-gate.py` | 152 → **164** | all pass |
| `corpus/shard-census.py` | +5 (2 gate-binding, 3 credential) | all planted defects caught |
| `corpus/make-summary.py` | 9 → **13** | all pass |
| `corpus/release-assets.sh` (new) | **6** | all pass |
| `corpus/build-shard.sh --selftest` | 4 | all pass |
| `corpus/pre-push-check.py --inject` | unchanged | all pass |

**Two controls failed usefully and both are worth recording.**

1. `verify-and-stamp.py`'s new clearance case failed on its first run. The fixture pinned a
   made-up `finding_digest`, so the clearance was inert for a reason that had nothing to do with
   the provenance question the case is about. Fixed to key on the finding the fixture row
   actually holds — a control that passes for the wrong reason is the thing this file exists to
   prevent, and it nearly shipped inside the control itself.
2. `release-assets.sh --selftest` printed every case as caught and **exited non-zero**.
   `scratch()` appended to a global array inside `$( )`, which is a subshell, so the append was
   lost, the cleanup list stayed empty, `${_SCRATCH[@]:-}` expanded to one empty string, and the
   `EXIT` trap returned 1. Every temp directory was also being left on disk. Found only because
   the exit status was checked and not just the output.

The new `credential_dispositions` invariant is a case where **the controls are the whole of the
check**: the population is two rows, both written this round, so the live run says nothing about
whether the rule works. Twelve cases in both directions, including the one that matters most —
*a kept credential does not by itself clear the gate.*

---

## 8. The upload, prepared and not performed

**Nothing was uploaded. No release was created. No tag was pushed.** `corpus/release-assets.sh`
prepares and verifies; it has no code path that publishes.

The requirement was that the command re-derive each hash *in the same run that verifies it*.
There is therefore **no stored list**: `--verify` recomputes each inner `.tar.zst` hash from the
file on disk, unwraps each `.zip` and asserts the tar inside is that same file, rebuilds each
shard from its own extracted contents and asserts the rebuild is byte-identical, and **only
then** writes `SHA256SUMS`. If anything fails, no list is written — a control asserts that too.

```
=== each shard: hashed now, not read from a list ===
  benign-attacker-artefacts-001      ad57ad98d932  zip holds it · rebuilds to it
  malicious-db-dropin-001            d216c69f1a41  zip holds it · rebuilds to it
  malicious-doorway-kit-001          1b8065bec8c7  zip holds it · rebuilds to it
  malicious-outside-webroot-001      b42218888ff9  zip holds it · rebuilds to it
  malicious-polyglots-001            b6f08b364f59  zip holds it · rebuilds to it
  malicious-polyglots-002            e4164a52adf5  zip holds it · rebuilds to it
  malicious-staging-001              af01239ec59e  zip holds it · rebuilds to it
  malicious-uploaders-001            5529ed57a033  zip holds it · rebuilds to it

wrote corpus/shards/SHA256SUMS  (8 inner .tar.zst, hashed in this run)
```

The checksum file covers the **inner tars** and not the `.zip`s, because the `.zip` cannot be
reproducible — ZipCrypto's randomised 12-byte per-entry header — so a `.zip` hash attests to one
upload arriving intact and nothing more.

```
corpus/release-assets.sh --print-upload corpus-2026.09.1
```

emits the three steps: `--verify`, then `git tag -a corpus-2026.09.1` and its push — **its own
tag, never retrofitted onto a scanner release**, which would change what an already-published
release contains — then `gh release create` with the eight `.zip` wrappers and `SHA256SUMS`,
`--notes-file docs/corpus-release-notes.md`.

`docs/corpus-release-notes.md` is written for a stranger: what the eight shards are, that the
samples are live malware extracted read-only at `0400`, the passphrase and the §7.4 open
procedure, how to verify an asset against the checksum file and why the `.tar.zst` is the hash
that certifies it, what the detection and false-positive figures mean — **including that the
headline 53.6% mixes in 1,131 samples of the rules' own source material while the in-scope
figure is 631 of 703** — and an explicit section on what a consumer may and may not conclude,
covering precision, the pinned-upstream benign half, and the 48% of the collection that is still
unreviewed.

---

## 9. Pre-report

```
python3 corpus/shard-gate.py corpus/index.jsonl               exit 0
python3 corpus/shard-gate.py corpus/local/index-local.jsonl   exit 0
python3 corpus/make-summary.py --check                        exit 0  "agrees with the index"
python3 corpus/pre-push-check.py                              exit 0  SAFE TO PUSH
```

`make-summary.py --check` **was failing** after the drops and the clearances, on six figures,
and was regenerated in the same commit the counts settled in:

```
  published_shipped_as_bytes      on disk=142  computed=140
  published_fetched_not_shipped   on disk=44402  computed=44404
  cleared_by_human_rows           on disk=0  computed=2
  cleared_by_human_findings       on disk=0  computed=2
  cleared_by_human_by_gate        on disk={}  computed={'secret_gate': 2}
  published_cleared_by_human_rows on disk=0  computed=2
```

Beyond the four: `corpus/shard-census.py --regate` exits 0 with zero findings, and
`corpus/verify.py` exits 0 with zero failures against the frozen `4c3e0af08988`.

**No customer identifier is quoted anywhere in this document.** The two adjudicated findings are
described by length, position, segment size and neighbour class only. The kept `c2` addresses
and campaign hosts on the polyglot rows **are** named in the index — deliberately, as indicators
under §4.1 — and none of them is a customer identifier; `shard-gate.adjudicationViolations`
asserts structurally that an adjudication may only resolve to an address the row declares in
`ioc.campaign_hosts`.
