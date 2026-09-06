# Corpus review round 12 — a tagger that cannot read its samples, and a rule that is not in the repository

**Date:** 2026-09-06
**Branch:** `corpus/unmasked-publishable` (from `master` at `ca0b9b4`)
**Scanner:** not run. No sample was scanned, no rule was touched, no detection figure moved
and none could have — nothing this round reads or writes `expect`, `observed_detection` or
any masking result.
**Index:** not written. Both halves are byte-identical to `ca0b9b4`.

**Status: the cause of all five unmasked-publishable rows is found and is one cause, not
five. The sensitivity rule is now in the repository with a control that proves it reproduces
the untracked original. The tagger/gate credential disagreement is reconciled and the nine
vacuous passes decompose into two causes. No row was retagged: four of the five cannot have
the masking pass the brief asks for, and the reason is §5.5.**

---

## Headline

> **The five rows are `clean` because the tagger cannot read them.**
> `sensitivity.classify()` has no decoder. Four of the five are gzip streams and the fifth
> hides its payload in a base64 literal, so every regex in the rule sees compressed noise and
> falls through to `if not tags: tags.add("clean")`. `clean` is the **default branch of a
> function with no decoder**, and it is the tag that means *publish as-is*. §5.4 already
> states the principle — "the absence of a plaintext hit is evidence the encoder worked, not
> evidence the sample is clean" — and `verify-content-mask.py` exists because of it. The
> tagger never got the lesson.

Decoded with the gate's own decoder, the same five bytes tag:

| row | recorded | over the same bytes, decoded |
|---|---|---|
| `1438674b06d8` | `clean` | `c2`, `identity`, `pii` |
| `c24465d301e2` | `clean` | `c2`, `identity`, `pii` |
| `cd98180175a5` | `clean` | `path` |
| `e50d85a3a815` | `clean` | `c2`, `identity`, `path`, `secret`, `pii` |
| `eba16e1e9159` | `clean` | `c2`, `identity` |

That is a re-derivation and is labelled as one throughout. Not one of those tags is proposed
for adoption on the strength of the re-derivation alone; §"Proposed tags" below adjudicates
every hit in context and rejects several of them.

---

## Four things in the brief were wrong, and the measurements are below

### 1. The exact-position hit lengths are `{3, 5, 7, 8, 19}`, not `{7, 8, 10, 19, 23}`

The brief reads the gate as failing "on exact-position hits at 7, 8, 10, 19 and 23
characters". Measured per row:

| row | exact-position identifier lengths | truncation |
|---|---|---|
| `1438674b06d8` | 3, 5, 8 | — |
| `c24465d301e2` | 5, 7 | — |
| `cd98180175a5` | 8 | 23 (domain) |
| `e50d85a3a815` | 5, 7 | 10 (domain) |
| `eba16e1e9159` | 8, 19 | — |

The brief's set is the **longest identifier length per row** — 8, 7, 23, 10, 19 — relabelled
as exact-position hits. It is not only the brief: the same claim is written into CORPUS_PLAN
§11's sixth instance, and is corrected there in this commit.

Two errors follow from the relabelling, and they point in opposite directions:

* **10 and 23 are truncation hits, not exact hits**, and `_profile`'s `len=N` on a truncation
  hit is the length of the identifier being *truncated*, not of the thing found. Both resolve
  to an account-slot value that is a **prefix** of a longer map domain. On `cd98180175a5` the
  slot value is the same 8-character account name already counted as the `exact` hit; on
  `e50d85a3a815` it is the same 7-character one. **They are not independent evidence — they
  are the same token counted twice**, once against the account and once against the domain it
  prefixes.
* **3 and 5 are dropped**, and they are the two shortest exact hits — the classes most likely
  to be coincidences. The brief's set therefore reads stronger than the evidence is.

### 2. Length is the wrong axis, and the repository already knows it

The brief expects "most of these to be real" because the lengths are "mostly above the length
where your own stock-CMS table says coincidences live". Regenerated today, the table
reproduces to the digit — 127 false positives, 104 of 8,000 files, 1.30%, 52 from 6+ — and it
says the opposite:

```
len=3 exact  49    len=7 begins 15    len=8 begins  4    len=7 contains 1
len=5 exact  18    len=8 contains 12  len=6 contains 3   len=6 exact    1
len=8 exact  15    len=3 contains  8                     len=6 begins   1
```

**`len=8 exact` is the third most common false-positive class in the table.** `_profile`'s
own docstring records this and retired the length grade for it: "On realistic content the
long rule is not meaningfully safer than the short one, and a label saying otherwise would
have been a licence rather than a measurement." The brief re-adopts the grade the code threw
away.

### 3. The zero-truncation null is vacuous — §11's seventh appearance

The table contains **no truncation class at all** — 0 false positives in 8,000 files — which
looks like the strongest evidence available. It is not evidence. Over the same 8,000-file
sample, drawn with the same seed:

```
stock files containing ANY eligible account-slot value :  6 / 8000  (0.075%)
eligible slot values in the whole sample               : 63
   IR-dir <x>-...-N-N   53
   _home*_<x>_           6
   /home*/<x>/           4     <- the slot shape both truncation hits use
```

The truncation check had **four opportunities to fire** in the entire null. A per-opportunity
false-positive rate as high as 50% still shows zero hits with probability 0.5⁴ = 6.3%, so
this null cannot exclude even a very high rate. **A denominator enumerated by a process that
does not resemble the population bounds the result and not reality** — CORPUS_PLAN §11, now
recorded there as the seventh instance. The aggregate 1.30% figure is sound for the
containment classes it measures and says nothing about truncation.

This matters less than it might, because §1 above shows the truncation hits are duplicates of
exact hits already counted. But a future finding that rests on a truncation hit alone has no
null behind it.

### 4. The masking pass the brief asks for is forbidden for four of the five

> "What they need is the masking pass none of them has had."

Four of them cannot have one. §5.5: **"archives are excluded from content masking entirely"**
— a gzip member is a compressed stream and a tar header carries a checksum over its own
bytes, so a length-preserving substitution does not rename a thing, it corrupts the container
and every member-level detection disappears at once. Measured there, not predicted: one
archive went from 27 firing rules to zero.

| row | container | maskable? |
|---|---|---|
| `1438674b06d8` | gzip → tar, 256 members, 5.03 MB | **no** — §5.5, both forms |
| `c24465d301e2` | gzip → SQL dump, 675 KB | **no** — §5.5 |
| `e50d85a3a815` | gzip → SQL dump, 2.78 MB | **no** — §5.5 |
| `eba16e1e9159` | gzip → SQL dump, 119 KB | **no** — §5.5 |
| `cd98180175a5` | PHP source, 3,143 B | yes |

What four of them need is not a masking pass. It is the `not_applicable_reason` decision the
29 existing archive rows already carry — which is the field the brief itself flags as written
by an uncommitted tool. That is not a coincidence: it is the same problem, and §"What is not
done" says why this round does not write it.

---

## Job 1 — the five rows

### Where they came from, and what they are

All five located by hash in the incident tree; `origin.path` could not be used because it is
already pseudonymised while the tree on disk is not. Sizes matched first, then SHA-256.

The **cause is single**. `sensitivity.classify()` is handed raw bytes and has no decoder, so:

```
row            sensitivity.py over raw bytes    over the decoded layers
1438674b06d8   clean                            c2, identity, pii
c24465d301e2   clean                            c2, identity, pii
cd98180175a5   clean                            path
e50d85a3a815   clean                            c2, identity, path, pii, secret
eba16e1e9159   clean                            c2, identity
```

This is not five accidents. It is one rule with one hole, and the hole empties into the tag
that means *publish as-is*.

### The per-identifier null, which is what actually adjudicates

The aggregate table cannot decide a single hit, because a hit's class is dominated by *which*
identifier produced it. Re-run over the same 8,000-file sample, per identifier:

| row | hit | identifier in stock files | reading |
|---|---|---|---|
| `1438674b06d8` | len 3 `exact` ×1 | **53 / 8000**, 49 FPs of this exact class | collision — this one identifier IS the table's whole `len=3 exact` class |
| | len 3 `contains` ×1 | 53 / 8000 | collision |
| | len 5 `exact` ×2 | **12 / 8000**, 14 FPs | collision |
| | len 6 `begins`/`contains` ×3 | 3 / 8000 | collision |
| | len 8 `exact` ×1 | 2 / 8000 | collision-prone |
| | **len 8 `contains` ×54 + `exact` ×1** | **0 / 8000** | **real — see below** |
| `c24465d301e2` | len 7 `begins` ×4, `contains` ×2 | **13 / 8000**, 15 FPs — the table's whole `len=7 begins` class | collision |
| | len 7 `exact` ×1, len 5 `exact` ×1 | 0 / 8000 | real |
| `cd98180175a5` | len 8 `exact` ×1 (+ its truncation duplicate) | 0 / 8000 | real |
| `e50d85a3a815` | len 7 `exact` ×5, `begins` ×2, `contains` ×4, len 5 `exact` ×1 | 0 / 8000 | real |
| `eba16e1e9159` | len 19 `exact` ×1, len 8 `exact` ×1, len 7 `begins` ×1 | 0 / 8000 | real |

Four of the five reduce to identifiers with no stock-CMS presence at all. The fifth reduces
to exactly one.

### `1438674b06d8` — the identifier is in the tar headers, and in nothing else

The one identifier with no stock presence appears 54 times in the decoded layer and:

```
tar members                       : 256
members whose PATH contains it    : 0
members whose BODY contains it    : 0
uname length, all 256 members     : 8     <- one distinct value, an exact map identifier
gname length, all 256 members     : 8     <- the same value
distinct (uid, gid) pairs         : 1
```

**The account name is in the `uname`/`gname` field of every member header and nowhere else in
the archive.** A member-level content scan sees nothing; only reading the container's own
metadata finds it. This is a leak form nothing in the tree currently looks for, and it is
invisible to content masking by construction — §5.5 forbids touching the container, and the
identifier is *in* the container rather than in a member.

Its other tags are false positives and the measurements say so:

* `identity` also fires on 81 e-mail-shaped strings across 44 domains in the member bodies —
  upstream contributor addresses in a translation-credits file. **Zero are on a customer
  domain.** The rule is `if cust_hosts or emails or ips`, so any e-mail anywhere is enough.
* `pii` fires on exactly **one** keyword occurrence, in a markdown changelog line. It is a
  documentation word, not personal data.
* `c2` fires because 73 external hosts are present, of which **20 are php.net, wordpress.org,
  github.com, MDN, two CDNs and Google Maps**. The rule is "an external host referenced from a
  malicious sample is attacker infrastructure", which holds for a webshell and not for a
  plugin tarball.

### `e50d85a3a815` — the brief's reading holds, and understates it

A full 37-table WordPress dump. The brief expected `identity` + `pii`; both are there and two
more with them.

```
aerusers      : ~2 rows, 2 e-mail addresses, 1 phpass password hash
aerusermeta   : ~44 rows; keys include first_name, last_name, nickname,
                session_tokens, last_login_time
aercomments   : ~17 rows
across the dump: 415 e-mail-shaped strings over 13 domains, 2 on map domains,
                 1 a consumer mail provider
contact block : an HTML list item carrying two telephone-shaped digit groups
/home*/<x>/   : one slot, a 7-character account name, 0/8000 stock presence
```

The telephone numbers the brief names are there. They are the *weakest* of the pii evidence:
the users, usermeta and comments tables are personal data outright, and `user_pass` plus
`session_tokens` make it `secret` as well. **`pii` is in `shard-gate.NEVER`, so this row is
permanently unpublishable** — index row and hash only, per §4.1.

Its `c2` is partly polluted the same way: 8 of 28 external hosts are wordpress.org, w3.org
and youtube.com.

### Proposed tags — three signed-off ready, two held

Every tag below is proposed, not written. Where a reading is ambiguous the row is held, per
the brief's instruction.

| row | proposed | evidence | confidence |
|---|---|---|---|
| `cd98180175a5` | `path` | a stock `template-loader.php` with a prepended `@include base64_decode(…)` whose 96-char base64 decodes to an absolute `/home/<8-char account>/public_html/wp-includes/…/<16>.ttf`. Identifier 0/8000 stock. No domain, e-mail, IP or external host in the file at all. The `len=23 domain truncation` is the same 8-char token. | **decided** |
| `eba16e1e9159` | `c2`, `identity` | SQL header names the database after an 8-char account (0/8000); a 19-char account identifier hits `exact` (0/8000); one customer host of shape `<19>.<3>`. 8 external hosts, **none** recognised public infrastructure — a spam-injection post table, which is what `c2` is for. | **decided** |
| `e50d85a3a815` | `c2`, `identity`, `path`, `pii`, `secret` | as above. `pii` → NEVER → permanently unpublishable, and the tagging should say so. | **decided** |
| `c24465d301e2` | `identity`, `c2` decided; **`pii` held** | database named after a 7-char account (0/8000); one customer host, one customer-domain e-mail; 52 external hosts, none public infrastructure. `pii` fires on `form-field` alone, over 65 keyword hits and 449 digit runs in spam post content — spam bodies routinely carry fabricated contact blocks, and telling those from a real customer's is a read this round did not do. | **held on one tag** |
| `1438674b06d8` | `identity` decided; **`c2` held** | `identity` from the tar `uname`/`gname` on all 256 members (0/8000 stock), **not** from the 81 upstream contributor e-mails. `pii` **rejected** — one changelog word. `c2` held: 20 of 73 external hosts are ordinary public infrastructure and separating plugin documentation links from campaign hosts in a 5 MB upstream-plus-trojan tarball is a read this round did not do. | **held on one tag** |

### Is the missing family/technique load-bearing? Incidental — with one refinement

The brief reads it as incidental. Measured, it is, and nothing in the tree contradicts that:

* `shard-gate.py` — "the only thing allowed to compute" `publishable` — **never reads
  `family` or `technique`.** Neither word appears in it.
* No script in `corpus/` blocks, defers or refuses on a missing classification. The only
  gate-shaped mentions are `make-summary.py`'s note and `verify.py:108`.
* The published half holds **44,402 of 44,544 rows with neither field**.

So the condition is not enforced anywhere. **The refinement:** all 140 published malicious
rows carry both fields, 140 of 140 — a convention with a 100% record and no enforcement
point. And `verify.py:108` does `if not r.get("family"): continue`, so a malicious row
published without a family would be **shipped and never run** by the suite, silently. The
classification is therefore load-bearing for *testing* and not for *publishing*: publishing it
unclassified loses the test rather than the gate. That strengthens the brief's reading rather
than qualifying it — the thing holding these rows is not a safety property.

---

## Job 2 — the rule that is not in the repository

### It was never only the `secret` tag

`classify()` returns **one set** covering `content`, `path`, `identity`, `secret`, `c2`, `pii`
and `clean`, and every one of the six modules that call it takes the whole set — `r["sensitivity"] =
tags`, `tags |= set(t)`. Not one selects a single tag. So the unreviewable surface is not 92
rows; it is every mechanically-derived sensitivity tag in the index:

```
clean 45,242   content 4,277   c2 788   identity 287   pii 178   secret 92   path 46
```

Only `unreviewed` (42,335) and `undecidable` (100) are outside its vocabulary. Attribution is
not inferred: **235 rows carry a `sensitivity_evidence` block whose keys and values are the
function's `ev` dict verbatim** — `customer_hosts`/`emails`/`ips`, `external_hosts`/`markers`,
and the `SECRET_PATTERNS` names `literal-password` (45), `wp-db-password` (14), `wp-db-user`
(14), `wp-salt` (14), `bcrypt-hash` (4), `private-key` (2), `phpass-hash` (1). A further 525
rows say so in `review.basis`.

**The direction that matters is `clean`.** `pii` and `content` are `NEVER`, so an error there
is over-blocking; `clean` is `ALWAYS_OK`, and it is the default branch. Every way this rule
can fail to read a sample arrives at the tag that publishes it.

### Now tracked: `corpus/sensitivity.py`

It **reproduces** the untracked original rather than improving it. A tracked module whose
behaviour differs from the one that ran cannot be used to review the rows it produced, which
is the whole point of tracking it. Two controls hold that claim:

* `--verify-reference` records the original's AST digest and reports `ok` / `moved` /
  `absent` — three answers, never two, so a stranger who does not have the gitignored file
  gets *"cannot check"* rather than a quiet pass;
* `--inject` imports the original where present and asserts **behavioural equality over 16
  probes**, none of which carries a customer identifier.

Two known defects are **reported and deliberately not fixed**, because changing either moves
tag counts on rows nobody has re-read: `identity` firing on any e-mail or IP, and `c2` firing
on any external host. Both are measured above and both are decisions for a human.

The repair that *is* made is additive and cannot change a stored tag on its own:
`classify_deep()` takes the same bytes through **`verify-content-mask.decode_layers` — the
gate's own decoder, not a second one** — so a tag and a gate that disagree are disagreeing
about a rule and never about which bytes each read. `ev["_read"]` records which form produced
what, because *clean over a gzip wrapper* and *clean over everything inside it* are different
claims that the index has been storing as the same word.

### The two credential definitions, and why they may legitimately differ

They answer different questions, and the boundary is a property of the pattern rather than a
judgement per row:

* the **tagger** asks *is a credential present*. It decides whether a masking pass is owed. A
  false positive costs one unnecessary pass; a false negative publishes a credential. It
  should over-match.
* the **gate** asks *did masking change every credential-shaped literal*. It is a differential
  over **values**, and it needs a value it can capture. A pattern matching a bare constant name
  has nothing on either side of the difference.

**A shape with no capturable value can only be tagged, never gated.** `SHAPE_KIND` records
which is which. The tagger is authoritative for tagging, the gate for gating, and neither may
be quietly narrower than the other where both can see a value. Two ways they currently are:

1. **The gate has no PEM shape at all.** `-----BEGIN … PRIVATE KEY-----` is tagged and is
   invisible to `SECRET_SHAPES`. A PEM block has a value — its base64 body — so this is
   gateable and the gate simply does not look.
2. **The gate's left lookbehind is stricter than the tagger's.** `quoted-credential` opens
   `(?<![A-Za-z0-9_])`; `literal-password` has no left boundary. Measured on the two rows
   where it bites, the character immediately before the keyword is `_` on one and a letter on
   the other. Synthetic control:

   ```
   $password = 'hunter2xx';        tagger=literal-password   gate=quoted-credential
   $user_password = 'hunter2xx';   tagger=literal-password   gate=-
   $adminpassword='hunter2xx';     tagger=literal-password   gate=-
   $pwd = 'hunter2xx';             tagger=literal-password   gate=-      (no `pwd` at all)
   'password' => 'hunter2xx',      tagger=-                  gate=-      (neither)
   ```

   §5.6 already rules on this shape: *"Lookarounds in an identifier regex should err towards
   over-matching"*, and records two leaks caused by a lookaround that was too strict. This is
   the third, on credentials rather than identifiers.

### The vacuous pass falls out, as the brief predicted

Nine rows carry `secret` and record `secret_gate: PASS` over zero literals both sides; one is
publishable. `reconcile()` decomposes them, and the two causes have different repairs:

```
162ccc9adf4e   pub=True    literal-password           gate-cannot-see
24d902d48a0d   pub=False   private-key                gate-cannot-see
bba931abc09d   pub=False   private-key                gate-cannot-see
e29dba8fde17   pub=False   literal-password           gate-cannot-see
3173640f08d8   pub=False   wp-salt                    name-only
49a4929b6305   pub=False   wp-salt                    name-only
655749f6b3a3   pub=False   wp-salt                    name-only
8adaec8baafd   pub=False   wp-salt                    name-only
c3070020e312   pub=False   wp-db-password,wp-db-user  name-only
```

* **five are name-only.** The bytes carry a bare constant name and no quoted value. Nothing
  exists to compare; the gate's zero is correct. The only defect is that `PASS` is the wrong
  word for a measurement with no subject.
* **four are a real divergence** — two PEM blocks the gate has no shape for, two passwords its
  lookbehind blocks.

**`162ccc9adf4e` is the one that matters.** It is `publishable: true`, its
`decoded_form_tags` recorded `literal-password` in a `base64` layer, last round adopted
`secret` from that record — and the gate then reported `secret_gate: PASS` with
`secret_literals_before/after: 0/0` and `literal_population_comparable: true`. A credential
in a decoded layer of a row that ships, with a gate that cannot see it and says PASS.

**Note the wider count.** 78 rows record `before == after == 0`, of which 38 are publishable.
The nine are the subset whose tags *demand* a `secret_gate`, which is the load-bearing set;
the other 69 owe no secret gate and their zero is not a claim about anything.

### Where the digest goes, and why it does not move

`gate_provenance.TOOLS` is "the modules whose logic decides a stored **gate verdict**", and
`shard-gate.py` is deliberately outside it because it consumes verdicts and does not produce
them. A sensitivity tagger produces no gate verdict either. Adding it would put all stamped
rows into re-measurement whenever a tagging rule moved, for a change that cannot alter a
single `plaintext_gate`, `encoded_layer_gate`, `secret_gate` or `detection_survived` result —
the same coupling the AST digest exists to avoid, pointed the other way.

**So it is kept out, and the answer to the real problem is that a sensitivity claim had no
provenance at all.** `sensitivity.digest()` gives it one on the same terms. Measured:
`gate_provenance.tools_digest()` is `6fecbeebbccc` before and after this round, **0 rows
re-stamped**, and `--assert-digest-unmoved` is the assertion.

### A control that was named and never written

`verify-content-mask.py` says *"`--assert-note-is-not-behaviour` is the control that says
so"*. **That flag does not exist anywhere in the tree.** The property it claims is true —
measured — but a true property with no check is one edit away from being a false property with
no check, and AGENTS.md's rule is specifically about this.

It cannot be added where it was promised: `verify-content-mask.py` is in `TOOLS`, so an
argparse branch there moves the `tools` digest and re-measures 140 stamped rows — **to install
a check whose subject is that prose edits do not do that.** A comment is absent from the AST,
so repointing the line costs nothing. `corpus/digest-controls.py` holds the implementation and
answers to the promised name; it is outside `TOOLS` for the same reason.

Its eight cases come in pairs, because a digest check has two ways to be useless:

```
prose in fp-note.txt                        6fecbeebbccc  no   ok
a comment in a TOOLS module                 6fecbeebbccc  no   ok
a docstring in a TOOLS module               6fecbeebbccc  no   ok
editing the sensitivity tagger              6fecbeebbccc  no   ok
a NEW RULE in the sensitivity tagger        6fecbeebbccc  no   ok    <- tools digest
a NEW RULE in the sensitivity tagger        5a691c9b850a  yes  ok    <- its own digest
a constant in a TOOLS module                d2e675a99e19  yes  ok
a regex literal in a TOOLS module           a1e0c6689840  yes  ok
```

---

## Job 3 — `decoded_form_tags`, sized and not touched

The brief asks for a size before either repair. Measured:

| | |
|---|---|
| rows carrying `decoded_form_tags` | **142** — all local, **0 published** |
| layers recorded across them | **318** — the brief's figure, reproduced exactly |
| rows whose `sensitivity` was adopted from the field | **11** |
| tools reading the field | one, `adopt-decoded-tags.py` |
| of the 142, bytes reachable from the existing worklists | **0** |

Two things the sizing found that change the shape of the job:

* **No published row's tags depend on this field.** The whole exposure is 11 local rows.
* **The recording pass used a second untracked module.** The recorded method vocabulary is
  `hex-escape` (154), `octal-escape` (75), `base64` (34), `base64+inflate` (32),
  `chr-sequence` (1) and nested forms — which is `trail-data/incoming/2026-09-03/deobfuscate.py`,
  3,208 bytes, gitignored under `trail-data` exactly as `sensitivity.py` is. The tracked
  decoder in `verify-content-mask.py` emits `base64`, `base64+inflate`, `hex-string`,
  `escape`, `chr-sequence`, `raw-inflate`. The vocabularies **overlap and conflict**: the
  recorder splits `hex-escape`/`octal-escape` where the tracked decoder merges to `escape`,
  and the tracked decoder has `raw-inflate` and `hex-string` the recorder has no name for.

So `decoded_form_tags` is not merely keyed to an unrecorded decoder *version*. It is keyed to
**a second untracked decoder**, in a method vocabulary that does not map onto the tracked
one — the same finding as Job 2, one level down and with a name. Any re-derivation needs the
bytes (not currently reachable), a vocabulary mapping, or a decision to derive fresh and
discard the recorded methods. **Not attempted this round**, and the brief's 6,120-layer figure
is not verified here because the bytes for the 142 could not be located from the worklists.

---

## Every count difference, with its cause

| figure | before | after | cause |
|---|---|---|---|
| tracked files scanned by `pre-push-check.py` | 185 | **187** | two new modules: `corpus/sensitivity.py`, `corpus/digest-controls.py`. Both PASS. |
| `gate_provenance.tools_digest()` | `6fecbeebbccc` | `6fecbeebbccc` | **unchanged, deliberately.** New modules are outside `TOOLS`; the only edit to a `TOOLS` file is a comment, which is absent from the AST. |
| rows carrying `masking.provenance` | 140 | 140 | nothing re-stamped |
| index rows, either half | 44,544 / 48,256 | 44,544 / 48,256 | no index write |
| `local_only_publishable_no_blocker` | 373 | 373 | no row retagged |
| stale rows (over / under / drift), both halves | 0 / 0 / 0 | 0 / 0 / 0 | unchanged |
| detection figures | — | — | **not measured.** No scanner run; `LYXBOSA_BIN` never invoked; `build-release` not rebuilt. |

**A count that did not change and carries a cause:** the 373 held rows are unchanged
*because tags were not written*, not because the gate re-agreed with them. Five of the 373 are
now known to be misclassified.

**One figure disagrees with a docstring.** `verify-content-mask.py` (twice) and
`gate_provenance.py` say "139 stamped rows"; the index carries **140** (8 published + 132 local), all at the same
digest. One row's difference, cause not established — the stamp is from `2026-09-06T12:10` to
`12:21`, i.e. last round's own pass, so the likeliest cause is a row stamped after the
docstring figure was written. Not repaired here: the fix is prose in a `TOOLS` file, which is
now provably free (see `digest-controls.py`), but the number should be re-derived rather than
edited to match a measurement taken once.

---

## What is deliberately not done

* **No index row was written.** Four of the five cannot have the masking pass the brief asks
  for (§5.5), the tags await signature, and the root cause is a rule that has just changed
  hands — retagging before that settles means re-deriving twice. `publishable` stays computed;
  nothing here can manufacture a field.
* **`identity`-on-any-email and `c2`-on-any-external-host are not fixed.** Both are measured
  above. Either would move tag counts on thousands of rows nobody has re-read.
* **The gate's missing PEM shape and its too-strict lookbehind are not fixed.** Both are in
  `verify-content-mask.py`, which is in `TOOLS`: repairing either moves the `tools` digest and
  puts all 140 stamped rows into re-measurement. That is the right price to pay — a credential
  the gate cannot see is exactly what the stamp exists to surface — but it is a decision to
  take deliberately and in its own commit, with the movement attributed, not as a side effect
  of this one.
* **`decoded_form_tags` is sized, not moved.**

---

## Commands

```
python3 corpus/sensitivity.py --inject                     # 16 probes, behavioural equality
python3 corpus/sensitivity.py --digest                     # rule digest + reference state
python3 corpus/sensitivity.py --verify-reference
python3 corpus/sensitivity.py --assert-digest-unmoved 6fecbeebbccc
python3 corpus/digest-controls.py --inject                 # 8 cases, four pairs
python3 corpus/verify-content-mask.py --stock-fp --json    # the null, regenerated
python3 corpus/shard-gate.py corpus/index.jsonl
python3 corpus/shard-gate.py corpus/local/index-local.jsonl
python3 corpus/pre-push-check.py
```

Classifying a sample, and asking why the two credential definitions disagree about it:

```
python3 corpus/sensitivity.py --deep --reconcile <file>
```
