# Corpus review round 11 — a zero that was measured, and 32,272 rows closed by hash

**Date:** 2026-09-05
**Branch:** `corpus/expand-benign-corpus`
**Scanner:** `build-release/lyxbosa`, unchanged throughout. No rule was touched this round.
**Pools:** the unreviewed `recovery/stock` and `live-webroot/context` rows, and the
false-positive population for `RULE_CANDIDATES.md` §4.

**Status: 50 benign sources pinned, 32,272 rows closed, candidate 4 measured and killed,
24 new false positives found and pinned. Detection did not move and was not expected to.
The baseline was not updated.**

---

## Headline

> **The SEO triple is not a discriminator.** It scored 0 false positives over 207,311 files
> because only **12** of those files could ever have matched it. Pin 566 pages of rendered
> documentation and the same candidate takes **494 false positives in 506 at-risk files**.
> Every page of a GNU Texinfo manual matches it, because Texinfo writes the node title into
> `<title>`, `meta[description]` and `meta[keywords]` — the same string, three times.

The second job produced a number and the first produced a lot of rows, and only one of them
changes what the scanner can do. Both are below, kept apart.

---

## Job 2 — giving candidate 4 a population that could refuse it

### What was asked for, and what was found

§4 asked for "a page-cache plugin's output directory, a static-site generator's output, or
any webroot where an SEO plugin has written meta tags into saved HTML", and named the
failure mode in advance: *a site where the SEO fields were left to auto-fill from the post
title would produce the triple honestly*.

A mainstream documentation generator does exactly that on every page it writes:

```html
<title>Top (GNU Coreutils 9.11)</title>
<meta name="description" content="Top (GNU Coreutils 9.11)">
<meta name="keywords" content="Top (GNU Coreutils 9.11)">
```

Three GCC manual trees are now pinned in `benign/sources.jsonl` under `kind:
rendered-html`, chosen so the measurement can go both ways:

| pinned source | pages | at risk | matches | why it is in the lockfile |
|---|---|---|---|---|
| `gcc-13.2.0/gcc-html` | 420 | 420 | **420** | the falsifying population |
| `gcc-9.5.0/cpp-html` | 74 | 74 | **74** | a second release and a second manual, so it is not one artefact |
| `gcc-4.9.4/cpp-html` | 72 | **0** | 0 | **the control** — older Texinfo emitted neither meta tag |

### The result

|  | before | after |
|---|---|---|
| examined | 207,311 | 263,408 |
| at risk (carries both meta tags) | 12 | **506** |
| false positives | 0 | **494** |
| what can honestly be said | 95% upper bound of 25% | **measured 97.6% of at-risk files** |

The third row is the point. Before, the candidate had been offered twelve chances to fail
and had taken none of them, which bounds nothing. After, it is a rate rather than a bound.

**The control is what makes the 97.6% mean something.** `gcc-4.9.4/cpp-html` is 72 rendered
pages of the same manual, and it contributes **zero** at-risk files. Without it, "rendered
pages match this candidate" and "the at-risk predicate counts all HTML" would be
indistinguishable — and the second would have been the §11 ritual with extra steps, padding
a denominator with files that could not have matched. The habit arrived with Texinfo 6; the
Texinfo that built the 4.9.4 manual wrote neither tag.

**The 494 are not near-duplicates, and that was checked rather than assumed.** Clustering
the 420 `gcc-html` pages on tag skeleton — the same transform that collapsed 495 doorway
rows to 3 templates — gives **399 classes**, not 3. Structurally they are 399 distinct
pages that each match independently. They do share one generator, so the honest reading is
*many distinct chances to fail, one root cause*, and both halves of that sentence are load
bearing.

### Why it is dead rather than sent back for another discriminator

Texinfo writes `<meta name="Generator" content="makeinfo">`, so an exclusion is available
and it should not be taken: it keys on the benign tree that happens to be pinned, and the
next generator with the same habit walks through it. What the measurement actually shows is
structural — `title == keywords == description` is not a property of doorway pages, it is a
property of any template that fills three fields from one variable. The doorway generator
does it with `$key = str_replace("-", " ", $keyfromurl)`; Texinfo does it with the node
title. A discriminator cannot separate two programs doing the same thing for different
reasons.

The cost of having shipped it is concrete: a customer hosting any Texinfo-built manual —
GCC, Bash, coreutils, Emacs — would get one critical SEO-doorway finding per page.

**Recall was never the problem and is unchanged at 495/495.** Those rows stay `known_miss`.

---

## Job 1 — mechanical closure, and where it stops

### How the versions were derived

Not from what upstream ships today. For every component directory on the collected hosts,
the version was read from the installed copy's own header:

| evidence | field |
|---|---|
| plugin | the main file's `Version:` header, preferring `<slug>.php`, else `readme.txt`'s `Stable tag:` |
| theme | `style.css`'s `Version:` header |
| core | `wp-includes/version.php`'s `$wp_version` |

That produced 85 (kind, slug, version) triples carrying at least one unreviewed blob, plus
3 further core versions declared on disk whose blobs were already resolved. **56 of the 88
were fetchable from wordpress.org at that exact version; 32 were not.** Each fetchable
candidate was then hashed member by member against the unreviewed rows *before* being
pinned, so the derivation was confirmed by measurement rather than by argument: a version
derived wrongly resolves nothing. One was already in the lockfile. Eight resolved nothing
that another kept source did not already cover — three of them resolved nothing at all —
and were dropped. **47 were pinned**, each closing between 3 and 3,300 rows.

### The movement, attributed by pool

| pool | unreviewed before | closed | unreviewed after | cause |
|---|---|---|---|---|
| `live-webroot/context` | 31,056 | 14,754 | 16,302 | byte-identical to a newly pinned upstream release |
| `recovery/stock` | 13,122 | 9,654 | 3,468 | as above |
| `quarantine/evidence` | 31,455 | 7,843 | 23,612 | as above — stock code sitting in quarantine directories |
| `other/audit` | 3,726 | 21 | 3,705 | as above |
| `legacy-tree/infected` | 222 | 0 | 222 | no pinned source reaches the legacy tree |
| **total** | **79,581** | **32,272** | **47,309** | |

Split by which lockfile the match came from, because they are different causes:

- **32,119 rows** matched one of the 47 sources pinned this round.
- **153 rows** matched a source pinned in an *earlier* round and had never been swept,
  because until now no committed tool did this pass. That is a backlog, not a discovery,
  and it is 0.5% of the total.

### Detection did not move, and that is the expected result

```
Detection      172 / 774   reviewed malicious samples detected   (22.2%)   unchanged
Known misses   602 recorded · 0 newly detected                             unchanged
Techniques      90 of 123 covered                                          unchanged
```

**The reviewed fraction went from 13.2% to 48.0% and that is a coverage statistic, not
progress.** Detection is computed over reviewed *malicious* samples; closing 32,272 benign
rows adds nothing to either side of it. A reviewed percentage that more than tripled while
detection sat still is exactly the kind of pair that reads as improvement if the two are
printed near each other without saying which one matters. Detection is the one that
matters, and it did not move.

### Where hash closure stops

32 component versions across 27 slugs were identified on the hosts and cannot be pinned:
premium plugins and themes never distributed on wordpress.org, agency-built and
site-specific code, one plugin whose directory was closed upstream, and two whose exact
installed version wordpress.org no longer retains. They account for **17,667 blobs no
pinned source reaches**. Substituting a nearby version for the two merely-unretained ones
would be a guess that looks like work: a version pinned on a guess that happens not to
match is indistinguishable from one that was never pinned, except in the effort it
consumed.

---

## The false-positive rate moved, and every one of the 44 is attributed

```
benign     146,713 files ·  8 false positives · 0.0055%      before
benign     197,559 files · 44 false positives · 0.0223%      after
```

**Both halves grew and the numerator grew faster.** The 36 additional file occurrences are
24 new distinct sha256, and they are attributed per source:

| what fires | rule | distinct files | sources involved |
|---|---|---|---|
| vendored Freemius SDK (`class-freemius.php`, `FreemiusBase.php`) | `OBF025` | 15 | the-events-calendar (2 releases), ignore-single-update (3), blog-designer-pack (2), menu-image (2), woo-permalink-manager, robin-image-optimizer, html5-video-player, ocean-extra, add-search-to-menu |
| LearnPress checkout and request handler | `EXP006` | 4 | learnpress 4.2.1.1, 4.2.3.2 |
| a vendored HTTP request class | `EXP006` | 1 | gallery-by-supsystic |
| plugin internals | `OBF013`, `OBF014`, `OBF018`, `PHI008` | 4 | blog-designer-pack, robin-image-optimizer, forminator, strong-testimonials |

All 44 are pinned as `known_fp` fixtures, so the whole figure is known, unfixed false
positives and none of them is removed from its own total — the asymmetry §8 records between
the two `known_*` columns, kept on the correct side.

**These were not found by scanning; they were found by closing.** Every one of the 24 was
already an index row carrying `observed_detection` from the scan that collected it. The
resolver refuses to wave those through: a row that is byte-identical to a pinned release
*and* was flagged is a false positive on upstream code, and it prints them separately for
exactly that reason.

### One false positive turned out to be already fixed

Stock WordPress core 4.8.3's `wp-admin/includes/class-ftp-sockets.php` was flagged `BD005`
by the scan that collected it and is **not** flagged by the current ruleset. A rule improved
between the two, and nothing could see it, because the file was not in a pinned benign tree
until 4.8.3 was pinned this round. It is now a plain `must_not_detect` rather than a
`known_fp`, which makes it a regression test: if `BD005` returns on stock core, the suite
goes red.

That is the §8 promotion path taken for the first time, and it is worth noting *why* it took
this long. The fixture only becomes checkable once the file is in the benign corpus, so
**every unpinned upstream version is also an unmeasurable rule fix**.

---

## The row-count question, measured — and the answer is no

§4 found row counts overstating distinct material about threefold (495 rows → 3 files,
29 → 2, 14 → 7) and asked whether the ratio holds for the quarantine/evidence pool, because
if it did, the remaining hard work would be a third of what the row count suggests.

**It does not.** The index is content-addressed, so rows are already deduplicated by exact
bytes; this measures *near*-duplicates, with the normalisation stated per kind: HTML by tag
skeleton, text by normalised line endings and collapsed whitespace, everything else by exact
bytes because a binary has no defensible normal form here.

| kind | rows | classes | factor |
|---|---|---|---|
| html | 1,387 | 223 | **6.22×** |
| text | 17,922 | 17,912 | 1.00× |
| other (binary) | 4,259 | 4,259 | 1.00× |
| oversize (>3 MB, not normalised) | 39 | 39 | 1.00× |
| **total** | **23,607** | **22,433** | **1.05×** |

5 of the 23,612 rows did not resolve to a file on disk and are counted as unmeasured, never
as distinct.

So the threefold overstatement is a property of single-campaign generated families, not of
the corpus. **The remaining 23,612 quarantine rows are about 22,433 distinct pieces of
material, and the timeline does not shrink.** That is the opposite of the hoped-for answer
and it is the useful one.

**One lead falls out of it.** A single tag-skeleton class holds **1,073** of the 1,387 HTML
rows: large saved pages, 330–694 KB each, one account, two directories, carrying scripts
and no keywords meta. One review decision covers 1,073 rows; nothing else in the pool has
that shape.

---

## What was built, and the control each one carries

| tool | what it does | control |
|---|---|---|
| `corpus/fetch-benign.sh` | now accepts `.tar.gz` as well as `.zip`; kind read off the URL, unknown suffix refused, unpacker dependencies tested one at a time | `--inject`: 5 hermetic `file://` cases — good zip verifies, corrupted zip refused, good tar.gz verifies, corrupted tar.gz refused, unknown suffix refused |
| `corpus/resolve-benign.py` | the hash-closure mechanism, committed for the first time | `--inject`: 9 cases, including that a human verdict is never overridden, that a superseded tag is recorded, that a flagged row is surfaced rather than closed, that the published row cannot carry an `origin`, and that the hasher is not silently reading zero files |

Both controls were run before their green results were trusted. `fetch-benign.sh --inject`
was additionally checked by hand for *why* each refusal happened, since a case can pass by
failing for the wrong reason.

### The lockfile was verified from a clean state, not assumed

Five pinned sources — all three `rendered-html` tarballs, which exercise the new unpack
path, plus two zips — had their cached archives **and** their unpacked trees deleted.
`VERIFY_ONLY=1` then reported all five `MISSING` and exited non-zero, which is the control
on the control; a plain run re-downloaded them from the pinned URLs, hash-verified them, and
reproduced all five trees **byte-for-byte** against checksums taken before the deletion.
All 136 sources verify.

---

## Every count difference, with its cause

| figure | before | after | cause |
|---|---|---|---|
| `total_blobs` | 92,800 | 92,800 | unchanged, as it must be: nothing was collected |
| `published` | 12,272 | 44,544 | 32,272 rows promoted, all reproducible from a pinned source |
| `local_only` | 80,528 | 48,256 | the same 32,272 rows leaving the local half |
| `verdicts.unreviewed` | 79,581 | 47,309 | closed by hash against a pinned source |
| `verdicts.benign` | 12,445 | 44,717 | the same rows |
| `sensitivity_tags.clean` | 12,780 | 45,049 | +32,269; three of the 32,272 were already tagged clean |
| `sensitivity_tags.unreviewed` | 73,783 | 42,343 | −31,440; the closed rows minus the 829 that carried a positive tag and the 3 already clean |
| `sensitivity_tags.content` | 5,084 | 4,277 | −807 bundled release images, superseded by hash identity |
| `sensitivity_tags.c2 / identity / secret / pii / undecidable` | 805 / 293 / 84 / 195 / 275 | 789 / 279 / 73 / 193 / 274 | −16 / −14 / −11 / −2 / −1, all vendored SDK code |
| benign files scanned | 146,713 | 197,559 | +50,846, from 50 newly pinned sources |
| benign files skipped | 11,993 | 17,330 | +5,337, excluded by extension in the new sources |
| false positives | 8 | 44 | +36 occurrences / +24 distinct sha256, all upstream library code |
| pinned FP fixtures | 6 | 31 | +24 `known_fp`, +1 plain `must_not_detect` |
| `reviewed_fraction` | 13.2% | 48.0% | coverage, not detection |
| **detection** | **172 / 774 (22.2%)** | **172 / 774 (22.2%)** | **unchanged. Closing benign rows cannot move it** |
| `known_miss` | 602 | 602 | unchanged |
| techniques covered | 90 of 123 | 90 of 123 | unchanged |

`corpus/verify.py` reports **0 failures**. `shard-gate.py` reports 0 stale rows in either
half, over-claimed, under-claimed or drifted, and its own `--inject` passes 12 of 12.

---

## A decision worth revisiting, stated rather than buried

The 32,272 closed rows were **promoted to the published half**, which is what the reason
code `pinned-benign-hash` has always meant and what the existing 9,168 such rows already
did. The cost is that `corpus/index.jsonl` grew from 4.5 MB to 18 MB in git.

The alternative — `resolve-benign.py --apply --no-promote` — closes them in place and keeps
the tracked index small, but then 32,272 rows sit in the local half computing
`publishable: true` under a summary key whose own note says such rows are held "because no
shard carries their bytes, or they lack the family/technique classification a published row
needs". Neither is true of a row that is a hash plus a lockfile entry, so that route makes a
stored explanation false for 32,272 of its 32,277 rows. The size was chosen over the lie; it
is reversible with one flag and a re-run.

---

## Two things this round did not do

- **The baseline was not updated.** The reviewed set moved by 32,272 rows, so the suite
  withholds the regression-rate delta and says why. Re-baselining exists to be done once,
  deliberately, at the end of a review round.
- **The README's detection paragraph is stale and was left alone.** It reads *"Detection:
  45.4% — 59 of 130 confirmed-malicious samples"*; the measured figure is 172 of 774, 22.2%,
  and has been for several rounds. The false-positive paragraph beside it was this round's
  to change and was changed; the detection claim is a different round's result and is
  flagged here rather than rewritten in passing.

---

## Commands

```
corpus/fetch-benign.sh --inject                 # control, 5 cases
corpus/fetch-benign.sh                          # 136 sources, all verified
corpus/resolve-benign.py --inject               # control, 9 cases
corpus/resolve-benign.py --dry-run
corpus/resolve-benign.py --apply
corpus/shard-gate.py corpus/index.jsonl
corpus/shard-gate.py corpus/local/index-local.jsonl
corpus/shard-gate.py --inject corpus/index.jsonl
corpus/make-summary.py && corpus/make-summary.py --check
corpus/fp-population.py --inject
corpus/fp-population.py trail-data/CMS trail-data/CMS-ext trail-data/Sites
corpus/verify.py
python3 corpus/pre-push-check.py --inject
python3 corpus/pre-push-check.py
```
