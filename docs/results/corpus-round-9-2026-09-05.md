# Corpus review round 9 — the legacy `Infected` tree

**Date:** 2026-09-05
**Branch:** `feat/infected-corpus`
**Scanner:** `build-release/lyxbosa`
**Pool:** the 1,127 files under `trail-data/Infected` that were not already in the index —
**all of them**, not a sample. 55.6 MB, from many older servers and older incidents.

**Status: written to the local half, published nothing.** `corpus/local/index-local.jsonl`
went 79,405 → 80,536 rows. `index-summary.json` was regenerated, `verify.py` was run, and
**the baseline was not updated.**

---

## Headline

> **Detection goes from 34.9% to 16.1%** (60 of 172 → 122 of 760), **of which 62 samples
> entered as detected, 526 entered as known misses and 313 entered as benign.**
> A further 230 entered as `unreviewed` and are in no detection pool at all.

Technique coverage goes **80 of 102 → 80 of 113**. The numerator does not move because
nothing new was published, so no new technique gained a tested sample.

**The same figure, computed without this tree, is unchanged at 60 of 172 (34.9%).** That is
not a coincidence and it is the point of the new `predates_ruleset` field: these are the
files the first version of these rules was written against, so detection over them is partly
a test of the rules against their own source material. §11 in a new place. The split is
recorded per row and summarised in `index-summary.json`, so the figure can be reported both
ways from here on rather than only the flattering one.

---

## The denominator, reproduced before anything else

| figure | value |
|---|---|
| files under `trail-data/Infected` | 5,339 |
| already in the union of both index halves | 4,212 |
| **not in the index** | **1,127** |
| bytes of those | 55,620,720 (55.6 MB) |

`import-infected-tree.py` refuses to run if any of those three numbers has moved, and it
proved that guard by refusing a second run once the rows were written.

Of the 4,212 already indexed, **4,195 are one client's directory** — the current incident,
indexed from its own tree. The remaining 17 are scattered.

The 1,127 files are **1,100 distinct blobs**; 27 files are byte-identical copies of another
file in the set. Rows written: **1,131** = 1,100 blobs + 31 archive members that exist only
inside containers.

---

## Every count difference, with its cause

§8 requires an attributed cause rather than a bare delta.

| figure | before | after | cause |
|---|---|---|---|
| Detection | 60 / 172 (34.9%) | 122 / 760 (16.1%) | numerator **+62** (files the scanner flags, read and confirmed); denominator **+588**. The fall is denominator-led and 495 of the 526 new known misses are **one campaign** |
| Detection excl. this tree | 60 / 172 (34.9%) | 60 / 172 (34.9%) | unchanged by construction — the new `predates_ruleset` split |
| Known misses | 112 | 638 | **+526**, of which 495 are `seo-doorway-madxtube-2017` |
| — re-run here | 78 | 78 | unchanged: nothing new was published, so nothing new is executable |
| Verdict `benign` | 12,132 | 12,445 | **+313**: 153 page-cache bodies, 144 cache sidecars, 8 FrontPage artefacts, 7 analysis documents, 1 keyword list |
| Verdict `unreviewed` | 79,365 | 79,595 | **+230**: 90 media in the triage queue, 11 archive containers, 23 archive members, 106 files no evidence-backed rule covered |
| Techniques known | 102 | 113 | **+11** newly-named techniques on reviewed malicious rows |
| Technique coverage | 80 / 102 (78.4%) | 80 / 113 (70.8%) | denominator only; nothing published, so the numerator cannot move |
| Total blobs | 91,669 | 92,800 | **+1,131** rows written |
| Published | 12,264 | 12,264 | **nothing was published this round** |

**Read the detection figure with the campaign in view.** 495 of the 526 new known misses are
generated doorway pages from one 2017 campaign with three page templates. They are real
malicious artefacts and belong in the index, but they are one family, and a per-sample
detection rate lets one family with many files dominate. `index-summary.json` now carries
`malicious_known_miss_by_family` so this is visible from the summary rather than only from
this document.

---

## What the tree actually turned out to be

Four presumptions in the brief were wrong, and reading the files is what established that.
Each is recorded because the name suggested one thing and the bytes said another.

| presumed | actually |
|---|---|
| `.php_expire` × 144 — "a hosting provider's quarantine rename" | **Joomla page-cache expiry sidecars.** All 144 are exactly 10 bytes holding a bare unix timestamp, spanning a 42-hour window in Feb 2016. Confirmed by reading every one |
| `.db` × 8 — "presumed secret or pii, a database dump" | **`Thumbs.db`** — Windows OLE thumbnail caches inside a phishing kit's image directory. Embedded JPEG thumbnails, no database, no credentials |
| `.cnf` × 7 — "a MySQL config, one of the two most likely places for live credentials" | **FrontPage Server Extensions config.** Six of the seven are 24-byte `vti_encoding` stanzas. The one real credential in that directory is a DES crypt hash in `service.pwd` — a `.pwd`, not a `.cnf` |
| `.zip` × 7 — archives to index as members | **12 containers, not 7.** Content sniffing found a `.rar`, a `.tgz`, a `.gzquar` and two extensionless zips named as PHP upload temp files. Extension-based counting missed five |

The `_private` directory the brief said to read before deciding holds exactly one file: a
FrontPage `.htaccess` denying `PUT`/`DELETE`. It is a FrontPage artefact directory, not a
secret store — but it names an account and a realm that appear in no directory name, which
is why it mattered.

**529 vs 514.** The brief's extension mix reproduces exactly for seven of eight buckets
(241 `.php`, 144 `.php_expire`, 95 media, 8 `.db`, 7 `.cnf`, 7 `.zip`) and the full
breakdown sums to 1,127. The eighth does not: **514** basenames contain no dot, not 529.
Two more carry a suffix that is not an extension (`.identifier`, and a maildir name ending
`,S=3087`), giving 516 on the most generous reading. The remaining 13 are unaccounted for and
the difference is stated rather than reconciled by adjusting the rule until it matches.

**Detection over the pool measured 7.7%** (87 of 1,127 files, per-sample `check`). The
brief's 60-file sample gave 12% ± 8, so 7.7% sits inside that interval. All 1,127 were proved
read: five files initially looked unread and were **archive containers**, whose output is
member-scoped (`Member:`) rather than file-scoped (`File:`) — an artefact of the check's
proof-predicate, not a skip.

---

## Masking

No pseudonym map existed for these servers. `account-mapping.json` covers 50 accounts on the
current incident host and none of these. A new map was built at
`trail-data/incoming/2026-09-03/private/infected-tree-mapping.json` (mode 0600, inside the
gitignored `trail-data/`), from a mechanical identifier sweep over all 1,127 files:
**7 accounts, 22 customer sites, 2 provider servers, 1 person, 45 kept c2 hosts.**

Accounts continue at `acct51` so they share one namespace with the existing map and satisfy
the existing `acctNN` form gate unchanged.

### The identifiers that no directory name revealed

This is the failure mode the brief describes, and the tree is full of it:

| identifier | where it actually came from |
|---|---|
| one account | 13,982 times in one `error_log`, as **`/home2/`** — not `/home/` |
| another account | a single PHP warning line in a phishing kit's `error_log` |
| the FrontPage account | the directory is named for the `.info` domain; the account and the realm are a different name and a `.com` |
| two more, differing in one letter | a config-spy log — while the **directory** is spelled with a *third* spelling, one character off both |
| five more customer domains | the same log, none of them a directory name anywhere |

`/home2/` matters twice: the gate's `HOME_RE` matched only `/home/`, so the tree's largest
account would have passed it unmasked. The gate is now `/home\d*/`.

### Verification

Not a substring sweep. The check enumerates every distinct path segment the rows actually
store — from every string value in every row, not just the field someone remembered to mask —
and asks which begin with a client identifier at a separator boundary. It shares no regex
with the masker.

- **3,413 distinct segments** across the 1,131 new rows: **PASS**
- the full local half, 80,536 rows: **PASS**
- the published half, 12,264 rows: **PASS**
- zero false hits, so the output is a list nobody has to triage

**The check was proved able to fail.** Nine forms were injected one at a time; all nine are
caught, including two the first version missed:

- a `%2F<client>.gr` reference splits to the segment `2f<client>`, which does not *begin*
  with the label. The masker handles that form; the check could not see it. Prefix matching
  became containment.
- taking a domain's *first* label turned `server.<x>.com` into the word `server`, and a
  `<name>.com.gr` into `com`, which reported three leaks that were not leaks. The label that
  names the owner is the one before the public suffix, and the public suffix is not always
  one label.

### One real corruption, caught by the collision check

The bare label of one client matched inside **`UpgradeConsumerSecret.php`**, rewriting it
mid-word. That is §5.3 failure mode 1 exactly, it was invisible to reading, and it was found
by running the masker over the stock CMS vocabulary. The repair is the positional rule: full
domains substitute anywhere; bare labels and account names must **start** at a
non-alphanumeric boundary. Leading-only, deliberately — the forms that occur are suffixed
(`php56-<acct>.conf.bak`), so a trailing boundary would miss them.

---

## The gate

`shard-gate.py` gains the same positive-form discipline for the two components this round
introduces, both map-free so a stranger can run them:

- `site` must be `siteNN`, `server` must be `srvNN`;
- checked on **both halves**, not only the published one — the local half is where the next
  promotion reads from;
- `HOME_RE` widened from `/home/` to `/home\d*/`.

Added with the fields rather than after them, per §5.3.

---

## Findings outside this round's scope

Two pre-existing leaks that this round's tooling found. Neither was introduced here and
neither was changed.

1. **2,479 rows of the local half carry an unmasked customer domain label** — 10 distinct
   domains, one of them alone in 2,403 rows. They are current-incident rows, and they show
   the §5.3 failure exactly: the *account* segment is masked (`acct12_public_html`,
   `/home/acct23/`) while the domain-derived directory name beside it is not
   (`<client>-backup-component-validation-...`). The local half is gitignored, so this has
   not left the machine.

2. **`results.json` is tracked in git and contains 18 occurrences of 5 client names** from
   this very tree. `.gitignore` already declares `/results*.json` with the comment "local
   scan reports - can quote customer paths and malware content" — but gitignore does not
   untrack a file already committed. `git rm --cached results.json` untracks it going
   forward; the names remain in history regardless, which is the part worth deciding about.

A third was in this round's own work and was fixed here: the importer is a **tracked** file,
and its first version spelled classification rules as `rel.startswith("<client>.gr/page/")`,
putting client names in git as surely as an unmasked row would. Worked examples in two other
new files did the same. Directory roles now come from the out-of-repo map, and a sweep of all
155 tracked files against 251 identifiers from both maps is clean. The same sweep found a
real account name in `shard-gate.py`'s own comment — left there by the commit titled *"scrub
three client names"*, in the paragraph explaining the scrub. Fixed.

---

## What was not done, and why

- **Nothing was published.** Publication needs masked bytes, three gates, a shard and
  expectations; this round produced provenance, classification and accounting. Every new row
  is `publishable: false` with a recorded blocker.
- **No verdict here is a human judgement.** Every one carries
  `review.human_confirmed: false` and a `local_only` blocker saying it awaits confirmation.
  The accounting moves; publication does not. §4.1's rule that nothing leaves `unreviewed`
  without a human is preserved at the point it protects.
- **The 90 structurally-clean media files were not classified.** They are the case §4.3 says
  automation must not decide, and they sit in the triage queue.
- **The baseline was not updated.**
- **106 files no evidence-backed rule covered stay `unreviewed`.** Guessing a verdict from a
  filename is a judgement, and §4.2 says automate triage, not judgement.
