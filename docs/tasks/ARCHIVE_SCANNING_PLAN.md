# Archive scanning plan

**Date:** 2026-09-02 · **Status:** implemented 2026-09-03 — see [What shipped](#what-shipped)

Archives are the largest remaining detection gap. In the labelled malware corpus,
**50 of 185 misses are `.zip` or `.tar`** — the scanner reads them as opaque bytes.
Unpacking them by hand and re-scanning recovers **49 of the 50**: the tar members
match with the *existing* ruleset, and 47 of 47 zip members match the proposed
`OBF026`/`OBF027` from the detection hardening plan. Nothing new has to be detected;
the containers just have to be opened.

Every number below was measured, and each measurement is reproducible from the
corpora under `trail-data/` (not committed). Sources are named so they can be
re-run.

---

## 0. What real backups actually look like

Validated against a production ISPConfig server backup — 50 sites, **164 GB**,
read-only. This changed two decisions in this plan, so re-check it before trusting
anything below.

**They are `.tar.gz`, not `.zip`.** 201 tar.gz archives, **zero zip**. Zip's
central directory is a real advantage where it applies, but it is not the case that
matters most; tar.gz has to be the primary path.

**They are large.**

```
site archives : 201, 149 GB total
median        : 82.5 MB
p90           : 1.6 GB
largest       : 13.3 GB      (24 over 1 GB, 7 over 5 GB)
```

Plus a sibling `db/` directory of loose `.sql` dumps up to **1.7 GB**, and one site
backup contained **110 `.sql` dumps inside it**.

**Streaming them is expensive.** Reading member headers only — no scanning — from a
90 MB archive ran at 21 MB/s of compressed input on this storage. At that rate the
13.3 GB archive costs **~10 minutes just to inflate**, before a single rule runs.
That is the strongest argument for §2: for a large backup, the finding that matters
is the archive itself, and it costs nothing.

Expansion ratios on real sites run higher than the malware corpus: **5.6×** on a
WordPress backup against 3.2× for the corpus archives.

---

## 1. There are two problems, not one

They need different handling, and conflating them is the main design risk.

| | archived payload | site backup |
|---|---|---|
| shape | 1–3 members | thousands of members |
| size | tens of KB | megabytes to **tens of gigabytes** |
| origin | dropped by the attacker | forgotten after a restore or migration |
| what matters | the malware inside | **the archive itself** |

Backups sitting in web roots after a restore are common and can be very large.
Fully scanning a 20 GB backup is neither affordable nor useful — it is mostly a copy
of the live tree that is already being scanned.

### Classifying from the index alone

No decompression and no CMS knowledge needed. Count, over the archive's entry list:

- entries ending `.php`, `.phtml`, `.inc`
- credential files, **path-qualified** (see below):
  `wp-config.php`, `configuration.php`, `.env` near the archive root, plus
  `sites/default/settings.php`, `app/etc/env.php`, `app/etc/local.xml`,
  `config/settings.inc.php`, `app/config/parameters.php`, `includes/configure.php`
- database dumps: `.sql`, `.sql.gz`, `.dump`

Measured on the corpus archives:

```
archive                  members     php  config   sql   ->
<hash>.gz                   1931     973       1     1   SITE BACKUP
<hash>.tar                    56      56       0     0   SITE BACKUP
<hash>.zip                     1       1       0     0   archived payload
```

Rule: **≥20 PHP entries, or any credential file, or any `.sql` dump → treat as a
site backup.** A `.sql` dump is the strongest single signal — nothing legitimate
ships one inside a deployment archive, and one real site backup held 110 of them.

> **Corrected in implementation: the PHP count alone is not enough.** Three vendor
> plugin bundles in one real WordPress theme — `js_composer.zip` (435 PHP),
> `revslider.zip` (290), `data.zip` (110) — clear the threshold and expose nothing,
> because they are public plugin code anyone can download. A PHP count measures
> size, not exposure. The shipped rule requires a credential file, a `.sql` dump,
> **or** ≥20 PHP entries *together with a platform marker from §3* — the thing that
> says this is a copy of an installed site rather than of somebody's plugin. See
> [What shipped](#what-shipped).

> **A bare basename is not a credential marker.** Matching `settings.php` anywhere
> hit `wp-admin/network/settings.php`, a WordPress core admin page, and reported six
> "credential files" in an archive that has one. Drupal's is specifically
> `sites/default/settings.php`. Qualify by path, or require the file within two
> levels of the archive root for the ones that genuinely live there
> (`wp-config.php`, `configuration.php`, `.env`). With that correction, eight real
> backups each reported exactly one credential file, and the CMS was identified
> correctly in every case.

---

## 2. The archive itself is a finding

Ship this first. It needs **no extraction at all**, and for the 20 GB case it is the
only thing that can be done cheaply.

An archive under a web root that contains executable source, a credential file or a
database dump is a **critical exposure**: anyone who guesses the URL gets the site's
source and, with `wp-config.php` or `.env`, its live database credentials. For the
operator the correct output is *"delete this, it is exposing your database
password"*, not *"here are three shells inside it"*.

This is platform-independent and index-only. It does not require identifying the CMS,
opening a single member, or knowing whether the archive is reachable over HTTP —
which the scanner generally cannot know anyway.

---

## 3. Identifying the CMS — useful, but never a gate

Only for wording the report ("Magento 2 backup exposed in web root"). Everything in
§2 works without it, so an unrecognised platform still produces the finding.

**Use distribution files, not config files.** The first attempt used config files and
failed against the corpora:

| marker set | stock WordPress | stock Joomla | stock Magento 2 | real site |
|---|---|---|---|---|
| config files (`wp-config.php`, `configuration.php`) | **nothing** | **nothing** | **"Joomla"** ✗ | Joomla ✗ + WordPress |
| distribution files (`wp-includes/version.php`, `bin/magento`) | WordPress ✓ | Joomla ✓ | Magento 2 ✓ | WordPress ✓ |

Config files do not exist in a stock distribution — they are written at install, and
`wp-config-sample.php` ships instead — and `configuration.php` is generic enough to
match both a Magento file and a random plugin.

Working marker set (≈15 entries, no false positives on the corpora):

```
wp-includes/version.php, wp-login.php                 WordPress
libraries/src/Factory.php,
  administrator/manifests/files/joomla.xml            Joomla
bin/magento, app/etc/di.xml                           Magento 2
app/Mage.php                                          Magento 1
classes/PrestaShopAutoload.php,
  config/defines.inc.php                              PrestaShop
system/startup.php,
  catalog/controller/common/home.php                  OpenCart
core/lib/Drupal.php                                   Drupal 8+
includes/bootstrap.inc                                Drupal 7
concrete/dispatcher.php                               Concrete
vendor/typo3/                                         TYPO3
```

Keep this list additive. A platform nobody added still gets §2's finding whenever
the archive carries credentials or a database dump — which every real backup
measured does. It is only the source-only case that now needs a marker, for the
reason in the note under §1.

---

## 4. Scanning contents: budget spent in priority order

Sequential extraction wastes the budget on whatever happens to be at the front of the
archive. Order the work instead.

Measured on a real production site (24,351 files, 694 MB), standing in for a backup:

| bucket | files | share of bytes |
|---|---:|---:|
| PHP under upload/cache/tmp-like paths | 164 | **5.6%** |
| other PHP | 9,935 | 12.9% |
| JS / HTML / CSS / SVG | 8,300 | 35.7% |
| everything else | 5,952 | 45.8% |

So the members most likely to hold a webshell are **39 MB of a 694 MB archive**.
Filtering by extension alone is far weaker — all code is 55.7% of bytes, saving only
~44%.

Priority order: hot-path scripts → remaining scripts → JS/HTML → everything else
(exhaustive mode only).

### The generic "hot path" test

`wp-content/uploads` is WordPress-only and must not be hardcoded. The
platform-independent version: **an executable script inside a directory that is
otherwise media or assets.** That is equally true of OpenCart's `image/catalog/`,
Magento's `pub/media/` and PrestaShop's `img/`. Where §3 did identify a platform, its
known-writable paths can raise priority further — as an addition, never a
requirement.

---

## 5. Progress: archives are directories, not files

An archive must not be one tick on the progress bar. A 20 GB backup would freeze the
display on a single "file" for minutes and strand the ETA — exactly the pathology the
work-based progress model was built to fix.

**Every member is a progress unit.** `filesScanned` advances per member,
`bytesScanned` by member size, and the current-file line reads
`backup.zip → 1203/28092  wp-content/uploads/x.php`. Scanning an archive should look
like scanning a directory, because that is what it is.

### Are they counted in the total? Zip yes, exactly

A zip's central directory sits at the end of the file and lists every member's name
and uncompressed size. Measured on a 337 MB, 28,092-member backup:

```
index read (no decompression) : 0.096 s   -> 0.8% of a full read
selective inflate, 212 hot PHP:  0.05 s   -> 39.1 MB of 694 MB
```

So the concurrent pre-count can open every zip, read the index, apply the §4
selection policy — which is deterministic from names and sizes — and add the exact
member count and byte total. **The ETA stays accurate and no member is decompressed
to get it.**

`ProgressModel` needs no change: a zip contributes
`sum(selected member sizes) + kFileOverheadBytes × selected member count`, in the
same units as a directory of loose files.

### tar.gz: measure progress in compressed bytes, do not guess

A `.tar.gz` is a solid stream. There is no index, and the gzip footer only stores the
uncompressed size mod 2³², so it is unusable for anything large. Reaching member
10,000 means inflating everything before it.

Two ways to get a total, and only one is honest:

- **Rejected — estimate the expansion ratio.** The corpus averages 3.2×, this backup
  is 2.16×, and a directory of images would be ~1.0×. An estimate that wrong makes
  the ETA worse than no ETA.
- **Rejected — inflate once to count, again to scan.** Doubles the cost of the
  single most expensive item in the scan.
- **Adopted — count the archive as its *compressed* size**, which is known exactly
  from the filesystem, and advance progress by compressed bytes consumed as the
  stream is read.

That is exact for "how far through this archive am I", needs no second pass, and the
work-rate EWMA absorbs the difference in cost-per-compressed-byte. Streaming is not
the expensive part anyway: 2,000 members came off the same backup in 0.18 s, so a
full pass over a 337 MB `.tar.gz` costs a few seconds of inflation. The scanning
dominates, and scanning is what the guards in §7 bound.

The asymmetry is real and worth accepting rather than papering over: **zip gets
selection and an exact total, tar.gz gets a full stream and an exact
compressed-byte position.** Both give the operator honest movement.

### Discovery races the scan

The pre-count runs concurrently, so an archive may be reached before its index has
been read. `ScanProgress.totalFiles` and `totalBytes` are already allowed to arrive
late — the display shows an indeterminate phase until they do. Totals may also be
revised upward mid-scan when a `.tar.gz` turns out larger than its compressed size
implied; `fraction()` already clamps to 1.0, so that degrades to a bar that stalls
near the end rather than one that lies.

### The pre-count must be guarded too

Opening archives during the pre-count means parsing attacker-controlled data on the
counting thread. Every guard in §7 applies there as well, and a corrupt or hostile
index must be caught and counted as `corrupt`, never allowed to hang or abort the
count.

## 6. Never extract to disk

Stream members into a bounded in-memory buffer.

Writing malware to the analyst's filesystem can trip their own AV mid-scan, land in a
watched directory, or survive a crash as litter. There is no temp directory to clean
up, no race with another process, and members are small — the largest archive in the
corpus expands to 16.9 MB.

---

## 7. Guards — on decompressed bytes, never archive size

Capping *archive* size protects nothing: `42.zip` is 42 KB and expands to 4.5 PB.

| guard | default | why that number |
|---|---|---|
| per-member size | 5 MB, pinned | was `scan.max_file_size` via the `0` fallback, which meant "consistent with loose files". Pinned on 2026-09-03 when the loose-file cap rose to 25 MB: a member is inflated into memory and shares one expansion budget with every other member of the same archive, so it wants the tighter bound. The largest webshell in the corpus is 843 KB. |
| total expansion per archive | 256 MB | largest real archive expands to 16.9 MB |
| compression ratio | 100:1 | corpus averages 3.2×; real site backups reach **5.6×** |
| nesting depth | 2 | corpus contains **zero** nested archives |
| wall-clock per archive | 60 s | bytes are unpredictable across ratios; time is what an operator can reason about |

Every threshold is far above anything real in the corpus, so none of them fires on
genuine malware while all of them stop a bomb.

Proposed configuration:

```yaml
archives:
  enabled: true
  max_depth: 2
  max_member_size: 5MB       # 0 = fall back to scan.max_file_size
  max_expansion: 256MB       # 0 = unlimited
  max_ratio: 100             # 0 = unlimited
  time_budget: 60s           # 0 = unlimited
  exhaustive: false          # skip the priority ordering, scan every member
```

`0 = unlimited` should be accepted and **warned about** — unlimited plus a crafted
bomb is a hang rather than a finding.

---

## 8. Nothing may be skipped silently

Silent skips are how the `goto` family was missed in the first place. Every member
not scanned is counted **by reason** — `size`, `depth`, `ratio`, `budget`,
`corrupt` — and surfaced in the summary and the report, the way `filesSkippedSize`
already is.

Findings inside an archive are addressed `archive.zip!member/path.php`. Members go
through the ordinary `MatchEngine`, so they get the same rules, the same literal
prefilter and the same escaping in reports — an archive member is just a file whose
bytes came from somewhere else.

---

## 9. Library choice is a security decision

The scanner currently never *parses* untrusted input — it treats every file as a flat
byte buffer for regex. An archive reader is a C parser consuming attacker-controlled
data, which is a genuinely new attack surface.

| option | covers | surface |
|---|---|---|
| **libzip + zlib** | zip, gz, tar.gz | small |
| libarchive 3.8.8 | everything incl. 7z, rar, xz | large; real CVE history |

**Start with libzip + zlib.** The corpus is 50 zip + 1 gz, and member types inside are
`.php`, `.js`, `.html`, `.css`, `.png`, `.svg` — no 7z, no rar, and no nested
archives. Add libarchive only when a real sample demands it, and treat that as a
deliberate risk decision rather than a convenience.

---

## 10. Suggested order

| step | work | value |
|---|---|---|
| 1 | **Exposure finding** — no extraction at all, plus §3 CMS naming | the only affordable answer for a 13 GB backup, and it is free |
| 2 | **tar / tar.gz streaming** — guards, time budget, skip accounting | the format every real backup uses |
| 3 | **Zip member scanning** — central-directory triage and priority order | recovers 47 of the 50 archive misses in the malware corpus |
| 4 | Progress integration — §5 | keeps the ETA honest |
| 5 | Exhaustive mode | for operators who want it |

Steps 2 and 3 are swapped relative to an earlier draft. The malware corpus is mostly
zip, so zip looked like the priority; the production backups in §0 are entirely
tar.gz. Both matter, but tar.gz is what an operator meets on a real server.

### Verification

The same discipline as every other change here: keep a known-good binary in
`.baseline/` and diff the JSON reports, ignoring `durationMs`. Archive support
**adds** findings, so the correct assertion is that every pre-existing finding is
still present and unchanged — not that the reports are identical. See
`docs/RELEASING.md` for the procedure.

Add a zip-bomb regression test. A small crafted archive that expands past every guard
belongs in `tests/`, asserting the scan terminates and reports the skip reason.

---

## Rejected, with the measurement

| idea | why not |
|---|---|
| cap on archive **file** size | protects nothing — 42 KB expands to 4.5 PB |
| extract to a temp directory | writes malware to the analyst's disk |
| identify the CMS to decide whether to report | config-file markers found nothing on stock WordPress and Joomla and misidentified Magento as Joomla; and the exposure is platform-independent anyway |
| triage by extension | code is 55.7% of a real site's bytes — only ~44% saved, against 94% for path-based triage |
| scan members sequentially | spends the budget on whatever is at the front of the archive |
| libarchive first | large parser surface on attacker-controlled input, for formats no observed sample uses |
| bare-basename credential markers | `settings.php` matches a WordPress core admin page; qualify by path or proximity to the archive root |
| hash members and skip ones already scanned on disk | saves the scan but not the decompression; ~3× at best, and real complexity. Revisit after step 3. |

---

## What shipped

All five steps, on 2026-09-03. Code lives in [`src-lib/cpp/archive/`](../../src-lib/cpp/archive/),
the rules in [`src-lib/cpp/rules/archive.cpp`](../../src-lib/cpp/rules/archive.cpp), and
the tests in [`tests/archive_test.cpp`](../../tests/archive_test.cpp).

| § | Shipped as |
|---|---|
| 1 | `IndexSummary` in `ArchiveIndex.cpp` — accumulates one name at a time, so a zip index and a tar stream share it |
| 2 | `ARC001` (critical, credentials or a dump), `ARC002` (high, source only), `ARC003` (low, unreadable) |
| 3 | 15 distribution-file markers, most hits wins; naming only, never a gate |
| 4 | `Bucket::{HotScript, Script, Markup, Other}`; zip is stable-sorted by bucket, `Other` needs `exhaustive` |
| 5 | Members are progress units; zip contributes an exact count from the central directory, tar.gz its compressed position |
| 6 | `MemorySource` / bounded `std::string`; there is no path in the code that writes a member anywhere |
| 7 | `archive::Budget`, shared down through nesting so a bomb cannot buy budget by nesting |
| 8 | `archive::Stats`, by reason, in the text summary and the JSON report |
| 9 | libzip 1.11.4 (`default-features: false`) + zlib, added to `vcpkg.json` |

### Measured against the corpora

`.baseline/lyxbosa-baseline` (5246db9) versus the new binary, JSON reports compared
per file and per match, ignoring `durationMs`:

```
corpus       lost matches  new matches  new rule mix
CMS                     0            0  -
Sites                   0            0  -
verified                0          570  OBF015 x556, RCE001 x7, EXP009 x4,
                                        BD012 x2, ARC001 x1
unverified              0            0  -
```

**Zero findings lost**, which is the assertion that matters: archive support adds
findings, it must not move one. The 570 new matches on the verified corpus are real
malware recovered from inside `.tar` and `.zip` files the scanner previously read as
opaque bytes — including `wp-log1n.php` under `.well-known/pki-validation/a/b/d/` —
and are the recovery §10 predicted.

One *record* changes on Sites without any finding changing: `revslider.zip` (8.4 MB)
used to appear as `skipped — size limit` with no matches, and no longer appears at all,
because it is no longer skipped. It is opened, indexed, and 2,116 of its members are
scanned. Reporting it as unscanned would now be false.

Cost, on `trail-data/CMS` (51,294 files, 455 archives): **5.40 s with archives against
5.14 s with `--no-archives`**, about 5%.

### Two things the corpora forced

**`__MACOSX` sidecars.** The first run added 1,501 findings on the Sites corpus, and
1,499 of them were `revslider.zip!__MACOSX/…/._index.php` — AppleDouble resource forks
that a Mac writes beside every file it zips. They start `00 05 16 07` and are pure
binary, so OBF036 (binary payload in a file that declares itself as source) fired on
every one, correctly and uselessly. `isContainerMetadata()` now skips `__MACOSX/`
trees, `._*` stubs, `.DS_Store` and `Thumbs.db` — counted as `policy` skips, and
excluded from the PHP tally that decides whether an archive is a site backup, since
otherwise a Mac-made zip doubles its own PHP count. After the fix the Sites corpus adds
exactly two findings, both ARC002, both real: plugin zips bundled inside a theme, in a
web root.

**Directory entries are not skipped members.** Counting them made `--exhaustive-archives`
report eight members "not scanned" on an archive where it had scanned everything.

### Deviations from the plan above

**§2 severity is split, and §1's threshold is tightened.** The plan calls any archive
holding executable source, credentials or a dump a critical exposure, on a ≥20 PHP
trigger. Both halves needed work, and the corpus said so:

- Two rules, not one. ARC001 is critical when there are credentials or a `.sql` dump;
  ARC002 is **high** when there is only source. Reporting a source disclosure at the
  same severity as a handed-over database password drowns the second in the first. The
  distinction is the one §2 draws in its own prose — *"delete this, it is exposing your
  database password"*.
- The ≥20 PHP trigger now also needs a platform marker. On its own it fired on all
  three vendor plugin bundles in the Sites corpus and on nothing else; those bundles
  are downloadable from the vendor, so there is no exposure to report. With the marker
  required, Sites contributes **zero** archive findings and every real backup measured
  still reports, because a backup carries distribution files, credentials and a
  database — all three.

**Exposure findings are never quarantined.** ARC001 says a file is in the wrong place,
not that it is hostile: it is the operator's own backup, possibly their only copy of
the site, possibly 13 GB of it. `fs::rename` across a filesystem boundary degrades to
copy-and-delete, so a full quarantine volume mid-copy is a bad failure on a file that
is not malware. Worse, a quarantine directory inside the web root would change the URL
without removing the exposure, while reporting it as handled. So the finding carries
the remediation — *"delete it or move it outside the web root"* — and the scanner does
not perform it. Malware *inside* an archive is a separate matter and still quarantines
the container, because a member cannot be moved out of one.

**Quarantining into a scanned directory is now refused outright.** The same reasoning
applies to ordinary malware and was not archive-specific: moving a file to a path that
is still inside a scanned root does not take it out of the tree, and if that path is
served the file stays reachable. This is a new error for a configuration that
previously ran; the message names both directories and the fix is one line of YAML.

**`check` sniffs an oversize file from disk.** `check` read the file bounded by
`scan.max_file_size` and sniffed the buffer, so a single-file check on the 8.4 MB
`revslider.zip` reported nothing while `scan` on its directory reported the exposure.
`scan` had always used the short-read path for oversize files; `check` now does too.

**Guards charge skipped bytes too.** Bytes stepped over inside a tar still count
against `max_expansion`. They have to: a member claiming 4.5 PB is skipped for its
size, but the stream still has to be inflated to get past it, and not charging that is
the hole a bomb would use. The consequence is that a 13 GB backup stops after 256 MB of
output — which is what §2 says should happen anyway, since the finding that matters is
the archive itself.

**A truncated stream is counted as one archive, not N members.** When a guard fires
part-way through a `.tar.gz`, how many members remain cannot be known without reading
the bytes the guard just refused. `archivesTruncated` records the archive; inventing a
member count would have been a number with nothing behind it.

**`check` opens archives too.** Not in the plan, but a single-file check on a backup
that reports nothing about its contents would be surprising once `scan` does.

### Left for later

- **libarchive.** Still not warranted: no observed sample uses 7z or rar. `§9` stands.
- **Hashing members against files already scanned on disk.** As §Rejected says — saves
  the scan but not the decompression. Revisit if the decompression ever dominates.
- **Priority order inside a tar.** A solid stream has no index, so a webshell late in a
  large `.tar.gz` is missed when the budget runs out. Nothing can fix that without
  a second pass, which costs more than it saves.
