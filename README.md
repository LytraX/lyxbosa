# LytraX Bot Search

LyxBoSa is a high-performance malware and webshell detection scanner written in C++20. It recursively scans files and directories for malicious code patterns using a multi-strategy matching engine that combines string, regex (RE2), hex, entropy, hash, and heuristic analysis. With built-in detection rules spanning backdoors, credential theft, code execution, obfuscation, phishing, and more, LyxBoSa is designed to identify compromised websites and server-side threats commonly found in CMS platforms. It supports YAML-based configuration, custom rule definitions, multiple report formats (Text, JSON, CSV), and actions such as quarantine and email alerts.

## Overview

LyxBoSa (LytraX Bot Search) is a command-line security tool built to detect server-side malware, backdoors, webshells, and other malicious code embedded in web applications and hosting environments. It is particularly useful for scanning CMS installations such as WordPress and Joomla, where attackers commonly inject hidden admin accounts, cron persistence scripts, plugin/theme backdoors, and credential-harvesting payloads.

### Detection Engine

At its core, LyxBoSa uses a layered matching engine that applies multiple pattern-matching strategies against each scanned file:

- **String patterns** -- fast literal matching for known malicious signatures.
- **Regex patterns** -- powered by Google's RE2 library for safe, linear-time regular expression matching.
- **Hex patterns** -- binary signature detection for encoded or packed payloads.
- **Entropy analysis** -- identifies high-entropy regions that may indicate encrypted or obfuscated content.
- **Hash matching** -- detects known malicious files by their cryptographic fingerprint (xxHash).
- **Heuristic analysis** -- behavioral detection for techniques like variable function calls, base64 concatenation, and goto-based obfuscation.
- **Constant folding** -- resolves string expressions the way PHP would, so identifiers assembled at runtime (`$f="ba"; $h="s"; $o=$f.$h."e64_decode";`, `strrev()`, `implode()`, `chr()` chains, nested decoders) are detected by what they resolve to rather than by how they were split up.

The engine also includes context-aware filtering, suppression comments, and false-positive reduction by recognizing SQL queries and code comments.

### Built-in Rule Categories

LyxBoSa ships with a comprehensive set of built-in rules organized into 12 categories:

| Code | Category | Description |
|------|----------|-------------|
| BD | Backdoor | Hidden admin creation, cron persistence, plugin/theme backdoors, credential harvesting |
| WS | Webshell | Remote shell access and command execution interfaces |
| RCE | Code Execution | Shell commands, eval() injection, dynamic code execution |
| OBF | Obfuscation | Base64 concatenation, variable function calls, goto obfuscation, encoded strings |
| CRED | Credential Theft | Form handlers, POST data exfiltration, login interception |
| PHI | Phishing | Phishing form and page detection |
| DRP | Dropper | Malware download and deployment scripts |
| EXP | Exploit | Vulnerability exploitation payloads |
| SEO | SEO Spam | SEO injection and hidden link spam |
| DEFC | Defacement | Website defacement markers |
| PL | Perl | Perl-based attack scripts |
| ARC | Archive | Site backups and source archives left exposed in the scanned tree |

Rules can be selectively enabled or disabled by category or individual rule code through the YAML configuration file. Custom rules can also be defined alongside the built-in set.

### CLI Commands

LyxBoSa provides four subcommands:

- **`scan`** -- Scan one or more directories for malicious files, with options for recursive traversal, quick mode, dry-run, verbose output, and configurable output format. See the [CLI Reference](#cli-reference) below.
- **`check`** -- Check a single file for malicious content (interactive prompt if no file is specified).
- **`validate-config`** -- Validate a YAML configuration file for correctness.
- **`init-config`** -- Generate a default configuration file to stdout.

### Archives

A `.zip` or `.tar.gz` is not opaque bytes: it is a directory that happens to be one
file. LyxBoSa opens them, and finds two different things.

**Malware staged inside one.** Members go through the same rules, the same literal
prefilter and the same escaping as a loose file, and are addressed
`backup.zip!wp-content/uploads/shell.php`.

**The archive itself.** A forgotten backup under a web root that holds `wp-config.php`,
`.env` or a `.sql` dump is a critical exposure in its own right: anyone who guesses the
URL gets the source and the live database password. That finding costs no
decompression at all — it comes from the entry list — which is the only affordable
answer for the 13 GB backups that turn up on real servers. Where the platform can be
identified from its distribution files the finding says so ("Magento 2 backup — 4,102
entries, 3,318 PHP — exposes app/etc/env.php").

It takes a copy of an *installed site* to raise that finding — credentials, a database
dump, or a platform's distribution files alongside the code. A vendor plugin bundle
sitting in `wp-content/uploads` is public code anyone can download, and is not
reported however much PHP it contains.

**An exposed backup is never quarantined.** It says a file is in the wrong place, not
that it is hostile — it is your data, possibly the only copy, possibly tens of
gigabytes. The finding carries the remediation ("delete it or move it outside the web
root") and the scanner leaves the file alone. Malware *inside* an archive is a
different matter and still quarantines the container.

Nothing is ever extracted to disk. Members are streamed into a bounded in-memory
buffer, so a scan never writes malware onto the analyst's filesystem.

Every guard is expressed in decompressed bytes or wall-clock time, never in the size of
the archive — `42.zip` is 42 KB and expands to 4.5 PB, so a cap on the file protects
nothing. And nothing is skipped silently: every member that was not read is counted by
reason (`not code`, `over size limit`, `budget spent`, `compression ratio`,
`too deeply nested`, `corrupt`) in the summary and in the JSON report.

```yaml
archives:
  enabled: true
  max_depth: 2            # 1 = top-level archives only
  max_member_size: 5MB    # 0 = fall back to scan.max_file_size
  max_expansion: 256MB    # total decompressed bytes per archive; 0 = unlimited
  max_ratio: 100          # decompressed / compressed; 0 = unlimited
  time_budget: 60s        # per archive; 0 = unlimited
  exhaustive: false       # scan every member, not only scripts and markup
```

Turning a guard off is allowed and is warned about, because unlimited plus a crafted
bomb is a hang rather than a finding.

Formats are zip, tar, tar.gz and gz, decided by the bytes rather than by the file name.
Progress treats an archive as the directory it is: a zip's central directory gives an
exact member count before anything is inflated, and a `.tar.gz` — which has no index —
reports its position in compressed bytes, which the filesystem already knows exactly.

### Skipped files

A file the scanner did not open is not a file it found nothing in, so every skip is
counted and named. Three things can happen to a file at the file level:

| reason | meaning |
|---|---|
| `size` | larger than `scan.max_file_size` |
| `excluded` | rejected by `scan.include` / `scan.exclude` |
| `unreadable` | `stat` or `open` failed — permissions, a race, a dead mount |

Archive members carry their own reasons (`not code`, `over size limit`, `budget spent`,
`compression ratio`, `too deeply nested`, `corrupt`), and both levels read the same way
in the summary:

```
Files scanned: 482013
Directories parsed: 39544
Files with matches: 12
Files not scanned: 208 (183 over size limit, 18 excluded by filters, 7 unreadable)
Directories unreadable: 2
Archives opened: 41 (18022 members scanned, 3.1 GB expanded)
Members not scanned: 906 (874 not code, 30 over size limit, 2 corrupt)
```

`Directories unreadable` is a coverage fact too: a directory the scanner was pointed at
and could not list is reported rather than treated as empty.

In JSON, a skipped file carries the reason alongside the flag, and the totals appear as
an object shaped like `archives.membersSkipped`:

```json
{
  "path": "/var/www/html/backup.zip",
  "skipped": true,
  "skipReason": "size",
  "quarantined": false,
  "matches": []
}
```

```json
"filesSkippedSize": 183,
"filesSkipped": { "total": 208, "size": 183, "excluded": 18, "unreadable": 7 },
"directoriesUnreadable": 2
```

CSV carries `skipped` and `skip_reason` as its last two columns, and a skipped file gets
a row with the rule, severity, line and column fields empty:

```
file,rule,severity,original_severity,suppressed,category,line,column,quarantined,skipped,skip_reason
/var/www/html/backup.zip,,,,false,,,,false,true,size
```

`check` reports it the same way for a single file — an oversize or unreadable file prints
`Not scanned (over size limit)` and exits `1`, so "no matches found" always means the
bytes were read.

Excluded files are always *counted*, so you can tell whether a pattern took effect, but
only *listed* on request: globs are how people cut `node_modules` out of a scan, and on
a real tree the excluded files outnumber the findings by orders of magnitude.

```yaml
scan:
  report_excluded: false   # true = emit a per-file record for every excluded file
```

### Choosing `scan.max_file_size`

The default is **25 MB**. A file over the cap is reported as a size skip and never read,
so the cap decides coverage, not correctness.

Two things it does *not* govern:

- **Archives.** A container past the cap still has its index read and its members
  scanned, so raising the cap to reach a large backup is unnecessary.
- **Archive members.** Those are bounded by `archives.max_member_size` (5 MB), which
  does not track this value. A member is inflated into memory and shares one expansion
  budget with every other member of the same archive, so it wants a tighter bound.

Sizing it, measured against a shared host of ~1.3 M files where a 5 MB cap left 423
files unread:

| cap | code/text files it reads | cost vs 5 MB |
|---|---|---|
| 5 MB | — | baseline |
| 16 MB | 22 of 36 | ~+2% |
| **25 MB** | **29 of 36** | **~+4%** |
| 100 MB | 35 of 36 | ~+10% |
| unlimited | 36 of 36 | ~+74% |

Of those 423 files, 87% of the bytes were archives — which the cap does not govern — and
most of the rest was PDFs, images and video. Only 36 files, 783 MB, were code or text.
25 MB reads 29 of them, including a 20.7 MB database dump, a 21.5 MB content import and
20.6 MB of page-cache HTML. The seven it leaves are logs — plugin failed-login records,
`debug.log`, `laravel.log`, up to 140 MB — which is why 100 MB costs more without
covering anything a rule can use.

Keep a cap rather than setting `0`: a file is read whole into memory, so unlimited means
pulling a multi-gigabyte backup into RAM, and past 25 MB the tail is media, containers
and logs.

Raising the cap buys coverage, not detections. On that host the extra 230 files it read
matched nothing — the reason to read them is that an unopened file should not be counted
as clean.

### Key Features

- Recursive directory scanning with configurable file size limits (default 25 MB) and symlink control.
- Archive scanning: zip, tar, tar.gz and gz opened and scanned member by member, with
  bomb guards on decompressed bytes and an exposure finding for backups left in the
  tree. See [Archives](#archives).
- File inclusion/exclusion filters using glob patterns.
- Severity levels (Critical, High, Medium, Low) for prioritizing findings.
- Quarantine support with optional directory structure preservation. Moving files is
  never the default, and an unattended run that would move files refuses unless it is
  asked to explicitly.
- Reports in Text, JSON and CSV, written incrementally as the scan proceeds, so an
  interrupted run still leaves a complete, well-formed report.
- Email alert notifications.
- Graceful interrupt handling: the first Ctrl+C finishes the report it has so far and
  exits 130; a second one leaves immediately.
- A full-screen scan UI when the terminal supports it, with the status block pinned
  while you scroll back through the findings — and an automatic, explained fallback
  when it does not.
- Live progress: percentage, files and directories scanned, the severity breakdown of
  what has been found so far, throughput and an ETA.
- Strict stream discipline — the report goes to stdout, progress and diagnostics go to
  stderr — so `lyxbosa scan /var/www > report.txt` shows live progress on the terminal
  while the report accumulates in the file, and the file never contains a single escape
  sequence.

## Detection coverage

Every figure here is stated with its denominator, and the two that matter most — detection
and the false-positive rate — are reproducible from a clean checkout:

```
corpus/fetch-benign.sh     # download and hash-verify the pinned benign corpus
corpus/verify.py           # run the golden suite
```

**The table below is generated** from `corpus/index-summary.json` by
[`corpus/doc-figures.py`](corpus/doc-figures.py), so it cannot drift from the corpus by hand.
`corpus/doc-figures.py --check` fails if it does. The prose around it is written by a person and
survives regeneration.

<!-- BEGIN GENERATED corpus-figures — corpus/doc-figures.py writes this block; edit the tool, not the block -->
| figure | value | denominator |
|---|---|---|
| **Detection** | **56.2%** | 730 of 1,299 reviewed malicious samples |
| **Detection, excluding the rules' own source material** | **94.6%** | 665 of 703 samples |
| Recorded known misses | 558 | 38 of them outside that source material |
| Recorded, but detected: no shard carries the bytes | 3 | 0 outside it; the suite has nothing to run the assertion against |
| Recorded, and not re-measurable here | 8 | 0 outside it; the bytes are not on this machine |
| Largest single known-miss family | 495 | `seo-doorway-madxtube-2017` |
| Samples a stranger can re-run | 131 | ship as bytes carrying a recorded expected rule |
| Technique coverage | 95 of 123 | distinct techniques in the reviewed set |
| Corpus | 92,800 blobs | 46,016 classified, 46,784 unreviewed |
| Of those, the tree the rules were written against | 1,131 blobs | excluded from the second detection figure |
<!-- END GENERATED corpus-figures -->

**Read the two detection figures together, and prefer the second.** The first denominator
includes the tree that the first version of these rules was written against. Measuring a rule
set against its own source material reports how well it memorised that tree, not how well it
generalises, so the in-scope figure is the honest one — and it is a *lower* bound set by the
same reviewing process that produced it, not a ceiling.

The denominator is every reviewed malicious sample, so reviewing a family the scanner misses
lowers this figure and shipping a rule for one raises it. Both directions are intended: it
measures coverage, not progress. **A jump is as likely to be a denominator moving as a rule
landing** — ruling 525 already-detected samples malicious in one pass moved it by 31 points with
no rule changing — which is why the sample count is quoted beside the percentage every time and
the series is never summarised as a trend.

The **numerator** moves the same way, for a second reason that is not detection either. A row
can only assert a rule if a public shard carries its bytes, so a sample the scanner detects and
nothing ships is counted as unasserted. Publishing 29 such samples moved this figure by 2.2
points with no rule changing — the scanner detected all 29 either way, and what changed is that
a stranger can check it. **Read a movement here as a change in what is *provable*** until
[CHANGELOG.md](CHANGELOG.md) says a rule landed.

**A known miss is recorded malware this version does not catch**, verified per file rather
than inferred from a directory scan. The largest family in that count is one 2017 SEO doorway
campaign, and the rule that would close it is deliberately not written — see
[docs/RULE_CANDIDATES.md](docs/RULE_CANDIDATES.md) §4, where it was measured against rendered
documentation and took 494 false positives in 506 at-risk files. The remainder includes a
fake-plugin family whose payloads are named `.png` (§2) and the webshells staged outside the
web root that [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) issue 3 rests on.

**Those three rows are one field, and only the first is a miss.** `expect.known_miss` marks a
sample the published suite asserts no rule for, and three different facts put a sample there.
The second row is malware the scanner *does* detect: no shard carries its bytes, so there is
nothing for the suite to run the assertion against, and
[`corpus/promote-pending.py`](corpus/promote-pending.py) refuses to record an expectation it
cannot evaluate. The third row is samples whose bytes are not on this machine, so nothing was
measured about them — counted apart rather than folded into either, because an unreachable
sample is no more evidence of a miss than it is of a catch. Collapsing the three into one number
would report files the scanner finds as files it fails on. The split is measured per file by
[`corpus/classify-known-miss.py`](corpus/classify-known-miss.py), which records on every row
the rules that fired and the binary they fired under, and
[`corpus/verify.py`](corpus/verify.py) prints the same three counts from the same source.

**Samples a stranger can re-run** are the ones whose bytes ship in a public shard *and* whose
expected rule is recorded, so the claim can be checked rather than believed. The rest of the
reviewed set is held locally — most of it carries customer content that cannot be masked —
and its results come from a recorded scan rather than from a run you can repeat. That count is
a regression denominator, not recall, and is never quoted as one.

### Family-weighted detection

Detection above weights every *sample* equally. That figure is dominated by whichever campaign
happened to be collected most heavily, and here one 2017 doorway campaign supplies 495 of the
1,299 reviewed malicious samples — so the headline can move by tens of points because of how
much of one thing was swept up. Family-weighted detection asks the other question: of the
distinct attacker campaigns this corpus has seen, how many does the scanner catch at all?

**The two answers are very different and both are true.** That one missed campaign is 495
missed samples and one missed family. Sample weighting says the scanner misses a great deal;
family weighting says it misses one thing prolifically. A reader needs both to know which,
so both are generated here, from the same rows and the same detection predicate.

**There is a column per sampling frame and no single family rate, deliberately.** A family
rate is a rate over the families somebody happened to label, and the two batches of labelling
this corpus has were selected in opposite ways. Reporting one number across both would average
two biases and name the result after the scanner.

*The family names below and elsewhere in this file are attacker-campaign labels — the names
given to malware families and kits during review. They are not customer or site identifiers,
and no customer identifier appears in this corpus's published index.*

<!-- BEGIN GENERATED family-detection — corpus/doc-figures.py writes this block; edit the tool, not the block -->
| figure | families labelled before this writer | families labelled from the unfamilied pool |
|---|---|---|
| **Sampling frame** | **sampling frame not recorded** | **detection-conditioned — 530 of 531 rows in the pool carry an expected rule** |
| Campaign families | 38 | 7 |
| Rows carrying the label | 707 | 180 |
| Families fully detected | 10 | 7 |
| Families partially detected | 5 | 0 |
| Families completely missed | 23 | 0 |
| Macro average — every family weighted equally | 32.8% | 100.0% |
| Micro average — every sample weighted equally | 19.7% (139 of 707) | 100.0% (180 of 180) |

| figure | value | denominator |
|---|---|---|
| **Sample-weighted detection, whole reviewed set** | **56.2%** | 730 of 1,299 reviewed malicious samples — unchanged by any labelling |
| Reviewed malicious rows carrying no family | 351 | 350 of them detected — outside both columns above |
| Rows under a provenance label rather than a campaign | 61 | `legacy-infected-tree-sample` — membership conditioned on detection, so excluded |
| Technique coverage | 95 of 123 | distinct techniques; 531 reviewed malicious rows carry none |
| Families a stranger can re-run in full | 24 | of 45; 17 have no re-runnable member, holding 712 rows |
<!-- END GENERATED family-detection -->

**Neither column is the headline, and that refusal is deliberate.**
The right-hand families were defined by bytes — a literal shared across their members, re-read
from each sample by the writer that recorded the label — so no rule change could move a single
membership decision. But they were all drawn from one pool, the reviewed malicious rows
carrying no family, and when they were assigned that pool held **530 detected rows out of
531**. Exactly one row in it was undetected, so at most one family drawn from it could ever
have scored below 100%. Their rate was settled before anybody opened a file.

The tempting repair is to exclude them and keep the left-hand column as the real number. That
column is not a clean control either, and in the opposite direction: **597 of its 707 rows
carry `expect.known_miss`**, and 565 of those are samples no rule fires on, because a mass miss
is what gets investigated and labelled, and one 2017 doorway campaign supplies 495 of them.
Drop that single family and the same micro average reads **49.5%** instead of 14.9%. Promoting
it to *the* family rate would publish a figure that can only ever deliver bad news, which is no
better than one that can only deliver good.

So both columns, each under its own frame, and no number spanning them. A rate across the two
would be a rate over a population nobody drew, and `corpus/doc-figures.py --check` refuses any
document with a generated region that quotes one — including this one, which is why the number
is not printed here. It also refuses a per-frame rate that appears anywhere in such a document
without its own denominator and its own frame beside it.

**What the table is still silent about.** A family figure can only be computed over families
that exist, and a family exists because somebody assigned one. The reviewed malicious rows
carrying no family are counted in the second table above rather than left out of it, and they
are not a random selection — almost every one of them is detected, so they hold most of the
recorded detections while appearing in neither column. That count *falls* as labelling
proceeds, and a falling number here is not the gap closing. A census over all 95 rule-set
clusters and all 531 rows found **428 reachable** by a literal shared distinctively across a cluster and **103 that are not**: 87 in
three clusters whose only cluster-wide literal is carried by roughly a fifth of the pool, 13 in
one cluster sharing no literal at all, and 3 singletons. Those need the sample's decoded
payload rather than its stored bytes. The census is a floor rather than a ceiling — 16 of those
103 have since been labelled by splitting a cluster on a literal only a minority of its members
carry — but **87 rows remain out of reach of this method** and stay counted where they are.

**Macro and micro are both reported because they disagree.** Within the left-hand frame the
macro average weights every family equally and reads 29.9%; the micro average over the
identical rows weights every sample equally and reads 14.9%. A macro average that tracked the
micro average on every input would not be measuring anything the micro average does not; the
gap is the measurement. In the right-hand frame they agree at 100.0%, which is not two
measurements agreeing — it is one pool showing through twice.

**Three states, never two.** A family counts as fully detected only if every member carries an
expected rule and as completely missed only if none does; the five in between are reported as
their own count. Collapsing partial into either neighbour discards exactly which campaigns the
scanner catches most of, which is the information a rule author needs first.

**A contaminated frame is not the same failure as a conditioned membership, and the corpus
records them under separate keys.** In the paragraph below, a sample is in the label *because
the scanner flagged it*: reading the code that assigns it is enough to see the problem, and no
rule change could move the figure. In the right-hand column above, every membership decision
would survive any rule change and the code that assigns them never consults the scanner — it is
the pool they were selected out of that is detection-dense. The first is visible in the
assigning code; the second is invisible there and shows up only when the pool is counted.
`index-summary.json` carries `families_detection_conditioned` for the first and
`families_sampling_frame_conditioned` for the second, and folding them together would discard
the distinction.

**One label is excluded from the family counts, and its rows are not.**
`legacy-infected-tree-sample` groups 61 samples that entered the corpus *because the scanner
flagged them* — the import pass assigns that label under a detection test, and the rows record
it as `reason: detected-and-read`. It would read fully detected however good or bad the rules
were, so counting it as a family inflates coverage by construction and in the flattering
direction. A census over all 39 labelled families found it is the only one: its 61 members
carry 39 different expected rule-sets with no rule shared by all of them, while every other
multi-member family either shares a rule or fires a single set. `make-summary.py` recomputes
that dispersion every run, so a second bucket arriving later is named rather than counted.

**Technique coverage is the same question a third way, and it cannot corroborate the other
two.** It counts techniques with a runnable published sample, and the rows carrying no technique
began as the identical set to the rows carrying no family — two coverage figures blind to the
same rows. Labelling has since moved one and not the other: 180 rows now carry a campaign label
and still no technique. The sets coming apart is a labelling artefact, not the coverage
improving.

**Technique coverage** should be read as a staleness signal rather than as completion: the
denominator is enumerated from what has been reviewed, so it cannot see a technique sitting in
the blobs that have not been. A coverage number going *down* is the healthy outcome of
reviewing something new.

**False-positive rate: 0.0223% — 44 of 197,559 files**, measured with **v2.2.0**. This one
names its build rather than being generated: it is a measurement over a binary and a fetched
tree, not a count the corpus index can produce, so the honest form ties the figure to the
release that produced it. A stale version is visible; a stale number is not.

The benign corpus is 136 sources pinned by version and sha256 in
`corpus/benign/sources.jsonl` — 87 WordPress plugins, 22 themes, 24 core versions and 3 trees
of rendered HTML documentation. Nothing is shipped: the script downloads each one and fails
hard on a hash mismatch, so the corpus regenerates anywhere and yields the same number. All 44
are upstream library code (mostly the Freemius SDK, plus an FPDF class and a handful of plugin
internals), pinned as `known_fp` fixtures — a rule change that fixes one is reported, and a
fixed one that comes back fails the suite. They stay counted inside the 44; pinning a defect
does not remove it from its own total.

That rate rose because the denominator and the numerator grew together: 50 sources were added
in one round, the versions taken from what was actually installed on collected hosts rather
than from what upstream ships today. **A rate that rises when the corpus is honestly extended
is the corpus working.** The previous figure, 8 of 146,712, was measured over a benign tree
that did not contain most of the plugin versions the scanner meets.

**Precision is not reported.** `tp/(tp+fp)` moves with the malicious-to-benign ratio, which is
about 1 in 35,000 on a real host and in any curated corpus is chosen by whoever did the
reviewing. False-positive rate and detection are each computed within a single population, so
neither depends on that ratio. Precision belongs to a field scan, which supplies the real ratio
by construction.

The corpus's construction, the classification rules and the reasoning behind each denominator
are in [docs/tasks/CORPUS_PLAN.md](docs/tasks/CORPUS_PLAN.md); the published shards and what a
consumer may conclude from them are in
[docs/corpus-release-notes.md](docs/corpus-release-notes.md).

## CLI Reference

```
lyxbosa [--color WHEN] <command> [options]
lyxbosa --help | --version
```

### Global options

These are accepted before the command, and every command also accepts them after it.

| Option | Description |
|--------|-------------|
| `-h, --help` | Show the full help for every command and exit |
| `-v, --version` | Show version information and exit |
| `--color WHEN` | `auto` (default), `always` or `never`. `auto` colors a stream only when it is a terminal, so a redirected report never contains escape sequences |
| `--no-ansi` | Alias for `--color=never` |

`NO_COLOR`, `CLICOLOR_FORCE` and `TERM=dumb` are honored.

### `scan` — scan directories for malicious files

```
lyxbosa scan [options] [DIRECTORY...]
```

Directories given on the command line override `scan.directories` from the
configuration. With neither, and no `--config`, the command prompts — unless stdin is
not a terminal, in which case it is an error rather than a guess.

**Input and rules**

| Option | Description |
|--------|-------------|
| `-c, --config FILE` | Configuration file (default: the built-in configuration) |
| `-r, --recursive` | Recurse into subdirectories |
| `--no-recursive` | Do not recurse into subdirectories |
| `--quick` | Quick scan: limit files to 1 MB and disable quarantine |

**Output**

| Option | Description |
|--------|-------------|
| `-o, --output FORMAT` | Report format: `text` (default), `json` or `csv` |
| `-O, --output-file FILE` | Write the report to FILE instead of stdout. `--output` then selects *that file's* format, while the terminal keeps the readable text view. Parent directories are created. Overrides `actions.report.file` |
| `-v, --verbose` | Full match details rather than one line per file |
| `-q, --quiet` | Suppress progress and the scan summary; findings are still written |
| `-s, --silent` | No output at all. Requires `-O/--output-file` (or `actions.report.file`), because a scan with nowhere to write is a scan nobody can read. Errors are still reported on stderr |

**Progress display**

| Option | Description |
|--------|-------------|
| `--progress WHEN` | `auto` (default), `tui`, `plain` or `none`. `auto` uses the full-screen UI when the terminal supports it, and otherwise a single throttled line on stderr |
| `--no-interactive` | Never take over stdout; same as `--progress=plain` |
| `--no-precount` | Do not pre-count files, so progress has no percentage or ETA. The count normally runs concurrently with the scan |

**Archives**

| Option | Description |
|--------|-------------|
| `--archives` | Open archives and scan their members, and report an archive that turns out to be a copy of the site. On by default |
| `--no-archives` | Treat archives as opaque bytes, as before |
| `--exhaustive-archives` | Scan every member, not only scripts and markup. The members otherwise skipped are 45.8% of a real site's bytes and have yet to hold a webshell in this corpus |

**Actions**

| Option | Description |
|--------|-------------|
| `--dry-run` | Report only; never move files |
| `--quarantine` | Move matched files to the quarantine directory. **Required for any unattended run that quarantines.** Exposure findings never move a file, and the destination must be outside every scanned root |
| `--no-quarantine` | Never move files, whatever the configuration says |
| `--force` | Skip the configuration summary and the confirmation prompt |

### `check` — check a single file

```
lyxbosa check [options] [FILE]
```

Prompts for a path when FILE is omitted. Quarantine is always disabled. Accepts
`-c/--config` and the global options. An archive is checked like the directory it is:
the exposure finding lands on the file, and each member with findings is listed under
it as `archive.zip!member/path.php`.

### `validate-config` — validate a configuration file

```
lyxbosa validate-config [options] FILE
```

Reports the rule, pattern and directory counts. Exit code 0 when valid, 1 when not.

### `init-config` — print the default configuration

```
lyxbosa init-config > lyxbosa.yaml
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No matches found, or the command was cancelled |
| `1` | Error: invalid arguments, missing file, invalid configuration, a file that could not be scanned, or a refused unsafe operation |
| `2` | Matches found |
| `130` | Interrupted with Ctrl+C (the partial report is still written) |

### Where output goes

The report goes to **stdout**; progress and diagnostics go to **stderr**. That
separation is what makes a redirected scan watchable.

| stdout | `--output-file` | On screen | Report |
|--------|-----------------|-----------|--------|
| terminal | no | Full-screen UI, or the findings as they are found | stdout |
| terminal | yes | Full-screen UI with the readable text view | the file, in `--output` format |
| pipe or file | no | Progress line on stderr, if stderr is a terminal | stdout, in `--output` format |
| pipe or file | yes | Progress line on stderr, if stderr is a terminal | the file; stdout stays empty |

### Full-screen UI keys

| Key | Action |
|-----|--------|
| `↑` `↓` `PgUp` `PgDn` `Home` `End`, mouse wheel | Scroll the findings. Scrolling up stops the view following new findings; reaching the bottom, or `End`, resumes it |
| `p`, `Space` | Pause and resume the scan |
| `q`, `Esc`, `Ctrl+C` | Stop early — the partial report is still written, exit code 130 |

The UI runs only when stdout is a terminal that supports it: color enabled, `TERM` set
and not `dumb`, not CI, and at least 40x10. Otherwise it falls back to the stderr
progress line and says why. On exit the findings and summary are written into the
normal terminal buffer, so nothing is lost when the alternate screen is torn down.
Build with `-DLYXBOSA_TUI=OFF` to compile it out entirely.

### Examples

```bash
# Scan a docroot, watch it, keep the report
lyxbosa scan /var/www --recursive --force

# Machine-readable report, progress still visible on the terminal
lyxbosa scan /var/www -O report.json -o json --force

# The same without --output-file: progress moves to stderr, stdout stays clean
lyxbosa scan /var/www -o json --force > report.json

# Unattended, no output whatsoever, results in a file
lyxbosa scan /var/www -O /var/log/lyxbosa.json -o json --force --silent

# Report only, never touch a file
lyxbosa scan -c lyxbosa.yaml --dry-run --verbose

# Unattended run that is allowed to move infected files
lyxbosa scan -c lyxbosa.yaml --force --quarantine

# Single file, and configuration handling
lyxbosa check suspicious.php
lyxbosa init-config > lyxbosa.yaml
lyxbosa validate-config lyxbosa.yaml
```

## Updating

There is no self-update yet. Releases are downloaded from
[the releases page](https://github.com/LytraX/lyxbosa/releases); the plan for an
`lyxbosa update` command, and the release-signing it depends on, is in
[docs/tasks/UPDATE_PLAN.md](docs/tasks/UPDATE_PLAN.md).

## Building

See [docs/BUILDING.md](docs/BUILDING.md).

## Changes

[CHANGELOG.md](CHANGELOG.md) — the **scanner**: detection rules, the CLI, report formats and
binary releases, versioned on the `v*` tags. Anything a configuration or a calling script has
to do differently is here. Releasing is [docs/RELEASING.md](docs/RELEASING.md).

[corpus/CHANGELOG.md](corpus/CHANGELOG.md) — the **corpus**: the sample index, the published
shards, masking and publication gates, and the measurement rounds, versioned on the
`corpus-YYYY.MM.N` tags. The two series move on different cadences on purpose — the scanner
versions on rules, the corpus on review rounds — and each file's header says which questions
belong to it.
