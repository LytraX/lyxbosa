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

## What the detection numbers actually are

Half of this is checkable today, and half is not. Both halves are stated, because a
detection number without its denominator is not evidence.

Run it yourself:

```
corpus/fetch-benign.sh     # download and hash-verify the pinned benign corpus
corpus/verify.py           # run the golden suite
```

### The false-positive side — checkable

**8 false positives across 146,711 files, a rate of 0.0055%.**

Those files come from 86 pinned sources — 48 WordPress plugins, 20 themes and 18 core
versions, each pinned by version and sha256 in `corpus/benign/sources.jsonl`. Nothing is
shipped: `corpus/fetch-benign.sh` downloads them, verifies every hash and fails hard on a
mismatch. Anyone can regenerate the same corpus and get the same number, which is the point
— the figure is reproducible rather than reported.

All 8 are upstream library code (the Freemius SDK, an FPDF class). They are pinned as
`known_fp` fixtures, so if a rule change fixes one the suite says so, and if a fixed one
ever comes back it fails.

### The malicious side — not yet a number

**Recall is 100% over seven reviewed samples, against 69 known misses. That ratio is the
honest summary: the suite tests seven samples and records sixty-nine pieces of real malware
it does not detect.**

The corpus holds 60,609 unique blobs; 12,202 are classified and 48,407 are still unreviewed.
Almost all of the classified ones are benign by hash match against pinned upstream, so the
reviewed *malicious* set is small. A recall figure over seven samples says nothing about the
scanner, and publishing it as though it did would be worse than publishing nothing.

**Precision is not reported at all, and that is a decision rather than a gap.** Precision is
`tp/(tp+fp)`, which only means something when the malicious-to-benign ratio resembles what an
operator actually faces — on the production host this corpus came from, roughly 37 true
findings in 1.3 M files, about 1 in 35,000. No curated set reproduces that. An earlier version
withheld the figure until the two sets were "commensurate" in size, which was the worse
repair: satisfying it means shrinking the benign side until the ratio is near 1:1, tens of
thousands of times more malicious than reality, and printing something flattering that means
nothing. Reporting it unconditionally is no better — it moves with how much reviewing has been
done rather than with detection quality.

False-positive rate and recall are reported instead because each is computed *within* one
population, so neither depends on the ratio between them. Precision belongs to a field scan of
a real host, which supplies the real ratio by construction; there it is about 37%, which is
low, and which is what the operator experiences. The two must never be quoted as though they
were the same measurement.

The suite also refuses to print some things it could:

- **A recall delta against the previous run is withheld** whenever the reviewed set changed
  size, because a figure over a set that grew is not the same measurement.
- **Known misses have their own column.** Sixty-nine samples are real malware this scanner
  does not detect at this version — an entire fake-plugin family among them, whose payloads
  live in files named `.png` that are not images (`docs/RULE_CANDIDATES.md` §2), plus the two
  webshells staged outside the webroot that `docs/KNOWN_ISSUES.md` issue 3 rests on. They
  count as expected, not as failures — but they are counted, and they are the reason the
  recall figure above is not evidence.
- **Technique coverage is reported instead of a sample count**: 55 of 55 distinct techniques
  in the reviewed set have a sample the suite actually checks. Read that as a staleness
  signal, not as completion — the denominator is enumerated from what has been reviewed, so
  it cannot see techniques in the ~700 detected blobs still unreviewed.

### Why publish the half that is ready

Because it can be verified today and can only improve. The benign half is a lockfile and a
script; the malicious half needs human review of 48,477 blobs, and that number is printed
next to every result until it comes down.

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

## Building

See [docs/BUILDING.md](docs/BUILDING.md).

## Changes

[CHANGELOG.md](CHANGELOG.md) — what changed per release, and anything a configuration or
a calling script has to do differently. Releasing is
[docs/RELEASING.md](docs/RELEASING.md).
