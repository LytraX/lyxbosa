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

A file that was not scanned is a fact about the scan's coverage, and the report says
which of three things happened to it:

| reason | meaning |
|---|---|
| `size` | larger than `scan.max_file_size` |
| `excluded` | rejected by `scan.include` / `scan.exclude` |
| `unreadable` | `stat` or `open` failed — permissions, a race, a dead mount |

This is the same treatment archive members already got, one level up. The summary
reads the same way for both:

```
Files scanned: 1303725
Directories parsed: 280704
Files with matches: 1751
Files not scanned: 512 (487 over size limit, 18 excluded by filters, 7 unreadable)
Directories unreadable: 2
Archives opened: 168 (91234 members scanned, 12.4 GB expanded)
Members not scanned: 4102 (3980 not code, 118 over size limit, 4 corrupt)
```

In JSON, `skipped` and `filesSkippedSize` keep exactly the meanings they always had,
and the detail is additive — a per-file `skipReason` when there is one, and a
`filesSkipped` object shaped like `archives.membersSkipped`:

```json
"filesSkippedSize": 487,
"filesSkipped": { "total": 512, "size": 487, "excluded": 18, "unreadable": 7 },
"directoriesUnreadable": 2
```

CSV gained `skipped` and `skip_reason` columns, appended so positional consumers keep
working, and now emits a row for a skipped file — which it previously did not, because
it wrote one row per match and a skipped file has none.

Excluded files are always *counted*, so you can tell whether a pattern took effect, but
only *listed* when you ask: globs are how people cut `node_modules` out of a scan, and
on a real tree the excluded files outnumber the findings by orders of magnitude.

```yaml
scan:
  report_excluded: false   # true = emit a per-file record for every excluded file
```

### Key Features

- Recursive directory scanning with configurable file size limits (default 5 MB) and symlink control.
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
| `1` | Error: invalid arguments, missing file, invalid configuration, or a refused unsafe operation |
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
