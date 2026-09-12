# CLI reference

Every command, option, exit code and stream rule. A first scan is in
[README.md](../README.md#scanning-a-docroot); what a scan opens and skips is in
[docs/SCANNING.md](SCANNING.md).

```
lyxbosa [--color WHEN] <command> [options]
lyxbosa --help | --version
```

## Global options

These are accepted before the command, and every command also accepts them after it.

| Option | Description |
|--------|-------------|
| `-h, --help` | Show the full help for every command and exit |
| `-v, --version` | Show version information and exit |
| `--color WHEN` | `auto` (default), `always` or `never`. `auto` colors a stream only when it is a terminal, so a redirected report never contains escape sequences |
| `--no-ansi` | Alias for `--color=never` |

`NO_COLOR`, `CLICOLOR_FORCE` and `TERM=dumb` are honored.

## `scan` — scan directories for malicious files

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

## `check` — check a single file

```
lyxbosa check [options] [FILE]
```

Prompts for a path when FILE is omitted. Quarantine is always disabled. Accepts
`-c/--config` and the global options. An archive is checked like the directory it is:
the exposure finding lands on the file, and each member with findings is listed under
it as `archive.zip!member/path.php`.

## `validate-config` — validate a configuration file

```
lyxbosa validate-config [options] FILE
```

Reports the rule, pattern and directory counts. Exit code 0 when valid, 1 when not.

## `init-config` — print the default configuration

```
lyxbosa init-config > lyxbosa.yaml
```

## `update` — install the newest release

```
lyxbosa update            # asks first
lyxbosa update --yes      # does not
lyxbosa update --check    # reports only; downloads nothing
```

`--check` exits 0 when up to date and 2 when a newer release exists. `update` itself exits
0 when it updated or had nothing to do, and 1 on any error or refusal. What it verifies,
and what it refuses to do, are in [docs/UPDATING.md](UPDATING.md); the rules for when a
scan checks on its own, and the privacy consequence, are there too.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No matches found, or the command was cancelled |
| `1` | Error: invalid arguments, missing file, invalid configuration, a file that could not be scanned, or a refused unsafe operation |
| `2` | Matches found; for `update --check`, a newer release is available |
| `130` | Interrupted with Ctrl+C (the partial report is still written) |

An update check never contributes to any of these. A scan that could not reach the releases
API, or reached it slowly, exits exactly as it would have without the check.

## Where output goes

The report goes to **stdout**; progress and diagnostics go to **stderr**. That
separation is what makes a redirected scan watchable.

| stdout | `--output-file` | On screen | Report |
|--------|-----------------|-----------|--------|
| terminal | no | Full-screen UI, or the findings as they are found | stdout |
| terminal | yes | Full-screen UI with the readable text view | the file, in `--output` format |
| pipe or file | no | Progress line on stderr, if stderr is a terminal | stdout, in `--output` format |
| pipe or file | yes | Progress line on stderr, if stderr is a terminal | the file; stdout stays empty |

## Full-screen UI keys

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

## Examples

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
