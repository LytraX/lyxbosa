# What a scan covers

What the scanner opens, what it declines to open, and what it believes about what it read.
The first three decide *coverage* rather than correctness, which is why each of them is
counted and named in the report: a file the scanner never read is not a file it found nothing
in. The last decides whether a marker written inside a scanned file may lower the severity of
a finding, and by default it may not.

The flags and configuration keys named here are described in full in
[docs/CLI.md](CLI.md) and in the output of `lyxbosa init-config`.

- [Archives](#archives) — zip, tar, tar.gz and gz, and the backup left in the web root
- [File names](#file-names) — when the name is the attack, and what is done about it
- [Skipped files](#skipped-files) — every file the scanner did not open, counted by reason
- [Choosing `scan.max_file_size`](#choosing-scanmax_file_size) — what the cap buys, measured
- [In-file annotations](#in-file-annotations) — and why a marker is not trusted by default

## Archives

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

## Quarantine

Quarantine is off by default, and an unattended run that would move files refuses unless
`--quarantine` is given explicitly. It moves a file only for a finding about that file's
own content: an exposure finding never moves anything, in an archive or out of one.

```yaml
actions:
  quarantine:
    enabled: false
    directory: /var/quarantine
    preserve_structure: true
```

A quarantined file is evidence, so the destination is built to answer two questions: what
was this, and where was it taken from.

With `preserve_structure` — the default — the source's **whole absolute path** is mirrored
under the quarantine directory, so `/var/www/a/wp/shell.php` lands at
`<directory>/var/www/a/wp/shell.php`. A Windows root name becomes one ordinary component
(`C:` → `C`, `\\server\share` → `server_share`). Mirroring the absolute path rather than
the path relative to the scan root is what makes two files unable to arrive at one
destination: `/var/www/a/wp/shell.php` and `/var/www/b/wp/shell.php` are the same relative
path under two roots, and on a shared host that is the ordinary case rather than the
exotic one. It is also the only form that says which original a sample was — the scan root
is exactly the part a relative path drops.

Without `preserve_structure` the quarantine directory is flat and holds filenames alone.
Two samples are still both kept, but where each came from is no longer recoverable from
the destination, which is the cost of that choice.

**Nothing in a quarantine directory is ever written over.** The move is the platform's
refusing one — `renameat2(RENAME_NOREPLACE)` on Linux, `renamex_np(RENAME_EXCL)` on macOS,
`MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` on Windows — so a destination that is
already taken fails rather than replaces, and the refusal is taken by the kernel rather
than by a preceding `exists()` that anything running alongside could invalidate. A name
that is taken is stepped past with a numeric suffix (`shell.php` → `shell.1.php`) in the
same directory, so a second run into the same quarantine directory keeps the first run's
sample and its path.

A rename cannot cross a filesystem boundary, so a quarantine directory on its own mount is
handled by creating the destination exclusively, copying the bytes through it, flushing,
and unlinking the source last. That path refuses an occupied destination the same way, and
leaves the evidence in two places rather than none if it is interrupted.

**A move that fails is reported, not dropped.** A quarantine directory that cannot be
created, a destination the process may not write, a source that disappeared under the
scan — the file stays exactly where it was found, and the operator needs to know which
webshell is still under the web root. It is counted in the summary, listed on stderr, and
carried per file in both machine-readable formats:

```
Files quarantined: 4
Files NOT quarantined: 2 (still in place)
```

```json
{ "path": "/var/www/html/wp/shell.php", "quarantined": false, "quarantineFailed": true }
```

`quarantineFailed` is present only when it happened, and `filesQuarantineFailed` is
always in the summary object. CSV carries `quarantine_failed` as a new last column, so
every column before it keeps the index it had. `quarantined: false` on its own cannot
answer this — it is also what an exposure finding and a run without `--quarantine` look
like, and the difference is whether the file was moved or could not be.

The count and the list are printed under `--quiet`, which suppresses progress and the
summary. Only `--silent`, which promises no output at all, holds them back. The exit code
is unchanged by it: a quarantine failure only happens where there was a finding, so the
run already exits `2`, and the report says which files it left behind.

### Where a file went, and what happened to a finding inside a container

Every row that says a file moved also says where to. `quarantinePath` in JSON, a
`quarantine_path` column in CSV, and `moved: <path>` on the readable line in both the
verbose and the compact view.

A finding inside an archive is reported as its own row, addressed
`backup.zip!wp-content/uploads/shell.php`. Malware in a member quarantines the
**container**, which goes as a unit and carries every member with it, so such a row
carries two paths and they answer different questions:

| field | answer |
|---|---|
| `path` | where it was found — never rewritten by a move, so it still matches an earlier report and an operator's own notes |
| `quarantinePath` | where the bytes are now, addressed under the container's destination in the same `archive!member` form |

```json
{
  "path": "/var/www/html/backup.zip!wp-content/uploads/shell.php",
  "quarantined": false,
  "quarantinePath": "/var/quarantine/var/www/html/backup.zip!wp-content/uploads/shell.php",
  "containerQuarantine": "moved"
}
```

**`quarantined` stays `false` on such a row, and that is not the fact to read.** A member
is not a file that was moved — `filesQuarantined` counts containers and loose files, and a
member claiming otherwise would make the rows disagree with the count. `containerQuarantine`
is the fact, it is a string rather than a flag, and it has three answers:

| value | meaning | what it asks of the operator |
|---|---|---|
| `moved` | the container was quarantined; these bytes left the tree inside it | nothing further |
| `moveFailed` | the container was selected and could not be moved | the webshell is still under the web root, at the same URL |
| *absent* | no quarantine decision was taken about the container | nothing was attempted: quarantine off, `--dry-run`, or an exposure-only finding |

The readable views say the same two things in words — `moved with its container: <path>`
and `container NOT quarantined - still at <path>` — and the full-screen view shows them as
chips on the finding's own line. CSV carries `container_quarantine`, empty when no decision
was taken.

## File names

A file's name is chosen by whoever uploaded it, and on a compromised host it is sometimes
the attack rather than a label on one. `x$(sleep 20)y.mdb` is evidence whatever is inside
it: somebody wrote a command substitution into a name hoping that something downstream —
a backup script, a log pipeline, a cron job building an argument list — would hand it to a
shell.

Six rules read the name. They are ordinary findings: they carry a severity, they appear in
the text, JSON and CSV reports beside every other finding, and they move the exit code to
`2` like any other match.

| code | severity | what it reads |
|---|---|---|
| FN001 | High | `$(...)`, a backtick pair or `${...}` — a shell would execute it |
| FN002 | Medium | a double quote, semicolon, pipe or backslash — ends an argument or a command |
| FN003 | Medium | a byte below `0x20` — splits a log line, a report row or a `read`-per-line pipeline |
| FN004 | Medium | a leading `-`, which a glob expansion hands to the next command as an option |
| FN005 | High | a dot-dot against a character that resembles a separator without being one |
| FN006 | High | `%00`, which truncates the name in anything that percent-decodes it |

Disable them like any other rule, by code or by category:

```yaml
builtin_rules:
  disable: [FN004]        # a tree of files whose names legitimately start with a dash
```

**A name finding never quarantines the file.** Quarantine acts on bytes, and these rules
have not read any: the file is very likely the customer's own database with a hostile
string written on the outside of it. Moving it would also carry that string into the
quarantine directory, which is the directory an operator is most likely to sweep later
with a shell loop. A file carrying a name finding *and* a content signature is still
quarantined, on the strength of the signature. The remedy for a hostile name is to delete
it or rename it, and which of those it is depends on whether anybody needs the file.

**`scan.include` does not hide a name.** That list decides what gets *opened*, and a name
costs no open — so a file no include pattern covers is still reported when its name is a
finding, with its row saying plainly that the bytes were never read. `scan.exclude` is the
other intention and is obeyed: a pattern the operator wrote to keep a tree out of the scan
keeps it out of this too.

**Volume.** One automated vulnerability scanner left 83 such names in a single upload
directory, and a worse host gives thousands. The summary rolls them up on one line rather
than repeating them:

```
Files with matches: 4118
Files with a hostile name: 4102 (the name is the finding; the bytes may be ordinary)
```

JSON carries the same count as `filesWithHostileNames`, always present.

### How a name is printed, and how a program gets back to the file

A name is untrusted text on its way to a terminal and untrusted *bytes* on its way to a
program, and a report owes both.

**The rendering.** Every path in every output goes through one escape before it is written.
Control bytes and DEL become a visible `\x0a`, `\x09`, `\x1b` and so on, and so does any
byte that is not part of well-formed UTF-8 — including overlong forms such as `c0 af`,
surrogates and anything past U+10FFFF. Well-formed UTF-8 is left exactly alone, so a name
in Greek, Japanese or French prints as it is. Two things depend on this. A terminal is the
one consumer that cannot be handed the bytes, because a name carrying `ESC ] 52 ; c ;` is
not text there but an instruction that writes the reader's clipboard. And a JSON document
has to stay valid UTF-8 or no parser will accept it, and a file name on a Linux host may be
any bytes at all.

**The bytes.** That escape is one-way — a backslash already in a name is written through
unchanged, so a file named with the six characters `a\x0ab` renders like one named `a`, a
newline, `b` — which is fine for a person and useless to a program that has to open, match
or delete the exact file. So a path the rendering could not carry exactly is accompanied by
its bytes in hex:

| output | field |
|---|---|
| JSON | `pathBytesHex`, and `quarantinePathBytesHex`, present only when that path's rendering is inexact |
| CSV | `file_bytes_hex` and `quarantine_path_bytes_hex`, the last two columns, empty otherwise |
| text | nothing — this is the terminal, and the rendering is the point |

A consumer that needs the real name reads the hex field when it is there and the rendered
path when it is not. Its presence *is* the statement that the path beside it is a rendering
rather than a name. An ordinary tree produces none of them, and in practice a Windows tree
produces none either: NTFS stores names as UTF-16 and the narrow API converts on the way in,
so a name that is not valid UTF-8 cannot exist there — it becomes whatever characters the
host's code page maps those bytes to, at the moment the file is created.

Hex rather than a reversible escape, deliberately. Doubling every backslash would make the
rendering reversible and would also rewrite every path in every report produced on Windows,
where the separator *is* a backslash — a break for every existing consumer, to pay for a
case that is rare. Hex is additive, has no escaping rules of its own to get wrong, and is
what a loader wants anyway.

### What this does not read

Only the final component of the path. A hostile directory name is a fact about that
directory, and putting it on every file underneath would be thousands of rows for one
thing. Archive member names are not read either — these rules are about files on disk.

On Windows, NTFS refuses several of these shapes outright, so a file created there cannot
carry them: a double quote, a pipe and every byte below `0x20` are rejected, and a trailing
space or a trailing dot is silently stripped before the name reaches the disk. A backslash
is always a separator there and never part of a name. What NTFS does accept is `$(`, a
backtick, `${`, a semicolon, `%00`, a leading dash, and both of the separator lookalikes
FN005 reads — U+FF0F and the re-encoded overlong slash — so those rules are as live on
Windows as on Linux.

## Skipped files

A file the scanner did not open is not a file it found nothing in, so every skip is
counted and named. Three things can happen to a file at the file level:

| reason | meaning |
|---|---|
| `size` | larger than `scan.max_file_size` |
| `excluded` | rejected by `scan.include` / `scan.exclude` |
| `unreadable` | `stat` or `open` failed — permissions, a race, a dead mount |

A skipped file can still carry a finding, and one line can say both. A name is knowable
without opening anything, so a file past the size limit, one that would not open and one
no include pattern covers can each raise an FN rule; the row then names the finding *and*
says the bytes were not read.

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

## Symlinks, and directories the walk will not re-enter

`scan.follow_symlinks` is `false` by default. A linked directory is not descended into
and a linked file is not read; both are simply not part of the scan. Turn it on and the
walk treats a link to a directory as that directory.

A tree can lead back into itself — a link pointing at a directory the walk is already
inside is the ordinary way, and a network or FUSE filesystem can present one with no link
in it at all. The walk asks the host which directory each path actually is, using the
device and inode pair on POSIX and the volume serial and file id on Windows, and declines
to enter one whose identity is already open above it on the same path. Those are counted:

```
Directories not re-entered: 2 (a loop - each is already open above it, and was read there)
```

**This is not a coverage gap and it does not change the exit code.** The directory that
was declined is the one already open above it, and its contents are read there. Only the
path is refused, never the content. The count is in the summary and in JSON as
`directoriesCycleSkipped`, because a directory total larger than an operator expected
should have an explanation, and because a loop under a web root is worth knowing about.

Two paths that reach the same directory without one being inside the other — a bind
mount presenting one tree at two places — are both walked, and their files are reported
under both paths. Refusing the second would be quicker and would drop a subtree from the
scan without saying so.

Traversal has no depth or breadth limit. Ctrl+C is what bounds a tree that is expensive
rather than looping: the walk polls for it as it reads each directory entry, not only
between files, so a tree holding no regular file at all still stops.

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

CSV carries `skipped`, `skip_reason`, `quarantine_failed`, `quarantine_path` and
`container_quarantine` as its last five columns, and a file with no matches — one that was
skipped, or a container whose quarantine outcome is the only thing to say about it — gets a
row with the rule, severity, line and column fields empty:

```
file,rule,severity,original_severity,suppressed,category,line,column,quarantined,skipped,skip_reason,quarantine_failed,quarantine_path,container_quarantine
/var/www/html/backup.zip,,,,false,,,,false,true,size,false,,
```

Every column is appended rather than inserted, so a reader consuming this format by
position keeps the indexes it already had.

`check` reports it the same way for a single file — an oversize or unreadable file prints
`Not scanned (over size limit)` and exits `1`, so "no matches found" always means the
bytes were read.

That holds one level down as well. A container `check` opened and could not read whole —
a truncated gzip, a member past `archives.max_member_size`, a guard that stopped the
stream — prints `Not fully examined`, names what was not covered in the scan summary's
own words, and exits `1`. Members the selection policy did not open are the one reason
that does not: they are the container-level counterpart of an excluded loose file, so
they are counted and named and the exit code stays `0`, with the verdict reading `No
matches found in what was scanned of:` rather than claiming the container was read
whole. The full table is in [docs/CLI.md](CLI.md#check--check-a-single-file).

An oversize *container* is not a skipped file in either command: its index is read and
its members are scanned, which is why raising `scan.max_file_size` to reach a large
backup is unnecessary.

Excluded files are always *counted*, so you can tell whether a pattern took effect, but
only *listed* on request: globs are how people cut `node_modules` out of a scan, and on
a real tree the excluded files outnumber the findings by orders of magnitude.

```yaml
scan:
  report_excluded: false   # true = emit a per-file record for every excluded file
```

## Choosing `scan.max_file_size`

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

## In-file annotations

A `// nolint`, `# noqa`, `phpcs:ignore`, `// eslint-disable`, `@SuppressWarnings` or
`// NOSONAR` on a matched line, or on the line before it, can mark that finding as
suppressed: it is reported at severity `low` with the original severity kept beside it
(`[SUPPRESSED:CRITICAL]` in text, `originalSeverity` and `suppressed: true` in JSON, the
`original_severity` and `suppressed` columns in CSV), it is still counted, and `check`
still exits 2.

**Whether a marker is obeyed is decided by the configuration, and by default it is not.**

```yaml
annotations:
  trust: false   # true = obey markers written inside the scanned files
```

The marker is inside the file being judged, and the two ways this tool is used read that
in opposite ways. On a repository you wrote, or a plugin you maintain, the marker is your
note that a line is a known false positive, and `trust: true` is the feature. On a web
root an attacker has written to, the file is the attacker's and so is the marker:
`$x = "FilesMan"; // nolint` would report a critical webshell signature as `low`, and
`low` is what a quarantine threshold, an alerting rule or a report filter reads. Nothing
in the file tells the two cases apart; only you know which scan this is. A scan with
`trust: true` says so in a warning before it starts.

The marker is matched as a substring of the line, not parsed as a comment, so under
`trust: true` the same bytes inside a string literal count too, and a marker one line
above a match counts even when it was written about a different line. That is the trade
of trusting the author: a suppression they did not mean is a `low` finding they still see.
