# What a scan covers

What the scanner opens, what it declines to open, and what it believes about what it read.
The first three decide *coverage* rather than correctness, which is why each of them is
counted and named in the report: a file the scanner never read is not a file it found nothing
in. The last decides whether a marker written inside a scanned file may lower the severity of
a finding, and by default it may not.

The flags and configuration keys named here are described in full in
[docs/CLI.md](CLI.md) and in the output of `lyxbosa init-config`. The configuration file is
read as UTF-8; what each platform does with a path or pattern in it that is not UTF-8 is under
`validate-config` there.

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
reason (`not code`, `excluded by filters`, `sidecar metadata`, `over size limit`,
`budget spent`, `compression ratio`, `too deeply nested`, `corrupt`) in the summary and in
the JSON report. The reasons are described under [Skipped files](#skipped-files).

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
`backup.zip!wp-content/uploads/shell.php` — the container's path, `!`, and the member's name
as the archive stores it (see *Where a member sits*). Malware in a member quarantines the
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

Seven rules read the name. They are ordinary findings: they carry a severity, they appear in
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
| FN007 | High | a `..` component, or a leading `/`, `\` or drive letter and colon, under either separator — extracting it writes outside the destination |

**FN007 reads the name whole.** A file on Linux may be named `..\..\index.php`, and the
backup that copies it stores exactly that member name; a Windows extractor splits it on the
backslashes and writes `index.php` two directories above where it was asked to. So FN007
splits a name on `/` and on `\` alike, on a loose file's name and on a member's whole stored
name, and a file and a member with the same name answer the same. On Windows no file name
holds a separator, a colon or a `..` component, so on disk FN007 reads nothing there; inside
an archive it reads the same on every platform. Probe archives holding each shape were
extracted with PHP's `ZipArchive`, PclZip, WordPress's `unzip_file`, Info-ZIP `unzip`, 7-Zip,
Python, GNU tar and PharData on Linux, and with PHP, Expand-Archive, bsdtar and Python on
Windows: PclZip called directly wrote outside its destination through `../` on Linux and
through `../` and `..\` on Windows, and every hardened extractor refused or stripped each
shape. A component of three or more dots is not a `..` component, and stayed inside the
destination or failed with every extractor.

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
keeps it out of this too, whether or not the include list covers the file.

**Volume.** One automated vulnerability scanner left 83 such names in a single upload
directory, and a worse host gives thousands. The summary rolls them up on one line rather
than repeating them:

```
Files with matches: 4118
Files with a hostile name: 4102 (the name is the finding; the bytes may be ordinary)
```

JSON carries the same count as `filesWithHostileNames`, always present.

### Names inside archives

A member of an uploaded zip named `x$(sleep 20)y.mdb` is the same evidence as a file on
disk named that way, so the same seven rules read member names, in zip, tar and tar.gz, at
every depth the scan opens. A member whose name raises a finding gets a row addressed
`upload.zip!docs/x$(sleep 20)y.mdb`, like any other member row.

**Which names are read.** A member's name is in the archive's index or header, so it is
known without opening the member, and the file-level rule applies unchanged. What decides
whether a member is *opened* — the selection that leaves non-code members shut,
`scan.include`, the sidecar entries a Mac writes, `archives.max_member_size` and the
expansion, ratio and time budgets — does not hide its name. Such a row carries the reason
its bytes were not read, in the same field a loose file's does: `skipReason` in JSON, the
`skip_reason` column in CSV, and `(not scanned: policy)` in the text report, in the
spellings the archive summary counts it under — `policy`, `excluded`, `sidecar`, `size`,
`budget`, `ratio` and `corrupt`. A member `scan.include` does not name reads `excluded`, as
the file of its name does. `scan.exclude` is obeyed for a member's name as for a file's. A member the
scan never reaches has no name to read: one inside an archive nested past
`archives.max_depth`, one after a guard stopped a tar stream, and one after an interrupt.
A single `.gz` stores no member name the scanner reads — its member is named from the
container's own file name, which is read as the file it is.

**Separators.** FN001 to FN006 read the final component, as for a file. Two readings decide
what separates the components, and the platform the scan runs on is never one of them:

| entry | separators |
|---|---|
| a zip entry whose host byte is MS-DOS, Windows NTFS or VFAT (0, 10 or 14) | `/` and `\` |
| any entry of a zip whose names use only backslashes | `/` and `\` |
| any other zip entry | `/` only |
| a tar member | `/` only |

A zip's names use only backslashes when no name in it holds a forward slash except as the
trailing slash of a directory entry — the `sub/` PHP's `addEmptyDir()` writes beside
backslash-spelled files — so that every separator any name holds is a backslash. The host
byte is asked per entry, since one archive can hold entries two tools added; the names are
asked per archive; and a zip inside a zip is asked about its own entries and names alone.

Neither reading is what one extractor does, because no two platforms agree. Every Windows
extractor measured — PHP's `ZipArchive`, PclZip, WordPress's `unzip_file`, Expand-Archive,
bsdtar, Python — makes directories of backslashes whatever the host byte. On Linux, PHP's
`ZipArchive`, PclZip, 7-Zip and Python keep a backslash as a character under every host byte,
and Info-ZIP's `unzip` splits one only under host byte 0 and only in a name that holds no `/`.
The readings are the writers' claims: Windows PowerShell 5.1's `Compress-Archive` and .NET
Framework's `ZipFile.CreateFromDirectory` store `site\wp-content\index.php` under host byte 0,
and PHP's `ZipArchive` records host byte 3 on Windows too while a PHP backup script there
stores every path as the directory iterator spells it — `site\index.php` — so that nothing in
the archive but its names says a Windows host wrote it. Read either way, such a backup raises
nothing for its separators and is still read for a hostile final component. Where neither
applies the backslash is a character and raises FN002: beside forward-slash names, a
Unix-made `uploads/a\zz.php` extracts on Linux as one file with a backslash in its name.

No reading withholds FN007, which splits the whole stored name both ways whatever the
readings say: a zip read as backslash-separated is exactly the one in which `..\..\` climbs.
And no reading reaches anything but the name rules — see *Where a member sits*.

A tar header stores a member's name as bytes, which need not be UTF-8. On Linux the address
carries them as they are, escaped and with `pathBytesHex` beside it like a file name. On
Windows a path cannot hold them, so the address shows U+FFFD for each byte that is not part of
well-formed UTF-8. The rules read the bytes the header holds either way.

**Quarantine and exit code.** A name finding on a member never moves its container, just
as it never moves a file; only hostile content inside does. A member row with a name
finding moves the exit code to `2`, and counts in `Files with matches` and
`Files with a hostile name` like a loose file's.

### Where a member sits

A member's name is written by whoever made the archive — or, in a backup, by whoever named
the file the backup copied — so nothing about where a member sits may be read from it that
the name does not really say.

**The address.** A member row is addressed by the container's path, `!`, and the member's name
exactly as the archive stores it: backslashes, a leading `./` and a leading `/` included. Two
members the archive holds apart are two rows, in the JSON, CSV and text reports, the
full-screen view and `check`: `src\vendor\x.php` and `src/vendor/x.php` are different entries,
and so are `./src/x.php` and `src/x.php`. The name is escaped for printing like any file name,
with `pathBytesHex` beside it when the escape lost something.

**What a location prior reads.** A context filter that drops a finding because of where a file
sits — under `vendor/`, `tests/`, `.ssh/`, a page builder's plugin directory — reads a member's
location as the container's directories on disk followed by the member's stored name. Only
directories that exist count: the ones the container sits in, and the ones the member's name
has between its forward slashes. A backslash in a member's name is never one of them, on any
platform, under any host byte and under either reading above. On Linux a file named
`tests\shell.php` keeps that name in the backup a PHP, Info-ZIP, 7-Zip, Python, Go or tar
archiver makes of it, and the backup is judged as the file is. The container's own file name
is not a directory either: an upload named `revslider-6.7.zip` grants its members no prior,
and a nested archive's name grants its members none. On Windows the container's path, where a
backslash is always a separator, is the only part read with backslashes as slashes.

**Patterns.** `scan.include` and `scan.exclude` are asked about a file and about a member by one
matcher, the same on every platform and against every C library, so that a file and the member
a backup makes of it answer every pattern alike. A file is asked about its path with `/` as the
separator: on Windows every backslash in it has become `/`, which is exact there, and on Linux
the path is the name's own bytes, a backslash included. A member is asked about the path it has
beside its archive: the archive's directory, then the member's stored name without its leading
`./` or `/`, a backslash in it a character. A pattern is matched against the final component —
everything after the last `/` — and, when it holds `**`, against the whole path. The matcher
answers as glibc's `fnmatch(3)` does with `FNM_PATHNAME`, so `*` and `**` alike stop at a `/`,
a bracket expression is a character class, and a backslash quotes the character after it. The
scanner carries it rather than calling the C library's: musl's `fnmatch(3)` answers two shapes
POSIX leaves undefined differently — a trailing backslash, and a backslash inside a bracket
expression — and Windows has none. Because a path is absolute, `vendor/**` names nothing on disk
and nothing inside an archive; a pattern that begins with a directory, such as
`/var/www/site/vendor/**`, names what sits directly in that directory, as a file or as a member
of an archive stored there, and `vendor\x.php` is not in it. The patterns are asked of a member
before anything else about it, as they are of a file, so a member they keep shut is counted as
`excluded` whether or not it is code and whether or not it is a sidecar, and a member and the
file of its name are counted alike. The stored name alone decides the sidecar test: a Mac's
`__MACOSX/` tree and `._name` stubs are left shut and counted as `sidecar`, and a member named
`uploads/__MACOSX\x.php` is not one of them.

### How a name is printed, and how a program gets back to the file

A name is untrusted text on its way to a terminal and untrusted *bytes* on its way to a
program, and a report owes both.

**The rendering.** Every path in every output goes through one escape before it is written.
Control bytes and DEL become a visible `\x0a`, `\x09`, `\x1b` and so on, and so does any
byte that is not part of well-formed UTF-8 — including overlong forms such as `c0 af`,
surrogates and anything past U+10FFFF. The C1 controls, U+0080 to U+009F, are well-formed
UTF-8 and are escaped all the same, one escape per byte: U+009B, which some terminals take
for `ESC [`, prints as `\xc2\x9b`. Every other well-formed character is left exactly alone,
so a name in Greek, Japanese or French prints as it is. Two things depend on this. A terminal is the
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
rather than a name. An ordinary tree produces none of them.

**The bytes are UTF-8, on every platform.** On Linux they are the name's own bytes, whatever
those are. On Windows NTFS stores a name as UTF-16, and the scanner converts it to UTF-8 and
back directly, never through the host's ANSI code page — so a program on Windows gets back to
the file by decoding the hex as UTF-8, and decoding it in the code page names a different
file. A name that is not valid UTF-8 cannot exist on NTFS, and NTFS refuses the C0 controls,
so a Windows tree carries the field for a name holding DEL or a C1 control such as U+009B. One
Windows name has no UTF-8 spelling at all: one holding an unpaired surrogate, which NTFS
accepts. It is scanned and reported with U+FFFD in the surrogate's place, and neither the
rendering nor the hex leads back to it.

Hex rather than a reversible escape, deliberately. Doubling every backslash would make the
rendering reversible and would also rewrite every path in every report produced on Windows,
where the separator *is* a backslash — a break for every existing consumer, to pay for a
case that is rare. Hex is additive, has no escaping rules of its own to get wrong, and is
what a loader wants anyway.

### What this does not read

Only the final component of the path, on disk and inside an archive. A hostile directory
name is a fact about that directory, and putting it on every file underneath would be
thousands of rows for one thing.

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

An archive member that is not scanned is counted under one of eight reasons, in
`archives.membersSkipped` and in the `Members not scanned` line. The first three are the
selection, asked in the order shown before any size or guard, so a member more than one of
them fits is counted under the first:

| reason | summary | meaning |
|---|---|---|
| `excluded` | `excluded by filters` | rejected by `scan.include` / `scan.exclude`, asked of the path the member has beside its archive |
| `sidecar` | `sidecar metadata` | an entry an archiver writes about the files rather than a file: `__MACOSX/`, `._name`, `.DS_Store`, `Thumbs.db` |
| `policy` | `not code` | neither a script nor markup, outside `archives.exhaustive`; or a member whose name is empty once its leading `./` and separators are read |
| `size` | `over size limit` | larger than `archives.max_member_size` |
| `budget` | `budget spent` | `archives.max_expansion` or `archives.time_budget` ran out |
| `ratio` | `compression ratio` | the archive expanded faster than `archives.max_ratio` |
| `depth` | `too deeply nested` | an archive nested deeper than `archives.max_depth` |
| `corrupt` | `corrupt` | truncated, encrypted or otherwise unreadable |

`excluded` is the file-level reason, in the file level's words: a file and a member one
pattern rejects are counted alike, each at its own level. A sidecar is counted apart from
`not code` because a `._index.php` is named like code, and it is left shut in exhaustive
mode too. A directory entry is not a member and is counted nowhere — not as scanned, not
as skipped, and not in the progress total.

Both levels read the same way in the summary, and a reason that did not occur is left out of
its line:

```
Files scanned: 482013
Directories parsed: 39544
Files with matches: 12
Files not scanned: 208 (183 over size limit, 18 excluded by filters, 7 unreadable)
Directories unreadable: 2
Archives opened: 41 (18022 members scanned, 3.1 GB expanded)
Members not scanned: 906 (862 not code, 12 excluded by filters, 30 over size limit, 2 corrupt)
```

`Directories unreadable` is a coverage fact too: a directory the scanner was pointed at
and could not list is reported rather than treated as empty. That includes a subdirectory
of a directory the scanning user may list but not search, which is entered and cannot be
listed.

An entry the host will not describe is a third. When the scanner cannot ask whether an
entry is a file or a directory — an app execution alias in a Windows profile, or, with
`scan.follow_symlinks` on, a link to something behind a directory the scanning user may not
search — nothing behind it is read, and it is counted:

```
Entries unreadable: 3 (the host would not say whether each is a file or a directory - none was scanned)
```

The line appears only when the count is not zero, and in JSON the count is
`entriesUnreadable`, always present. It is in neither `Files not scanned` nor `Directories
unreadable`, because each of those says what the thing was, and the directory the entry was
listed in is not reported unreadable: it was read. With `scan.follow_symlinks` off, a link is
recognised as a link before anything asks what it leads to, so a link the scanner cannot see
through is counted in `Links not followed` below and never here. A link that leads nowhere —
one whose target is gone, or one that leads back to itself, directly or around a ring of
links — is not counted under either setting.
Like the unreadable directories beside it, **it does not change the exit code**.

A FIFO, a socket or a device node is neither read nor counted. None of them has contents a
scan could read — reading a FIFO waits for a writer that may never come — so passing one by
leaves nothing out. On Windows the scanner cannot ask an AF_UNIX socket file its type, so
there a socket is counted with the entries above.

## Symlinks, junctions, and directories the walk will not re-enter

`scan.follow_symlinks` is `false` by default. A linked directory is not descended into
and a linked file is not read. Turn it on and the walk treats a link as what it leads to.

A link is a symbolic link on every platform and, on Windows, a **directory junction** as
well — what `mklink /J` makes. A junction needs no privilege to create and can point
anywhere on the machine, so it takes exactly the rule a directory symbolic link takes.

Two things on Windows share part of a link's machinery and are not links:

- **A volume mount point** — a volume attached at a folder instead of a drive letter — is
  walked like any other directory whatever `follow_symlinks` says, as a mount is on Linux.
  It carries the same reparse tag as a junction, and the walk tells them apart by what the
  file system stores for it: the root of a volume, where a junction stores a directory. The
  volume holds content reachable by no other path under the root.
- **Every other reparse point** — a OneDrive or other cloud placeholder, a deduplicated
  file — is the file or directory it presents, and is scanned as one. None of them is
  decided by name. An app execution alias is not a link either, but the scanner cannot ask
  one what it is, so it is counted as an entry it could not read — see
  [Skipped files](#skipped-files).

When the file system will not return what a junction-tagged entry stores, the walk goes
through it as a directory: an unwanted walk through a link costs time, which the loop check
below and Ctrl+C bound, and a refused directory would cost coverage that nothing recovers.

A root named on the command line or in `scan.directories` is walked even when it is itself
a link or a junction. The setting is about the links the walk finds inside the tree, and so
is the count below; the pre-count behind the progress bar applies the same rule.

Whatever is reachable only through a link the walk did not follow was not scanned, and no
other count in the report goes down when that happens, so the links are counted:

```
Links not followed: 3 (scan.follow_symlinks is off - anything reached only through them was not scanned)
```

The line appears only when the count is not zero, and in JSON the count is
`linksNotFollowed`, always present. It includes a link whose target the scanner may not look
at — one into a directory the scanning user may not search — because it may lead to a file
or a tree, and with the setting off neither was going to be read; with the setting on, the
same link is counted in `Entries unreadable` instead. A link to a directory is not counted by
a scan that does not recurse, which enters no directory either way. A link that leads nowhere,
dangling or leading back to itself, is not counted, and nothing is counted with the setting on. **It does not change the exit code**: the configuration
asked for links not to be followed, as an exclude pattern asks for files not to be read.

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
an object shaped like `archives.membersSkipped`, which carries every member-level reason
at zero or more whenever an archive was opened:

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
"directoriesUnreadable": 2,
"entriesUnreadable": 3
```

```json
"membersSkipped": { "policy": 862, "size": 30, "budget": 0, "ratio": 0, "depth": 0,
                    "corrupt": 2, "excluded": 12, "sidecar": 0 }
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
own words, and exits `1`. Members left shut by selection — `not code`, `excluded by
filters` and `sidecar metadata` — are the reasons that do not: they are the
container-level counterpart of an excluded loose file, so they are counted and named and
the exit code stays `0`, with the verdict reading `No matches found in what was scanned
of:` rather than claiming the container was read whole. The full table is in [docs/CLI.md](CLI.md#check--check-a-single-file).

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
