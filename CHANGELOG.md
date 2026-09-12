# Changelog

Written for people running the scanner: what it detects, what it reports, and what a
configuration or a calling script has to do differently.

**Scope: detection rules (by rule code), the CLI, report and output formats, and binary
releases.** Versions are the `v*` git tags described in [docs/RELEASING.md](docs/RELEASING.md).

**The corpus has its own changelog**, [`corpus/CHANGELOG.md`](corpus/CHANGELOG.md), versioned
on the `corpus-YYYY.MM.N` tags. The sample index, the published shards, masking and publication
gates, the tooling under `corpus/`, and corpus-wide measurement rounds are all there and not
here — this file was previously carrying them under `Unreleased`, which meant it asserted
*unreleased* about work that had already shipped in `corpus-2026.09.1`. A rule's own entry —
what it matches and what it measured — is here; the corpus-wide coverage figure that moved when
it landed is there, because that denominator is the corpus's and moves without any rule
changing.

This file starts at 2.1.0. For anything earlier, the GitHub release notes carry a
commit list that CI generates per tag.

---

## Unreleased

### Added

- **Six rules that read a file's name rather than its bytes (`FN001`-`FN006`).** On a
  compromised host the name is sometimes the attack: a file called `x$(sleep 20)y.mdb` is
  evidence whatever is inside it, because somebody wrote a command substitution into a
  name hoping something downstream would hand it to a shell.

  | code | severity | what it reads |
  |---|---|---|
  | `FN001` | High | `$(...)`, a backtick pair or `${...}` |
  | `FN002` | Medium | a double quote, semicolon, pipe or backslash |
  | `FN003` | Medium | a byte below `0x20` |
  | `FN004` | Medium | a leading `-`, which a glob hands to the next command as an option |
  | `FN005` | High | a dot-dot against a character that resembles a separator without being one |
  | `FN006` | High | `%00` |

  Six rules rather than one because they are six intentions with six different next
  questions, and because a tree of files whose names legitimately begin with a dash has a
  reason to disable `FN004` and none to disable `FN001`. They are disabled by code or by
  `category:filename` like any other rule.

  **Where the line is.** Measured against 22,728 files an automated vulnerability scanner
  left in an upload directory on a production server. The character set these rules read
  fires on 83 of them and every one of the 83 is the scanner's — precision 100%. Adding
  the apostrophe and the ampersand takes it to 175 files, of which 89 are ordinary
  customer uploads, and precision falls to 49%: `O'Brien & Sons Invoice.pdf` is what real
  file names look like. Neither character appears in any rule. Two places are tighter than
  the measured set at no cost to recall: a bare `$` does not fire, because `~$Report.docx`
  is the lock file Word and Excel write beside an open document, and a bare `..` does not,
  because a name has no separators in it and `photo_2_final..jpg` is a doubled extension
  dot. Against 268,853 real file names from CMS, site and malware trees the whole rule set
  fires zero times.

  **A name finding never quarantines the file.** Quarantine acts on bytes and these rules
  have read none: the file is very likely the customer's own database with a hostile string
  written on the outside of it, and moving it would carry that string into the quarantine
  directory. A file carrying a name finding *and* a content signature is still quarantined,
  on the strength of the signature.

  **`scan.include` does not hide a name.** That list decides what gets opened, and a name
  costs no open — 73 of the 83 observed names are `.mdb`, which no include pattern covers.
  Such a file is reported with its row saying plainly that the bytes were never read.
  `scan.exclude` is the operator saying *do not look here* and is obeyed.

### Fixed

- **A file name carrying bytes that are not valid UTF-8 no longer makes the report invalid
  UTF-8.** Control bytes in a name were escaped into a visible `\x0a` and quoted correctly
  in CSV, but any byte from `0x80` up was written through raw — so a name containing, say,
  `c0 af` produced a JSON document that a standard parser refuses outright. The two halves
  of one question were answered differently by one code path.

  Every byte that is not part of a well-formed UTF-8 sequence is now escaped the same way a
  control byte already was, including overlong forms, surrogates and anything past
  U+10FFFF. Well-formed UTF-8 is still left exactly alone, so a name or a quoted excerpt in
  Greek, Japanese or French is unchanged. The bytes are preserved in the escape rather than
  replaced with U+FFFD, because an operator has to be able to get from the report back to
  the file.

  The escape is **one-way, and the machine-readable reports now carry the bytes beside it.**
  A backslash already in the name is written through unchanged, so a file whose name really
  is the six characters `a\x0ab` prints identically to one named `a`, a newline, `b`. That
  is fine for a person at a terminal — the one consumer that cannot be handed the bytes,
  since a name carrying `ESC ] 52 ; c ;` writes their clipboard — and useless to an external
  program that has to open, match or delete the exact file. So JSON gains `pathBytesHex` and
  `quarantinePathBytesHex`, and CSV gains `file_bytes_hex` and `quarantine_path_bytes_hex`,
  carrying the path in hex whenever its rendering is inexact. The JSON document stays valid
  UTF-8 and every parser still reads it.

  Hex rather than a reversible escape: doubling every backslash would make the rendering
  reversible and would also rewrite every path in every report produced on Windows, where
  the separator is a backslash — a break for every existing consumer, to pay for a case
  that is rare.

- **A skipped file no longer swallows a finding in the text report.** A file the scanner did
  not open can still carry a name finding, and the text printer returned on the skip before
  it printed any match — so JSON and CSV named the finding and the text report did not.
  Both text views now print the skip and the finding, the compact line carrying
  `(not scanned: <reason>)` after the severity counts.

### Compatibility

- **New rule codes `FN001`-`FN006` appear in reports**, in the `category` field of a JSON
  match, the `category` column of a CSV row and the rule line of the text report. A
  consumer with a fixed list of rule codes, or one that maps a code to a remediation, sees
  six it does not know. They can be turned off with `builtin_rules.disable: [FN001, ...]`
  or `category:filename`.
- **`scan` exits 2 where it exited 0** on a tree holding a file with a hostile name and
  nothing else. A name finding is an ordinary finding and moves the exit code like any
  other match.
- **Files no `scan.include` pattern covers can now appear in a report.** They are still
  counted as `excluded` and their bytes are still not read; what is new is a row for one
  whose *name* is a finding. `report_excluded` is unchanged and still off by default — it
  governs rows for excluded files with nothing to say about them.
- **JSON gains `filesWithHostileNames`**, always present, beside `filesWithMatches`.
- **The text summary gains `Files with a hostile name: N`** when the count is not zero.
  Suppressed by `--quiet` with the rest of the summary.
- **The compact text line gains `(not scanned: <reason>)`** on a file that was skipped and
  still carried a finding, and the verbose view now prints that file's matches under its
  skip line. A file that was skipped with nothing found prints exactly what it did before.
- **A path or a quoted excerpt containing bytes that are not valid UTF-8 now renders as
  `\xNN` escapes rather than raw bytes.** A consumer that was reading those bytes back out
  of a report was reading from a document no standard JSON parser would accept; one that
  parsed reports successfully is unaffected, because such a document never parsed.
- **JSON gains `pathBytesHex` and `quarantinePathBytesHex`**, each present on a file only
  when that path's rendering is inexact — never in an ordinary tree. A consumer that needs
  the real bytes reads the hex when it is there and the rendered path when it is not.
- **CSV gains `file_bytes_hex` and `quarantine_path_bytes_hex` as its last two columns.**
  Appended, so every existing column keeps its index — `container_quarantine` is still
  index 13 and is no longer the last field on the line. A reader that takes the last field
  positionally rather than by header name needs adjusting. Both are empty for every path
  the escape rendered exactly.
- **`check` escapes the path it was given.** It printed `File: <path>` and its three
  verdict lines with the raw argument, so a file named with an ESC sequence reached the
  terminal unescaped from the one command most likely to be pointed at a single suspicious
  file. The member lines in the same output had always been escaped.

### Fixed

- **Three commands no longer report an operation that did not happen as one that did.**
  One defect in three places, so one entry.

  `check` printed `No matches found` and exited `0` for an archive whose contents were
  never examined — a truncated gzip of a webshell, or a member past
  `archives.max_member_size` — which is exactly what a genuinely clean file prints.
  `scan` had always named members it did not scan, by reason, in its summary; the
  coverage simply had no way to travel out of a single-file check, because the counters
  lived on the whole-scan result. They now ride on the file result, so `check` prints
  `Not fully examined` with the same sentence the scan summary uses and exits `1`.
  Members the selection policy did not open are counted and named but still exit `0`,
  with the verdict reading `No matches found in what was scanned of:` — they are the
  container-level counterpart of an excluded loose file. Findings are printed in full
  either way; where coverage is incomplete the exit code is `1` rather than `2`, because
  `2` means "these are the matches" and not "these are some of them". An oversize
  container is no longer called a skipped file by `check`, which `scan` had never done.

  A report that could not be written printed `Report written to FILE` and exited `0`. The
  stream was checked when it was opened and never afterwards, so an unattended run that
  lost its report to a full disk said nothing at all. The write, the flush and the close
  are all checked now; a failure names the path on stderr and exits `1`, which outranks
  the findings for `-O` because the report is the answer.

  A quarantine that failed was silent: no counter, no warning, no report field, so a file
  the scanner was asked to contain and could not read exactly like one quarantine was
  never enabled for. The summary now carries `Files NOT quarantined: N (still in place)`,
  stderr lists the paths, JSON gains `quarantineFailed` per file and
  `filesQuarantineFailed` in the summary, and CSV gains a `quarantine_failed` column
  appended last so every existing column keeps its index. The exit code is deliberately
  unchanged: the scan's answer is complete and says which files were left behind.

- **A finding inside a quarantined container is no longer addressed at a path that holds
  nothing, and the report says where every moved file went.** Three defects sharing one
  reproduction: a webshell in a zip that genuinely compresses, under a scanned root, with
  `--quarantine`. The container is moved, correctly — malware in a member quarantines its
  container — and the report then described the member three different ways that were all
  wrong.

  The member row was addressed `backup.zip!wp-content/uploads/shell.php` using the
  container's path *at the time it was scanned*, and the container was no longer there. An
  operator following that path found nothing, and so did a tool. It was an ordering
  property rather than a mistake in a writer: the row was published as the member was
  found, and the quarantine decision was taken afterwards. Member rows are now published
  once the container's outcome is known, so the row a report file, a terminal and the
  full-screen view each receive is the corrected one rather than a value patched up
  afterwards where only an in-process caller could see it. `path` is still where the file
  was found — it is what an earlier report and an operator's notes say — and the new
  `quarantinePath` beside it is where the bytes are now, in the same `archive!member` form.

  The member row said `quarantined: false`, which is equally what an exposure finding, a
  run with quarantine switched off and a failed move look like. A member is not a file
  that was moved, so it does not claim `quarantined`; it carries `containerQuarantine`,
  which is `moved`, `moveFailed`, or absent when nothing was attempted. `moveFailed` is
  the one an operator has to act on: the container did not go, so the webshell is still
  under the web root at the same URL.

  And the destination was known to the scanner with exactly one consumer — the `moved:`
  line of the verbose text view — so a pipeline was told a file had been quarantined and
  never told where to. It is now in JSON, in CSV, and on the readable line in the compact
  view as well as the verbose one, which is what an operator watching a `--quarantine` run
  actually reads and which previously said nothing at all about the one destructive thing
  the command does.

- **Quarantine no longer replaces one sample with another, and the destination says where
  a file came from.** With `preserve_structure` the destination was built from the path
  *relative to the scan root*, which discards which root that was: two roots holding the
  same relative path — `/var/www/a/wp/shell.php` and `/var/www/b/wp/shell.php`, the
  ordinary shape of a shared host — produced one destination, and the move replaced
  silently. The summary said two files were quarantined and one of them was gone. The same
  collision happened between two runs into one quarantine directory, which is how an
  operator uses one.

  The destination now mirrors the source's whole absolute path under the quarantine
  directory, so it cannot collide and an analyst can read the original path off it. A
  Windows root name becomes one component (`C:` → `C`). Flat mode (`preserve_structure:
  false`) still holds filenames alone and still keeps both samples.

  Separately from the destination, the move itself now refuses rather than replaces:
  `renameat2(RENAME_NOREPLACE)` on Linux, `renamex_np(RENAME_EXCL)` on macOS, and
  `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` on Windows. An occupied name is stepped
  past with a numeric suffix rather than written over. The previous flat-mode handling was
  `while (exists(dest))` followed by a rename, which is a time-of-check-to-time-of-use race
  and protected against a second file in the same run and nothing running beside it. A
  quarantine directory on a different filesystem — where a rename cannot work at all — is
  handled by an exclusive create, a copy, a flush, and unlinking the source last; it refuses
  an occupied destination the same way.

- **Malware inside an archive now quarantines the container, as documented.** A member with
  findings is reported as its own result and its compressed bytes match nothing in the
  container, so the quarantine decision — which asked only about the container's own
  matches — never saw it. A webshell in a zip that actually compresses was detected, named
  in the report, and left on disk; one in a zip too small to compress was quarantined,
  because the literal survived in the container's bytes. An exposure finding on a member
  still moves nothing, in either direction. A container moved for what was inside it now
  appears in the report as a file that was quarantined, rather than being dropped for
  carrying no match of its own.

- **A tree that leads back into itself no longer walks without end.** With
  `scan.follow_symlinks: true`, a link to a directory was queued with no question asked
  about which directory it was, so a link pointing back up the path the walk was already
  on queued that path again. A directory holding two links to itself kept the walk
  entering 33,120 directories a second, and would have entered 2.2 trillion of them —
  every one of the 2^41 paths the kernel's 40-link resolution limit allows. The walk now
  asks the host which directory a path actually is, using the device and inode pair on
  POSIX and the volume serial and file id on Windows, and declines to enter one already
  open above it on the same path. Two paths to one directory where neither is inside the
  other — a bind mount — are both still walked, because refusing the second would drop a
  subtree from the scan without saying so. The declines are counted, in the summary as
  `Directories not re-entered` and in JSON as `directoriesCycleSkipped`. Nothing was left
  uncovered, so no exit code moves.

- **Ctrl+C now stops a scan of a tree that holds no file.** Interruption was noticed only
  when a file was handed to the scanner, and a tree of directories and directory symlinks
  hands it none, so a scan of one ignored SIGINT entirely and had to be killed — and a
  scan of 200,400 empty directories that was interrupted ran to the end and reported a
  completed clean run with exit code 0. The walk polls for the interrupt as it reads each
  directory entry and as it enters each directory, so a single directory holding millions
  of entries stops too, and the scanner records that the run was cut short whether or not
  a file reached it. Both traversals honour it, including the pre-count that runs on its
  own thread.

### Compatibility

- **`check` exits 1 where it exited 0**, when a container's members could not all be read —
  a truncated archive, a member over a size limit, a spent budget, a compression ratio or a
  nesting depth. It previously printed `No matches found` and exited 0, which is what a
  genuinely clean file prints. A caller treating 0 as "this file is clean" was being told that
  about a file whose contents were never examined.
- **`check` exits 1 where it exited 2**, when there are matches *and* something went unread.
  The findings still print in full. 2 is withheld because it means "these are the matches"
  rather than "these are some of them", which is the rule `scan` already follows for a missing
  root. **A monitor keyed on 2 will see 1 on such a file**; 1 reads as "look at this", which is
  the safe direction, but a script that treats 1 as an error to skip past needs adjusting.
- **`scan` exits 1 where it exited 0**, when the report could not be written. Delivering the
  report is part of completing the command: `-O /dev/full` previously printed `Report written`
  and exited 0.
- **CSV gains `quarantine_failed` as its last column.** Appended, so every existing column
  keeps its index.
- **JSON gains two keys**: `filesQuarantineFailed` always, and `quarantineFailed` on a file
  only when true.
- **The text summary gains `Files NOT quarantined: N (still in place)`**, and the per-file
  line gains `NOT quarantined - still at <path>`. Both are held back by `--silent` only, never
  by `--quiet`: a file the tool was asked to contain and could not is not progress chatter.
- **`scan` exits 130 where it exited 0**, when a scan of a tree holding no regular file was
  interrupted. Such a run previously reported a completed clean scan.
- **JSON gains `directoriesCycleSkipped`**, always present beside `directoriesUnreadable`, and
  the text summary gains `Directories not re-entered: N` when the count is not zero. It is a
  coverage note rather than a failure — nothing was left unread — so `--quiet` suppresses it
  along with the rest of the summary. CSV is unchanged: it carries one row per match and no
  directory-level count, which is where `directoriesUnreadable` already sits.
- **JSON gains two per-file keys**, each present only when it has something to say:
  `quarantinePath`, the destination of a file that was moved, and `containerQuarantine`,
  which is `"moved"` or `"moveFailed"` on a row for a finding inside an archive. A consumer
  that enumerates keys sees two more; one that reads by name is unaffected, and a report
  from a run that moved nothing is unchanged.
- **CSV gains `quarantine_path` and `container_quarantine` as its last two columns.**
  Appended, so every existing column keeps its index — `quarantine_failed` is still index
  11 and is no longer the last field on the line. A reader that takes the last field
  positionally rather than by header name needs adjusting.
- **`quarantined: false` on an archive member no longer means the finding was not
  contained.** It never did, but there was nothing else to read; `containerQuarantine` is
  now the field that answers it. **A consumer that counted unquarantined findings by
  testing `quarantined == false` was already counting members of containers that had been
  moved**, and should test `containerQuarantine` too.
- **The compact text line gains `moved: <path>` under a file that was quarantined.** The
  verbose view already printed it; the default console view printed nothing, so a
  `--quarantine` run named no destination anywhere a human could read it. A finding inside
  a moved container gains `moved with its container: <path>`, and one whose container could
  not be moved gains `container NOT quarantined - still at <path>` in both views.

## [2.5.0] - 2026-09-11

### Added

- **One command installs the scanner, on Linux and on Windows.**
  `curl -fsSL https://github.com/LytraX/lyxbosa/releases/latest/download/install.sh | sh`,
  and `irm .../install.ps1 | iex` in PowerShell. Both scripts are published as release
  assets, so each is covered by the release's `SHA256SUMS` and by the minisign signature
  over that list — the same list and the same signature as the binaries. Every download is
  checked against it; the signature is verified when minisign is installed, and the script
  says which of the two levels of checking was achieved rather than implying the stronger
  one. `docs/INSTALL.md` writes the same steps out by hand, and says what piping a script
  into a shell does and does not give you.

  On Linux the script picks between the four Linux binaries without asking: architecture
  from `uname -m`, and the C library by finding the dynamic loader at the path the ABI fixes
  and reading the highest `GLIBC_2.N` out of the first readable `libc.so.6` — the same
  method, the same four paths and the same 2.28 floor the binary uses to decide whether to
  print its portable-build notice. A host it cannot read gets the portable build, which runs
  everywhere. The verified download is also run once before it is installed, so a standard
  build that will not start here is replaced by the portable one rather than installed.

  It installs to `/usr/local/bin` as root and `~/.local/bin` otherwise, and **refuses any
  destination under the twelve prefixes `lyxbosa update` declines to write** — an install
  under `/usr/bin` is a binary that can never update itself. On Windows it installs to
  `%LOCALAPPDATA%\Programs\lyxbosa`, which is per-user and writable for the same reason,
  and adds it to the user PATH.

  It never quietly replaces a `lyxbosa` found elsewhere on PATH, and it never crosses
  between the standard and the portable build on its own: `lyxbosa update` deliberately
  never crosses either, so a host already running the portable build keeps it and is told
  the faster one is available. `--standard` and `--portable` are how somebody crosses on
  purpose.

- **A release now publishes eight assets.** The six binaries, plus `install.sh` and
  `install.ps1`. `SHA256SUMS` covers all eight and `SHA256SUMS.minisig` signs it, so a
  release carries ten files in total.

### Changed

- **The portable-build notice no longer quotes a speed figure, and no longer claims to be
  said only once.** It said the standard build "is about 10% faster on a scan". That came
  from one tree on one machine, and the difference is a property of the work rather than of
  the two binaries: 11% over 53,977 mostly small files, 9% over 136 archives totalling
  991 MB, and 2.5% on a live server scanning 81,701 files with 301 MB of archive expansion,
  warm against warm — the most realistic of the three and nearly four times smaller than
  the number the binary was printing. A percentage compiled into a binary also cannot be
  corrected without a release. The line now says the standard build is faster and that how
  much depends on the tree and the host; the three measurements, with what each was over,
  are in `README.md` under *System support*, where they can be added to.

- **That notice is now repeated at most once every 30 days instead of only ever once.**
  Once-ever was not quiet, it was unobservable: a server scan's output scrolls, the state
  file belongs to whichever user ran the scan, the person reading the output is routinely
  not the person who installed the binary, and from outside the process "said once, months
  ago" and "never said" are the same thing. The interval is the notice's own and is
  deliberately **not** `updates.interval`: lengthening that buys less traffic to a
  rate-limited API, and it must not also silence a line that opens no socket, for the same
  reason the notice has never been gated on `updates.check`.

  Everything about when it may speak at all is unchanged: an interactive scan only, stdout
  a terminal, suppressed by `--quiet`, `--silent`, `--force`, a pipe and CI, silent unless
  the host is proven able to run the standard build, and silent on any run whose state file
  cannot be written.

  **On upgrade it does not immediately repeat itself.** The cached state file gains a
  `portable_notice_epoch` timestamp beside the `portable_notice_shown` flag it already
  carried. A file holding only the old flag knows the line was said and not when, so the
  first qualifying run writes a timestamp and prints nothing — the line is then due 30 days
  later rather than at once, and rather than never. The old key is still written as well, so
  a binary rolled back to a version that only understands it keeps its own once-ever
  behaviour instead of announcing the line again. The file lives under the cache directory
  and remains safe to delete.

### Fixed

- **An update check no longer resets the portable-build notice's interval.** Three places
  recorded what a check had found — a scan's own background check, `update --check`, and
  `update` — by building a cache record from nothing and writing it. Each wrote its own two
  fields correctly and erased every other field the file held, so any run that reached the
  network cleared the record of when that notice was last said and the line came back early.
  All three now go through one function that reads the file before changing it, which is
  also why there is one function rather than three corrected copies.

### Compatibility

- **This is a minor bump, not a patch.** A release gained two assets and the project gained
  an install method, which is new surface rather than repair.
- **A release publishes ten files rather than eight.** Six binaries and the two install
  scripts, beside the unchanged `SHA256SUMS` and its signature. A script globbing the release
  and expecting eight names will see ten; one asking for a binary by name is unaffected.
- **`install.sh` and `install.ps1` are covered by the same signature as the binaries**, so a
  reader who verifies the checksum list can verify the installer with it. Being a release
  asset does not make piping into a shell safe, and `docs/INSTALL.md` says what it does and
  does not give you.
- **Nothing about scanning changes.** Detection, the exit codes, every report format, and
  everything that runs unattended are byte for byte as before. The portable-build notice
  changed its wording and its cadence, and it remains on stderr and only when stdout is a
  terminal, so a redirected report still cannot contain it.

## [2.4.0] - 2026-09-11

### Fixed

- **A deep directory tree can no longer take the scanner off the end of a stack.** The
  walk descended by calling itself once per directory level, so a tree's depth was paid
  for in call frames - and directory depth is whatever the host's filesystem holds, which
  on a compromised site is whatever the attacker put there. It now keeps an explicit list
  of directories still to read, so depth costs no stack at all and ends where the
  filesystem ends it. Only directories are held and never the files in them, so a
  directory with ten million files in it costs the walk nothing either.

  This was reachable on the musl build in particular. A scan runs a second walk on a
  spawned thread to count files for the progress bar, and a spawned thread gets 8 MB of
  stack from glibc and 128 KB from musl, so the static build had far less room for the
  same tree. Reports are unchanged: files are now listed in a slightly different order -
  every file of a directory before anything in its subdirectories, where before a
  subdirectory's contents appeared where the subdirectory did - and nothing else about
  them moves. Detection over the whole reviewed corpus is identical on both builds.

### Added

- **The musl binary carries its own allocator**, which is most of what made it slower
  than the glibc one. musl's allocator is deliberately small and simple and a scan asks a
  great deal of it; mimalloc is now linked into the static build in its place. Measured
  over 53,977 files with the page cache warm, alternating the two binaries: the musl
  build went from 9.32, 9.38 and 9.33 seconds to 8.04, 8.11 and 8.07, against 7.43, 7.37
  and 7.39 for the glibc binary of the same commit. On a tree of small files, where
  allocation is most of the work, it is nearly all of the difference: 0.20 seconds
  becomes 0.13 against glibc's 0.11. What remains is not the allocator: jemalloc,
  linked the same way, lands on the same numbers to within a hundredth of a second on
  all three trees, and on large files neither moves much. Detection is unchanged - 730 of
  1,299, regression 131 of 131, 44 benign findings in 197,559 files read, the same as the
  glibc build. The glibc binary is unaffected; only the static build links it, because
  only the static build needed it.

- **`--version` says which build it is.** It now reads
  `2.3.0 (portable build, lyxbosa-linux-amd64-portable)` or
  `2.3.0 (standard build, lyxbosa-linux-amd64)`, which is the first question any support
  conversation asks and was previously answerable only by knowing what `file` says about
  a static binary. The version is still the first whitespace-delimited token, so a script
  reading it is unaffected.

- **A portable build on a host that did not need one says so, once.** After a scan, and
  only where the reader can act on it: somebody whose installer fell back further than it
  had to, or who fetched the wrong asset by hand. It names the standard asset, says it is
  about 10% faster, and is not repeated.

  On a host that cannot run the standard build it stays silent, because there is no choice
  to offer - and so it does not become a line about a decision the reader does not have.
  Answering that needs the host examined, which the portable build does by looking for the
  dynamic loader and reading a version out of the host's own C library. It acts only on a
  proven yes: a host it cannot read is treated exactly like one with no alternative. It is
  also silent under `--quiet`, `--silent` and `--force`, when stdout is not a terminal, in
  CI, and on any run whose state file cannot be written - the same conditions as the
  update notice, and the same state file, so there is one mechanism rather than two.

- **A portable build of the Linux binary, published beside the standard one.** Every
  release now carries `lyxbosa-linux-<arch>-portable` for amd64 and arm64 as well as
  `lyxbosa-linux-<arch>`. The standard build is linked against the glibc of AlmaLinux 8 and
  refuses to load on anything older - CentOS 7 and Ubuntu 16.04 print `GLIBC_2.28' not
  found` and never start - which is the hosting where compromised sites tend to live. The
  portable build is statically linked against musl, needs nothing from the host, and runs
  there; it is musl rather than a static glibc because a static glibc binary still loads
  the host's name-service modules and segfaults in `update --check` on CentOS 7. Measured
  on `centos:7`, `ubuntu:16.04` and `ubuntu:24.04`: the portable build scans, reports the same
  findings byte for byte over the whole reviewed corpus - detection 730 of 1,299,
  regression 131 of 131, 44 benign findings in 197,559 files read, identical to the glibc
  build - and completes `update --check` on all three. It is about a third larger,
  because the C library is inside it.

  `lyxbosa update` stays on the build it was installed as: the standard binary fetches the
  standard asset and the portable binary the `-portable` one, never the other. Before the
  suffix existed a musl binary asked to update on a current host fetched the glibc asset,
  passed the start-up check and installed it, silently swapping the C library; now the
  asset name carries the distinction and the updater cannot. Moving between the two is
  done once, by hand. When a standard build's update is refused because the download will
  not start on the host, the message now names the `-portable` asset as the way forward.

  The asset says `portable` rather than `musl` because it names what the build is for -
  running on an older host - rather than the C library that delivers it, which is a
  detail nobody choosing a download should have to learn. The build itself keeps the
  accurate word wherever a maintainer reads it: the CMake option is `LYXBOSA_LIBC_MUSL`
  and the container is `docker/build/Linux-musl/`.

  A release publishes **eight** files rather than six: two more binaries, plus the
  unchanged `SHA256SUMS` and its signature. The release job's count of the binaries it
  expects moves from four to six with it.

- **`lyxbosa update` replaces the binary on Windows.** A running `.exe` cannot be
  overwritten or deleted, but it can be renamed, so the replace there is two moves inside
  the install directory: the running `lyxbosa.exe` is moved aside to `lyxbosa.exe.old`, and
  the verified download is moved into its place. Between the two there is a moment with no
  `lyxbosa.exe`; if the second move fails the first is undone and the message says so, and
  a failure to undo it names exactly where the old binary is and what to rename it to. Each
  move is retried against a file something else has open - a real-time scanner reading a
  freshly written executable is the ordinary cause - for up to five seconds, and the real
  reason is reported on giving up. A lock is never treated as success.

  `lyxbosa.exe.old` is removed the next time `lyxbosa` starts, whichever command that is,
  once nothing is running from it. Its name is fixed, so at most one ever exists: the next
  update replaces it. A failure to remove it is silent, because the usual reason is that a
  copy of the old binary is still running.

  The binary the updater installs carries no Mark of the Web - the updater writes it
  itself and attaches no zone identifier - so SmartScreen does not raise the
  unknown-publisher warning on it that a browser download gets. Under `Program Files` a
  process that is not elevated is refused exactly as an unprivileged user is on Linux,
  with the reason, and it never relaunches itself as administrator.

  The signature verifier is now compiled into the Windows binary as well: libcrypto is
  built there for Ed25519, BLAKE2b-512 and SHA-256, while TLS stays with Schannel and the
  certificate store the OS maintains. The whole chain is the same code on both platforms,
  including the smoke test that runs the download once before installing it.

### Compatibility

- **This is a minor bump, not a patch.** Two of the entries above are new capability rather
  than repair: a release now publishes a second Linux binary per architecture, and `update`
  replaces the binary on Windows where it previously refused to. Either alone would be more
  than a patch.
- **A release publishes eight files rather than six.** Four binaries become six, beside the
  unchanged `SHA256SUMS` and its signature. A script that globs the release and expects six
  names will see eight; one that asks for a binary by name is unaffected.
- **`--version` gained a suffix.** It now reads `2.4.0 (standard build,
  lyxbosa-linux-amd64)`. The version is still the first token on the line, so anything
  cutting on whitespace or matching a leading semver is unaffected.
- **`lyxbosa update` on Windows now exits 0 having updated, where it exited 1 refusing.**
  A script that treated that refusal as the normal outcome will see success instead.
- **Nothing that runs unattended changes.** The portable-build notice is on stderr and only
  when stdout is a terminal, so a redirected report cannot contain it, and `--quiet`,
  `--silent`, `--force`, a pipe and CI each suppress it outright. `check`, the exit codes
  and every report format are byte for byte as before.

## [2.3.0] - 2026-09-10

The scanner can tell you a newer release exists, and now fetch it, check it and replace
itself with it.

### Added

- **`lyxbosa update` downloads the newest release, verifies it, and replaces the binary you
  are running.** It asks first; `--yes` skips the question, and without a terminal and
  without `--yes` it refuses rather than treating silence as consent. Exit code **0** when it
  updated or had nothing to do, **1** on any error or refusal.

  **What it checks, in this order, and the order is the guard:**

  1. the minisign signature over the release's `SHA256SUMS`, against a list of keys compiled
     into the binary from `keys/minisign-trusted.txt`;
  2. the *global* signature, which is what covers the trusted comment - so the line naming
     the release is signed rather than asserted;
  3. that the trusted comment names **this** release, because a `SHA256SUMS` and signature
     pair lifted from an older release verifies perfectly and describes the wrong binaries;
  4. and only then the SHA-256 of the downloaded file against its line in that verified list.

  A hash checked against an unverified list defends against a corrupted transfer and nothing
  else, because whoever can rewrite the asset can rewrite the list beside it.

  **The replace.** The new file is written beside the old one, given the old one's permission
  bits and owner, run once to confirm it starts on this host, flushed to disk, and then
  renamed over the old binary. The rename is atomic and a running process keeps its inode, so
  a failure at any point leaves the binary you are running exactly where it was. Nothing is
  ever written into the target itself, and no step is trusted to finish what an earlier one
  started.

  **What it refuses**, rather than working around: a release older than the running version
  (a signed old release is still signed, and rolling somebody backwards into a known defect
  needs no forgery); a release signed by a key this build does not carry; an install a
  package manager owns; a target this user cannot write - it never re-runs itself under
  `sudo`; and a verified binary that will not start on this host.

  **There is no `--to VERSION`.** It is the one option that puts a hole in the downgrade rule
  by construction, and it is not worth having in the release that first teaches this program
  to replace itself. `docs/tasks/UPDATE_PLAN.md` §10 records the argument and what would
  bring it back.

- **The trusted keys are compiled into the binary**, generated by CMake from
  `keys/minisign-trusted.txt` so the two cannot drift. A verifier that read its keyring from
  disk at run time would be one an attacker with write access to that disk can edit.

  The consequence is designed for rather than discovered: **a binary from an earlier release
  has never seen a key introduced later** and cannot verify a release signed by it. It
  refuses and tells you to download the release and verify it by hand. The three-release
  rotation in `keys/minisign-trusted.txt` is what keeps that gap from opening in normal
  operation.

- **`update` is refused on Windows and on macOS, for different reasons.** On Windows a
  running `.exe` is locked, so the replacement has to happen on the next start - phase 4, and
  the one place the platforms genuinely differ. On macOS and everything else a release
  publishes no binary at all, so there is nothing to install. Both say which it is.

- **`lyxbosa update --check` reports whether a newer release exists.** Exit code **0** when
  up to date and **2** when one is available, so a monitoring script can use it without
  reading the text - the same discipline the scan exit codes already follow. Anything else
  is 1: a failed request, or a development build, which reports version `0.0.0` and has no
  released version to compare against and says so rather than reporting that everything is
  newer than it.

  `--check` still downloads nothing and needs no key: it compares version strings and stops.

- **A scan may check on its own, at most once a day, and only when someone is watching.**
  Never from `check` - this repository's own harness runs it 167 times in one suite run, and
  a network call per invocation would break that and the scripted use the command exists for.
  Never under `--quiet`, `--silent` or `--force`, never with stdout redirected, never in CI,
  never on a development build, and never twice inside the interval.

  It **cannot fail a scan, change an exit code, or delay output**. The request is
  asynchronous with a hard timeout of about two seconds, and a result that has not arrived
  by the time the report is printed is discarded rather than waited for. Measured: a scan
  with no route to the network at all takes the same wall time and exits with the same code
  as one with a working connection, and prints nothing about the failure.

  The answer is cached, so one scan a day asks and the rest of that day's scans repeat what
  it learned without opening a socket. The attempt is recorded *before* the request, so an
  unreachable network costs one attempt a day rather than one per run.

- **A new top-level `updates:` configuration section**, beside `scan`, `archives`,
  `builtin_rules` and `actions`:

  ```yaml
  updates:
    check: periodic      # off | on-demand | periodic
    interval: 24h
  ```

  `off` and `on-demand` both mean the binary never opens a socket unless
  `lyxbosa update --check` is typed. Both settings **refuse rather than defaulting**: `check: of`
  is an error, not a silent revert to the compiled-in default, because that default decides
  whether the tool reaches the network at all. An `interval` that does not parse is an error
  for the same reason - `0` and `daily` both mean "every run", which is the thing the design
  exists to prevent.

  **The privacy consequence is documented in `README.md` beside the setting**: a version
  check tells whoever serves it your IP address, which version you are running, and when you
  ran it. On an incident-response engagement that is telemetry about the investigation.

- **`interval: 7d` means seven days.** `parseDurationSeconds` understood `s`, `m` and `h` and
  silently read an unknown unit as seconds, so `7d` was seven *seconds* - a check firing on
  every run, written by someone who asked for weekly, with nothing to say so. It now
  understands `d`, which `archives.time_budget` gains too.

### Security

- **A webshell could lower the severity of its own detection by writing a comment into
  itself.** `<?php $x = "FilesMan"; echo $x; // nolint` was reported by `check` as `[LOW]`,
  and the same line without the comment as `[CRITICAL]`. Twelve markers - `// nolint`,
  `# noqa`, `phpcs:ignore`, `// eslint-disable`, `@SuppressWarnings`, `// NOSONAR` and six
  more - on a matched line or the line before it lowered any finding of any rule to `low`,
  keeping the original severity beside it. The finding was still printed and the exit code
  was still 2; the severity is what a quarantine threshold, an alerting rule or a report
  filter reads, and the attacker wrote the comment as surely as the shell. The marker was
  found by substring, so `$y = "// nolint";` on the line did the same, and the previous-line
  rule doubled the surface. `check` printed the lowered severity with no sign it had been
  lowered.

  Whether a marker is obeyed is now the configuration's decision, and the default is no:
  `annotations.trust: false`. The bytes cannot say who wrote them, and that is the whole
  question - on a developer's own repository the marker is their note about a known false
  positive, on a web root it is the attacker's - so only the operator can answer it. With
  `trust: true` every marker works as before for every rule, signatures included, because a
  trusted author annotating a table of signature strings is a real case; a scan that trusts
  says so in a warning before it starts, and `check` now prints a lowered finding as
  `[SUPPRESSED:CRITICAL]` the way `scan` always did. Rejected: withholding annotations from
  signatures only, which would have left every Critical heuristic (`BD005`, `DRP001`,
  `CRED007` ...) steerable by the same bytes on a hostile host; requiring the marker to be a
  real comment or to name the rule, which an attacker writes as easily as `// nolint` and so
  closes nothing where it matters; a severity floor, which is a smaller weakening and still
  one.

  Measured before the default was chosen, with the same corpus and stock trees on both
  sides: in 197,553 stock CMS files the scanner reports 148 matches and not one has a marker
  on its line or the line before, in trees where more than 15,000 files carry `phpcs:ignore`
  or `phpcs:disable` somewhere; in the 182 shipped malicious samples, 175 matches and none.
  Detection 730 of 1,299 reviewed samples, 131 of 131 regression samples rule-exact, 44
  benign findings in 197,559 files, on both sides - the same files, the same matches and the
  same severities pair by pair. The default holds back nothing and closes the repro.

- **A webshell could suppress its own detection by choosing its file name.** The 8
  September release reports `WS006`, the Critical FilesMan signature, for `shell.php` and
  nothing for `shell_test.php` or `shellTest.php` - identical bytes, three names, one
  directory - because the rule's context filter skipped any path containing `Test.php` or
  `_test.php`, fragments with no separator that matched inside the file name. Seven
  fragments across the filters had that shape, `BD005` tested ten more (`ftp`, `socket`,
  `Handler.php` ...) and `OBF004` looked for `.js` anywhere in the path, so a Critical
  socket-backdoor finding was silent for a file named `ftp.php` and a long base64 decode
  for one named `shell.js.php`. This was never platform-specific.

  Two decisions, both pinned by tests:

  - **A signature has no path suppression.** Every `WS` rule matches the name of a malware
    family, and where a file sits is no evidence about that; `WS006`'s filter is gone and
    its verdict is a function of the bytes. The only benign occurrences in 214,675 stock
    CMS files were the inside of a longer identifier (`DeployedFilesManager`, in a Magento
    list of obsolete classes), so the pattern now ends on a word boundary and they do not
    match. No shipped corpus sample expects `WS006`; that boundary is measured on the
    benign side only. Severity is not the gate: `DRP001`, `BD005` and `BD013` are Critical
    and heuristic, and a location is real evidence for a heuristic.
  - **A heuristic's path suppression names a directory, compared case-insensitively, and
    never the file name.** Every fragment is now a whole directory component (`vendor`,
    `tests`, `.ssh`, `wflogs` ...) or, for a product whose directory name varies by
    distribution (`elementor`, `elementor-pro`), part of one. `OBF003` drops `sodium`,
    `openssl` and `php-jwt`: no file under any of the 2,676 stock paths carrying those
    names has the rule's shape. `BD005` drops its list entirely: what it shielded was
    WordPress core's own `class-ftp-sockets.php`, whose `_exec()` method the pattern's
    bare `exec` reached, and the pattern now asks for a call at a word boundary. `OBF004`
    tests the trailing extension.

  Case folding is a behaviour change on Linux: `OBF002` now treats Magento's `Test/Unit/`
  as a test directory, as `BD013` and `OBF003` already did and as Windows always did for
  every rule, its file systems being case-insensitive. It moved nothing in the stock trees.

  Measured with the same corpus and stock trees before and after: detection 730 of 1,299
  reviewed samples on both sides, 131 of 131 regression samples still firing and rule-exact,
  30 pinned false positives still firing and none regressed; benign sweep 44 findings in
  197,553 files on both sides, the same 44 files and the same 148 matches pair by pair. The
  36 findings the old path suppressions were holding back - 25 `BD005` on WordPress core's
  FTP class, 9 `OBF003` on vendored phpseclib and PhpSpreadsheet, 2 `WS006` on the Magento
  fixtures - are held back after the change by the pattern or by a directory, and every
  fragment removed was holding back nothing, which is why removing it moved nothing.

### Fixed

- **On Windows, none of the path-based suppressions fired.** Twelve fragments in the
  context filters - `/vendor/`, `/tests/`, `/.ssh/`, `/wflogs/` and eight more - are spelled
  with forward slashes, and a Windows path arrives with backslashes, so `\vendor\` never
  contained `/vendor/`. Measured over the same corpus and the same stock CMS trees, the
  Windows binary reported 47 benign-sweep findings against 44 on Linux, a strict superset:
  OBF003 on a vendored PhpSpreadsheet writer and WS006 on two Magento test fixtures.
  Detection agreed exactly on both platforms and is untouched. On Windows the separator is
  now normalised once, where the match context is built, before any filter runs. On Linux
  and macOS nothing changes: a backslash there is a character in a file name, and a file
  *named* `tests\shell.php` must not read as a fixture under `tests/`. Nothing about how a
  path is *printed* in a report changes anywhere.

- **On Windows, a file at a path of 260 characters or more could not be opened.** Fifteen
  files in the stock CMS trees, at 260 to 271 characters, were counted unreadable by a scan
  and reported as not found by `check`, while Python opened every one of them - on a machine
  that had `LongPathsEnabled` set. Windows requires that registry value *and* a
  `longPathAware` entry in the executable's manifest, and `lyxbosa.exe` carried no manifest.
  It does now. The registry half is still the machine's: without it, such files are counted
  as before.

- **`SSL_CERT_FILE`, `CURL_CA_BUNDLE` and `SSL_CERT_DIR` did nothing, and setting one made
  things worse.** The version check treated any of the three being set as "the operator has
  pointed us somewhere", and stood aside instead of configuring the trust store itself.
  libcurl reads none of them: `CURL_CA_BUNDLE` is a compile-time macro inside libcurl and an
  environment variable only for the curl *command-line tool*, and `SSL_CERT_FILE` reaches
  OpenSSL only through a default-paths fallback that curl skips once it has a `CAINFO` of its
  own - which it always has, because it bakes one in at configure time.

  So a user who set one got the run-time probe turned off and libcurl falling back to a path
  from the machine the binary was *built* on: exactly the failure the probe exists to
  prevent. The three values are now read and passed to `CURLOPT_CAINFO`/`CAPATH`, kind by
  kind, so naming a bundle does not throw away a probed directory. Found by running the new
  local demonstration script against an origin on this machine.

- **The generated configuration pointed at a repository that is not this one.**
  `lyxbosa init-config` wrote `# https://github.com/Lyr-7D1h/LyxBoSa` into the header of every
  configuration file anyone generated.

- **A scan of a directory that does not exist reported success.** `scan /path/that/is/not/there`
  printed `Files scanned: 0`, `No matches found` and exited **0** - byte-identical to a scan of
  a clean tree apart from the directory count. A typo in a cron entry therefore reported clean
  for as long as nobody looked, and the exit code agreed with it.

  A root named by the operator - on the command line or in `scan.directories` - is now checked
  before any work starts. If any named root is missing, or is not a directory, the whole run is
  refused with the offending path and exit **1**; the roots that *were* there are not scanned
  either, because scanning three of four and reporting the result as "the scan" is the same
  quiet under-coverage one level up. A root that disappears *while* the scan is running is a
  race rather than an operator error: those findings are still reported and written, the paths
  are named on stderr, and the run exits **1**.

  A subdirectory that vanishes mid-walk is unchanged, and so is an unreadable directory - that
  is still counted and non-fatal, so scanning `/` as an ordinary user is not an error.

- **The update notice could not appear at all for anyone whose scans are quick.** The check
  reserves its interval by writing a timestamp *before* the request - it has to, or an
  unreachable network means an outbound request on every single run - and the answer was
  written only when the fetch finished. Teardown cancelled the worker the moment the scan
  ended, so a scan that finished before its request did spent the interval and learned nothing:
  the state file recorded that a check had happened and never what it found, and every later
  scan inside that interval read an empty cache and stayed silent.

  Teardown now waits up to one second for an answer the interval has already been paid for,
  and `Ctrl+C` ends that wait at once. It costs no output - the wait begins after the last byte
  is printed and after the exit code is decided - and it is skipped entirely when the answer
  already arrived, which is every scan slower than one request.

- **The update refusal pointed at a file that releases do not ship.** A platform that cannot
  replace its own running binary refuses and tells the user how to install by hand; that text
  named `keys/minisign-trusted.txt`, which exists only in a source checkout. A release
  publishes the binaries, `SHA256SUMS` and `SHA256SUMS.minisig` and no keyring, so the one
  instruction a stranded user was given could not be followed.

### Compatibility

- **A finding is no longer marked `suppressed` unless the configuration says
  `annotations.trust: true`.** A report consumer that relied on `suppressed: true`,
  `originalSeverity` or the `[SUPPRESSED:...]` text marker sees those findings at their
  rule's own severity instead, which is the point of the change. An existing configuration
  file keeps working and gets the compiled-in default (`false`); add
  `annotations:\n  trust: true` to keep the old behaviour on trees you wrote, or regenerate
  the file with `lyxbosa init-config`. No exit code changes.
- **`scan` can now exit 1 where it exited 0.** A run whose named directory is missing or is not
  a directory is refused instead of reported as clean. Any script that has been scanning a path
  that stopped existing has been reading a false all-clear and will now see the error; that is
  the point of the change, and the fix is to correct the path or drop it from
  `scan.directories`. Exit **2** for findings and **0** for a clean scan are unchanged.
- **JSON reports carry a new `rootsMissing` array.** It is empty on an ordinary scan, and names
  any root that disappeared while the scan was running, so a consumer reading only the counters
  cannot mistake a scan of nothing for a clean tree. Existing fields are unchanged. CSV is
  unchanged: it is one row per match with no scan-level channel.
- **This is a minor bump, not a patch.** A new subcommand and a new top-level configuration
  section are both user-visible surface, and the default behaviour of `scan` changes: an
  interactive scan on a terminal may now make one outbound request a day. A subcommand that
  rewrites the user's own binary is as user-visible as this project gets, but it is *new*
  surface rather than changed behaviour: nothing that ran before behaves differently because
  it exists, and it does nothing until somebody types it.
- **Nothing that runs unattended changes.** `check`, `--quiet`, `--silent`, `--force`, a
  redirected stdout and CI all behave exactly as before, byte for byte, and none of them
  reaches the network. Every existing exit code is unchanged, and no scan can now fail for a
  reason it could not fail for before.
- **An existing configuration file keeps working and gets the compiled-in default**
  (`periodic`), because the file has no `updates:` section to say otherwise. Add
  `updates:\n  check: off` to opt out, or regenerate the file with `lyxbosa init-config`.
- **`keys/minisign-trusted.txt` is now a build input.** CMake reads it and generates the
  header the verifier parses, so changing that file changes the binary, and a build with no
  keyring in it fails at configure time rather than shipping a verifier that trusts nobody.
  Adding a key is still a commit; the release job's own refusal to publish without a
  `signing` key is unchanged.

- **The updater needs Ed25519, BLAKE2b-512 and SHA-256, which come from the OpenSSL that
  `curl[ssl]` already builds on Linux and macOS.** No new port, no new download; `find_package(OpenSSL)`
  is REQUIRED there and is not attempted on Windows, where curl uses Schannel and no OpenSSL
  is built at all. A build either has verification compiled in or is a platform known not to
  have it - there is no third state in which it quietly disables itself.
- **There is one new dependency: `libcurl`, HTTPS only.** `vcpkg.json` asks for `curl` with
  `default-features: false` and the single feature `ssl`, which drops FTP, LDAP, SMTP,
  telnet, dict, gopher and the rest of the protocols out of the build; `CURLOPT_PROTOCOLS_STR`
  says the same thing again at runtime, so the guarantee does not rest on the port's feature
  resolution staying as it is.

  `ssl` is **Schannel on Windows** - the operating system's TLS stack and certificate store,
  so no library is built there at all - and **OpenSSL on Linux and macOS**. **No certificate
  bundle is shipped, embedded or vendored**; the host's own store is located at run time,
  because curl bakes its CA path in at configure time and a binary built on AlmaLinux 8 does
  not find `/etc/pki/tls/certs/ca-bundle.crt` on a Debian or Ubuntu host. That failure was
  observed on the real release artefact and is what the probe exists for.
  `SSL_CERT_FILE`, `SSL_CERT_DIR` and `CURL_CA_BUNDLE` take precedence over the probe - see
  *Fixed* above for what that took. Both libraries are linked statically: `ldd` on the built
  binary shows no new shared library.

  Measured cost of adding it, cold: OpenSSL 3.6.4 59s, curl 8.21.0 38s. The release triplets
  are release-only, so CI builds half that, once, and the binary cache carries it afterwards.

- **The Linux build image gains `perl` and `perl-IPC-Cmd`.** They are OpenSSL's build
  requirement, not the scanner's: its `Configure` is a Perl script, and AlmaLinux 8 ships a
  minimal `perl` without `IPC::Cmd`, which the vcpkg port refuses outright. Windows needs
  neither. This changes the CI cache key, so the first release after it rebuilds every
  dependency once.

## [2.2.1] - 2026-09-08

Releases are verifiable: a checksum list and a signature over it.

### Added

- **Releases publish `SHA256SUMS` and `SHA256SUMS.minisig`.** Until now a `v*` release was
  four bare binaries with nothing to check a download against. There are now six assets: the
  four binaries, a checksum file, and a [minisign](https://jedisct1.github.io/minisign/)
  signature over it. `docs/RELEASING.md` has the commands to verify both, and the order they
  go in — signature first, because the checksum file is published beside the files it
  describes and anyone who can write to the release can rewrite it.

  This matters more here than for most tools: `lyxbosa` is run as root, on compromised hosts,
  during incident response, and a download nobody can verify is a bad thing to hand somebody
  in that position.

  `SHA256SUMS` lists bare names in byte order and does not list itself, so
  `sha256sum -c SHA256SUMS` works in the directory the assets were downloaded into, and two
  releases of the same bytes produce the same file.

- **The public keys a release may be signed with are tracked, in `keys/minisign-trusted.txt`.**
  It is a list with one key in it rather than a single key, from the first release onwards: a
  verifier that accepts exactly one key cannot survive that key being compromised, and the
  shape of the file is the expensive part to change later. The file carries the rotation
  procedure — a new key ships as `trusted` one release before it starts signing, and the old
  one is dropped two releases after — along with what rotation cannot do for a binary that has
  the list compiled in.

### Compatibility

- **Nothing changes for anyone who does not verify downloads**, and nothing in the binary reads
  a signature yet: `lyxbosa` gained no flags, no configuration and no network access. The
  updater that will use this is [planned](docs/tasks/UPDATE_PLAN.md) and not built.
- **This does not make Windows trust the binary.** That is Authenticode with an EV certificate,
  which is a different mechanism answering a different question; a browser download still shows
  an unknown-publisher warning exactly as before.
- **A release will not publish at all until the signing key is provisioned.** The keypair is
  generated on a person's machine and never in CI, so it could not ship with this change. The
  release job refuses rather than degrading to an unsigned release — see *Provisioning the
  signing key* in `docs/RELEASING.md`. One command and one repository secret, once.

## [2.2.0] - 2026-09-07

Ten new detection rules, and three candidates measured and declined.

### Fixed

- **The next scanner release would have announced itself as "Since `corpus-2026.09.1`".**
  `.github/workflows/build.yml` picked the previous tag with an unfiltered
  `git describe --tags --abbrev=0`, which returns the newest tag of *either* series. The
  corpus now has its own, on a different cadence, and it is newer than `v2.1.0` — so the
  release notes would have named a corpus review round as the previous scanner release and
  listed a commit range starting there. `--match 'v*'` asks the question the workflow meant to
  ask. Found by sweeping for claims a release can falsify: this one is a *tool* making the
  claim rather than a sentence, which is the same defect in a place prose sweeps do not reach.

### Not added, and this is the round's main result

- **A second candidate for the same family was measured and declined: the split include
  path.** Five `.php` loaders in `fake-plugin-image-payload-loader` reach their second stage
  with `include_once __DIR__ . "/tiguc" . "y.txt"` — a filename cut between two literals so
  that searching the tree for it fails. Keying on the included file's *extension* had already
  been rejected in an earlier round, so the argument was that the **split** is the honest
  discriminator and the extension never was.

  That argument was wrong, and only measuring it says so. Over the same three benign trees:
  **422 false positives among 29,342 at-risk files (1.44%) to reach 5 samples** — three times
  the cost of the extension-keyed candidate it was meant to improve on, which re-measures at
  124 today. Splicing a path across literals is ordinary in Magento and in requirejs. Declined,
  and kept reproducible as `REJECTED:split-literal-include` in `corpus/fp-population.py` so it
  is not re-derived and re-argued next round. **Those 5 loaders are still known misses, and
  the two `README.txt` payload blobs in the same family with them.**

- **The `woocommerce-card-skimmer` misses were read, and no rule was proposed for them.** All
  six are the trojanised plugin's *carrier* files rather than the skimmer: a gettext `.mo`, its
  `.po` and `.pot` sources, a WordPress `index.asset.php` dependency manifest, an ordinary
  WooCommerce block-integration class, and the built `index.js` whose card fields are the same
  shape a genuine payment gateway has. The skimmer proper is already detected — `CRED007` on
  one row, `BD011` on another. There is no discriminator here that is not simply "this is a
  WooCommerce payment plugin", so the honest outcome is six known misses left standing.

- **The rule that would close the largest single block of known misses will not be written.**
  One 2017 SEO doorway campaign accounts for 495 missed samples, and the candidate for them
  was `title == meta[keywords] == meta[description]`, exactly. It scored **0 false positives
  over 207,311 files** — and was refused twice, because only 12 of those files carried both
  meta tags, so it had twelve chances to fail and a rule-of-three bound of 25%.

  Round 11 pinned the population it actually needed: three trees of rendered HTML
  documentation. Measured against those, the candidate takes **494 false positives in 506
  at-risk files — 97.6%**. GNU Texinfo writes the node title into `<title>`,
  `meta[description]` and `meta[keywords]` verbatim on every page it generates, so the
  "discriminator" describes a documentation generator rather than a doorway page.

  What that means: **the largest single block of misses is now a family whose rule has been
  measured and rejected rather than merely unwritten**, so corpus coverage will not rise much
  from that direction. A 495-sample jump was available at any point for the price of shipping
  on twelve files' evidence. The coverage figure itself lives in
  [`corpus/CHANGELOG.md`](corpus/CHANGELOG.md) — it is the corpus's denominator and it moves
  without any rule changing, which is why quoting it here went stale by 34 points.

### Added

- **`OBF042` (critical)** — a literal holding every base64 character exactly once, in an
  order that is not the standard one. The second stage of the fake-plugin loader family
  carries two 65-character alphabets, builds a `strtr()` table out of them character by
  character, then `base64_decode()`s and `eval()`s the result: the pair *is* the substitution
  table, and a stock base64 decoder reads nothing out of the payload.

  The character set is not the signal and could not be — holding all 64 base64 characters is
  what a base64 *implementation* does. **317 alphabet literals occur across
  `trail-data/CMS`, `CMS-ext` and `Sites`, and every one of them is in standard order**,
  because no other order decodes base64. So the order is the only part an implementation
  cannot vary, and a shuffled one is a table someone chose. Both widths are read: the pad is
  optional in an alphabet literal, and a 64-character form is matched on the same terms.

  Measured over those three trees — **263,408 files, 218 of them at risk** (files carrying a
  64- or 65-character base64 alphabet literal): **0 false positives, 95% upper bound 1.4%.
  Recall 5 of 5.** The at-risk population deliberately *includes* the standard-order
  literals, so that zero is a discrimination against the hard case rather than a filter that
  never met one.

  **It is a new rule rather than a widening of `OBF039`, and that was checked first.**
  `OBF039` detects a substitution cipher by its *decode loop* — a `strpos()` position used as
  an index into a second, assembled alphabet. These five files have no `strpos` and no
  assembled alphabet, so `OBF039` runs on them and correctly declines. The two rules key on
  different observables — a loop shape and a literal's contents — and either can occur
  without the other, so folding them into one code would put two meanings behind one finding.

- **`OBF041` (high)** — a file that opens with the ASCII letters `PNG` or `GIF` where a
  real image signature belongs. A real PNG begins with the byte `0x89` precisely so it
  cannot be read as text; a real GIF's version field is `87a` or `89a`. Forty files named
  `.png`/`.gif` in five staged plugin directories are base64 payloads behind a three-byte
  cover word, and the cover does not track the file's own name, so the rule reads content
  only. Plain extension/magic mismatch would take 18 ordinary files — misnamed JPEGs and
  empty test fixtures — to reach samples this already reaches. 0 of 11,522 at-risk files
  in the benign trees.

- **`WS011` (critical)** — a bundled mailer behind a password written into the source. A
  bulk-mailer kit ships a whole copy of PHPMailer with a send UI and a password prompt
  whose secret is a literal on line 3. Bundling PHPMailer alone is *more common in
  ordinary plugin code than in malware* — 225 files in the benign trees do it — so the
  gate is the rule, not the library and not the kit's brand, which one rename defeats.
  0 of the 230 files that bundle the library.

- **`BD018` (critical)** — a `rename()` that undoes a quarantine: a source carrying
  `.suspected` (what cPanel and ImunifyAV append when they quarantine a file) and a
  target with an executable extension. Anti-remediation, and there is no honest reading
  of it — a legitimate program has no reason to know that suffix exists. Renaming *to*
  `.php` is ordinary and wp-super-cache does it; renaming *from* a quarantine suffix
  happens nowhere in 207,311 benign files. 0 of 343 files containing a `rename()`.

- **`PHI009` (critical)** — `mail()` in a file that reads submitted fields out of a
  superglobal and carries the recipient as a literal. Each conjunct is load-bearing:
  without the address literal the shape costs 30 false positives, because WordPress's
  own `wp_mail()` path reaches `mail()` and `$_REQUEST` in one file — but every address
  it sends to arrives as an argument or through a filter; without the superglobal it
  costs 24, on PHPMailer's own docblock example address. A CMS contact form takes its
  recipient from configuration; a drop is written down. 0 of 175 files calling
  `mail()`.

- **`CRED007` (critical)** — a card security code read from the request and reaching a
  remote-fetch sink without leaving the enclosing block. A fake payment gateway packs
  the card number, expiry, CVC and the whole billing and shipping record into one array
  and `file_get_contents` a remote URL with it. The CVC is the discriminator: a real
  gateway tokenises client-side and PCI DSS forbids retaining it, so a server-side
  security code in transit is close to definitionally wrong — while a card *token*
  crossing a server is ordinary, which is why keying on "card" would take two honest
  WooCommerce gateways. 0 of the 465 files carrying a card-code token.

- **`RCE015` (critical)** — a file written, executed with `include`/`require`, then
  deleted. A remote loader fetches PHP over HTTPS, writes it to a path, includes the
  path and unlinks it, which is `eval` performed through the filesystem: it needs no
  `eval`, no `allow_url_include`, and leaves nothing behind for the next scan. The rule
  is the three-way linkage on one path variable — written, included, unlinked, in that
  order and within 400 bytes. Nine files across 279,337 in the benign trees put one
  variable through both an include and an unlink; in eight the unlink comes *before* the
  include, and the ninth is 10,731 bytes away.

- **`OBF040` (high)** — a URL whose scheme word is cut in half. `'htt'.'ps://c.by'.'a61
  .xy'.'z/'` folds to a C2 address that no search for `https://` will find. Assembling a
  URL from concatenated literals is ordinary and 208 benign files do it; cutting between
  two letters of `http`/`https` rather than at its punctuation is what the rule tests,
  and it is what separates the malware from the one benign file that splits a scheme at
  all (w3-total-cache, wrapping a message at the colon).

- **`WS010` (high)** — a 404 a file tells about itself. The shell answers
  `404 Not Found` and exits unless a magic request parameter is present, so it reads as
  absent to every crawler, uptime probe and operator that fetches the URL. Benign code
  that returns 404 decides on the state of a resource — `! is_file( $file )`,
  `$current_blog->archived`; this decides on whether the caller knows a token.

- **`OBF039` (critical)** — a per-file substitution cipher. A WordPress `db.php` drop-in
  campaign resolved every dangerous identifier at runtime through a table lookup, so nothing
  was written down for a pattern to match and the alphabet differed per file. It matches the
  decoder instead: the position `strpos` finds used as an index into a second alphabet that
  the file assembles from short literals. Closes 46 known misses; what that did to corpus
  coverage at the time is recorded in [`corpus/CHANGELOG.md`](corpus/CHANGELOG.md).

## [2.1.0] - 2026-09-03

Archive scanning, and 96% fewer false positives.

### Detection

**False positives down 96% against a live shared host.** A production scan of a
multi-site host produced 1,751 findings, of which 27 were malware, 10 were real
vulnerabilities in third-party code, and 1,714 were false positives. Rescanning the
same 1.3 M-file tree now reports **63** of those false positives, with **all 27 malware
files and all 10 vulnerability findings still detected**, and finds 7 files the earlier
scan missed — every one of them malware. Scan time is unchanged (17.6 min against 19.5).

The precision was concentrated in a handful of rules, and so is the fix. Five clusters
accounted for 88% of the noise:

- `OBF036` matched protobuf-generated PHP, macOS AppleDouble resource forks and iconv
  charset tables. It now rejects the first two on content — the AppleDouble magic
  number and the generated-protobuf header — and requires control bytes to be
  *adjacent*, which is what separates a stored payload from a byte table.
- `DEFC006` matched every module of a webpack development bundle. It now reads the
  bundler's own markers out of the evaluated string.
- `RCE*`, `WS*`, `DRP*`, `EXP*` and `BD*` matched attack URLs quoted inside GoAccess
  analytics reports. Execution evidence inside a serialised field of a file the
  webserver serves as data is a log, not code.
- `DRP002` matched the composer install one-liner wherever it appears as
  documentation, and now carries an installer-domain whitelist like `DRP001` already
  had.
- `BD002` and `BD004` matched a caching plugin's own settings screen. `BD002` keys on
  argument position — only a superglobal in the cron *hook* means the attacker chose
  what runs — and `BD004` requires a consumer that ships the config somewhere.

Two rules were matching things they were never meant to. `EXP009` and `RCE008` used an
unanchored function-name alternation, so any identifier ending in `exec` matched, as did
the English phrase `Booking System (`. `OBF022` fired at critical on WordPress core's
`block-editor.js`, because `${` also opens a JavaScript template literal.

A further sixteen rules were narrowed to the shape they were written for:
`OBF002`, `OBF003`, `OBF005`, `OBF009`, `OBF011`, `OBF016`, `OBF021`, `OBF024`,
`BD001`, `BD008`, `BD013`, `DEFC002`, `DEFC004`, `DRP008`, `DRP010`, `PHI001`,
`RCE011`, `SEO001`.

### Added

- **Archive scanning.** `.zip`, `.tar`, `.tar.gz` and `.gz` are opened and their members
  scanned by the same rules, addressed `backup.zip!wp-content/uploads/shell.php`.
  A container that turns out to be a copy of an installed site raises an exposure
  finding of its own and is never quarantined. Every guard is expressed in decompressed
  bytes or wall-clock time, and nothing is extracted to disk. On the host above this
  found 348 files the loose-file scan could not see, including two obfuscated webshells
  and a JPEG/PHP polyglot uploader inside backups left in web roots.
- **`OBF029` (critical)** — a payload staged as a long run of small uniform `.=` appends.
  One sample was staged as 203,831 appends of four characters each, which every
  length-based and adjacency-based rule walked past.
- **`RCE014` (critical)** — `eval` over a decryption call (`openssl_decrypt`,
  `mcrypt_decrypt`, `sodium_crypto_secretbox_open`, `openssl_open`). Executing
  ciphertext has no honest use.
- **`SEO008` (high)** — PHP user-agent cloaking: crawler names tested against
  `HTTP_USER_AGENT` in a file that fetches a hardcoded remote address and prints it.
  `SEO003` only ever read `.htaccess`, and this is the far more common form.
- **`OBF038` (high)** — generated noise comments, wordless filler wedged between tokens
  to break pattern matching.
- **Skip reasons.** Every file the scanner does not open is counted and named — `size`,
  `excluded` or `unreadable` — and directories it could not list are counted too. See
  [Skipped files](docs/SCANNING.md#skipped-files).
- **`scan.report_excluded`** (default `false`) — list every file the include/exclude
  globs rejected, not just count them.
- The eval-family rules now tolerate block comments between a function name and its
  opening parenthesis, which closes `@/***//*!50000*/eval/***/(` for `RCE001`,
  `RCE002`, `RCE004`, `RCE005` and `RCE012` at once.

### Changed

- **`scan.max_file_size` default is 25 MB**, up from 5 MB. On the host above this reads
  230 more files for about 4% more scan time. It buys coverage rather than detections —
  those 230 files matched nothing — the point being that a file the scanner never opened
  should not be counted as clean. See
  [Choosing `scan.max_file_size`](docs/SCANNING.md#choosing-scanmax_file_size).
- **`archives.max_member_size` is pinned at 5 MB** and no longer follows
  `scan.max_file_size`. A member is inflated into memory and shares one expansion budget
  with every other member of the same archive, so it wants the tighter bound.
- **The pre-scan confirmation summary is compact.** It was 160 lines with the default
  filter list, which pushed the directories and the quarantine setting off the screen.
  It is now about 18 lines: directories in full, everything else one labelled line each,
  filter lists flowed to the terminal width, and byte counts in human units. `-v` lists
  every pattern.
- **The summary line for unscanned files** reads
  `Files not scanned: 512 (487 over size limit, 18 excluded by filters, 7 unreadable)`,
  and is printed only when something was skipped.

### Removed

- **`BD010`.** It matched `add_filter('auto_update_...')`, the documented WordPress API
  for a plugin managing its own updates, and produced no true positive across 1.3 M
  loose files, 2 M files with archives opened, or the malware corpus. Naming it in
  `builtin_rules.use` or `builtin_rules.disable` is a silent no-op, not an error.

### Fixed

- **A file that could not be read was reported as scanned and clean.** `readFile`
  returned an empty string on a failed open; that string was matched against every rule,
  found nothing, and the file was counted as scanned with no findings. It now fails, and
  the file is reported as `unreadable`.
- **A failed `stat` was reported as an oversize file and then read anyway.** The walker
  tested `ec` and the size cap in one condition, so on failure the size was unspecified
  and the scanner tried the file regardless.
- **Glob-excluded files vanished** — no callback, no count — so there was no way to tell
  whether an exclude pattern did anything.
- **An unreadable directory was indistinguishable from an empty one**, because the
  directory iterator was told not to report permission errors.
- **`check` reported "No matches found" for a file it never read.** An oversize or
  unreadable file now prints `Not scanned (over size limit)` — see *Compatibility*.
- **`-DLYXBOSA_TUI=OFF` did not compile**, though it is the documented switch for the
  minimal and static builds.
- **Configuration warnings were suppressed whenever archives were disabled**, because
  the whole check returned early. It also now warns when e-mail alerts are enabled with
  no recipient — a configuration that would otherwise have failed silently at the end of
  a long scan.
- **The generated configuration documented `alert:` without its `email:` sub-block**,
  where the parser actually reads `to`, `from` and `subject`. Setting `to:` one level up
  silently did nothing.

### Report format

Additive in JSON. `skipped` and `filesSkippedSize` keep their exact meanings, and
`archives.membersSkipped` is byte-identical, so existing consumers are unaffected:

```json
"skipReason": "size",
"filesSkipped": { "total": 208, "size": 183, "excluded": 18, "unreadable": 7 },
"directoriesUnreadable": 2
```

CSV gains `skipped` and `skip_reason` as its **last two** columns, so positional
consumers keep working, and a skipped file now produces a row — it produced none before,
because the writer emitted one row per match.

### Compatibility

- **`check` exit code.** An oversize or unreadable file now exits `1` instead of `0`.
  A script of the form `lyxbosa check "$f" && echo clean` previously treated an unread
  file as clean and no longer does. This is the one change here that can alter the
  behaviour of an existing caller.
- Configuration schema, CLI flags and every other exit code are unchanged.

---

[Unreleased]: https://github.com/LytraX/lyxbosa/compare/v2.5.0...HEAD
[2.5.0]: https://github.com/LytraX/lyxbosa/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/LytraX/lyxbosa/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/LytraX/lyxbosa/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/LytraX/lyxbosa/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/LytraX/lyxbosa/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/LytraX/lyxbosa/compare/v2.0.2...v2.1.0
