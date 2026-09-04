# Changelog

Written for people running the scanner: what it detects, what it reports, and what a
configuration or a calling script has to do differently.

This file starts at 2.1.0. For anything earlier, the GitHub release notes carry a
commit list that CI generates per tag. Versions are the git tags described in
[docs/RELEASING.md](docs/RELEASING.md).

---

## Unreleased

### Added

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
  the file assembles from short literals. Closes 46 known misses and takes corpus detection
  from 10.0% to 45.4%.
- **A golden corpus and a reproducible suite** (`corpus/`). The benign half is 86 upstream
  sources pinned by version and sha256 — nothing is committed, `corpus/fetch-benign.sh`
  downloads and hash-verifies — so the false-positive rate regenerates anywhere and yields
  the same number. `corpus/verify.py` runs it. See
  [Detection coverage](README.md#detection-coverage).

### Changed

- **Detection is reported over every reviewed malicious sample.** It previously printed
  `recall 100%`, which was true and meaningless: `must_detect` was populated from a rescan,
  so a sample carried it *because* it had been detected, and anything known not to be
  detected was moved to a `known_miss` column and out of the denominator. The figure could
  only fall if a working detection broke. That measurement is still reported under the name
  of what it is — a regression check — and the coverage figure is now stated over the whole
  reviewed set, where it can deliver bad news.
- **Precision is no longer reported at all.** It had been withheld until the malicious and
  benign sets were "commensurate" in size, which was the worse repair: satisfying that means
  shrinking the benign side until the ratio is near 1:1, tens of thousands of times more
  malicious than a real host, and printing something flattering that means nothing.
  `tp/(tp+fp)` belongs to a field scan, which supplies the real ratio by construction.
- **Known false positives stay counted in the false-positive total.** Pinning a defect
  records it; it does not remove it from the number it belongs to.

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
  [Skipped files](README.md#skipped-files).
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
  [Choosing `scan.max_file_size`](README.md#choosing-scanmax_file_size).
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

[Unreleased]: https://github.com/LytraX/lyxbosa/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/LytraX/lyxbosa/compare/v2.0.2...v2.1.0
