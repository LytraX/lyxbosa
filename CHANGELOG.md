# Changelog

Written for people running the scanner: what it detects, what it reports, and what a
configuration or a calling script has to do differently.

This file starts at 2.1.0. For anything earlier, the GitHub release notes carry a
commit list that CI generates per tag. Versions are the git tags described in
[docs/RELEASING.md](docs/RELEASING.md).

---

## Unreleased

### Changed

- **The false-positive denominator moved: 8 of 146,712 becomes 44 of 197,559, a rate of
  0.0055% to 0.0223%.** `corpus/benign/sources.jsonl` grew from 86 pinned sources to 136.
  The 50 additions are not a wider sample of what is popular — each version was read off
  the copy actually installed on a collected host (a plugin's main-file `Version:` header,
  a theme's `style.css`, core's `wp-includes/version.php`), so the benign corpus now
  contains the versions the scanner meets rather than the versions upstream ships today.
  **Both halves of the rate grew and the numerator grew faster**, which is the expected
  direction: the previous benign tree could not have produced these findings because it
  did not contain the code. All 44 are upstream library code and all 44 are pinned as
  `known_fp` fixtures in `corpus/expect/benign-false-positives.json` — 24 of them new this
  round, most inside vendored copies of the Freemius SDK. They stay counted inside the 44.
  The figure is quoted in the README, which is updated to match. Anyone regenerating it
  needs `corpus/fetch-benign.sh` again: the lockfile changed.

- **One false positive was found already fixed, and is now pinned as fixed.** Stock
  WordPress core 4.8.3's `wp-admin/includes/class-ftp-sockets.php` was flagged `BD005` by
  the scan that collected it and is not flagged by the current ruleset. Nothing had been
  able to notice, because the file was not in a pinned benign tree until 4.8.3 was pinned
  this round. It carries a plain `must_not_detect` rather than `known_fp`, so the fix is
  now a regression test: if `BD005` returns on stock core, the suite goes red.

### Added

- **`corpus/fetch-benign.sh` accepts `.tar.gz` sources as well as `.zip`.** The archive
  kind is read off the URL and an unrecognised suffix is a hard failure rather than a
  fall-through to `unzip` — CORPUS_PLAN §8's rule that a silent fallback is how two
  artefacts that claim to be the same thing stop being the same thing. Unpacker
  dependencies are now tested one at a time and only for the formats the lockfile actually
  contains, which is the same lesson as the `command -v zstd tar jq` that reported success
  while `zstd` was absent. `corpus/fetch-benign.sh --inject` is the positive control: five
  hermetic cases over `file://` URLs, asserting that a good zip and a good tar.gz verify,
  that a one-byte corruption of either is refused, and that an unknown suffix is refused.

- **`corpus/resolve-benign.py` — the closure mechanism that decided 92% of this corpus now
  exists in the repository.** Rows byte-identical to a file in a pinned source were being
  closed by ad-hoc scripts in collection directories, so the reason code
  `pinned-benign-hash` appeared on 9,168 published rows and nowhere in the tree. It closes
  a row only when the verdict is still `unreviewed`, records superseded sensitivity tags
  rather than overwriting them, builds the published row from a whitelist so it cannot
  carry an `origin`, and prints separately any row whose collecting scan had already
  flagged it — those are false positives on upstream code, not closures to wave through.
  `--inject` is the control, nine cases.

### Not added, and this is the round's main result

- **The rule that would close 82% of the known misses will not be written.** 495 of the 602
  samples this version misses are one 2017 SEO doorway campaign, and the candidate for them
  was `title == meta[keywords] == meta[description]`, exactly. It scored **0 false positives
  over 207,311 files** — and was refused twice, because only 12 of those files carried both
  meta tags, so it had twelve chances to fail and a rule-of-three bound of 25%.

  Round 11 pinned the population it actually needed: three trees of rendered HTML
  documentation. Measured against those, the candidate takes **494 false positives in 506
  at-risk files — 97.6%**. GNU Texinfo writes the node title into `<title>`,
  `meta[description]` and `meta[keywords]` verbatim on every page it generates, so the
  "discriminator" describes a documentation generator rather than a doorway page.

  What that means for the headline: **detection will not rise much from 22.2% soon**, because
  the largest single block of misses is now a family whose rule has been measured and
  rejected rather than merely unwritten. A 495-sample jump was available at any point for the
  price of shipping on twelve files' evidence.


### Fixed

- **The publishability gate was only half a gate, and the half it was missing is the half
  that mattered.** `corpus/shard-gate.py` computes `publishable` from the §4.1 rule and is
  the only thing allowed to write it. It failed when a row *claimed* publishable and was
  not, and it was **silent when a row was publishable and did not claim it**. Two operator
  review passes — six samples in one, eight in another — set `verdict: malicious` and
  `sensitivity: ["c2"]` without re-running it, so fourteen rows kept `publishable: false`
  and kept recording *"verdict is unreviewed"* and *"sensitivity not yet assessed"* as
  their blockers after both statements had stopped being true. Every run recomputed all
  fourteen, printed `publishable flags corrected: 14`, and exited 0. Nothing downstream
  reads the row — `promote-pending.py` defers on the recorded blocker and
  `index-summary.json` counts it — so a stale blocker was a stale denominator, and the two
  blocker tallies sat exactly 14 above the sensitivity and verdict counts they mirror.
  This is the same shape as the regex that matched `/home/` and not `/home2/`: a check
  narrower than the thing it guards, silent in exactly the direction its subject drifted.
  The gate now reports **over-claimed**, **under-claimed** and **blocker drift** — the
  third for a row whose boolean is right and whose recorded reasons are not — and fails on
  any of them. `shard-gate.py --inject <index>` is the positive control; it passes twelve
  of twelve here and fails seven of twelve against the pre-fix gate, which is how the
  green result above is worth reading. A `--fix` run that corrects anything now exits
  non-zero on purpose: the correction is not the result, the result is that something
  upstream changed a verdict without re-running the gate.

- **The suite's headline detection figure could not fail.** `corpus/verify.py` built its
  `Detection` line entirely out of `index-summary.json`, so it printed a recorded number
  regardless of what the binary under test did. Pointed at a build containing none of the
  current rules, the suite reported `shard-run 7/95, 88 missed` and `Regression 7/95` — both
  correctly red — and directly above them `Detection 169/774 (21.8%)`, with the sub-line
  "95 verified by re-running `check`" when 7 had been verified and 88 had just failed. The
  figure a reader sees first was the one that could not deliver bad news about the
  instrument. It now reconciles the recorded count against what the run actually detected,
  says plainly that the number is read from the summary when they disagree, and fails.

### Added

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

### Detection coverage

**Corpus detection is 169 of 774 reviewed malicious samples (21.8%), up from 128 of 774
(16.5%).** The five rules above measured 75 samples they newly detect; 41 of those were in
published shards and are now promoted from `expect.known_miss` to `expect.must_detect`.

The whole difference is those 41 rows and nothing else. The denominator did not move — 774
reviewed malicious samples before and after — so this is the first round in which the figure
rose rather than falling or holding: promoting a known miss whose rule now fires moves a
sample from the denominator-only side to both sides. Known misses fall 646 → 605, the suite's
executed set goes 54/54 → 95/95 with all 95 matching their expected rule exactly, and the
false-positive rate is unchanged at 8 of 146,713 benign files. Technique coverage is also
unchanged at 80 of 123, which is correct rather than surprising: a `known_miss` sample
already contributed its techniques to both sides of that ratio.

Each row was re-measured with `check` against the bytes the suite runs before being applied,
because `expect.must_detect` is compared to `check`'s output exactly. `corpus/verify.py` now
reports **0 newly detected** — the same figure a scanner built before these rules would
report, so it is worth saying how the two are told apart: the run immediately before the
promotion, using the same binary, reported 41, and running the promoted corpus against a
pre-`OBF041` build turns 88 of the 95 executed samples red instead of printing the same
numbers quietly.

**34 samples are still owed** and stay in `corpus/pending-promotions.jsonl`: 29 blocked on
masking they have not had, 3 on a sensitivity assessment, and 2 on a human verdict that only
the operator can give. Their detection is real; none of those blockers is about whether a
rule fires, which is why the file records the blocker rather than just the hash.

**Corpus detection is now 172 of 774 (22.2%), from 169 of 774 (21.8%).** Two movements, with
separate causes, and only one of them touches that figure:

- *Recomputing fourteen stale rows moved no count at all*, which is the correct result for
  fixing a derived field and is why it is stated rather than omitted. The two blocker
  tallies fell by 14 each — `verdict is unreviewed` 79,595 → 79,581 and `sensitivity not yet
  assessed` 73,797 → 73,783 — and now equal the verdict and sensitivity-tag counts they are
  meant to mirror, which is the arithmetic that had been 14 out for two rounds.
- *Publishing eight of them and promoting three* is the rest. The eight components of one
  2017 SEO doorway kit move from the local half to the published half and ship as
  `malicious-doorway-kit-001` (12 KB, unmasked — the independent gate found nothing to mask
  in the plaintext or the raw bytes, and there is no encoded layer to hide one in). Three of
  the eight are the `BD018` deployers that had been sitting in the handoff blocked on the
  stale state above; they are re-measured against the shipped bytes and promoted, taking
  known misses 605 → 602 and detection 169 → 172. Publishing does not move detection on its
  own — a published row and a held row are both in the denominator — but it moves what a
  stranger can reproduce: the suite's **executed set goes 95 → 98**, all 98 matching their
  expected rule exactly, and the known misses it can re-run go 37 → 42. **Technique coverage
  goes 80 → 90 of 123**, all ten from these rows and none previously covered by any tested
  sample. The false-positive rate is unchanged at 8 of 146,713 benign files: no rule and no
  benign source changed.

`corpus/index-summary.json` gains `local_only_publishable_no_blocker`, which reads **5**.
Those are rows the §7.2 gate does not block that are still held — the five remaining
incident samples from those two reviews, which carry no `family`, `technique` or `reason`
and so cannot be published without a classification nobody has made. Before this round the
key would have read 0 for the wrong reason, because a row that became publishable was never
recorded as having done so. A sixth was **held deliberately**: §7.2's secret scan fires on
its bytes, and the corpus's only other sample carrying that technique is tagged `c2+secret`
and held for masking, so its `sensitivity: ["c2"]` looks under-tagged. Re-tagging axis B is
a human assessment and the row waits for one.

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
