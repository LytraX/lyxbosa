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

The scanner can tell you a newer release exists. It still cannot fetch one.

### Added

- **`lyxbosa update --check` reports whether a newer release exists.** Exit code **0** when
  up to date and **2** when one is available, so a monitoring script can use it without
  reading the text - the same discipline the scan exit codes already follow. Anything else
  is 1: a failed request, or a development build, which reports version `0.0.0` and has no
  released version to compare against and says so rather than reporting that everything is
  newer than it.

  `lyxbosa update` without `--check` refuses and explains, rather than not existing. A user
  who reads about the command and gets "unknown command" learns less than one who is told
  what does work. There is no `--to` and no download path.

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

### Fixed

- **The generated configuration pointed at a repository that is not this one.**
  `lyxbosa init-config` wrote `# https://github.com/Lyr-7D1h/LyxBoSa` into the header of every
  configuration file anyone generated.

### Compatibility

- **This is a minor bump, not a patch.** A new subcommand and a new top-level configuration
  section are both user-visible surface, and the default behaviour of `scan` changes: an
  interactive scan on a terminal may now make one outbound request a day.
- **Nothing that runs unattended changes.** `check`, `--quiet`, `--silent`, `--force`, a
  redirected stdout and CI all behave exactly as before, byte for byte, and none of them
  reaches the network. Every existing exit code is unchanged, and no scan can now fail for a
  reason it could not fail for before.
- **An existing configuration file keeps working and gets the compiled-in default**
  (`periodic`), because the file has no `updates:` section to say otherwise. Add
  `updates:\n  check: off` to opt out, or regenerate the file with `lyxbosa init-config`.
- **Nothing in the binary reads a signature yet.** The check compares version strings and
  needs no key; `keys/minisign-trusted.txt` is still a tracked file that nothing compiled
  reads. Verifying a downloaded binary is phase 3 of
  [docs/tasks/UPDATE_PLAN.md](docs/tasks/UPDATE_PLAN.md), and embedding the keyring belongs
  with it rather than ahead of it.
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
  `SSL_CERT_FILE`, `SSL_CERT_DIR` and `CURL_CA_BUNDLE` still take precedence. Both libraries
  are linked statically: `ldd` on the built binary shows no new shared library.

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

[Unreleased]: https://github.com/LytraX/lyxbosa/compare/v2.2.1...HEAD
[2.2.1]: https://github.com/LytraX/lyxbosa/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/LytraX/lyxbosa/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/LytraX/lyxbosa/compare/v2.0.2...v2.1.0
