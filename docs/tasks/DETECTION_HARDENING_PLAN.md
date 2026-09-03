# Detection hardening plan

**Date:** 2026-09-02

Derived from measuring the scanner against a labelled malware corpus (340 confirmed
samples across 38 families, recovered from a compromised multi-site WordPress host) plus
two false-positive control corpora. The corpus, its per-sample analysis and the raw
numbers live under `trail-data/` and are deliberately not committed; this document keeps
only what generalises.

> **Status.** Steps marked ✅ are done. Everything else is unstarted.

Target: **44.8% → 92.2%** detection on the labelled set while holding the current
false-positive record.

**Start at step 0 in the ordering table at the end.** Steps 0–3 deliver 78% of the
available recovery with no change to the matching architecture and zero measured false
positives.

## The constraint that governs everything here

`trail-data/CMS` (stock WordPress, Joomla, Magento — 51,294 files after the filter
widening) produces **zero** matches. `trail-data/Sites` (a real production site, 22,416
files) produces **four**, all medium `OBF025` on Freemius and Redux, which
`obfuscation.cpp` already documents as an accepted trade. That record is the product's
main asset and no rule below may spend it.

**Rule for every addition: it ships only with a measured TP and FP count against
`trail-data/CMS` *and* `trail-data/Sites`.** Stock CMS alone is not enough — real sites
carry page builders, Freemius, Snoopy, phpseclib, Wordfence and minified vendor bundles
that stock CMS does not, and several candidates here were caught by `Sites` after passing
`CMS` clean.

A harness that reproduces every number is described in [§6](#6-reproducing-and-regression-testing-these-numbers).

---

## The failure mode this plan exists to fix

Rules are regexes over raw bytes, so they match one *spelling* of a technique rather than
the technique. Anything inserted between a function name and its argument defeats them:

1. `goto` chains breaking statement adjacency.
2. Indirection through a helper: `helper(2)($dir, 0755, true)`.
3. Comments inside the call: `eval/******/("?>".file_get_contents("https://…"))`.
4. Value flow through a variable: `$fn='base64_decode'; $s=$fn($z); eval($s);`.
5. Whitespace jitter: `$x  =  defined("FOO")    ?     FOO  : …`.

Four secondary gaps compound it: `eval` is recognised in only two shapes; archives are
never opened; there is no Python coverage and Perl coverage is cut too narrow; and
several existing rules are written against an incidental detail of one sample rather than
the technique (see [§0.9](#09-audit-existing-rules-for-over-fitting)).

---

## Phase 1 — Normalization

> **Sequencing note (measured).** An earlier draft put normalization first. That was
> wrong. Of the 110 rule-recoverable files, **103 match on raw text and only 7 require
> the normalizer** — it is the most invasive change in the plan (offset mapping through
> `MatchEngine` so line/column stay truthful) and the smallest immediate payoff. Build
> it, but build it *fourth*.
>
> Its real value is durability, not yield: it collapses a whole class of future variants
> rather than the four rules it happens to unlock here.
>
> **Update 2026-09-03 — the comment half is done without the normalizer.** The two live
> samples that needed comment handling (§4 GAP-2 and GAP-4) are both detected now. Rather
> than build the offset map, the eval family's `\s*` gap between a function name and its
> `(` became a shared `LYX_GAP` fragment that also admits block comments, and the
> `-*///` noise itself became a rule (`OBF038`). Whitespace collapse and escape decoding
> are still unbuilt, and the normalizer is still the durable answer — but it is no longer
> blocking any known sample.

Add a normalization pass ahead of `MatchEngine`, producing a normalized buffer plus an
offset map back to the original so reported positions stay truthful.

1. **Strip PHP comments** (`/* */`, `//`, `#`) while respecting single- and double-quoted
   string state. Must be **PHP-scoped**: `#` is a comment in PHP but significant in
   `.htaccess`, Perl and Python, and stripping it there silently broke four candidates
   during development.
2. **Collapse whitespace** around `( ) . , = ;`.
3. **Decode `\xNN` and `\NNN` escapes** in double-quoted strings for a second matching
   pass, so `"\x7a\x69\x70\x3a\x2f\x2f"` is matchable as `zip://`.

What each part buys, measured against the 185 labelled misses:

| Part | Rules it unlocks | Extra files | Cost |
|---|---|---:|---|
| **Escape decoding** (`\xNN`, `\NNN`) | `BD018`, `OBF030` | 6 | Cheap — a local transform inside the rule, needs no pipeline change. Already folded into those two rules. |
| **Comment stripping + whitespace collapse** | `RCE010`, `RCE011`, `OBF031`, `OBF033` | 7 | Expensive — needs the offset map. |

So the cheap half is already paid for by writing two rules; only the expensive half is a
Phase of its own.

**Guard:** normalization must not change what a rule *means*, only how it is spelled.
Re-run the full CMS + Sites baseline afterwards; the expected delta is zero.

---

## Phase 2 — New rules, ranked by validated yield

All counts are TP against the 185 labelled misses, FP against CMS and Sites.

### Tier A — large yield, zero FP

#### OBF026 · character-map substitution decoder — 63 TP / 0 / 0 — `critical`

The largest single family in the corpus builds every dangerous name at runtime through a
substitution cipher, so no dangerous literal appears anywhere. Match the *shape* of the
decode loop, not any literal:

```
strpos\s*\(\s*\$\w+\s*,\s*\$\w+\s*\[\s*\$\w+\s*\]\s*\)
```
AND
```
\$\w+\s*\.=\s*\(\s*\$\w+\s*===?\s*false\s*\)\s*\?
```

A `strpos` into an alphabet indexed by the source character, with a `=== false`
passthrough, is a substitution cipher. Nothing in 73k clean files does this.

#### OBF027 · call-of-call computed callee — 63 TP / 0 / 0 — `critical`

```
(?<![\$>:\w])([A-Za-z_]\w{2,})\((?:\d{1,4}|\$\w+)\)\(
```

`helper(1)($dir)` — the callee is the *return value* of a call. Two mandatory qualifiers,
both learned from measured FPs:

- **PHP files only.** In JavaScript `f(1)(x)` is ordinary currying — `lodash.js`,
  `pdf.js` and `block-editor.js` all matched before this gate (4 CMS + 6 Sites FPs → 0).
- **Exclude language constructs** (`isset`, `empty`, `array`, `list`, `echo`, `unset`,
  `include`, `require`, `return`, `if`, `while`, `function`, `strlen`, `count`, …).
  Without the list, getID3's `(isset($framedata) ? strlen($framedata…` matched.

#### OBF028 · irregular whitespace jitter — 38 TP / 0 / 0 — `medium`

Per line, count runs of `\S {2,}\S`; a line with ≥3 such runs is "jittered". Flag when
≥6 lines jitter **and** they are >30% of non-blank lines.

The ratio is what makes this safe. getID3 aligns assignments into columns, which trips a
naive count — but alignment is confined to a few blocks, whereas a jittering obfuscator
hits nearly every line. Ratio-gating took this from 5 CMS + 6 Sites FPs to zero. Ship as
`medium`: it is a style signal, strong as a corroborator.

### Tier B — targeted, zero FP

| Code | Detection | TP | Severity | Notes |
|---|---|---:|---|---|
| ✅ `OBF029` | chunked uniform base64 `.=` accumulation | 6 → **12** | `critical` | **Shipped 2026-09-03.** ≥20 consecutive appends to the *same* variable, ≤3 distinct widths, mean width <16, joined result pure base64. Shipped at `critical` rather than `high`: the live sample was a 268 KB webshell staged as 14,066 appends, and the four conditions together have no legitimate shape. Found 12 files in the corpus, not the 6 predicted — the whole "Smart Chunk" family was sitting undetected. 0 FP on CMS, Sites and the live sample corpus. |
| `BD018` | stream wrapper in `include`/`require` | 6 | `critical` | `(include\|require)(_once)?` followed by `php://`, `data://`, `zip://`, `phar://`, `glob://`, `expect://`, `compress.*://`. **Requires Phase 1 escape decoding** — samples write it as `"\x7a\x69\x70\x3a\x2f\x2f…"`. |
| `OBF030` | mixed hex/octal escape superglobal | 6 | `critical` | A literal of ≥4 consecutive `\xNN`/`\NNN` escapes **and** a variable-variable subscript `${$var}[`. Catches `array("\x5f\107\x45\x54")` → `${$x[0]}["of"]`. |
| `SEO007` | gambling doorway keyword density | 6 | `high` | ≥8 occurrences of a localized gambling-spam keyword set (*slot gacor, situs slot, anti nawala, maxwin, judi bola, togel, rtp slot, link alternatif*). Samples carry 55–117. Density, not presence. |
| `BD019` | `include` of a hidden dotfile | 5 | `high` | `include`/`require` of a path matching `/\.[A-Za-z0-9]{6,}\.(php\|inc)`. A dot-prefixed random-hex include is never a legitimate autoload. |
| `RCE010` | `eval('?>' . X)` **+** remote fetch | 4 | `critical` | See Tier C for why the fetch is required. |
| `OBF031` | mixed-case PHP builtin call | 2 | `high` | A dangerous builtin written in jittered case (`pARSe_sTr`, `sYsTeM`) — not all-lower, not all-upper, not `Ucfirst` (which would hit class names). |
| `BD020` | fake-404 gate on a magic parameter | 2 | `critical` | `if(!isset($_GET[…]))` within ~900 chars of `http_response_code(404)` or `header("HTTP/1.1 404")` plus `die`/`exit`. |
| `BD021` | `wp_set_auth_cookie` + superglobal | 2 | `critical` | Exclude files that also define `wp_signon`/`retrieve_password`/`class WP_` so WP core itself is never flagged. |
| `EXP011` | ELF executable in a web tree | 2 | `critical` | `\x7fELF` magic. Needed the include filter widened (step 0.5, done). |
| `BD022` | gsocket persistence marker | 2 | `high` | Literal `DO NOT REMOVE THIS LINE. SEED PRNG` — a known gs-netcat/gs-dbus IOC. |
| `OBF032` | chained string-literal subscripts | 1 | `critical` | `("abc")[2].("def")[1].("ghi")[0]` — **≥3 chained, PHP only**. The unchained form cost 20 CMS + 50 Sites FPs. |
| `OBF033` | self-referential dead-store padding | 1 | `medium` | ≥4 of `$x = str_replace("k","","k")`, `substr("k",7,0)`, `implode("k",array())`. Signature dilution. |
| ✅ `SEO008` | user-agent cloaking + remote fetch | 1 → **4** | `high` | **Shipped 2026-09-03.** ≥3 crawler names (raised from 2 — caching and analytics plugins legitimately name one or two) matched against `HTTP_USER_AGENT`, *plus* a hardcoded `http(s)://` literal within 800 bytes of a fetch call, *plus* an emitter, *plus* an executable file type (no extension still counts). Extends `SEO003` from htaccess to PHP, the far more common form. The URL-next-to-fetch condition was added after a full-tree rescan: crawler names plus any fetch also describes a maintenance-mode plugin letting bots through and a security plugin blocking scanners, and it took 3 FPs. Every known cloaker writes the address it serves beside the call that fetches it — 103–427 bytes — while the maintenance plugin's nearest pair is 15 KB apart and the firewall has no URL literal at all. |
| `OBF034` | numeric `curl_setopt` constants | 1 | `high` | ≥3 of `curl_setopt($c, 10002, …)` — raw option integers instead of `CURLOPT_*` is deliberate opacity. |
| `BD023` | `unlink(__FILE__)` | 1 | `high` | Single-use backdoors erase themselves. |
| `DRP011` | `base64 -d \| sh` pipeline | 1 | `critical` | Shell persistence in `.bash_profile`/`.bashrc`. |
| `PL010` | Perl CGI shell | 1 | `critical` | `read(STDIN,$x,$ENV{'CONTENT_LENGTH'})` + `system`/`exec`/`open`/backticks. Closes the `PL004` gap, which needs `$ENV` *inside* the `system()` argument. |
| `PY001` | Python CGI shell | 1 | `critical` | `cgi.FieldStorage()` + `os.popen*`/`os.system`/`subprocess.*`. **First Python rule** — the category does not exist today. |
| `WS010` | obfuscator.io string-array JS | 1 | `high` | ≥2 of: `while(!![])`, ≥3 `parseInt(x(0x…))`, ≥3 hex-arithmetic groups `(-0x2b6*-0x4+…)`, `_0x[0-9a-f]{4,}` identifiers. |
| `BD011` (extend) | bcrypt password gate | 1 | `high` | Add `'$2[aby]?$\d{2}$[./A-Za-z0-9]{53}'` + `password_verify`/`hash_equals`/`crypt`. Today `BD011` knows only md5 and sha1. |
| ✅ `RCE014` | `eval` over a decryption call | **2** | `critical` | **Shipped 2026-09-03.** Not in the original plan. No rule paired `eval` with a *cipher*: a live sample held its payload as AES-128-ECB ciphertext and ran `eval(openssl_decrypt($data, 'AES-128-ECB', $kunci, 0))`. Covers `openssl_decrypt`, `mcrypt_decrypt`, `sodium_crypto_secretbox_open`, `openssl_open`. |
| ✅ `OBF038` | generated noise comments | **4** | `high` | **Shipped 2026-09-03.** Not in the original plan; closes the `-*///` loader family (see §4 GAP-4) without needing the Phase 1 normalizer. ≥10 block comments, mean length <64, ≥70% of them "noise". Getting *noise* right is the whole rule: a first cut tested only for "no words" and took 88 FPs, because `/****/` banners, `/* @var int */` docblock fragments and `/* 1 << 128 */` arithmetic notes are all wordless. It now requires high character diversity in a short span, or a run of ≥6 non-ASCII bytes over ≥4 distinct values, and excludes a comment whose body is only quotes, whitespace and hex digits around a backslash. Both exclusions are icon fonts: one ships `/* '\uE002' */` per glyph, another `/* '\1f3b5' */`, 285 of them in one stylesheet, and both have exactly the character diversity a hex string always has. |
| ✅ `OBF036` | binary payload in a text-declaring file | 40 | `high` | **Shipped.** Counts C0 controls only (never bytes ≥0x80, so UTF-8 in any script scores 0.000%); UTF-16/32 exempted by BOM or alternating-NUL. Gated to text extensions, minus `wflogs/` and `.sql`. |
| ✅ `OBF037` | mixed octal/hex escaped string | 67 | `high` | **Shipped.** ≥8 escapes in one run with ≥2 of *each* notation. See [§0.9](#09-audit-existing-rules-for-over-fitting). |
| ✅ `OBF015` (fix) | goto label may follow `;` with no space | +74 | — | **Shipped.** `\s+` → `\s*`. |
| ✅ `DEFC001` (fix) | prose filter on "hacked by" | — | — | **Shipped.** Discards `hacked by identifying/exploiting/the/…`; keeps `Hacked By <handle>`. |

### Tier C — ship, but not at critical

| Code | Detection | TP | FP | Severity | Why capped |
|---|---|---:|---|---|---|
| `WS011` | single-file file-manager webshell | 5 | 1 CMS, 2 Sites | `high` | Composite: ≥5 of {`scandir`/`opendir`/`glob`, `move_uploaded_file`, `unlink($…)`, `rename`/`copy($…)`, `file_put_contents($…)`, superglobal + `realpath`/`__DIR__`/`DOCUMENT_ROOT`, `enctype=multipart`}. Real file managers exist; 3 FPs in 73k is acceptable at `high`, not at `critical`. |
| `RCE011` | `eval('?>' . X)` without a fetch | 6 | 1 CMS | `high` | The FP is php-debugbar's Twig bridge, a genuine template compile. With a remote fetch in the same file (→ `RCE010`) it is 0 FP and `critical`. |
| `OBF035` | sensitive fn name in a variable, then called | 6 | 1 CMS | `high` | `$fn='base64_decode'; … $fn($z);`. Complements `OBF024` (which folds *assembled* names); this one is a plain literal, which the folder does not treat as assembly. |

### Explicitly rejected

Measured and not worth it:

| Candidate | TP | FP CMS | FP Sites | Reason |
|---|---:|---:|---:|---|
| generic `eval()` on any non-literal argument | 8 | 9 | 7 | phpseclib `Blowfish`/`SymmetricKey`, Twig, `class-snoopy.php`, `class-json.php`, Magento's `WrapperGenerator`, Wordfence's scanner, WPCode's snippet runner. `eval` is a legitimate tool; only provenance makes it a finding. |
| high-entropy binary blob (all files) | 54 | 215 | 1378 | Fonts, images, compiled assets. Survives only when scoped to text-declaring extensions (→ `OBF036`). |
| escape run of ≥8, either notation | 74 | 32 | 27 | getID3, phpseclib and minified JS carry long single-style runs. Survives only when the run must *mix* notations (→ `OBF037`). |
| bare `("abc")[2]` | 2 | 20 | 50 | Chained-only (→ `OBF032`). |
| comment between identifier and `(` | 2 | 29 | 28 | Phase 1 removes the need. |
| any `.htaccess` `AddHandler` | 2 | 1 | 1 | Magento ships `AddHandler cgi-script .php .pl .py .jsp .asp …` in `pub/media/.htaccess`. Restrict to non-standard extensions. |
| rules for stock-WordPress `.htaccess` and empty stubs | — | — | — | 9 labelled samples are malicious by *location*, not content. Unreachable without path context; chasing them is pure FP risk. |

---

## Phase 3 — Capability gaps

### 3.1 Archive traversal — the single largest remaining block

50 of the 185 misses are `.zip`/`.tar`. Proven by experiment: unpacking them and
re-scanning with the **current** ruleset yields 60 matches inside the tar members, and the
47 zip members match `OBF026`/`OBF027` at **47/47**.

Result: 49 of 50 archives become detectable. Requirements — recurse into `zip`, `tar`,
`tar.gz`, `gz`; cap nesting depth and expansion ratio (zip-bomb guard); report findings as
`archive.zip → member/path.php`.

### 3.2 ✅ Include filter — done (step 0.5)

Widened from 27 globs to ~130. Worth 3 files directly, but it was the precondition for
archive traversal and `EXP011`, and it converted an entire family of video-extension
polyglots (`.mov`, `.wmv`, `.mp4`, `.avi`, `.flv`, `.mpg`) from 0/12 to **12/12** using
only the rules that already existed.

Still outstanding: prefer content-based typing over an ever-growing extension list — read
the first bytes and dispatch on magic (`PK\x03\x04`, `\x1f\x8b`, `\x7fELF`, `<?php`)
rather than trusting extensions.

### 3.3 `*.min.js` exclusion

`*.min.js` is excluded by default while 137 corpus samples are obfuscated JS. Minified and
obfuscated JS are not distinguishable by filename. Either drop the exclusion and rely on
`WS010`'s specificity, or keep it but always scan minified files under `wp-content/uploads/`,
`wp-includes/` and theme asset directories.

---

## Phase 4 — Capability scoring (design work, not a rule)

Eight residual samples share a shape: no single dangerous primitive, but a combination that
only a webshell has. One of them advertises *"No eval • No system • No exec • No shell"* in
its own header and is a fully functional file manager.

Sketch: give each file a capability vector — `{fs_read, fs_write, fs_delete, upload, exec,
net_fetch, auth_bypass, self_delete, request_gated, output_html}` — and score combinations.
A single self-contained PHP file that is request-gated *and* writes *and* deletes *and*
uploads is a webshell regardless of which functions it uses.

This needs its own FP study against `Sites` before any threshold is chosen; page builders
and backup plugins legitimately hold several of these capabilities at once. Do not ship it
on the strength of one corpus.

---

## Phase 5 — Corpus hygiene

- Bulk sweep directories must be excluded from any detection-rate metric. They contain
  quarantined-then-restored CMS core and plugin code — 577 files in the current corpus are
  byte-identical (sha256) to stock upstream. Counting them makes the headline number
  meaningless.
- Those directories are, however, a **good adversarial FP corpus**: real-world messy
  plugin and theme code, unlike stock CMS.
- Candidate rules flag 19 files in them that are confirmed malicious. Promote those into
  labelled families.
- Store `.htaccess` samples so they match the `.htaccess` glob, or teach the manifest to
  carry the original basename, so filter fidelity can be tested.

---

## 6. Reproducing and regression-testing these numbers

Every figure came from measuring candidate implementations against three corpora at once.
Fold that into the repo so it does not have to be rebuilt by hand:

1. **Ground truth.** The labelled malware families, excluding bulk sweeps.
2. **FP corpora.** `trail-data/CMS` (stock) **and** `trail-data/Sites` (real production).
   Both, always — `Sites` caught FPs that `CMS` did not.
3. **Adversarial FP corpus.** The bulk sweep directories, with known-malicious files
   allowlisted.
4. **Gate.** A rule ships only when its FP count on CMS + Sites is stated. Zero for
   `critical`; a documented handful for `high`/`medium`, in the manner of `OBF025`.

Suggested make target: `make detection-eval` — prints the TP/FP table in the shape used
here, and fails CI if total FPs on `CMS` + `Sites` rise above the committed baseline
(today: 0 and 4).

---

## 0.9 Audit existing rules for over-fitting

Two shipped fixes came from the same defect, and it is worth assuming the rest of the
ruleset has it too.

**`OBF015`** required `goto\s+<label>;\s+<label>:` — one-or-more whitespace after the
semicolon. An emitter that writes `goto kPpzye;LQL4spRSOK:` scored **zero against 52 jumps
in one file**. `\s+` → `\s*` recovered 74 files at zero FP; the precision was never in the
whitespace, it is in requiring a mixed-case identifier either side of the `;`.

**`OBF016`** requires 8+ consecutive **octal** escapes. A string that alternates notations
(`"\74\144\x69\166\x3e\x3c"`) defeats both it and any hex-only rule — 98 octal and 73 hex
escapes in one file, never eight octal in a row.

Both encode an incidental detail of whatever sample the rule was written against as though
it were part of the technique. The audit question for each of the ~120 existing rules:

> **Which byte in this pattern is the technique, and which is just how the sample I had
> happened to be written?**

### ✅ Audit performed — what it found

Two systematic defects across all 122 rules, both now fixed.

**Case sensitivity (90 patterns).** PHP resolves function names case-insensitively; the
patterns did not. `EvAl(BaSe64_DeCoDe(…))`, `SySTeM($_GET['cmd'])`, `AsSeRt($_POST['x'])`
and `UnSerialize($_COOKIE['c'])` all execute exactly as their lowercase forms and all
scored **zero detections**. Changing the case of a function name evaded the entire
ruleset. Builtin names are now wrapped in `(?i:…)` rather than the whole pattern being
made case-insensitive, because case still carries meaning elsewhere — the uppercase HTTP
verb in `EXP010`, hex classes, base64 alphabets.

**Patterns that never compiled (23 patterns, 20 rules).** They used PCRE possessive
quantifiers (`[^)]*+`) or backreferences (`\1`). RE2 supports neither.
`PatternCache::get()` returns `nullptr` on a compile failure and both `matches()` and
`findMatches()` skip a null quietly — so a syntax error does not fail the build or the
scan, it **silently disables the rule**. `BD001`–`BD009`, `BD014`, `CRED003`, `CRED005`,
`DEFC007`, `PHI001`, `PHI004`, `PHI005`, `PHI007`, `SEO001`, `SEO002`, `SEO005` and
`SEO006` had been dead since they were written.

`BuiltinPatternTest.EveryPatternCompiles` now walks every rule and fails the build on an
invalid pattern. That guard should have existed from the start.

**Reviving 20 rules is not free.** The FP corpora caught three problems at once, and the
lesson generalises: a rule that has never run has never been FP-tested either.

| Rule | Defect exposed on revival | FPs | Fix |
|---|---|---:|---|
| `BD007` | unbounded `.*?` between `base64_decode` and `fsockopen`; with `dot_nl` it spans the whole file | 3 CMS, 2 Sites | bound to 200 chars |
| `SEO001` | matched any hidden anchor; themes emit `<a style="display:none" href="<?php echo …">` | 9 Sites | require a literal external URL; gate off `.js` |
| `BD014` | `touch()` relaxed from its backreference matches legitimate `touch($file,$time,$atime)` in WP and phpseclib | 2 CMS, 1 Sites | pattern dropped — the identity was the whole signal and RE2 cannot express it |

`DEFC007` kept its identity check by moving to an analyzer: the handler assigned to
`document.onkeydown` must name a function that pops an alert. That is the general escape
hatch — when the precision needs something RE2 lacks, do the second step in C++ rather
than weakening the pattern.

Net: CMS 0 and Sites 4, unchanged — but now genuinely earned.

### Still worth checking

- `\s+` where `\s*` is meant — any required whitespace between tokens.
- One notation where several exist: octal vs hex vs unicode escapes; `'` vs `"`;
  `array()` vs `[]`; `<?php` vs `<?=`.
- Required argument order or count in a call that accepts either.
- Fixed distances (`.{0,40}`) tuned to one sample's spacing.
- Unbounded `.*?` between two required tokens — `dot_nl` is on, so it spans files.

Each candidate change gets the same treatment as a new rule: measure TP on the labelled
set, FP on CMS *and* Sites, and only relax when the precision demonstrably lives elsewhere
in the pattern.

### On the regex engine

RE2 lacks backreferences, lookarounds and possessive quantifiers, and vcpkg offers
alternatives that have them: `pcre2`, `oniguruma`, `boost-regex`, `srell`. **Do not
switch.** RE2 guarantees linear-time matching; every backtracking engine can be driven
into exponential time by crafted input, and this scanner's input is malware chosen by an
attacker who can read these rules. A file that hangs the scanner is an attack on incident
response. Possessive quantifiers exist in PCRE precisely to suppress backtracking, so on
RE2 they are redundant, not missing. For the rare rule that genuinely needs a
backreference, use an analyzer.

`hyperscan`/`vectorscan` are worth a look if multi-pattern throughput ever becomes the
bottleneck — they are faster than RE2 at scanning many patterns at once and share its
linear-time property — but they also lack backreferences, so they change nothing here.

---

## Suggested order

Ordered by *validated files per unit of risk*, not architectural tidiness.

| Step | Work | Yield | Risk | Needs Phase 1? |
|---|---|---:|---|---|
| **0** | §6 eval harness + committed baseline (0 CMS / 4 Sites) | protects everything after it | low | no |
| ✅ **0.5** | Include filter widened (~130 globs) | **+14 files**, video polyglots 0/12 → **12/12**, 0 new FP | low | no |
| ✅ **0.6** | `OBF036` binary-in-text + `DEFC001` prose filter | **+2 labelled, +18 bulk**, 0 FP | low | no |
| ✅ **0.7** | Escape-injection sanitiser (`utils/SafeText.h`) | security: blocks DA1/OSC52/OSC0 injection from quoted malware | low | no |
| ✅ **0.8** | `OBF015` `\s*` fix + `OBF037` mixed octal/hex | **+15 bulk**, 0 FP | low | no |
| **0.9** | Audit the remaining ~120 rules for the same over-fitting | unmeasured | low | no |
| **1** | `OBF026` + `OBF027` | **63 files**, 0 FP | low | no |
| **2** | Phase 3.1 archive traversal | **49 files** | medium — zip-bomb guards | no |
| **3** | Tier B rules that match raw | **~34 files**, 0 FP | low | no |
| **4** | Phase 1 normalization + the 4 rules it unlocks | 7 files + future variants | medium — offset mapping | — |
| **5** | `OBF028` jitter, Tier C at `high` | corroboration; 3 FP | low | no |
| **6** | Phase 5 corpus hygiene | better ground truth | low | no |
| **7** | Phase 4 capability scoring | ~8 files | high — own FP study first | no |
| **8** | Head/tail scanning for large binaries | unmeasured | medium | no |

Step 8 exists because `max_file_size` is 5 MB: the widened filter admits `.mp4`/`.avi` but
a genuine large video is still skipped by size. The known polyglots are 5–6 KB. Catching a
payload appended to a 50 MB video needs head/tail scanning, not a wider filter.

> **Update 2026-09-03.** The default `max_file_size` is now 25 MB (see the README for the
> measurement). That moves the threshold but not the argument: a 50 MB video is still
> skipped, and reading a whole video to find 6 KB appended to it is the wrong shape of
> work either way. Step 8 stands, and the cap change does not shrink it — what the cap
> recovered on the measured host was 29 code and text files, not media.

Steps 1–3 are **145 of the 185 misses (78%)** with no change to the matching architecture
and no measured false positive. That is the first release; everything after it is
diminishing returns on rising risk.

### What "done" looks like per step

Each rule lands with: a unit test in `tests/rules_test.cpp` asserting it fires on a
representative construct and stays silent on a benign counter-example; and a line in the
eval-harness table recording its TP / FP-CMS / FP-Sites. No rule merges without both.
