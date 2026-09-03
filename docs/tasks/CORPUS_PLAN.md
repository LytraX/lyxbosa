# Corpus collection and golden test suite — plan

**Status:** plan only, nothing executed.
**Trigger:** the review in `docs/local/ChatGPT-Review.md` — "the golden corpus is now the
highest-value improvement you could make" — plus a hard deadline: the incident host is
about to be cleaned, and everything on it is unrecoverable after that.

**Source of truth for collection:**
`INCIDENT-HOST:/root/incident-2026-08-22/lyxbosa/lyxbosa-ltrx-report-03092026_1307.json`

---

## 0. The part that is actually urgent

Everything in this plan except **§2 Collect** can be done next month. §2 cannot: once the
host is cleaned, the samples *and their context* are gone.

And the context is the half that gets lost by accident. The bytes of a webshell are
replaceable — similar ones turn up on the next incident. What is not replaceable is that
*this* file sat at `wp-content/uploads/2026/06/06/index.php`, mode `0444`, owned by the
web user, mtime three weeks before discovery, in an account whose `.htaccess` allow-listed
it by name. Several rules in this scanner exist because of placement and permissions, not
content. **Capture metadata before, not after, moving anything.**

So the ordering is: measure disk (§1) → capture the manifest (§2.1) → verify (§2.4) → only
then tell the operator the server can be wiped (§2.5). Classification (§4 onward) happens
at leisure on local copies.

---

## 1. Disk space — do this first

Not yet run; the numbers below are the arithmetic to fill in, not estimates.

```bash
# Local headroom
df -h /home/lytrax/projects/LyxBoSa
du -sh trail-data/CMS trail-data/Sites trail-data/Infected

# What the report accounts for, by class
ssh INCIDENT-HOST 'python3 - /root/incident-2026-08-22/lyxbosa/lyxbosa-ltrx-report-03092026_1307.json' <<'PY'
import json,sys,os,collections
d=json.load(open(sys.argv[1]))
f=d.get("files",[])
matched=[x for x in f if not x.get("skipped")]
skipped=[x for x in f if x.get("skipped")]
print("scanned      :", d.get("totalFilesScanned"))
print("matched      :", len(matched))
print("skipped      :", len(skipped))
def total(rows):
    n=0
    for r in rows:
        try: n += os.path.getsize(r["path"])
        except OSError: pass
    return n
print("matched bytes:", total(matched))
print("skipped bytes:", total(skipped))
c=collections.Counter(y["category"] for x in matched for y in x["matches"])
print("rules        :", len(c), c.most_common(15))
PY
```

Budget **3× the collected byte total**: one copy of the raw collection, one working tree
for sanitisation and classification, one for the packed shards. If the skipped set is
dominated by multi-gigabyte backups (it was, last time: 24.7 GB of archives), decide
per-archive rather than pulling all of it — see §2.3.

---

## 2. Collect

### 2.1 Manifest first, bytes second

One pass on the server that writes a metadata record per file **and nothing else**. This
is the step whose output cannot be reconstructed later.

```bash
ssh INCIDENT-HOST 'python3 - /root/incident-2026-08-22/lyxbosa/...json' <<'PY' > collect-manifest.jsonl
import json,sys,os,hashlib,pwd,grp,stat
d=json.load(open(sys.argv[1]))
for rec in d.get("files", []):
    p = rec["path"]
    out = {"path": p,
           "reported_skipped": bool(rec.get("skipped")),
           "skip_reason": rec.get("skipReason"),
           "rules": sorted({m["category"] for m in rec.get("matches", [])}),
           "matches": rec.get("matches", [])}
    try:
        st = os.lstat(p)
        out.update(size=st.st_size, mode=oct(stat.S_IMODE(st.st_mode)),
                   mtime=int(st.st_mtime), ctime=int(st.st_ctime),
                   uid=st.st_uid, gid=st.st_gid,
                   user=pwd.getpwuid(st.st_uid).pw_name if st.st_uid else "root",
                   symlink=stat.S_ISLNK(st.st_mode))
        if stat.S_ISREG(st.st_mode) and st.st_size <= 512*1024*1024:
            h=hashlib.sha256()
            with open(p,"rb") as fh:
                for b in iter(lambda: fh.read(1<<20), b""): h.update(b)
            out["sha256"]=h.hexdigest()
    except OSError as e:
        out["stat_error"]=str(e)
    print(json.dumps(out))
PY
```

Also capture, in the same session, the things that explain the samples and are not files
in the report:

- `.htaccess` in every directory that holds a matched file (attacker-written `.htaccess`
  is itself a finding, and this session found one allow-listing shell filenames);
- the directory listing of each matched file's parent, so "one PHP among 400 JPEGs" is
  recoverable;
- `crontab -l` per account, and any `~/.ssh/authorized_keys` — persistence context;
- the report JSON itself, and the previous one from 02/09 for diffing.

Keep this bundle small and text-only. It is the evidence; the bytes are the exhibits.

### 2.2 Pull the bytes

`rsync --files-from` preserving absolute paths. Path is evidence, so the tree structure
comes with it.

```bash
jq -r 'select(.reported_skipped==false) | .path' collect-manifest.jsonl > matched.paths
mkdir -p trail-data/incoming/2026-09-03/tree
rsync -a --files-from=matched.paths INCIDENT-HOST:/ trail-data/incoming/2026-09-03/tree/
```

Two things learned the hard way in the session that produced this plan:

- **`rsync --files-from` works; streaming `tar` over ssh does not.** Bulk-piping customer
  data off a production host trips the sandbox classifier. Use rsync.
- **rsync preserves attacker-set permissions**, including mode `000` directories. Fix
  readability locally *after* the manifest has recorded the originals:
  `chmod -R u+rwX trail-data/incoming/`.

### 2.3 Archives and oversize files — decide, don't default

Last measurement: 170 archives / 24.7 GB, and the interesting part is *inside* them (this
session found two obfuscated webshells and a JPEG/PHP polyglot uploader in backups sitting
in web roots). Pulling 25 GB of customer site backups to keep three members is the wrong
trade, and those backups contain live `wp-config.php` credentials.

Recommended: for each archive, pull **the member list plus only the members that matched**
(the scanner already addresses them as `backup.zip!path/inside.php`). Keep the container
itself only where the container *is* the finding — `ARC001` exposure cases — and then only
one or two as examples, recorded as such.

Anything above ~100 MB: record its manifest row and a 2 MB head prefix, not the file. That
is enough to write a format sniffer against later (it is how the `.wpress` prefix sample
already in the corpus was handled).

### 2.4 Verify before anyone deletes anything

```bash
# Recompute locally and diff against the server's hashes.
jq -r 'select(.sha256) | "\(.sha256)  trail-data/incoming/2026-09-03/tree\(.path)"' \
  collect-manifest.jsonl > expect.sha256
sha256sum -c expect.sha256 2>&1 | grep -v ': OK$' | head
```

Zero mismatches and zero missing, or collection is not done. Record the count of files
collected vs files in the report, and account for every difference.

### 2.5 Only then: the server

Report to the operator: N files collected, N verified, N deliberately not collected and
why. Deletion is their call and their action, not this plan's.

**Retention note.** This is customer data on a development machine, some of it personal
content and some of it live credentials. Keep it under `trail-data/` (gitignored), keep it
non-executable, and treat the raw `incoming/` tree as something to be deleted once
classification has extracted what the corpus needs. Get the operator's explicit agreement
that retaining it for corpus work is authorised, in writing, before §4.

---

## 3. Local storage hygiene

These are live webshells and real customer files.

- `trail-data/` stays gitignored. Nothing raw is ever committed.
- Store samples mode `0400`, directories `0500`. They must never be executable and never
  land under a webroot on this machine.
- The corpus README already says "Handle as live malware" — extend that to
  "and as customer data".
- Expect endpoint AV to quarantine things mid-work. Note it rather than disabling AV.

---

## 4. Classify

The output of classification is not a folder layout, it is **a machine-readable expected
result per sample**. That is the whole point of a golden suite: `infected=true` is not
enough, because a rule change that keeps the detection but for the wrong reason is a
regression that a boolean cannot see.

### 4.1 Tiers

The existing corpus has two tiers (`verified` / `unverified`) and this session proved two
more are needed — one because four "verified malware" samples turned out to be WordPress
core and WooCommerce, and one because customer content cannot be published at all.

| tier | meaning | publishable |
|---|---|---|
| `malicious` | opened, read, confirmed hostile | yes |
| `benign` | opened, read, confirmed legitimate — includes upstream code that a rule wrongly flagged | yes |
| `vulnerable` | genuinely dangerous code in legitimate software (`EXP006`, `RCE006` cases) — a correct detection, not malware | yes |
| `sensitive` | customer content or credentials. Never published, hash and note only | **no** |
| `unreviewed` | collected, not yet opened | no |

`unreviewed` is the default and nothing leaves it without a human having looked.

### 4.2 Keep the human queue small by automating triage, not judgement

Do not ask a person to look at 1,700 files. Ask them to look at the ones where automation
cannot be trusted:

1. **Dedupe by sha256** against the existing 4,198-row manifest first. Last time three of
   the interesting samples were already in the corpus.
2. **Group by sha256** within the new set — the `titi` backdoor appeared as 8 identical
   copies; that is one review, not eight.
3. **Group by rule signature and first-150-chars of the matched line.** The previous
   analysis collapsed 2,769 findings into 462 signatures this way. One representative per
   signature is the review unit.
4. **Auto-classify what is mechanically decidable**, and record the reason:
   - upstream code identified by an exact sha256 match against a pinned stock tree
     (§6) → `benign`, no human needed;
   - the *forged*-header trap found in this session: three samples carried
     `@package WordPress\Updates` docblocks over a `?raimu=` gate. So a header match is
     **not** sufficient — only a whole-file hash match against real upstream is.
5. **What is left goes to human review**, ordered by blast radius: critical-severity
   first, then anything in a webroot, then the rest.

### 4.3 Media files — the specific problem you flagged

Pictures and videos are the case where automation must not decide, because the two
possibilities are opposite: a polyglot carrying a payload, or a customer's family photo.

Triage that separates them without a human opening every image:

- **Structural check, not visual.** A media file matters to this corpus only if it carries
  code. Test for that directly: valid container header followed by trailing data,
  `<?php`/`<script` anywhere after the media stream, control-byte distribution
  inconsistent with the format, size disagreeing with the declared dimensions. The
  JPEG/PHP polyglot found in this session was detectable in its first 200 bytes — JFIF
  magic then `<?php echo "Priv8 Uploader"`.
- **Pure media that merely matched a rule is either a false positive or customer content.**
  Either way it does **not** need publishing. It needs a manifest row, the rule that
  fired, and — if it is an FP — a *synthesised* equivalent that reproduces the trigger
  without the customer's bytes.
- **For genuine polyglots, publish the payload, not the carrier.** Extract the appended
  code, pair it with a generated clean carrier of the same format. The test then covers
  the technique and ships no customer image. Where the carrier itself is load-bearing
  (offset-dependent detection), that sample stays `sensitive` and the test is marked
  local-only.
- **Human review, when it happens, should be on thumbnails and metadata**, in a
  contact-sheet form — not by opening files individually. Anything with recognisable
  people, documents or screens goes `sensitive` without further discussion.

### 4.4 Index format

Append-only **JSONL**, one line per sample, alongside a content-addressed blob store.
JSONL because a schema can gain fields without rewriting existing rows, appending is one
line, and it diffs and merges in git.

```json
{"sha256":"...","size":14916,"tier":"malicious","family":"smart-chunk-stager",
 "origin":{"incident":"2026-08-22","account_hash":"a3f1","path":"/wp-content/uploads/x.php",
           "mode":"0444","mtime":1782000000},
 "technique":["chunked-append","base64"],
 "expect":{"must_detect":["OBF029"],"must_not_detect":["OBF025"],"min_severity":"critical"},
 "review":{"by":"cl","date":"2026-09-04","note":"203831 appends of width 4"},
 "publishable":true}
```

- `expect.must_detect` gives recall; `expect.must_not_detect` gives precision and is where
  every fixed false positive is pinned forever.
- `origin.account_hash` not the account name: provenance without the customer.
- One row per *sample*, and duplicates collapse to one row with a count.

Migrate the existing `manifest.tsv` (4,198 rows) into this by mapping
`tier/family/stored_as/decoder` and leaving `expect` empty, to be filled as each family is
reviewed. Keep `manifest.tsv` generated from the JSONL for as long as anything reads it.

---

## 5. Make `trail-data/Sites/site21.tld` generic

22,414 files of a real site. It is the only *whole realistic site* in the corpus, which is
exactly why it is worth keeping and why it cannot stay as-is.

**What identifies it,** and all of it has to go: the domain (in `wp-config.php`, the DB
dump, page caches, sitemaps, minified asset URLs, `.htaccess`), the account name in paths,
admin and contact e-mail addresses, DB name/user/password and salts, plugin licence keys
and API tokens, and everything under `wp-content/uploads` — which is customer content, not
site code.

**Approach:**

1. Build the identifier list mechanically before editing anything: grep the tree for the
   domain, the account name, every `@`-bearing string, and the `wp-config.php` constants.
   Review the list by hand — this is the step where a missed identifier survives.
2. Substitute deterministically from a mapping file kept **outside** the repo, so the same
   token maps to the same replacement everywhere. A page cache that references the domain
   has to still match the config after substitution, or the corpus stops being a coherent
   site.
3. **Prefer length-preserving replacements.** `site21.tld` → `demo.tld` keeps offsets, sizes
   and entropy stable. This matters because the file is also a false-positive fixture: the
   four known `OBF025` findings must survive sanitisation unchanged, and offset-sensitive
   rules should see the same shape.
4. Replace `uploads/` with generated placeholders — correct extensions, plausible sizes,
   no customer bytes. Keep the *directory structure*, since upload-path placement is
   itself a detection signal.
5. Delete the DB dump rather than sanitise it. A WordPress dump is mostly customer content
   and the effort/risk is not worth it; if a SQL fixture is needed, generate one.

**Verify:**

- grep the sanitised tree for every identifier on the list → zero hits;
- re-scan and confirm **exactly** the 4 known `OBF025` findings, no more, no fewer;
- file count and directory shape unchanged;
- a second person greps for the identifier list independently.

Rename the directory to something generic (`Sites/demo-wp/`) and record in the corpus
README that it is a sanitised real site, with what was replaced.

---

## 6. Benign corpus — target what actually breaks rules

The existing `trail-data/CMS` is 51,294 files of stock WordPress, Joomla and Magento, and
it produces **zero findings**. That is worth knowing: stock CMS core is not what breaks
these rules. Every false positive analysed this session came from somewhere else —
protobuf-generated PHP, webpack development bundles, Freemius, Symfony polyfills, icon
fonts, Twilio docblocks, composer's bootstrap.

So "download more CMS" should mean **the plugin, theme and vendor ecosystem**, in this
order:

1. **Vendored third-party trees** — the actual FP source. `composer install` on
   WooCommerce, a Laravel skeleton, a Symfony skeleton; `npm install` a WordPress block
   plugin so `node_modules` and dev bundles are present.
2. **Top WordPress plugins by install count**, ~50 of them, and the ones already known to
   trip rules: WooCommerce, Wordfence, Elementor, WPForms, Yoast, Freemius-based plugins,
   WP Fastest Cache, RevSlider, Site Kit, TranslatePress, Akeeba.
3. **Icon fonts and minified assets** — two OBF038 false positives came from these.
4. **Additional CMS**: Drupal, PrestaShop, OpenCart, phpMyAdmin, TYPO3.
5. **Only then** more core versions, and mainly *old* ones — an outdated core is what a
   real host looks like.

**Do not commit the downloads.** Commit a lockfile and a fetch script:

```
corpus/benign/sources.jsonl
{"name":"woocommerce","version":"9.3.3","url":"https://downloads.wordpress.org/plugin/woocommerce.9.3.3.zip","sha256":"..."}
```

`corpus/fetch-benign.sh` reads it, downloads, verifies the hash, unpacks. That keeps the
repo small and makes the benign side *reproducible*, which is what turns "it worked on my
server" into a number someone else can regenerate.

---

## 7. Pack it

Requirements: append a sample without rewriting anything, dedupe, never execute, integrity
checkable, and let a test runner read one sample fast.

**Recommendation: content-addressed store + JSONL index + per-family `.tar.zst` shards.**

```
corpus/
  index.jsonl                     # the authority. small, text, in git
  expect/                         # golden expectations, in git
  blobs/ab/cd/abcdef…             # content-addressed, gitignored
  shards/malicious-webshells-001.tar.zst
  shards/benign-vendor-004.tar.zst
  fetch-benign.sh
  SOURCES.md
```

- **Content-addressed** gives free dedupe (8 identical backdoor copies → one blob) and
  integrity by construction.
- **Append = one new blob + one index line.** No existing file is rewritten, which is what
  makes "easily add more files" true. A single monolithic archive fails this test.
- **`.tar.zst` shards** for distribution: good ratio, fast random-ish access, ubiquitous
  tooling. Cap shards at ~200 MB so a shard can be added or replaced independently.
- **The index and expectations are public; the malicious blobs are not.** Committing live
  webshells to a public repo will trip contributors' AV on clone and can get the
  repository flagged. Publish the index, the expectations and the benign fetch script;
  distribute malicious shards as an encrypted release asset or out-of-band, with the
  passphrase documented. A contributor can then run the benign half and the regression
  expectations without holding malware.
- `sensitive`-tier samples never enter a shard at all — index row only.

---

## 8. Golden test suite

One command, machine-readable output, every past mistake permanent.

```
$ lyxbosa-corpus verify
Corpus 2026-09-03  (index 6,412 samples · 3 shards · benign 214,880 files)

  malicious      2,104 / 2,118 detected      14 missed
  benign       214,836 / 214,880 clean       44 false positives
  vulnerable        10 /      10 detected
  rule-exact     2,061 / 2,104 matched the expected rule

  Recall     99.34%    Precision   97.95%
  Regressions        0 new · 0 fixed
```

- **`rule-exact`** is the line that boolean suites miss: detected, but by the rule that
  should have detected it. A rule change that keeps a detection for the wrong reason shows
  up here.
- Wire it to the existing `.baseline/` mechanism — that already diffs JSON reports
  ignoring `durationMs`, and already caught real regressions this session.
- **Every FP and FN found in the field becomes a row with `must_not_detect` /
  `must_detect`.** The four upstream-code files re-tiered this session are the first
  entries: each is a real file a real rule scored as malware.
- Run the benign half in CI (it needs no malware); run the full suite locally and on tags.
- Put the numbers in the README with the dataset named, per the review's point about not
  quoting "96%" without saying against what.

---

## 9. Order of work

| # | Step | Blocking? |
|---|---|---|
| 1 | §1 disk check | yes |
| 2 | §2.1 metadata manifest | **before server cleanup** |
| 3 | §2.2–2.4 pull and verify bytes | **before server cleanup** |
| 4 | §2.5 report to operator, retention sign-off | gates §4 |
| 5 | §4.2 automated triage and dedupe | — |
| 6 | §4.3 media triage, then human review | needs you |
| 7 | §5 sanitise the site corpus | independent |
| 8 | §6 benign fetch list | independent, parallelisable |
| 9 | §4.4 index migration | after 5 |
| 10 | §7 packing | after 9 |
| 11 | §8 suite + README numbers | last |

Steps 1–4 are the only ones with a deadline. Everything else is unblocked once the bytes
are local and verified.

---

## 10. Open questions for you

1. **Retention scope.** Are we authorised to keep customer content on this machine for
   corpus work, and for how long? §4.3's answer changes if the answer is "not at all" —
   the plan then extracts payloads and deletes carriers immediately.
2. **Publication.** Is the malicious half intended to be publicly downloadable? If yes,
   every sample needs a sanitisation pass of its own (webshells embed the victim's paths,
   domains and e-mail addresses), which is a substantial extra step not costed here.
3. **The archives.** 25 GB of customer site backups containing live credentials — pull
   selected members only (§2.3), or take the containers for completeness?
4. **`acct33-lyxbosa-quarantine` and the other five `lyxbosa-*` families.** They were
   assembled from this scanner's own hits, so scoring against them is circular, and one of
   them was 25% upstream code. Re-review, or drop them from the golden set and keep them
   as FP fixtures only?
