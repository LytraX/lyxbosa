# Corpus collection and golden test suite — plan

**Status:** under review. Plan only, nothing executed.
**Revision:** 2 — sensitivity reworked as a separate axis; backups excluded; publication assumed.
**Trigger:** the review in `docs/local/ChatGPT-Review.md` — "the golden corpus is now the
highest-value improvement you could make" — plus a hard deadline: the incident host is
about to be cleaned, and everything on it is unrecoverable after that.

**Source of truth for collection:**
`<host>:/root/<incident>/lyxbosa/lyxbosa-ltrx-report-<stamp>.json`

`<host>`, `<incident>` and `<stamp>` are placeholders: this file is tracked, and no customer
hostname, account name or incident name goes in a tracked file. The real values — and the
substitution needed to make every command below runnable verbatim — are in
`trail-data/incoming/2026-09-03/SOURCE-OF-TRUTH.md`, which is gitignored.

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
ssh <host> 'python3 - /root/<incident>/lyxbosa/lyxbosa-ltrx-report-<stamp>.json' <<'PY'
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
ssh <host> 'python3 - /root/<incident>/lyxbosa/...json' <<'PY' > collect-manifest.jsonl
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

**Do not order triage by mtime.** Captured mtimes are worth having and are not evidence of
age: 94 files in this collection carry mtimes spread over 2015–2018 on content provably
written in 2026, and they are not stomped to match their siblings (2 of 94 match one exactly,
none within an hour), so the dropper set them from somewhere else. Any queue sorted
oldest-first buries them.

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
rsync -a --files-from=matched.paths <host>:/ trail-data/incoming/2026-09-03/tree/
```

Two things learned the hard way in the session that produced this plan:

- **`rsync --files-from` works; streaming `tar` over ssh does not.** Bulk-piping customer
  data off a production host trips the sandbox classifier. Use rsync.
- **rsync preserves attacker-set permissions**, including mode `000` directories — and
  `chmod` afterwards does not converge at scale. `rsync -a` re-applies the source mode to
  every directory it touches, so a chmod-then-retry loop keeps re-breaking what it just
  fixed: measured at 7,971 errors, still 7,594 after five passes. Set the modes *during*
  transfer instead, and let the manifest hold the originals:

  ```bash
  rsync -a --chmod=Du+rwx,Fu+rw --files-from=… <host>:/ dest/
  ```

  An aborted pass leaves `.~tmp~` files behind. Identify them against the manifest and
  remove them before verifying, or they show up as orphans.

### 2.3 Archives: take the members, never the containers

Site backups are **not** corpus data. They are tens of gigabytes, they are full of real
customer records, and cleaning one is harder than cleaning the site it came from. Last
measurement: 170 archives, 24.7 GB, and 32 of them held a live `wp-config.php`, `.env` or
`.ssh/id_rsa`.

So: for every archive in the report, collect **the member list plus only the members that
matched**. The scanner already addresses them as `backup.zip!path/inside.php`, and the
members are the interesting part — this is how the two obfuscated `wp-admin/index.php`
webshells and the JPEG/PHP polyglot uploader were found.

Nothing above ~100 MB comes across at all. Record its manifest row and, where a format
sniffer is wanted later, a 2 MB head prefix.

**"Not corpus data" is not "not evidence", and conflating the two cost a misclassification.**
A slug in the 2026-09-04 review was recorded as attacker staging on the strength of the one
hostile file collected from it. The rest of that directory was inside a 24 KB quarantine
tarball — which this section correctly keeps out of the corpus, and which nobody therefore
opened. It held the complete, unmodified wordpress.org plugin the directory had been renamed
from, and the classification was wrong. Excluding an archive's *contents* from the sample set
is right; excluding its *member list and members* from the evidence a reviewer reads is not,
and §2.3 already captures both. Read them.

**Archive fixtures get emulated, not collected.** The suite needs archive coverage — bombs,
nested archives, malformed central directories, a container that is a copy of an installed
site — and every one of those is better *generated* than harvested:

- deterministic, so a fixture is reproducible from a script rather than a 600 MB download;
- no customer bytes, so it can be public without a sanitisation pass;
- and it can be built to hit an exact guard, which a real backup cannot.

`tests/archive_test.cpp` already generates zips and tars in-process, including a 64 MB
bomb from 64 KB. Extend that generator into a `corpus/generate-archives.sh` producing the
fixture set, and pair each with its expected outcome (`ARC001` on a synthesised site copy,
`skippedRatio`/`skippedBudget` on the bomb, `skippedCorrupt` on a truncated one).

### 2.3b Collect by directory, not by finding

**When a directory contains a finding, collect the whole directory.** This is a collection
principle, not a refinement of §2.3, and getting it wrong is unrecoverable.

Collection driven by a scan report captures the files the rules already flagged. Everything
else in the same directory is skipped — and *the sibling files are the context a
placement-based rule needs*. They are, by definition, individually unremarkable: that is
what makes them camouflage, and it is exactly why no content rule fires on them.

This was learned by losing it. A randomly-named theme directory in this collection
held four zlib payload blobs, which the scanner flagged and which were duly collected. Live
on the host the same directory also held a copy of a legitimate commercial theme's
`style.css` and `screenshot.png` — the two files that made a fake theme look like a theme.
Neither matched a rule, so neither was collected, and the host is now authorised for wipe.
**The corpus has the payload and not the disguise**, which means it cannot support the
placement rule the sample argues for (`docs/RULE_CANDIDATES.md` §1).

The general form is the more uncomfortable statement:

> A corpus assembled from findings can only support rules resembling the ones that built it.

(This is one of four appearances of the same property; see §11.)

That is the `discovered_by` problem from §4.4 arriving from a different direction. There the
concern was circularity in *measurement* — recall computed over samples the scanner found
itself is close to 100% by construction. Here it is circularity in *capability*: a new rule
needs to see what the old rules ignored, and a finding-shaped collection has already thrown
that away. Recording provenance fixes the first; only collecting differently fixes the
second.

**What to do next time, at collection:**

- for every finding on disk, collect its **parent directory in full** — every sibling file,
  with metadata, not just the flagged one;
- keep the directory listing regardless, so the shape is recoverable even where the bytes
  are too large or too sensitive to take (§2.1 already captures listings; this extends it to
  bytes);
- apply the usual exclusions to the *contents* — backups, huge media — but let the default be
  take-the-directory rather than take-the-file;
- for archive members, the equivalent is the member's directory prefix inside the container.

The cost is bounded and small: webshells sit in directories of ordinary size, and the
oversized cases are already excluded on other grounds. The cost of not doing it is that the
context is gone the moment the host is wiped, and no amount of later analysis brings it back.

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

### 4.1 Two independent axes

This is the part the first draft of this plan got wrong. It treated classification as one
question — is this malicious — when there are two, and they do not correlate:

- **Verdict:** what the scanner should say about the file.
- **Sensitivity:** what real-world information the file carries, and therefore what has to
  be masked before it can be published.

They are orthogonal. A webshell is malicious *and* sensitive: it embeds the victim's
absolute paths, their domain, the attacker's callback host, sometimes an e-mail address or
a hardcoded password hash. A `wp-config.php` flagged by `BD004` is benign *and* highly
sensitive. An upstream Symfony polyfill is benign and carries nothing. Classifying on one
axis and assuming the other follows is how secrets end up in a public corpus.

**Axis A — verdict**

| verdict | meaning |
|---|---|
| `malicious` | opened, read, confirmed hostile |
| `benign` | confirmed legitimate — includes upstream code a rule wrongly flagged |
| `vulnerable` | genuinely dangerous code in legitimate software (`EXP006`, `RCE006`) — a correct detection, not malware |
| `unreviewed` | collected, not yet opened. The default; nothing leaves it without a human looking |

**Axis B — sensitivity**, recorded as a set of tags, not a single level, because a file can
carry several kinds at once and each is masked differently:

| tag | what it means | what happens to it |
|---|---|---|
| `secret` | credentials, API keys, DB passwords, salts, private keys, session tokens | replaced with a synthetic value of the same shape and length |
| `identity` | domains, hostnames, IPs, e-mail addresses, account and customer names | deterministic substitution from a mapping kept out of the repo |
| `path` | absolute filesystem paths that name an account or a customer | account segment substituted, structure preserved |
| `pii` | personal data — names, phone numbers, addresses, order records, log lines with user data | sample is not published; index row only |
| `content` | customer-authored media or documents that are not code | not published; see §4.3 for the polyglot case |
| `c2` | attacker infrastructure — callback hosts, bucket URLs, Telegram tokens | **kept**, deliberately: it is an IOC and it is the attacker's, not the customer's |
| `clean` | carries none of the above | published as-is |

Two consequences worth stating plainly:

- **`c2` is the one category we do not mask.** A cloaker's `https://…/index.txt`, a
  `gsocket.io` installer URL, a `jan09.ofu5563ytu` campaign marker — those are the value
  of the sample and they belong to the attacker. Masking them would destroy the IOC.
- **`pii` and `content` are not maskable, so they are not published.** There is no
  substitution that makes a customer's order export or family photo safe. Those get a
  manifest row, a hash and a note, and the test that needed them gets a synthesised
  equivalent instead (§4.3, §7).

A sample is publishable when its verdict is not `unreviewed` **and** every sensitivity tag
on it is either `clean`, `c2`, or has been masked and re-verified.

> **Masking is not review.** Every gate can pass on a file nobody has looked at. The gates
> answer *"does this leak"*; the verdict answers *"what is this"*. Conflating them is how an
> unreviewed sample ships wearing a green tick — and it is not hypothetical: the §7.2 gate's
> first run found **103 rows flagged publishable that were still `unreviewed`**, because the
> masking pass had set the flag from its own gate results alone. This is precisely why
> `publishable` is computed by one piece of code from this rule, and never asserted by hand.

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
{"sha256":"...","size":14916,
 "verdict":"malicious","family":"smart-chunk-stager",
 "sensitivity":["path","c2"],
 "masked":{"path":"account segment -> acct01","c2":"kept deliberately (IOC)"},
 "publishable":true,
 "origin":{"incident":"<incident>","account_hash":"a3f1",
           "path":"/home/<acct01>/public_html/wp-admin.php",
           "mode":"0444","mtime":1782000000},
 "discovered_by":"lyxbosa-scan",
 "technique":["chunked-append","base64"],
 "expect":{"must_detect":["OBF029"],"must_not_detect":["OBF025"],"min_severity":"critical"},
 "review":{"by":"cl","date":"2026-09-04","note":"203831 appends of width 4"}}
```

- `expect.must_detect` gives recall; `expect.must_not_detect` gives precision and is where
  every fixed false positive is pinned forever.
- `sensitivity` and `masked` are the audit trail for §7. A sample cannot become
  `publishable: true` while a tag is unmasked and not on the keep-list.
- `origin.account_hash` rather than the account name: provenance without the customer.
- **`discovered_by`** records how the sample came to us — `lyxbosa-scan`, `manual-sweep`,
  `operator-report`, `third-party-scanner`. This is not a quality judgement on the sample;
  every one of them is real malware regardless. It exists so recall can be reported two
  ways: overall, and excluding samples this scanner found itself. A recall figure computed
  only over `lyxbosa-scan` samples is close to 100% by construction and would overstate
  what the tool does on malware it has never seen. Six families in the current corpus are
  in that category, which is worth being able to say out loud rather than hide. This is one of
  four appearances of the same property; see §11.
- One row per *sample*; duplicates collapse to one row with a count.

Migrate the existing `manifest.tsv` (4,198 rows) by mapping `tier/family/stored_as/decoder`
onto `verdict/family`, leaving `sensitivity` as `["unreviewed"]` and `expect` empty until
each family is reviewed. Keep `manifest.tsv` generated from the JSONL while anything still
reads it.

## 5. Masking

Two jobs that share one mechanism: sanitising the one real site in the corpus, and
sanitising the samples themselves. The second is the one that is easy to forget — a
webshell is not customer content, but it is *full of customer identifiers*.

### 5.1 Every sample, including the malicious ones

What the malware in this corpus carries about its victims, from files already read this
session: absolute paths naming the account (`/home/<acct>/public_html/…`), the site's
domain in cloaker configs and injected markup, admin e-mail addresses, hardcoded password
hashes, and in one case an admin address inside a database dump. A `wp-config.php` flagged
by `BD004` carries DB credentials and salts outright.

The masking rules, per §4.1's tags:

| tag | rule |
|---|---|
| `secret` | replace with a synthetic value of the **same shape and length** — a 64-hex salt stays 64 hex, a bcrypt hash stays a valid-looking bcrypt hash |
| `identity` | deterministic substitution from a mapping kept outside the repo, so the same domain maps to the same replacement in every file |
| `path` | substitute the account segment only; keep depth and structure, because placement is a detection signal |
| `c2` | **keep**. Attacker infrastructure is the IOC and is not the customer's |
| `pii`, `content` | not maskable — do not publish (index row and hash only) |

**Length-preserving wherever possible.** Several rules here are offset- and
entropy-sensitive — `OBF036` measures control-byte ratio and adjacency, `OBF029` measures
chunk width uniformity, `DRP007` needs a literal of a minimum length. A substitution that
changes a file's size can change whether it is detected, which would make the fixture test
the mask instead of the malware.

**Verify per sample, mechanically:** after masking, re-scan and assert the sample still
produces exactly its `expect.must_detect` set. If masking moved the verdict, the mask is
wrong, not the rule.

### 5.2 The site corpus (`trail-data/Sites/<site>/`)

22,414 files of a real site — the only whole realistic site in the corpus, which is why it
is worth keeping and why it cannot stay as-is.

1. Build the identifier list mechanically first: grep for the domain, the account name,
   every `@`-bearing string, and the `wp-config.php` constants. **Review that list by
   hand** — this is the step where a missed identifier survives.
2. Substitute deterministically from the same out-of-repo mapping, so cross-file references
   still resolve: a page cache that references the domain must still match the config, or
   the corpus stops being a coherent site.
3. Prefer length-preserving replacements (the real domain → `demo.tld`, same length). The four known `OBF025`
   findings are a false-positive fixture and must survive unchanged.
4. Replace `wp-content/uploads` with generated placeholders — correct extensions, plausible
   sizes, no customer bytes. Keep the directory structure; upload-path placement is itself
   a signal.
5. Delete the DB dump rather than sanitise it. A WordPress dump is mostly customer content;
   generate a SQL fixture instead if one is needed.

**Verify:** grep the sanitised tree for every identifier → zero hits; re-scan and confirm
*exactly* the 4 known `OBF025` findings; file count and directory shape unchanged; and a
second person greps for the identifier list independently.

Then rename to something generic (`Sites/demo-wp/`) and record in the corpus README that it
is a sanitised real site, and what was replaced.

### 5.3 What a first masking attempt actually got wrong

Recorded because every one of these passed a casual read and was caught only by a gate.
The context was masking `origin.path` for the corpus index, which §4.4 puts in git.

**Four failure modes, all in one implementation:**

1. **No token boundaries.** A plain regex alternation of account names substituted on bare
   substrings. One account's name is a substring of `ir-malware-samples` and another's of
   `manual-sweep`, so both of those got rewritten. This corrupts unrelated data rather than
   leaking, which is why it survives review — the output still *looks* masked.
2. **A field nobody thought of.** `prior_corpus.family` carried names like
   `<acct>-lyxbosa-quarantine` straight through. Masking was applied to the path field only,
   because the path was the field the author was thinking about.
3. **Only one identifier class handled.** Account names were mapped; **domains, the incident
   name and the provider hostname were not**, so `okf.<acct>.gr` and the incident directory
   name survived. Building the identifier list mechanically first (§5.2 step 1) found 92
   domain-like strings that no one would have enumerated by hand.
4. **Identifiers appear mid-token, not just as prefixes.** Quarantine tooling encodes the
   original path into a flat filename — `_home_<acct>_public_html_wp-admin_index.php` — and
   related forms appear as `php56-<acct>.conf.bak`, `wp-core-repair-test-<acct>-2026...` and
   `villa-<acct>`. Prefix-and-exact-segment masking missed all of them; one account alone
   leaked 164 times.

**The two rules that come out of it:**

- **An account name can appear anywhere inside a token, so boundary-aware masking is not
  sufficient.** Masking must handle the encoded-path forms (`_home_<acct>_…`) and
  delimiter-joined occurrences explicitly, not just segment prefixes.
- **A colliding identifier must be masked positionally, with a gate that asserts precisely
  that.** One account here had a two-character name identical to the CMS's own path prefix.
  Substituting it as a token would have rewritten `wp-content`, `wp-admin`, `wp-includes` and
  `LayerSlider/wp/` across tens of thousands of legitimate paths — corrupting the corpus to
  hide one name. The workable rule is to mask it only in the position where it *can* be the
  account (`/home/<acct>/`, and the underscore-encoded `_home_<acct>_` form), and to have the
  gate check exactly that and nothing broader. A gate that is stricter than the masker can be
  is a gate that can never pass.

**Verification must not share the masker's regexes.** A self-check built from the same
patterns passes while being wrong — it is testing that the code does what the code does.
The check that found the real leaks was an independent one: a raw substring grep for every
known identifier, whose hits were then explained one class at a time until only expected
ones remained. In this corpus that meant enumerating all 140 distinct tokens following
`/wp-` and confirming each was a WordPress script handle (`wp-polyfill`, `wp-emoji`) or an
attacker-renamed directory (`wp-content__<hash>`) — the latter being an IOC worth keeping.

Treat "the gate passes" as a claim about the gate until an independent check agrees.

**The standing rule, because this is now twelve failures and not an anecdote.** Every one was
caught by a gate; **none** was caught by reading the code — including the fifth, a field
whose contents are account names *by construction*, which slipped through because the
masking helper applied a four-character minimum. So:

- **Masking correctness is not reviewable by inspection.** Do not accept "I checked it" for
  a masking change, from a person or from a model.
- **Every new field that can carry an identifier gets gate coverage before it is populated,
  not after.** The gate is part of adding the field, not a follow-up.
- **Verification always uses a check that does not share the masker's own patterns.** Same
  regexes on both sides tests only that the code agrees with itself.

A further failure should be assumed to exist in whatever field is added next. Seven more have
occurred since this was written, taking the tally to twelve — and, as predicted, every one was
caught by a check and none by reading code. The eighth and ninth were not masking bugs at all
but the same class of defect in adjacent machinery, which is why the rule is stated about
*checks* rather than about masking:

8. **`undecodable` conflated two different facts** — "there is an encoded layer I could not
   open" and "there is no encoded layer at all" — and §5.4 then held the sample permanently on
   the first reading. Of 380 blobs carrying it, 281 genuinely have an encoded layer and **99
   have none**, so 99 samples were held for a reason that did not apply to them.
9. **The sensitivity tagger matched PII field *names*, not values.** A skimmer reading
   `$_POST['billing_phone']` contains the name of a personal field and nobody's phone number.
   The fix was *not* to loosen the test until it agreed: a second, independent scan for
   personal-data **values** was written and validated against four positive and four negative
   controls **before** its answer was trusted. It fires on all four positives; on the seven
   samples in question it finds nothing.

Two of the nine were also caught in fields nobody expected to carry identifiers, and two more
— the eighth and ninth — in code that was not the masker at all. The rule generalises: any
check that decides what may be published is load-bearing, and none of them is reviewable by
reading.

**Tenth: `--collisions` could not report the strongest collision it can meet.** The
attribution loop in `incident_mask.collisions()` required `real != token.lower()`, so a token
that *is* an identifier — an account name that is also an ordinary word used as a stock-CMS
filename token — was rewritten by `mask()` and then dropped on the way to the report. The
check printed **0 tokens would be rewritten** while the masker rewrote one, and SOURCES.md's
claim that both maskers rewrite nothing in the stock trees rested on that zero. Exactly the
shape AGENTS.md names: a check silent in one direction, and the direction with the worst
consequence, since over sample bytes that rewrite lands inside working code.

**Eleventh, underneath it: `tiers()` gave the strongest collision the weakest treatment.**
The length test came first and the exact-match case fell through to `B` or `C`, both of which
rewrite a token equal to the identifier. An identifier that is indistinguishable from stock
vocabulary is the *most* colliding case, not a marginal one, and 5.3's rule for a colliding
name is positional and nothing broader. It is now `D`. Tiers are stored in the map, so the
fix changes nothing until the map is regenerated; the byte masker therefore re-derives the
tier from a vocabulary it is handed rather than trusting the stored one, and its driver
treats a missing vocabulary as a hard failure rather than running without a collision
reference.

**The regeneration was built, run, measured and rolled back, and that is the durable
result.** `regen-tiers.py` moved exactly one name and every contents assertion passed, but a
tier is a *substitution width*, and the demotion cost 6 masked occurrences of that name over
a census of 247,829 collected paths (29 → 23) while the over-masking it prevents measures
zero across 48,256 `origin.path` values. §5.6 settles that direction: leaving a name costs
everything, over-masking costs nothing. The map stays at `C` for row masking; the byte masker
continues to demote it to `D` because it re-derives, so the two disagree on this one name
deliberately — over a row field the wrong tier over-masks a path segment, over sample bytes it
rewrites a working identifier inside code.

Two things that only the attempt could have taught. `--collisions` **cannot report a `D`-tier
name at all** — `vocabulary()` yields bare tokens and every `D` rule needs a separator — so
the 0 the regenerated map produced meant the name had left the check's reach, not that the
collision was resolved. And a contents assertion cannot see a width change: six mutation
controls passed while the map got weaker, because a demotion moves no identifier, no
pseudonym and no key. `regen-tiers.py` now measures coverage per changed name before writing
and refuses a measured loss, with `--allow-coverage-loss` as an override that has to be typed.

**Twelfth, and it is the lookaround again.** The slot rules that mask a value no map can
name — a third party's account written into a sample's own UI — ended with a positive list
of the delimiters expected to follow. An example path written into a page as
`/home/<acct>/<domain><br>` ends at `<`, which was not on the list, so the account was masked
and the site name beside it was not. 5.6 already records two of these and already gives the
rule; a positive list of delimiters is a promise to have thought of all of them, and the
guard is now the negative form. Both occurrences were in one sample and both were caught by
reading the masker's own output, not by the gate — the gate is map-driven and neither name is
in either map, which is the whole reason the slot rules exist.

**Two more have since occurred, both exactly as predicted.** The sixth was in the content
masker, a new component that shipped without a gate: it rewrote the string literal
`"wp_based"` inside a webshell because the bare-token account rule matched a two-character
account name against a `wp_`-prefixed identifier. The seventh was a *gate result* stored in
the index — a field whose contents are, by construction, the names of the identifiers the
gate just found. Storing the finding stored the leak. Gate results now record category and
count only.

That is two independent recurrences of the same root cause in fields nobody expected to
carry identifiers. The rule stands and should be read as load-bearing.

**It was, and it took eight days to appear.** Content masking — masking sample *bytes*
rather than index paths — is a new component, and it shipped without a gate. Its first run
rewrote the string literal `"wp_based"` to `"ha_based"` inside a webshell, because the
bare-token account rule matched the two-character account name against a `wp_`-prefixed
identifier. Same collision, same root cause, new component, and again invisible to reading.
The fix is the same positional rule, and the content masker now has its own gate that shares
no regexes with it.

### 5.5 Never byte-mask an archive container

Length-preserving substitution is safe on source files and fatal on archives. A tar header
carries a checksum over its own bytes, and a gzip member is a compressed stream: changing a
byte inside either does not "rename a thing", it corrupts the container. The container then
stops parsing, and **every member-level detection disappears at once**.

Measured, not predicted: masking a set of collected `.tar` and `.gz` files took one from 27
firing rules to zero, and others from a dozen to zero. The plaintext gate passed on all of
them, because the identifiers really had been substituted — the detection-parity check is
what caught it. A gate that only asks "are the identifiers gone" would have called this a
success.

So: **archives are excluded from content masking entirely.** This costs nothing, because
§2.3 already says archives are not corpus data — members are collected individually and
archive fixtures are generated. If a masked archive is ever genuinely needed, the only
correct route is to mask each member and repack, never to edit container bytes in place.

### 5.6 Two gates and a parity check, because each catches a different thing

The masking pass runs three independent checks, and every one of them has now caught
something the others did not:

| check | what it catches | caught here |
|---|---|---|
| plaintext gate | identifiers left in the visible bytes | a customer domain surviving because the regex lookbehind blocked a match after `.`, and another surviving because a lookahead blocked a match before a digit |
| encoded-layer gate | identifiers inside base64/gzip/hex layers | 7 samples whose encoded payload still carried an account name or domain |
| detection parity | masking that silently destroys the sample | 12 archives reduced from full detection to nothing |

**Parity must be measured with `check` per sample, never inferred from a batch scan.** This
is a requirement, not a preference. A batch `scan` cannot distinguish *"the walker declined
to open this file"* from *"the scanner opened it and found nothing"* — both appear in the
report as an absence. During this pass the batch comparison flagged 14 parity changes; two
of them were pure artefacts of the masked copies' filenames, whose extensions were not in
the include allow-list, so those files were never scanned at all. In the batch output they
were indistinguishable from the twelve archives whose detection had genuinely been destroyed.
Only `check`, which reads the file it is given, separated them.

This is the same silent-skip class the `SkipReason` work exists to close, resurfacing one
level up — in the measurement harness rather than in the scanner. Anywhere a verification
step reads "no findings", it must first be able to prove the file was read.

Two more rules follow. **Lookarounds in an identifier regex should err towards over-matching** —
masking a few extra characters of an unrelated token costs nothing, leaving a customer
domain costs everything; both misses above were caused by a lookaround that was too strict.
And **a masked sample is publishable only when all three checks pass**, never on the
strength of one.

### 5.4 Length-preserving masking cannot reach an encoded payload

A separate limit, discovered masking the polyglot samples, and it constrains what can be
published rather than being a bug to fix.

Plaintext masking substitutes identifiers in the bytes it can see. When a sample carries an
encoded layer — base64, gzip, hex — any identifier *inside* that layer is invisible to it.
Two samples in this corpus embed an IPv4 address inside a `base64+inflate` blob; masking the
plaintext leaves it untouched, and the sample still carries it.

The obvious repair does not work. Decoding, masking and re-encoding changes the encoded
blob's length and bytes, which:

- moves every offset after it, and `OBF029`/`OBF036` are offset- and distribution-sensitive;
- changes the sample's hash, so it is no longer the sample that was collected;
- can change the verdict, which is exactly the failure §5.1 warns about — the fixture would
  be testing the mask rather than the malware.

So the rule is: **a sample whose encoded layer carries a customer identifier is not
publishable.** Not "mask harder" — the sample stays local-only with the reason recorded, and
a synthesised stand-in is generated for any test that needed it, the same treatment `pii`
and `content` already get.

**That rule is right for a compressed layer and wrong for a plain base64 one, and the
difference is measurable rather than arguable.** Of the three objections above, only the
first is specific to an encoded layer: the hash changes for any masking at all, which the
corpus already accepts and records as `masked_sha256`, and a changed verdict is what the
parity check measures. Offsets moving is the real one, and it is a property of *deflate*,
whose output length is a function of its content — which is what the two samples this
section was written about actually contain. Base64 is a fixed 3-to-4 block code, so a
length-preserving substitution in the decoded bytes yields an encoded region of exactly the
same length, differing only in the characters covering the bytes that changed. **Nothing
after it moves, and nothing outside it changes.**

**Do not re-derive this from a small sample: deflate can look length-preserving.** Measured
with the same substitution used above, deflate held its length at 37 bytes (45 → 45) and at
68 (76 → 76), and only moved at 400 (366 → 368). Two short inputs would have "shown" that the
rule can be relaxed for compressed layers too. What licenses the base64 case is not that its
length was observed to hold — it is that base64's length is a function of its input's *length*
alone, which is arithmetic and needs no sample, while deflate's is a function of its
*content*, where a run of equal lengths is a coincidence of the inputs tried. §5.4 stands
unchanged for every compressed layer, and a measurement that appears to relax it is the
§11 shape again: a check that cannot deliver the bad news at the sizes it was run at.

Three samples were held under this rule and each carried a short `/home/<acct>/…` path
constant inside a plain base64 region, 37 to 68 bytes decoded. `content_mask.py` repairs that
case and only that case, under five conditions checked per region rather than argued once:
the region must decode, this encoder must reproduce it byte for byte (padded or unpadded —
anything else, including non-zero bits in the final padding group, is refused), the
substitution must preserve length in the decoded domain, the spliced file must have the same
total length, and detection parity must hold. Measured: all three decoded to the same length
after masking, all three kept their exact file size, and all three kept their rule set.

This is the same shape as the eighth recorded failure — `undecodable` conflating "there is a
layer I could not open" with "there is no layer", and holding 99 samples for a reason that
did not apply to them. **A sample whose encoded layer this masker cannot reach is still not
publishable**, and the gate is what decides which is which: a refused region is reported, the
encoded-layer gate then reads it anyway with a decoder deliberately wider than the masker's,
and the sample is held if a name is in there.

The masking pass therefore runs **two** gates, not one:

1. a plaintext gate over the masked bytes, and
2. an **encoded-layer gate** that decodes every static layer of the *masked* output and
   re-checks it.

A sample is publishable only when both pass. In this corpus, all six polyglots passed both —
their only identifiers are `c2` hosts, which are kept deliberately — but two are still held,
because an embedded IP inside the encoded layer is ambiguous between an attacker callback
(`c2`, keep) and a customer host (`identity`, mask), and that call is not mechanical.

## 6. Benign corpus — keep the stock trees, add what actually breaks rules

`trail-data/CMS` exists to prove no rule fires on clean software, and it does that job:
51,294 files of stock WordPress, Joomla and Magento, **zero findings**. It stays, and every
new core version added strengthens it — a rule change that starts flagging stock core is
caught here and nowhere else.

The point is only that stock core is not where the risk is. Every false positive analysed
this session came from somewhere the stock trees do not reach: protobuf-generated PHP,
webpack development bundles, Freemius, Symfony polyfills, icon fonts, Twilio docblocks,
composer's own bootstrap. So expanding the benign corpus means expanding *outward* from
core, in this order:

1. **Vendored third-party trees** — the measured FP source. `composer install` on
   WooCommerce, a Laravel skeleton, a Symfony skeleton; `npm install` a WordPress block
   plugin so `node_modules` and dev bundles are present.
2. **Top WordPress plugins by install count**, ~50, and specifically the ones already known
   to trip rules: WooCommerce, Wordfence, Elementor, WPForms, Yoast, any Freemius-based
   plugin, WP Fastest Cache, RevSlider, Site Kit, TranslatePress, Akeeba, unyson.
3. **Icon fonts and minified assets** — two `OBF038` false positives came from these.
4. **More CMS**: Drupal, PrestaShop, OpenCart, phpMyAdmin, TYPO3.
5. **Older core versions** of what is already there — an outdated core is what a real host
   looks like.

**Do not commit the downloads.** Commit a lockfile and a fetch script:

```
corpus/benign/sources.jsonl
{"name":"woocommerce","version":"9.3.3","url":"https://downloads.wordpress.org/plugin/woocommerce.9.3.3.zip","sha256":"..."}
```

`corpus/fetch-benign.sh` reads it, downloads, verifies the hash, unpacks. That keeps the
repo small and makes the benign half *reproducible* — which is what turns "it worked on my
server" into a number someone else can regenerate. It is also the half that can run in
public CI with no malware present at all.

## 7. Pack it, and publish it

Requirements: append a sample without rewriting anything, dedupe, never execute, integrity
checkable, let a test runner read one sample fast — and be publishable from a public
GitHub pipeline.

**Layout: content-addressed store + JSONL index + per-family `.tar.zst` shards.**

```
corpus/
  index.jsonl                     # the authority. small, text, in git
  expect/                         # golden expectations, in git
  blobs/ab/cd/abcdef…             # content-addressed, gitignored
  shards/malicious-webshells-001.tar.zst
  shards/benign-vendor-004.tar.zst
  fetch-benign.sh
  generate-archives.sh
  SOURCES.md
```

- **Content-addressed** gives free dedupe (the `titi` backdoor was 8 identical copies → one
  blob) and integrity by construction.
- **Append = one new blob + one index line.** Nothing existing is rewritten, which is what
  makes "easily add more files" true. A single monolithic archive fails that test.
- **`.tar.zst` shards**, capped ~200 MB, so a shard can be added or replaced independently.

### 7.1 A password on a public archive is not confidentiality

The goal is a public GitHub pipeline, so this has to be said plainly: **if CI can open the
archive, so can anyone.** The passphrase has to be readable by the workflow, and a workflow
is public. Encrypting the corpus with a strong password does not keep secrets in it secret.

What a password *does* buy, and these are real:

- **stops GitHub's and AV vendors' scanners flagging the repository** as malware-hosting,
  which can get it blocked;
- **stops contributors' endpoint AV quarantining files on clone**;
- **stops accidental execution and casual scraping.**

So: use it, for those reasons, and do not treat it as a control on sensitive data.

**Masking is the actual control.** Nothing sensitive goes into a published shard unmasked —
that is what §4.1's tags and §5's rules are for, and why `publishable` is a computed field
rather than a human's assertion. A sample that cannot be masked (`pii`, `content`) is not
published at all; it stays local with an index row and a hash, and the test that needed it
gets a synthesised stand-in.

Practically, that means two shard classes:

| shard | contents | where |
|---|---|---|
| public | benign, and masked malicious with `publishable: true` | release asset, zstd + password |
| local | anything `pii`/`content`, or malicious not yet masked | never leaves this machine |

The index lists both, with `publishable` saying which is which, so the suite can report
"3,410 of 3,462 samples verified, 52 local-only" rather than silently testing less than it
claims.

### 7.2 The gate that makes this safe

Before any shard is built, a check that fails the build rather than warns:

- every sample in a public shard has `publishable: true`;
- no `pii` or `content` tag appears in a public shard;
- a secret scan over the unpacked public shards — the same identifier list from §5, plus
  generic detectors for keys, bcrypt hashes, JWTs, private keys, `DB_PASSWORD` — returns
  zero hits;
- every sample still produces its `expect.must_detect` set after masking.

That last one is what stops masking from silently destroying the corpus's value.

**The secret bullet as written cannot be satisfied, and §5.1 is the reason.** §5.1 requires a
masked secret to be replaced by a synthetic of the *same shape*, so a correctly masked sample
still contains something bcrypt-shaped and a scan of the output alone must report it. The two
rules cannot both hold in this form: 54 credential-shaped literals remain across the 39
samples masked in the round that found this, every one synthetic by construction. **§7.2 is
the half that bends**, because stripping the shape destroys the detection the sample exists to
demonstrate — the fixture would be testing the mask rather than the malware, which is exactly
what §5.1 forbids.

The replacement is differential rather than absolute: no credential-shaped literal in the
output is byte-identical to one in the input, over the plaintext and every decoded layer.
`verify-content-mask.secret_gate()` already implements it per sample, it needs no knowledge of
whose secret it is, and it has already failed usefully — on an attacker password literal
assigned to a `$pass` variable the masker's keyword list did not cover.

The structural half is now done. `shard-gate.evaluate()` requires
`masking.secret_gate == "PASS"` on a `secret`-tagged row whose masking is applied, with a
separate blocker for a recorded FAIL and for no result at all — the repair differs, so the
reasons differ. It sits inside the `applied` branch, because a row with masking *not*
applied already carries one blocker for that cause and §8 counts reasons.

**The count previously recorded here as "seventeen" was measured on the wrong side of that
round's own `--apply`.** Two things establish it. No variant of the predicate returns 17
against the index — seven were tried and they return 10, 13, 15, 15, 10, 8 and 51 — so it is
not a miscount. And every other figure from that pass reproduces exactly against the index
today, so the index still stands where the round left it and a figure that does not
reproduce was taken before the write. That 17 → 15 happened by two rows gaining a
`secret_gate` from the run being described is a reconstruction from the blocker arithmetic,
not a measurement; on two other readings of values the commit does not state, the pre-write
count is 16. The correction worth keeping is the discipline, not the digit: **a figure quoted
in a commit that also performs a write must say which side of the write it was taken on.**

The measured population, against `index-local.jsonl` — 88 rows carry the tag, all local,
none published: 46 applied with a passing gate, 8 `applied: false` with a recorded
`not_applicable_reason`, 32 with no masking record at all, and **2 applied with no gate**,
which is what remains of the fifteen after re-measurement. Thirteen of the fifteen cleared
the secret gate; two were refused, each carrying one `wp-credential`-shaped literal that
came through masking byte-identical to its input. Those two are now blocked, which is the
first time this rule has been observed to say no.

No shard carries a `secret`-tagged sample today, so arming it moves no published figure —
the published half holds zero `secret`-tagged rows, and its gate run is unchanged at
44,544 publishable, 0 stale.

## 8. Golden test suite

One command, machine-readable output, every past mistake permanent.

```
$ lyxbosa-corpus verify
Corpus 2026-09-03  (index 6,412 samples · 3 shards · benign 214,880 files)

  malicious      2,104 / 2,118 detected      14 missed
  benign       214,836 / 214,880 clean       44 false positives
  vulnerable        10 /      10 detected
  rule-exact     2,061 / 2,104 matched the expected rule

  Detection    13 /   84 reviewed malicious samples detected   (15.5%)
  Regression    7 /    7 expected detections still firing
  False-positive rate  0.0055%
  Known FPs          6 expected · 0 newly fixed
  Known misses      71 recorded · 69 of them re-run here · 0 newly detected
  Techniques        55 of 55 known techniques covered by a tested sample
  Regressions        0 new · 0 fixed
```

`Detection` and `Regression` are two different questions and only the second can honestly be
100%: see §11. Reporting them under one name called "recall" put a tautology in the headline.

- **`rule-exact`** is the line that boolean suites miss: detected, but by the rule that
  should have detected it. A rule change that keeps a detection for the wrong reason shows
  up here.

### The corpus measures false-positive rate and recall. A field scan measures precision.

The suite reports no precision figure, and this is a decision rather than a gap to be closed
later. It is worth stating plainly because the pull towards printing one is strong.

Precision is `tp/(tp+fp)`. It is only meaningful when the malicious-to-benign ratio in the
measured set resembles the ratio an operator actually faces. **On the production host this
corpus came from, that was roughly 37 true findings in 1.3 M files — about 1 in 35,000.** No
hand-curated set reproduces that, and every curated set inflates it by orders of magnitude.
A precision figure computed on the corpus is therefore a statement about *the corpus's
composition*, not about the scanner.

Two repairs were considered and both are worse than not reporting it:

- **Withhold until the two sets are "commensurate" in size.** This was implemented first and
  is the more dangerous of the two, because satisfying it makes the number *less* honest:
  commensurability means shrinking the benign side to a few hundred files, which puts the
  ratio near 1:1 — tens of thousands of times more malicious than reality. It would print
  something flattering that means nothing. It is the same error as quoting a raw 7.89%,
  inverted.
- **Report it unconditionally with the population sizes beside it.** This stops lying by
  construction but produces a figure dominated by curation: at 472 malicious samples against
  8 false positives it reads 98.3%; review 200 instead and it reads 96%. The number moves
  with how much reviewing has been done, not with how good the scanner is, and publishing it
  invites exactly the misreading this plan exists to avoid.

**False-positive rate and recall are the honest pair, precisely because each is computed
within one population.** 8 in 146,710 benign files. Detected over reviewed malicious. Neither
depends on the ratio between the two sets, which is why neither inherits the coupling problem
— and it is why adding sources to `benign/sources.jsonl` does not move a goalpost: the FP
denominator grows, the FP rate stays comparable, and recall is untouched.

There *is* one place a precision figure is genuinely meaningful, and it is not the corpus: a
**field scan of a real host**, which supplies the real ratio by construction. On the 1.3 M-file
tree above it is 37 true findings against 63 remaining false ones — precision around **37%**,
which is low, and which is exactly what the operator experiences. That number belongs in
field measurement, reported against a named host and a named scan. It does not belong in a
curated suite, and the two must never be quoted as though they were the same measurement.

### The milestone is technique coverage, not sample count

The suite's stop condition was originally "precision starts printing". That was unreachable
by construction — it required 1,467 reviewed malicious samples against a ceiling of 472, and
the requirement *moved away* as the benign corpus grew. That is a defect in the milestone,
not a shortfall in the work, and the repair is to replace it rather than to satisfy it.

> **The malicious set covers every distinct technique currently known, recall is reported
> over it, and the technique count is stated beside it.**

That is checkable, it does not move when the benign corpus grows, and it maps to what someone
actually wants to know about a scanner — not "what percentage" but "does it catch the things
we have seen". `index-summary.json` carries `techniques_known` and `techniques_published`;
the suite prints coverage and names every technique with no tested sample, so the remaining
work is a list rather than a number.

**Read `55 of 55` as a staleness signal, not as completion.** The denominator is enumerated
from what has been reviewed, so the milestone self-satisfies: review nothing new and coverage
stays at 100% for ever. What it actually asserts is narrow and worth stating in those words —
*nothing currently in the reviewed set is untested*. It says nothing whatever about the ~700
detected blobs across 183 technique clusters that are still unreviewed, and unknown techniques
live precisely there, where this measurement cannot see them.

So the number going **down** is the healthy outcome: it means a review round found a technique
the corpus did not previously know about. A round that leaves it at 100% has either tested
everything new or reviewed nothing, and the coverage figure cannot tell those apart. Pair it
with the reviewed-sample count, which can.

This is a specific case of a property that has now turned up four times in this project;
see **§11** — where the fourth instance is the recall figure this section used to print.

### `known_fp` is the mirror of `known_miss`, and needs the same treatment

`known_miss` exists because a golden suite must be able to say *"we know we miss this"*.
The same is true in the other direction, and it is easy to miss: **a known, unfixed false
positive**.

`expect.must_not_detect` pins a false positive that has been *fixed* — if the rule ever fires
on that file again, that is a regression and the suite goes red. But the false positives you
find in the field are, by definition, not fixed yet. Pinning them as `must_not_detect` on the
day you find them makes the suite red immediately, for a defect everybody already knows
about — the exact failure `known_miss` was written to prevent, arriving from the other side.

So a false-positive fixture carries `known_fp: true` while the rule still fires:

- a `known_fp` that **still fires** is the expected result, counted in its own column, never
  a failure;
- one that **stops firing** is a *result*: the rule got better. Surface it, then promote the
  fixture to a plain `must_not_detect` so the fix is pinned and can never silently regress;
- a plain `must_not_detect` that fires again **is** a regression, and is red.

The two columns together are what let the suite report honestly on both axes at once:

```
  Known FPs        6 expected · 0 newly fixed
  Known misses    71 recorded · 69 of them re-run here · 0 newly detected
```

Neither is a failure. Both are measurements of where the scanner currently stands, and both
turn into news the moment they change.

### The two columns were built with opposite conventions, and only one was right

This is the narrower lesson behind §11's fourth instance, and it is worth stating separately
because it is easier to act on.

The columns look symmetric and are not. **A `known_fp` sample stays inside the number it
belongs to.** Measured: the benign sweep counts 8 false positives, and all 8 are pinned
`known_fp` material — the whole figure is known, unfixed false positives, and reporting it as
`0.0055%` is honest precisely because none of them was taken out. (The fixture list holds 6
sha256 and matches 8 files, because `class-freemius.php` and `FreemiusBase.php` appear under
several plugins; the store is content-addressed and the sweep is not.)

**A `known_miss` sample was removed from its denominator entirely.** Same concept, mirrored
layout, opposite effect: one column reports "here is a defect, and it is in the total", the
other reported "here is a defect, and the total is computed as though it were not".

The symmetry *was* checked — both columns exist, both stay green, both promote to a hard
assertion when they change. What was never checked is what each does to its own denominator.
So:

> **When you build a mirror, check that the reflection behaves the same way, not just that it
> is there.**

And the reason nobody noticed for several rounds is worth recording too: **the false-positive
side happened to be correct**, so there was nothing to contrast the other against. A pair
where one half is right and the other is wrong looks, from a distance, exactly like a pair
where both are right. Reviewing them side by side is what finds it; reviewing each on its own
never will.

### Every count difference must carry an attributed cause

A summary line that says a number changed is not a result until it says *why*. In a corpus
report, **"fewer files scanned", "fewer files present" and "files present but skipped" are
indistinguishable**, and all three render as a smaller number.

This has now bitten in three separate places in this project:

- **In the scanner**, which is why `SkipReason` exists at all — a file the walker declined
  to open looked exactly like a file that was scanned and found clean.
- **In the masking harness**, where a batch scan reported 14 parity changes; two were
  masked copies whose extensions were not in the include allow-list, so they were never
  scanned, and they were indistinguishable in the report from twelve archives whose
  detection had genuinely been destroyed. Only per-sample `check` separated them.
- **In site sanitisation**, where the sanitised tree scanned 110 fewer files than the
  original — entirely because a customer ZIP's many members had been replaced by a
  placeholder with one member. On-disk counts were unchanged.

So the suite must not print a bare delta. Any difference between two corpus states —
sample counts, files scanned, findings, shard contents — is reported with a cause attributed
to one of: *not present*, *present but not scanned* (with the reason), *scanned and clean*,
or *scanned and changed*. A difference the suite cannot attribute is itself a finding and
should be surfaced as one rather than smoothed into a total.

**A check must verify what it appears to verify.** Two failures of this during the corpus
work, both of which reported success while checking nothing of the sort:

- `command -v zstd tar jq` was used as an all-present test. It is not one: it reported
  success while `zstd` was absent, because the shell builtin's exit status does not mean
  *"all of these exist"*. A check that looks like it verifies three things and verifies only
  some of them is worse than no check, because it converts an absent dependency into a
  silent fallback. Test dependencies one at a time, and fail on the first missing one — the
  standard `fetch-benign.sh` already applies to `jq` and `sha256sum`.
- The WordPress **themes** API is a different endpoint and response shape from the plugins
  API. Reusing the plugins resolver against theme slugs returned 404 for all fourteen, and
  because the loop logged and continued, the run "succeeded" with a lockfile that was simply
  missing every theme. A resolver that skips is fine; a resolver that skips *everything* of
  one kind and still exits zero is a silent partial result. Assert the expected count.

The same rule applies to anything derived from those counts. A recall or precision figure
computed across a set whose membership changed for an unattributed reason is not comparable
to the previous run's, and reporting it as though it were is how a suite starts lying
quietly.

**And a count that does not change still has to carry a cause.** The encoded-layer blocker
read 2 before a round and 2 after, which is the easiest kind of number to skip past and the
one that already drifted here once. Establishing that it was the *same two rows* took three
steps and none of them was the count itself: only the 15 rows in the re-measure worklist had
their masking records touched, so every other row's verdict is unchanged by construction; of
the 24 rows carrying a non-`PASS` encoded gate, the 22 outside that worklist produce no
blocker at all and so contributed 0 on both sides; and inside the worklist, a verdict that
flipped in either direction would have changed the row's blocker set, which is exactly what
`shard-gate`'s **blocker-drift** class detects — it reported two rows, and on both the encoded
blocker was present in the recorded set *and* the computed set. Membership held. The general
form: **a stable count is a claim about a set, and the set is what has to be shown.**

The 22 silent rows are their own lesson. "24 rows fail the encoded gate and 2 are reported"
is not a discrepancy — 16 have `applied: false`, so the gate fields are never consulted and
the row is blocked once for one cause, and 6 are tagged `clean` alone, so `unmasked` is empty
and the whole masking branch is skipped. That is the same tag arithmetic as the `c2` hole in
§4.1, in its other tag, and it means **a blocker count is a count of rows the gate reached**,
never a count of rows in that condition.

**A gate result recorded by an earlier version of the gate is not evidence, and re-measuring
is how you find out.** Two rows moved `plaintext_gate` `PASS → FAIL` on re-measurement and
neither was a regression: the masker's span selection is unchanged over the commit that wrote
the old records, the slot rules that *are* new mask strictly more, and the survivor is an
eight-character tier-`B` identifier sitting after an alphanumeric where the masker cannot
reach it and the gate's containment rule can. The earlier `PASS` was simply wrong. Re-gating
all 82 remaining rows with the same superseded records put a number on it — 79 hold, 3 do
not, one of the 3 being `publishable: true` — which is a census of that population rather
than an extrapolation from the two that were noticed first.

### `known_miss` is a separate column, never a failure

Some samples in the index carry `expect.known_miss: true` with `must_detect: []`: they are
real malware that this scanner, at the recorded version, does **not** detect. The first
three are polyglots — two defeated by `KNOWN_ISSUES.md` issue 4, one a PHP payload inside a
PNG `tEXt` chunk.

They must be counted as **expected misses**, in their own column, and must not contribute to
the failure count:

- a `known_miss` sample that is still missed is the **expected** result — the suite stays
  green, because nothing regressed;
- a `known_miss` sample that starts being **detected** is a *result*, not a broken test. The
  suite should surface it prominently — "1 newly detected" — and the fix is to clear the
  flag and promote the observed rules into `must_detect`, pinning the new coverage;
- a sample that was detected and stops being detected is a **regression**, and that is the
  only one of the three that is red.

Getting this wrong has a predictable failure mode: if expected misses are scored as
failures, the suite reports red on the day it is introduced, everyone learns to ignore the
red, and it stops being a signal at all. A suite that cannot express "we know we miss this"
will be made to lie about it instead.

This is also the honest way to state recall. Recall computed only over samples the scanner
already finds is close to 100% by construction; the `known_miss` column is what stops the
headline number from quietly excluding the cases that motivated the corpus. Report it
alongside recall, not folded into it.
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

## 10. Decisions taken, and what is still open

Recorded so the plan is not re-litigated:

| question | decision |
|---|---|
| Metadata as well as bytes? | **Yes, and first.** §2.1 — it is the only truly unrecoverable part |
| Are the infected files "customer content"? | **No.** They are malicious data. They still get a sensitivity pass, because they carry the customer's paths, domains and addresses (§5.1) |
| Public corpus? | **Yes**, a public GitHub pipeline is the goal. Masking is the control; the archive password is for AV and scanner noise, not confidentiality (§7.1) |
| Site backups as corpus data? | **No.** Too large, real data, not cleanable. Members only, and archive fixtures are generated (§2.3) |
| Samples this scanner found itself? | **Keep all of them** — they are real malware. Provenance is recorded in `discovered_by` so recall can also be reported excluding them (§4.4) |
| Stock CMS trees? | **Keep and extend.** They are the clean-software baseline; the ecosystem is added alongside, not instead (§6) |

Still open, and each changes the work:

1. **Retention authority.** Are we cleared to hold the raw `incoming/` tree — customer
   paths, credentials, some personal content — on this machine while classification runs,
   and for how long? If the answer is "as briefly as possible", §4 reorders to extract and
   mask first and delete the raw tree immediately, which is slower but holds less.
2. **Masking effort on the malicious half.** §5.1 is per-sample work on ~1,700 files. It is
   the largest single cost in this plan and it is what publication requires. Worth deciding
   whether the first public release ships the *benign* half plus expectations only — which
   already gives a runnable public suite and a reproducible FP number — with the malicious
   shards following once masked.
3. **Who reviews the media queue**, and against what standard. §4.3 shrinks it to a contact
   sheet, but the "is there a recognisable person or document in this" call is yours.

---

## 11. One property, five appearances: a measurement that cannot deliver bad news

Five separate cautions in this plan share one diagnostic tell. Four of them are the same
statement in different clothes; the fifth reaches the same place by a different mechanism and
needs a different repair, which is exactly why they are worth listing together:

> **Any measurement whose denominator is enumerated by the same process that produces the
> numerator is bounded by that process, not by reality.**

The four instances:

| where | the numerator | the denominator, and who chose it |
|---|---|---|
| §4.4 `discovered_by` | samples this scanner detects | samples this scanner found. Recall over them is close to 100% by construction |
| §2.3b collect-by-directory | files the rules flagged | files the rules flagged. "A corpus assembled from findings can only support rules resembling the ones that built it" |
| §8 technique coverage | techniques with a tested sample | techniques seen in the reviewed set. Review nothing and coverage is permanently 100% |
| §8 recall, **as it used to be reported** | samples detected | samples carrying `must_detect` — and a sample carries `must_detect` *because* it was detected. Anything known not to be detected gets `known_miss` and leaves the denominator |
| backup verification by spot check | files compared and found equal | eight files out of 191,141 — not a denominator fault at all, but a sample too small to fail. See below |

In every case the figure is true, useful and worth reporting — and in every case it measures
*the reach of the process*, not the reach of the scanner. None of them is fixed by computing
it more carefully, because the arithmetic is not what is wrong.

They split into three kinds, and each takes a different repair. The first three are
denominators that **bound what a number can say**; the repair is a second, independently
sourced denominator. The fourth is a denominator that made a number **say something it did not
mean**; no second denominator fixes that — it has to be renamed. §8's note on the two `known_*`
columns is the narrow, checkable version of that one. The fifth is not a denominator problem at
all, and is set out below.

**The fourth was the headline, which is what made it the worst of them.** `Recall 100.00%`
printed directly above `Known misses 69`, and the layout invites reading the first as the
result and the second as a footnote when the relationship is the reverse. Nothing was hidden —
both numbers were on the screen — but the label did the misleading. That is worth separating
out: the first three were denominators that bounded what a number *could* say; this one was a
denominator that made a number say something it did not mean.

The repair is to report both figures under honest names, because they answer different
questions and only one of them can be tautological:

```
  Detection      13 / 84   reviewed malicious samples detected   (15.5%)
  Regression      7 / 7    expected detections still firing
  Known misses   71 recorded · 69 of them re-run here · 0 newly detected
```

**Detection** is over every reviewed malicious sample, detected or not. It falls when a family
nothing catches is reviewed — which is the correct behaviour, not a problem to be smoothed —
and it rises only when rules improve. It cannot be gamed by review order. **Regression** is the
old figure under the name of what it always was; being 100% by construction is fine there,
because reporting a break is its entire job.

What each of them needed instead was a **second, independently-sourced denominator**, and
that is the general repair:

- `discovered_by` records provenance, so recall can also be reported over the ~54,592 blobs
  this scanner did *not* find;
- collect-by-directory takes the siblings, so the corpus contains files no rule selected —
  and the whole `fake-plugin-image-payload-loader` family exists only because of that;
- technique coverage is paired with the reviewed-sample count and with the count of detected
  blobs still unreviewed, so "55 of 55" cannot be read as completion.

**The tell is always the same**: a number that cannot get worse no matter what happens in the
world. Recall over self-found samples cannot fall; a finding-shaped corpus cannot contain a
counterexample; technique coverage cannot drop while nothing is reviewed; and a recall whose
denominator excludes every known miss can only ever report a regression. When a measurement
has no way to deliver bad news about the thing it appears to be about, the denominator is what
to look at.

A corollary worth keeping: **the honest number is usually the better advertisement.** 15.5%
demonstrates a suite finding real gaps in the scanner it tests; 100% demonstrates a suite
confirming what already works. The second is easier to print and worth less.

### The fifth is a power problem, not a denominator problem

A backup was verified with an **eight-file spot check**, which passed, and the backup was
reported verified. An exhaustive comparison of all **191,141** files then found **147
differences**, concentrated in directories the eight-file sample had never touched.

Nothing about the denominator was wrong: the check compared eight files and reported on eight
files. The defect is that **a sample that small over a set that large could not have failed**.
With 147 differences in 191,141 files the per-file probability of picking a differing one is
about 0.00077, so the chance that eight independent draws contain even one is roughly 0.6%.
The check was therefore about 99.4% likely to pass *whether or not the backup was sound*. It
consumed effort and produced no information, and it did so while returning the word
"verified".

That is the same tell as the other four — a result that cannot get worse no matter what is
true — reached from the opposite direction. The first four could not report bad news because
of *what was counted*. This one could not because of *how little was*.

**The repair is a stated power, and it is neither of the other two.** A sampling check should
report the size of the difference it was capable of finding:

> this check would have detected a discrepancy affecting at least *N* files with probability
> *P*

Eight files out of 191,141 detects a 1%-of-files discrepancy with probability **7.7%**, and a
0.077% discrepancy — the real one — with probability 0.6%. Reaching 92% power against even
that 1% discrepancy would take **251** draws, not eight. Stating that turns "verified" into
"verified against defects larger than X", which is a claim someone can act on: they can decide
X is too coarse and ask for more samples. A bare "verified" hides the question.

The first draft of the sentence above said 92% rather than 7.7%, and the slip is worth
keeping on the page. 92.3% is `0.99**8` — the probability the check *misses* a 1% discrepancy,
not the probability it finds one. Inverting it flattered an eight-file sample by a factor of
twelve, inside the very section arguing that overstated power is the defect. Which is the
point: a stated power is only useful if the statement is checked as arithmetic, and "state
your power" is not self-executing. Compute it, then compute what it would take to reach the
power you actually wanted.

**The degenerate case turned up in the same round, and the same repair catches it.** A
checker in this round's tooling reported 0 problems over a set that was empty: its key list
had been truncated at 14 entries and `verdict` sorts after `size`, so the field it filtered on
was never in the list and the set it tested had nothing in it. Power zero, reported as a clean
pass. Nothing about the logic was wrong — it correctly found no problems in no files.

This is why the stated power has to include the *N*, not just the probability. "Checked 0
samples" is impossible to misread; "no problems found" over the same 0 samples reads as a
result. Any check in this project that reports a count of problems must report the count of
things it examined beside it, and a reviewer should treat the second number as the one that
says whether the first means anything.

The general form, worth applying to any spot check in this project: **a check that samples
must state what it could have caught, or it is not a check, it is a ritual.** The three
existing verification passes in §2.4 are exhaustive and so are exempt; anything that samples
is not.

### Repairing a report does not repair the rows it was computed from

The fourth instance was fixed in the reporting: the figure was renamed to a regression check
and detection was recomputed over every reviewed sample. **943 rows still carried the
artefact.** `expect.must_detect` had been written onto them by the scan that discovered them
— the same mechanism, unchanged — while their `verdict` was still `unreviewed`. So 943 rows
asserted that a sample *must* be detected when no human had ever looked at it.

It never reached the headline: the numerator counts only `verdict: malicious`, so the figure
was right for a reason unrelated to these rows being wrong. That is what let it sit. A defect
that does not show up in the number it belongs to has nothing pulling on it.

The distinction the repair turns on: **`expect` is an assertion and belongs to a reviewer;
what a scan saw is an observation and belongs to the scan.** Those 943 rows now carry
`observed_detection` — the rules, the severity, and a note saying it asserts nothing — and
`expect` is absent until somebody sets a verdict. No information is lost; the triage value of
"the scanner already flags this" is exactly as available as before. What is gone is the claim.

`shard-gate.py` now **fails** on `verdict: unreviewed` carrying `expect.must_detect`, as a
hard error rather than a publishability blocker — an unreviewed row is already unpublishable
for a different reason, and routing it through that path would have hidden it behind the
generic blocker, which is the mistake §8 records about storing only the first reason.

The general form: when a measurement is repaired, ask separately whether the data it was
computed from was repaired. The two are different jobs and only one of them is visible in the
output.

A sixth instance should be assumed to exist in whatever is measured next — the same standing
assumption §5.3 makes about masking, and for the same reason: this class of error is invisible
to reading the code, because the code computes exactly what it says it computes.
