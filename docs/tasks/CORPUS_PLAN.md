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
  in that category, which is worth being able to say out loud rather than hide.
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

**The standing rule, because this is now five failures and not an anecdote.** Every one was
caught by a gate; **none** was caught by reading the code — including the fifth, a field
whose contents are account names *by construction*, which slipped through because the
masking helper applied a four-character minimum. So:

- **Masking correctness is not reviewable by inspection.** Do not accept "I checked it" for
  a masking change, from a person or from a model.
- **Every new field that can carry an identifier gets gate coverage before it is populated,
  not after.** The gate is part of adding the field, not a follow-up.
- **Verification always uses a check that does not share the masker's own patterns.** Same
  regexes on both sides tests only that the code agrees with itself.

A sixth failure should be assumed to exist in whatever field is added next.

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
  Known misses       3 expected · 0 newly detected
  Regressions        0 new · 0 fixed
```

- **`rule-exact`** is the line that boolean suites miss: detected, but by the rule that
  should have detected it. A rule change that keeps a detection for the wrong reason shows
  up here.

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
