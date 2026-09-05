# Corpus sources and layout

```
corpus/
  index.jsonl                       the published half: one row per unique blob, 44,544 rows
  make-summary.py                   regenerates index-summary.json from the two halves
  expect/                           golden expectations, per shard
  benign/sources.jsonl              pinned benign sources: name, version, url, sha256, size
  fetch-benign.sh                   downloads, verifies hashes, unpacks. Downloads are not committed
  resolve-benign.py                 closes rows byte-identical to a file in a pinned source
  shard-gate.py                     §7.2 — computes `publishable` and fails the build
  make-shard-manifest.py            regenerates a shard's MANIFEST.json from the index
  promote-pending.py                applies pending-promotions.jsonl; re-measures every row
  build-shard.sh                    packs a staged shard; requires zstd, fails hard without it
  local/index-local.jsonl           local-only rows (gitignored)
  import-infected-tree.py           imports the legacy trail-data/Infected tree
  infected_mask.py                  path masking for that tree; map is out of repo
  incident_mask.py                  path masking for the current incident; map is out of repo
  verify-infected-mask.py           the independent masking check, either tree: --map <path>
  promote-gate.py                   §5.3 — the map-AWARE check, run when a row is promoted
  index-summary.json                the denominator: counts and blockers, tracked
  shards/                           built shards (gitignored; release assets)
```

## The index

The index is **split in two, and both halves matter**:

| file | rows | tracked? | what it is |
|---|---|---|---|
| `index.jsonl` | 44,544 | yes | published samples — the ones a public suite can verify |
| `local/index-local.jsonl` | 48,256 | no | everything held back, with each row's blockers |
| `index-summary.json` | — | yes | the counts, so the denominator survives without the rows |

"index.jsonl is small and lives in git" and "the index lists every blob including local-only"
were in tension; splitting resolves it without dropping the accounting. **`index-summary.json`
is the part that stops the suite overstating itself** — it lets a run report *"10,018 verified,
50,591 held, of which 380 obfuscated-and-undecodable, 29 archive containers, 3 known misses"*
rather than quietly reporting a percentage of a denominator it chose.

A row can carry several blockers and is counted under each, so the blocker counts sum to more
than the row count. That is deliberate: collapsing to one reason per row hides the specific,
actionable blocker behind the generic one — which is exactly what happened when the gate first
stored only the first reason and the encoded-layer failures disappeared behind "unreviewed".

**`index-summary.json` is generated, not written.** It used to be maintained by hand, which
is how it came to say `shipped-sample: 2353` in its reason codes while also saying
`published_shipped_as_bytes: 6` — two claims that cannot both be true. `make-summary.py`
computes it from the two halves, and `make-summary.py --check` fails non-zero if the file on
disk disagrees with the index. Run it after any change to either half.

`publishable` is **computed by `shard-gate.py`, never asserted by hand**. Running it with
`--fix` recomputes every row; running it without arguments fails non-zero if the stored
answer disagrees with the computed one. It caught 103 rows on its first run — samples that
had been masked and gated but never actually reviewed, and 14 that carried `pii`.

**It only looked one way for its first nine rounds, and that is the direction it did not
need to look.** The gate failed when a row claimed publishable and was not, and was silent
when a row was publishable and did not say so — so two operator review passes, six samples
and eight, could set `verdict: malicious` and `sensitivity: ["c2"]` without re-running it,
and fourteen rows kept `publishable: false` and kept recording *"verdict is unreviewed"* and
*"sensitivity not yet assessed"* as their blockers long after both had stopped being true.
Every run recomputed all fourteen, printed `publishable flags corrected: 14`, and exited 0.
Nothing downstream could see past the record: `promote-pending.py` defers on the stored
blocker and `index-summary.json` counts it, so a stale blocker is a stale denominator — the
two blocker counts stood exactly 14 above the sensitivity and verdict tallies they are meant
to mirror, which was the arithmetic tell nobody read.

The gate now reports three classes and fails on any of them: **over-claimed** (stored true,
computed false — the original rule), **under-claimed** (stored false, computed true — the
fourteen), and **blocker drift** (the boolean agrees and the recorded reasons do not, which
matters because §8's accounting is built out of the reasons). A `--fix` run that corrects
anything exits **non-zero on purpose**: the correction is not the result, the result is that
something upstream changed a verdict or a tag without re-running the gate. The green result
is the plain run afterwards. `shard-gate.py --inject <index>` is the control, and it fails
seven of its twelve cases against the pre-fix gate.

The field stays **stored** rather than computed on read, and the reason is in the code: the
published half is a tracked document a stranger reads without running anything, and
`publish_blockers` has to be materialised anyway because it is where the denominator comes
from. A stored derived value is a cache; the repair is not to stop storing it but to assert
that it still equals its source.

### The suite's binary is overridable, and two build directories are enough

`corpus/verify.py` reads `$LYXBOSA_BIN`, falling back to `build-release/lyxbosa`. Set it when
you are measuring a rule change against a build of your own:

```
LYXBOSA_BIN=$PWD/build/lyxbosa corpus/verify.py
```

This exists because the path used to be hardcoded, and that produced a bad instruction: two
agents working this tree at once were told to use a *third* build directory, when `build`
(debug) and `build-release` were already one each. The count of directories was never the
problem. The problem is that a suite which can only read one path forces anyone measuring a
change to rebuild the very binary the suite is reading, and a rebuild part-way through a run
leaves the per-sample `check` calls straddling two binaries with nothing reporting an error.
Overriding the path removes the conflict without inventing a directory to hold it.

### The legacy `Infected` tree, and why its rows carry `predates_ruleset`

`trail-data/Infected` is not the current incident. It is many older servers and older
incidents, and it is **the material the first version of these rules was written against**.
Detection measured over it is therefore partly a test of the rules against their own source
material — CORPUS_PLAN §11 in a new place.

So every row imported from it carries **`predates_ruleset: true`**, and `index-summary.json`
carries the split:

```
malicious_reviewed        760      malicious_reviewed_excl_predates_ruleset   172
malicious_detected        122      malicious_detected_excl_predates_ruleset    60
        16.1%                                     34.9%
```

Both figures are true and they answer different questions. The field costs nothing to record
now and cannot be reconstructed once the rows are indistinguishable, which is the whole
argument for writing it at import rather than later.

`malicious_known_miss_by_family` is there for the adjacent reason: 495 of the 638 known
misses are a single 2017 doorway campaign, and a per-sample rate lets one family with many
files dominate a figure that reads as capability. A bare total cannot show that.

Three tools support the import, and the split between them is deliberate:

| file | needs the map? | what it does |
|---|---|---|
| `import-infected-tree.py` | yes | reproduces the denominator, refuses to run if it moved, sniffs content, triages media structurally, indexes archive members and never containers, classifies with the evidence recorded |
| `infected_mask.py` | yes | path masking, and `collisions()` — which proves *which* identifiers rewrite something they should not, against a real vocabulary |
| `verify-infected-mask.py` | yes | the independent check. Shares no regex with either masker |

`incident_mask.py` is the same pair of jobs for the **current incident**, whose map and
identifiers are different. Its widths are measured rather than chosen: each identifier gets
the widest substitution its own collisions against the stock CMS trees permit, so a name
that is also an English fragment is masked as a whole word while a distinctive one is masked
anywhere in a token. Both maskers rewrite **nothing** in the 158,675 files of `trail-data/CMS`
and `trail-data/CMS-ext`, which is what `--collisions` asserts.

A shard's `MANIFEST.json` and its tracked copy in `expect/` both carry every sample's
`expect`, which is three places one answer can be written and two of them can be wrong
silently — `verify.py` reads `expect` from the **index**, so a stale manifest changes nothing
the suite prints. `make-shard-manifest.py` regenerates the index-owned half of a manifest
(`verdict`, `family`, `sensitivity`, `expect`, `technique`) and writes both copies from the
one text. The packaging half — which file holds the bytes, what it hashes to after masking,
the entry order, the prose note — is carried over from the stage and *checked*: the bytes are
re-hashed, and `masked: false` must mean the shipped hash equals the source hash. `size` is
the shipped file's size and comes from disk, never from the index row, which is the source
blob's size and differs wherever a payload was extracted onto a generated carrier.

Its control is that it reproduces every already-built manifest byte for byte from the
unmodified index. That is what caught both of the above while they were still wrong, and on
its first real run it also found `expect/malicious-db-dropin-001.json` a full round behind —
still declaring 46 samples undetected after the round that closed them, unnoticed because
nothing reads that file at run time.

`shard-gate.py` is the one that must **not** need the map, and does not: it asserts the
*form* of what is allowed (`acctNN`, `siteNN`, `srvNN`), so a stranger can run it.

**That map-free property leaves one hole, and `promote-gate.py` is where it is closed.**
Incident-response directories are named `<token>-<what was done>-<8 digits>-<6 digits>`, and
the leading token is an account name often enough to matter and an operation verb most of
the time. A published row carrying one leaks a customer, and neither map-free invariant sees
it: it is not an `origin` field and it holds no `/home<digits>/`. A *form* rule cannot close
it either — requiring that leading token to be a pseudonym flags **16,656** of the local
half's rows to reach the **2,425** that actually named a customer, 85.4% false positives, on
`live`, `ir`, `cross`, `renamed`, `post`, `orphaned`, `active`, `core`. The discriminator is
the map and only the map, so the check runs where the map is: at promotion, over the exact
text about to be written, recording category and count and never the identifier.

**Directory names live in the map, not in the tools.** `import-infected-tree.py` is tracked,
and a classification rule spelled `rel.startswith("<client>.gr/page/")` puts a customer's
name in git exactly as surely as an unmasked index row would. The map holds the names; the
tool reads roles. This is §5.3's "a field nobody thought of", one level out — it was not a
field at all, it was the tool's own source.

### `acct<unmapped:XXXX>` — what it means and why 16 of them stay

A row carries `acct<unmapped:XXXX>` when the collection knew an account by its hash but no
map named it. It is already a pseudonym, so it is not a leak; it is a gap in the map.

The hash is `sha256(account_name)[:4]`, verified against all 85 known name/hash pairs with
zero disagreements — which is what makes the gap closable at all. Feeding it the 76 distinct
`/home*/<name>/` components from the whole-host manifest resolved **7 of 23** markers, every
one of them to an account the map *already* held. Those rows said "unmapped" while the answer
was on disk, so that was a masker gap rather than a map gap, and it is now substituted.

**The remaining 16 are not chaseable from anything this corpus holds.** Their account names do
not appear in the host manifest, which was taken after the incident: an account deleted or
renamed between compromise and collection leaves rows that reference it and a filesystem that
does not. Four hex characters is 65,536 values against 76 candidates, and there were zero
collisions, so this is a genuine absence rather than an ambiguity.

Do not resolve them by guessing. A wrong name attached to a real account's rows is worse than
no name, because it is indistinguishable from a right one afterwards.

### Tag `secret` from the bytes, not from the review

Thirty-one unreviewed rows carry a non-empty `DB_PASSWORD` literal — harvested `wp-config.php`
copies from a cross-account symlink farm, 15 distinct databases, plus auth salts. They were
held by exactly one lock: `verdict: unreviewed`.

One lock is not enough here, and the failure mode is the ordinary one rather than an exotic
one. The operator answers a review queue by setting a verdict and a sensitivity in the same
pass. Get the sensitivity wrong — type `c2` on something that also carries a secret, which
happened on a different row earlier the same day — and the row is publishable, because `c2`
is in `ALWAYS_OK` and buys a free pass through every masking gate.

So `secret` is now set on those 31 rows **from a content match, before any verdict exists**.
That is not the judgement a human owes: whether a sample is malicious is axis A and stays
theirs. Whether the bytes contain a password literal is a fact a tool can read, and it is the
floor under the judgement rather than a substitute for it. `secret` is not in `ALWAYS_OK`, so
it demands the plaintext gate, the encoded-layer gate and detection parity no matter what else
lands on the row.

The general rule this yields: **tag from the bytes wherever the bytes can be read, and reserve
the review for what they cannot settle.** A tag derived mechanically cannot be mistyped in a
hurry, and it survives a review that gets a different axis wrong.

### A `c2`-only row skips every masking gate, and the tag is the only thing stopping it

`evaluate()` computes `unmasked = tags - ALWAYS_OK - …`, and `ALWAYS_OK` is
`{"clean", "c2"}`. So for a row tagged `c2` alone, `unmasked` is empty and the whole masking
branch is skipped: no plaintext gate, no encoded-layer gate, no detection-parity check. A
human typing `["c2"]` is the entire distance between those bytes and a public shard.

That is not hypothetical. One row from the 2026-09-05 operator review was tagged `c2` alone
while carrying an attacker password-gate hash — the class §7.2's secret scan must return zero
hits on over a public shard. The scan cannot tell whose secret it is, so the tag has to
reflect what the scan will find, and the corpus's only other sample with that technique
already carried `c2+secret`. It has been re-tagged and is now blocked for the honest reason.

**The structural hole is still open and is the next round's job.** `shard-gate.py` reads index
rows, not bytes, so it cannot verify a content claim — the check belongs at publish time,
where the bytes are in hand. Until then: `c2` and `clean` are the two tags that buy a row a
free pass, so they are the two that need reading rather than trusting, and a review that sets
either should say what it read.

The general form, which this corpus has now paid for in three places: **a gate that trusts a
field is only as good as whatever wrote the field.** The publishability boolean drifted
because nothing asserted it against its source; the blocker strings drifted the same way; and
the sensitivity tag can drift because nothing asserts it against the bytes.

### `pending-promotions.jsonl` — measured by one side, applied by the other

A rules round measures which `known_miss` rows its new rules now detect. It does not flip
them: all index writes go through the corpus side, so a rules agent that also wrote the index
would be two hands on one file. The measurement has to survive the gap between the two, and a
number that lives only in a report does not — it is in a session scratchpad that gets cleared.

So the rules side writes `corpus/pending-promotions.jsonl`: one row per sample, its sha256,
the exact rule codes `check` returns for it, which index half it is in, and its publish
blockers if any. The corpus side applies rows from it and **deletes each row as it is
applied**. When the last row goes, so does the file. A non-empty file means work is owed; an
absent file means none is.

Each row's `now_detects` is measured per sample with `check`, never inferred from a batch
scan, because `expect.must_detect` is compared to `check`'s output exactly and a batch scan
does not tell you which rule fired on which file.

Rows in the `local` half usually cannot be promoted immediately even though the detection is
real: their blockers are masking and review, which are independent of whether a rule fires.
That is why the file records the blocker rather than just the sha256 — otherwise the next
reader has to re-derive why 34 of 75 did not move.

`promote-pending.py` is the applier, and it treats the file as a handoff rather than an
authority: every row is re-measured with `check` against the **shipped** bytes in the shard,
and a row whose measurement disagrees with what it recorded is refused rather than written.
An empty measurement on a row the file says now fires is a hard refusal that names the
binary, because that is what a build made before the round's rules looks like — it promotes
nothing and reports zero newly detected, which reads as a result rather than an error. A row
whose `publish_blockers` are non-empty is deferred with the blocker quoted back, never
resolved here; resolving one is masking or review, which is somebody else's job.

A promotion rewrites exactly one field. `expect.known_miss` and `known_miss_reason` become
`expect.closed_known_miss` — date, the rule that closed it, and verbatim the reason the row
used to give — and `must_detect` becomes the measured set. Verdict, publishability,
sensitivity and masking are untouched: a promotion is a statement about detection and about
nothing else.

### Any writer of either half goes through `indexio.py`

`write_jsonl_atomic` for the write, `index_lock` around a read-modify-write. Not a style
preference — both were paid for on 2026-09-04, when two sessions worked this tree at once.

`shard-gate.py --fix` used to `open(path, "w")`, which truncates a 62 MB index before the
first row lands. A concurrent reader measured 48,407 rows, then 14,148, then 79,467 — three
moments of one write, and indistinguishable from corruption from the outside. It also saw
fields that "appear nowhere in my sources" and were gone seconds later: another session's
merge, half-written. The round stopped and reported possible corruption, which was the right
call on the available evidence and cost the round anyway. **The tell is a
`make-summary.py --check` that passes in one instant and fails the next.**

The second failure mode did not fire and is the worse one. Two writers each doing a
read-modify-write of the whole file means the last one silently drops the other's rows, and
**every gate still passes** — a half-merged index is internally consistent, so no integrity
check can catch it. Only the lock can.

`python3 corpus/indexio.py --selftest` reproduces the torn read against the old write and
shows it absent from the new one. It keeps the control on purpose: a test that only proves
the new path is clean cannot tell you the old path was the cause.

`reason` is a short code rather than prose, to keep the file a reasonable size:

| code | meaning |
|---|---|
| `stock-cms-hash` | byte-identical to a file in the pinned stock CMS tree |
| `pinned-benign-hash` | byte-identical to a file in a source pinned in `benign/sources.jsonl` |
| `stock-cms-hash-resolved-prior` | as above, and it resolves a prior corpus row that was tier `unverified` |
| `media-polyglot` | media container carrying executable code |
| `media-clean-not-published` | structurally clean media: no code, so a false positive or customer content |
| `staging-directory-review` | a human opened the whole directory, confirmed it is attacker staging, and the sample passed both gates |
| `doorway-kit-review` | a human read one legacy-tree doorway kit end to end — deployers, generator, installed `.htaccess`, templates — and ruled on the whole kit |

## The benign half is fetched, not shipped

Of the 44,544 published rows, **44,460 are reproducible from a pinned source or from the
stock CMS tree** and are therefore *not* shipped as blobs — they are an index row plus a
lockfile entry. **84** samples ship as bytes: 7 polyglot fixtures, 67 staging samples, 8
doorway-kit samples and 2 outside-webroot wrappers.

That is the point of §6: the benign half is a lockfile and a script, so anyone can
regenerate it and get the same false-positive number, instead of taking ours on trust.

```
corpus/fetch-benign.sh              # download, verify, unpack
VERIFY_ONLY=1 corpus/fetch-benign.sh   # re-check hashes already on disk
corpus/fetch-benign.sh --inject     # the control: prove the hash gate can refuse
```

`benign/sources.jsonl` currently pins **136 sources**: 87 WordPress plugins, 22 themes,
24 WordPress core versions including deliberately old ones because an outdated core is what
a real host looks like, and 3 trees of rendered HTML.

**The versions are derived, not chosen.** The first 86 sources pinned each slug at whatever
upstream shipped that day, which pins the version a host is *least* likely to be running.
The 50 added in round 11 were read off the installed copy on a collected host — a plugin's
main-file `Version:` header, a theme's `style.css` header, core's
`wp-includes/version.php` — and every one of them was confirmed by measurement rather than
by argument: a version derived wrongly resolves nothing, and each of these resolved
between 4 and 3,300 rows. Pinning them mechanically decided a further **32,272 rows**, of
which 7,843 were sitting in quarantine directories while being ordinary stock code.

**Deriving a version is not the same as being able to pin it.** 32 component versions
across 27 slugs were identified on the collected hosts and could not be pinned: premium
plugins and themes never distributed on wordpress.org, agency-built and site-specific
code, one plugin whose directory was closed upstream, and two whose exact installed
version wordpress.org no longer retains. They account for **17,667 blobs that no pinned
source reaches**, and they are the reason this pass closed 32,272 rows rather than 50,000.
Substituting a nearby version for the two that are merely unretained would be a guess that
looks like work — a version pinned on a guess that happens not to match is
indistinguishable from one that was never pinned.

**`kind: rendered-html` exists for one reason and it is a measurement, not a corpus gap.**
The stock trees are almost entirely source, so a discriminator keyed on `<title>` and
`<meta>` had 12 files in 207,311 that could ever have matched it — a 25% rule-of-three
bound dressed up as a zero. Three Texinfo-generated GCC manuals are now pinned, two that
carry the meta tags and one older build that does not, which turned that bound into a
measured 97.6% and closed `docs/RULE_CANDIDATES.md` §4. The third is a **control**: without
a rendered-page tree that is *not* at risk, "rendered pages match" and "all HTML matches"
are indistinguishable.

A hash mismatch in `fetch-benign.sh` is a hard failure, never "probably a new version":
upstream may have been replaced. The archive kind is read off the URL — `.zip` and
`.tar.gz` — and a suffix the script does not recognise is refused rather than passed to
`unzip` on the assumption it is close enough.

### `resolve-benign.py`, and the 92% it implements

92% of everything ever closed in this corpus was closed by exact hash against a pinned
source; 8% by human review. Until round 11 the 92% had **no committed implementation** —
it was done by an ad-hoc script in a collection directory, so `pinned-benign-hash` appeared
as a reason code on thousands of published rows and nowhere in the repository. A mechanism
that decides tens of thousands of rows has to be readable by whoever audits those rows.

What it will and will not do:

  * it closes a row only while the verdict is `unreviewed`. A human verdict is never
    overridden by a hash;
  * it **supersedes** a sensitivity tag rather than overwriting it, and records what the
    tag was. 829 rows carried `content`, `c2`, `identity`, `secret`, `pii` or `undecidable`
    and were byte-identical to a pinned release anyway — vendored SDKs contain API hosts
    and key material, and plugin releases contain images. The tag described the bytes
    correctly and their owner incorrectly, and hash identity is what settles it: the same
    bytes are downloadable by anyone from the same pinned URL;
  * it builds the published row from a **whitelist**, so it cannot carry an `origin`. Four
    rows once did, because a promotion copied the whole local row and removed what it
    remembered to remove;
  * it prints separately every row whose collecting scan had already flagged it. Those are
    **false positives on upstream code**, not closures to wave through — 25 of them this
    round, and they are why the pinned `known_fp` list went from 6 sha256 to 31.

## Shards

`shards/malicious-polyglots-001.tar.zst` — 6 masked polyglot samples and 3 clean-carrier
precision fixtures, 128 KB. Expectations in `expect/malicious-polyglots-001.json`.

`shards/malicious-staging-001.tar.zst` — 67 samples from 14 confirmed attacker-staging
directories, 3.0 MB, in 7 families: a fake-plugin loader that keeps its payload in files
named as images, a WooCommerce card skimmer, a self-hiding fake core plugin, a forged
update-header request gate, a forged-plugin auto-login backdoor, a fake theme of raw zlib
blobs, and a timestamp-named theme stager. Expectations in
`expect/malicious-staging-001.json`.

**Twenty-three of the 67 are `known_miss`** — real malware this scanner does not detect at
the recorded version. It was 64 of 67 when the shard was built, which is the point of
shipping them: the corpus previously measured recall over six samples it already found.
`OBF041` closed 40 of them and `CRED007` one, all promoted in one batch on 2026-09-05 and
recorded per row as `expect.closed_known_miss`. See `docs/RULE_CANDIDATES.md` §2.

`shards/malicious-outside-webroot-001.tar.zst` — the two hex-digest wrappers from `/var/tmp`
that `docs/KNOWN_ISSUES.md` issue 3 rests on. Polymorphic siblings in two different accounts;
each rewrites a plugin inside the webroot while keeping three state files outside it. Both are
`known_miss`. Account paths masked length-preservingly, both gates pass over the plaintext and
the ~98 KB decoded stage, detection parity verified per sample.

These two rows carry a **`placements`** field, which exists because of them. The index is
content-addressed and kept one example path per blob; these blobs have 16 and 14 paths, and the
one shown was an IR quarantine copy. `/var/tmp` — the placement that is the entire finding —
was invisible. `placements` records the count per placement class, so a placement-based claim
has something to rest on.

`shards/malicious-doorway-kit-001.tar.zst` — the eight executable and template components
of one 2017 SEO doorway kit from the legacy `Infected` tree, 12 KB. Three deployers, three
generators and two presentation templates, shipped **as collected**: the independent gate
found nothing to mask in any of them, in the plaintext or in the raw bytes, and the
encoded-layer audit finds no region able to carry an identifier. Five are `known_miss`; the
three deployers are the samples `BD018` closed, promoted in this shard's first round. This
is the corpus's first published material from the legacy tree, so every row carries
`predates_ruleset: true` — detection over them is partly a test of the rules against their
own source material, and the summary reports the figure both ways for exactly that reason.
Expectations in `expect/malicious-doorway-kit-001.json`.

`shards/malicious-polyglots-002.tar.zst` — one fixture plus one clean carrier. A 510-byte
"Priv8 Uploader" PHP block injected straight after a real image's JFIF header and terminated
with `__halt_compiler()` so PHP ignores the ~140 KB of image that follows. The image is
customer content and is **not** shipped: the payload is paired with a generated 166-byte
baseline JPEG. Parity was measured rather than assumed — original `OBF036`; payload alone
nothing; generated carrier alone nothing; generated carrier plus payload `OBF036`.

Nothing in the staging shard was masked, and that is a result rather than an omission: the
independent identifier gate found nothing to mask, in the plaintext or in any of the 40
statically decoded payload layers. Detection parity therefore holds by construction — the
bytes are the bytes that were collected.

Every sample in it is a **generated carrier plus an extracted payload**: no customer image
or document bytes are present, verified by confirming no 64-byte run is shared with the
original outside the payload itself. The clean carriers exist to pin the other direction —
a valid PNG, GIF or PDF must produce no findings at all.

### On the format

`.tar.zst`, per §7. The choice is about **decompression speed for a runner reading one
sample at a time**, which is the property xz is worst at, so the format is not up for
renegotiation because a dependency is missing.

`build-shard.sh` therefore treats a missing `zstd` as a **hard failure** and prints the
install command, exactly as `fetch-benign.sh` does for `jq` and `sha256sum`. It does not
fall back to another compressor: a silent fallback is how two artefacts that claim to be the
same shard stop being the same shard.

### On the password

`malicious-polyglots-001.tar.zst.zip` is the same shard inside a zip with the passphrase
`infected`. The passphrase is deliberately public and documented here, because §7.1 is
explicit: **if CI can open the archive, so can anyone.** It is not a confidentiality control
and must never be treated as one. It buys three real things: GitHub's and AV vendors'
scanners stop flagging the repository as malware-hosting, contributors' endpoint AV stops
quarantining files on clone, and casual scraping and accidental execution get harder.

**Masking is the actual control.** Nothing enters a shard unmasked, which is what
`shard-gate.py` exists to enforce.

## Running the suite, and the review-round workflow

```
corpus/verify.py                      # full run
corpus/verify.py --skip-benign        # fast: skips the 146k-file benign sweep
corpus/verify.py --json               # machine-readable
corpus/verify.py --update-baseline    # re-baseline after a review round
```

**Batch your reviews, then re-baseline.** This is a workflow consequence of the guard in
§8, and it is worth choosing rather than discovering.

Every batch of human review moves samples out of `unreviewed` and into the recall
denominator. The suite correctly refuses to compare recall across a changed denominator — a
figure over a set that grew is not the same measurement — so it withholds the delta and says
why. That is the right behaviour, and it has a consequence: **reviewing in many small
batches means never seeing a comparable recall figure**, because the denominator moves every
run.

So:

- review in **larger, less frequent batches** when a comparable trend matters;
- or run `--update-baseline` **once, deliberately, at the end of a review round**, which
  makes the new set the reference point that subsequent runs compare against.

What not to do is re-baseline on every run to make the withheld delta go away. The
withholding is the signal that the population changed; suppressing it by moving the
reference point each time gives a smooth-looking series that compares nothing.

The same applies to the benign side, though less often: adding sources to
`benign/sources.jsonl` changes the false-positive denominator, so the FP *rate* before and
after a lockfile change are also not directly comparable.

## What is deliberately not here

- **Archives.** §2.3: not corpus data. Members are collected individually and archive
  fixtures are generated, never harvested. Byte-masking an archive corrupts it — see §5.5.
- **`pii` and `content` samples.** Not maskable, so never published; index row and hash only.
- **Samples that did not decode.** Held permanently: absence of a plaintext identifier in an
  obfuscated file is evidence the encoder worked, not evidence the file is clean.
