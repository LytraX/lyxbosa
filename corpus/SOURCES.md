# Corpus sources and layout

```
corpus/
  index.jsonl                       the published half: one row per unique blob, 12,264 rows
  make-summary.py                   regenerates index-summary.json from the two halves
  expect/                           golden expectations, per shard
  benign/sources.jsonl              pinned benign sources: name, version, url, sha256, size
  fetch-benign.sh                   downloads, verifies hashes, unpacks. Downloads are not committed
  shard-gate.py                     §7.2 — computes `publishable` and fails the build
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
| `index.jsonl` | 12,264 | yes | published samples — the ones a public suite can verify |
| `local/index-local.jsonl` | 80,536 | no | everything held back, with each row's blockers |
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
`--fix` recomputes every row; running it without arguments fails non-zero if any row claims
a publishability it cannot justify. It caught 103 such rows on its first run — samples that
had been masked and gated but never actually reviewed, and 14 that carried `pii`.

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

## The benign half is fetched, not shipped

Of the 12,202 publishable rows, **12,126 are reproducible from a pinned source or from the
stock CMS tree** and are therefore *not* shipped as blobs — they are an index row plus a
lockfile entry. **76** samples ship as bytes: 7 polyglot fixtures, 67 staging samples and 2
outside-webroot wrappers.

That is the point of §6: the benign half is a lockfile and a script, so anyone can
regenerate it and get the same false-positive number, instead of taking ours on trust.

```
corpus/fetch-benign.sh              # download, verify, unpack
VERIFY_ONLY=1 corpus/fetch-benign.sh   # re-check hashes already on disk
```

`benign/sources.jsonl` currently pins **86 sources**: 48 WordPress plugins,
20 themes, and 18 WordPress core versions including deliberately old ones, because an
outdated core is what a real host looks like. The plugin and theme list is not guesswork —
it was taken from the corpus itself, by counting which slugs the unreviewed backlog actually
contained. Pinning them mechanically decided **7,050 rows**, of which 2,940 were sitting in
quarantine directories while being ordinary stock plugin code.

A hash mismatch in `fetch-benign.sh` is a hard failure, never "probably a new version":
upstream may have been replaced.

## Shards

`shards/malicious-polyglots-001.tar.zst` — 6 masked polyglot samples and 3 clean-carrier
precision fixtures, 128 KB. Expectations in `expect/malicious-polyglots-001.json`.

`shards/malicious-staging-001.tar.zst` — 67 samples from 14 confirmed attacker-staging
directories, 3.0 MB, in 7 families: a fake-plugin loader that keeps its payload in files
named as images, a WooCommerce card skimmer, a self-hiding fake core plugin, a forged
update-header request gate, a forged-plugin auto-login backdoor, a fake theme of raw zlib
blobs, and a timestamp-named theme stager. Expectations in
`expect/malicious-staging-001.json`.

**Sixty-four of the 67 are `known_miss`** — real malware this scanner does not detect at the
recorded version. That is the point of shipping them: the corpus previously measured recall
over six samples it already found. See `docs/RULE_CANDIDATES.md` §2.

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
