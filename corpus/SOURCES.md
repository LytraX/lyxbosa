# Corpus sources and layout

```
corpus/
  index.jsonl                       the published half: one row per unique blob, 12,199 rows
  make-summary.py                   regenerates index-summary.json from the two halves
  expect/                           golden expectations, per shard
  benign/sources.jsonl              pinned benign sources: name, version, url, sha256, size
  fetch-benign.sh                   downloads, verifies hashes, unpacks. Downloads are not committed
  shard-gate.py                     §7.2 — computes `publishable` and fails the build
  build-shard.sh                    packs a staged shard; requires zstd, fails hard without it
  local/index-local.jsonl           local-only rows (gitignored)
  index-summary.json                the denominator: counts and blockers, tracked
  shards/                           built shards (gitignored; release assets)
```

## The index

The index is **split in two, and both halves matter**:

| file | rows | tracked? | what it is |
|---|---|---|---|
| `index.jsonl` | 12,199 | yes | published samples — the ones a public suite can verify |
| `local/index-local.jsonl` | 48,410 | no | everything held back, with each row's blockers |
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

Of the 12,199 publishable rows, **12,126 are reproducible from a pinned source or from the
stock CMS tree** and are therefore *not* shipped as blobs — they are an index row plus a
lockfile entry. **73** samples ship as bytes: 6 polyglot fixtures and 67 staging samples.

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

Nothing in this shard was masked, and that is a result rather than an omission: the
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
