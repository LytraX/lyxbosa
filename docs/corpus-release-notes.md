# LyxBoSa malware corpus — `corpus-2026.09.1`

A set of eight archives of real web-server malware, collected from live incident response,
masked, and published so that a scanner's detection and false-positive figures can be checked
by somebody who did not produce them.

**These archives contain live malware.** Read *Opening a shard* before you download anything.

---

## What this is

Eight `.tar.zst` shards, each wrapped in a password-protected `.zip`, plus a checksum file.
Together they carry **140 samples and 4 generated carrier files**, with one JSON manifest per
shard describing every member and what a scanner is expected to do with it. 138 of the samples
are malicious; 2 are benign and carry `must_not_detect: ["*"]`, so a scanner that fires on
them fails the suite.

| shard | samples | carriers | what is in it |
|---|---:|---:|---|
| `malicious-staging-001` | 66 | — | an attacker staging directory: fake plugins whose payload hides in files named as images, card skimmers, auto-login backdoors |
| `malicious-db-dropin-001` | 46 | — | database drop-ins and related webshells from an undetected-sample review |
| `malicious-uploaders-001` | 11 | — | file uploaders and session-stub droppers; one of the eleven is an inert orphaned stub, published as a must-not-detect case |
| `malicious-doorway-kit-001` | 8 | — | an SEO doorway-page generator kit |
| `malicious-polyglots-001` | 6 | 3 | files that are simultaneously a valid image or PDF and executable PHP |
| `malicious-outside-webroot-001` | 1 | — | a wrapper that rewrites a plugin inside the webroot while keeping its state outside it |
| `malicious-polyglots-002` | 1 | 1 | a JPEG with an injected uploader |
| `benign-attacker-artefacts-001` | 1 | — | an attacker-created file that is *inert* — a failed-fetch artefact — published so a scanner can be checked for not flagging it |

A **carrier** is a clean, generated image or PDF used to build a polyglot fixture. It has no
index row and is not a sample; it is there so the fixture can be rebuilt.

### What is *not* here

The benign half of this corpus is not distributed, and that is deliberate rather than an
omission. It is 197,559 files of stock WordPress, Joomla and Magento cores, plugins and
themes, every one pinned by upstream URL and sha256 in `corpus/benign/sources.jsonl` (136
sources). Republishing vendor archives would add nothing and would make this release a
mirror of software that already has one. `corpus/fetch-benign.sh` downloads and hash-verifies
them.

This matters for reading the false-positive figure below: **you can reproduce the benign
half exactly, but you have to fetch it.**

---

## Opening a shard

The `.zip` wrapper is encrypted with the passphrase:

```
infected
```

**The passphrase is public, on purpose, and it is not confidentiality.** It exists to stop
GitHub's and endpoint antivirus scanners flagging the archive on download or on clone, and to
stop casual scraping and accidental execution. Anyone who can read this file can open the
archive. What protects the people whose servers these files came from is *masking*, not the
password — see *What was masked* below.

```sh
unzip -P infected malicious-polyglots-001.tar.zst.zip
zstd -d malicious-polyglots-001.tar.zst
tar -xf malicious-polyglots-001.tar          # extracts read-only, mode 0400
```

Samples extract at `0400` — read-only, not executable — because they are live malware. Do not
extract them into a web root, a synced folder, or anywhere a PHP interpreter can reach.

Each shard contains `MANIFEST.json` at its root: one entry per member with its name, path,
sha256, size, verdict, family, technique list, and the `expect` block a test runner reads.

---

## Verifying what you downloaded

`SHA256SUMS` in the release lists the sha256 of each **inner `.tar.zst`** — not of the `.zip`.

```sh
for z in *.tar.zst.zip; do unzip -o -P infected "$z"; done
sha256sum -c SHA256SUMS
```

**Why the `.tar.zst` and not the `.zip`.** The `.tar.zst` is reproducible: unpack it, repack
it with `corpus/build-shard.sh`, and you get the same bytes, because member order, mtimes,
ownership and permissions are all pinned. The `.zip` is *not* reproducible and cannot be made
so — ZipCrypto prefixes every entry with a randomised 12-byte encryption header, so three
wraps of one byte-identical input give three different hashes. A `.zip` hash would attest that
one upload arrived intact and nothing more. **The `.tar.zst` hash is the one that certifies
the artefact.**

---

## What was masked, and what deliberately was not

These files came from real customers' servers. Before publication every sample is passed
through a length-preserving masker and then through two independent gates that share no
pattern with it:

- a **plaintext gate**, which looks for customer names and domains in the visible bytes;
- an **encoded-layer gate**, which decodes every static base64, gzip, hex and escape layer of
  the *masked* output and looks again.

Masking is length-preserving so that a sample's detection does not change: a substitution that
altered a file's size could change whether a scanner matches it, and the fixture would then be
testing the mask rather than the malware. Every masked sample is re-scanned and must produce
the same rule set it produced before.

**Attacker infrastructure is kept on purpose.** Command-and-control hostnames and addresses,
attacker-created directory names, and the access parameters of a backdoor are *indicators*,
and masking them would destroy the thing the sample is for. Where a row keeps one, it says so:
`ioc.campaign_hosts` lists the hosts, and a kept credential-shaped literal carries a recorded
disposition saying what it is and why it was kept. **None of these is a customer's.** Where
the distinction was not mechanical it was adjudicated by hand and the argument is recorded in
the index.

**Two samples were dropped from this release rather than published.** Each carried a short
token — three and four characters — that a customer-name predicate matched inside a longer
random-looking run. Both are almost certainly coincidences, and neither could be repaired by
the masker, so the files were removed from their shards. Losing a sample is recoverable;
publishing a customer identifier is not.

---

## What the figures mean

Measured with the scanner build `4c3e0af08988`, over this corpus, on 2026-09-07:

| | |
|---|---|
| samples the suite executed | **97 of 97 detected**, all matching the exact expected rule |
| detection over all reviewed malicious samples | **696 of 1,299 — 53.6%** |
| detection excluding the rules' own source material | **631 of 703 — 89.8%** |
| false-positive rate | **0.0223%** — 44 files of 197,559 benign |
| recorded known misses | 603 |
| technique coverage | 90 of 123 known techniques have a tested sample |

**Read the two detection figures together, and prefer the second.** The 53.6% denominator
includes 1,131 samples from the tree the first version of these rules was *written against*.
Measuring a rule set against its own source material tells you how well it memorised that
tree, not how well it generalises. The 89.8% figure excludes that tree; it is the honest one,
and it is lower-bounded by the same reviewing process that produced it.

**The 97-of-97 is not a recall figure.** It is a regression check: those are the samples whose
bytes ship here and whose expected rule is recorded, so a stranger can re-run them. The other
599 reviewed malicious samples are held locally — most carry customer content that cannot be
masked — and their results come from a recorded scan rather than from a run you can repeat.

**A "known miss" is not a failure.** 603 samples are recorded as *not detected by this
scanner at this version*, verified per file rather than inferred from a directory scan. They
are in the corpus precisely so that a future rule change is measured against them.

### What a consumer may conclude, and what they may not

**You may** re-run the 97 shipped, expectation-carrying samples against any scanner and compare
rule-for-rule; check the false-positive rate against the pinned benign sources; use the
manifests' technique lists to see which classes of attack are represented; and audit the
masking, because the gates' predicates are in the repository and the published index records
what each gate returned and which tool version produced it.

**You may not** read any of this as a field precision figure. Precision — `tp/(tp+fp)` —
depends on the ratio of malicious to benign files, which on a real host is roughly 1 in 35,000
and here is whatever the people curating this corpus chose. It is a property of a scan of a
named host, not of a corpus. The false-positive rate and the recall figure above are each
computed within a single population, which is why they are the two that are reported.

**You may not** treat the benign half as representative of the web. It is pinned upstream
CMS source: stock cores, plugins and themes. A false-positive rate measured on it says a rule
does not fire on shipped vendor code. It says nothing about a rate on hand-written application
code, on minified JavaScript bundles, or on a customer's own theme — and those are where
false positives on a real host actually come from.

**You may not** conclude that 53.6% or 89.8% is what this scanner would achieve on your
server. The malicious half is a curated set of families from a specific set of incidents, and
48% of the whole collection is still unreviewed. Detection is reported over the reviewed set
and says so.

---

## Provenance and reproducibility

- Every published row records which tool version produced each gate result (`masking.provenance.tools`,
  a digest over the six modules that decide a verdict) and the sha256 of the exact bytes that
  result was measured over (`masking.provenance.bytes_sha256`). Both are recomputable from a
  clone.
- The index (`corpus/index.jsonl`) and the per-shard expectations (`corpus/expect/`) are in
  the repository and are checked against the archives by `corpus/shard-census.py`, which opens
  each shard, resolves every member to its row, and re-runs the identifier gates over the
  shipped bytes.
- Rebuilding: `corpus/build-shard.sh <stage-dir> <name>` reproduces a shard from its extracted
  contents byte for byte. `corpus/build-shard.sh --selftest` asserts that it does.

## Licence and use

These are files taken from compromised servers; nobody claims copyright in them. They are
published for security research, detection engineering and scanner evaluation. Handle them as
you would any malware sample.

If you find a customer identifier that survived masking in any of these files, that is a
serious defect and we want to know immediately — open an issue describing *where* it is
(shard, member, offset) without quoting the value.
