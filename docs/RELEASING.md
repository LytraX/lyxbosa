# Releasing

Releases are driven entirely by git tags. Pushing a tag matching `v*` to GitHub
builds every target and publishes a release; nothing else triggers one, and there is
no manual upload step.

The workflow is [`.github/workflows/build.yml`](../.github/workflows/build.yml).

---

## The tag format is a hard requirement

```
vMAJOR.MINOR.PATCH        e.g. v1.2.0
```

Three components, all numeric, prefixed with `v`. This is not a style preference —
the build parses it:

```cmake
string(REPLACE "." ";" _VERSION_LIST "${LYXBOSA_VER_STRING}")
list(GET _VERSION_LIST 0 LYXBOSA_VER_MAJOR)   # and 1, and 2
```

and feeds the pieces to the Windows resource, which needs integers:

```
FILEVERSION    @LYXBOSA_VER_MAJOR@,@LYXBOSA_VER_MINOR@,@LYXBOSA_VER_PATCH@,0
```

So:

| Tag | Result |
|---|---|
| `v1.2.0` | works |
| `v1.2` | **CMake error** — `list(GET ...)` index 2 is out of range |
| `v1.2.3-rc1` | **Windows build fails** — emits `FILEVERSION 1,2,3-rc1,0`, which is not valid RC syntax |
| `1.2.0` (no `v`) | nothing happens; the workflow only triggers on `v*` |

Pre-release tags are therefore not supported as-is. If you need one, see
[Pre-releases](#pre-releases) below.

---

## How the version reaches the binary

```
git tag v1.2.0  ->  GITHUB_REF_NAME = v1.2.0
                 ->  strip the leading v  ->  1.2.0
                 ->  Linux:   docker/build/Linux/build.sh <arch> dist 1.2.0
                              -> LYXBOSA_VERSION -> -DLYXBOSA_VERSION_OVERRIDE
                 ->  Windows: env LYXBOSA_VERSION -> -DLYXBOSA_VERSION_OVERRIDE
                 ->  CMake: LYXBOSA_VERSION="1.2.0"  ->  lyxbosa --version
```

**Every build that is not from a tag reports `0.0.0`.** `project(LyxBoSa VERSION
0.0.0)` in [`CMakeLists.txt`](../CMakeLists.txt) is the fallback, and
`LYXBOSA_VERSION_OVERRIDE` is only set by CI. A local build from either preset always
says `0.0.0`; that is expected, not a misconfiguration. There is no version string to
bump anywhere in the tree — the tag is the single source of truth.

---

## Cutting a release

### 1. Pre-flight on master

Use the presets — they decide the build type and the directory:

| Preset | Build type | Directory |
|---|---|---|
| `debug` | Debug | `build/` |
| `release` | Release | `build-release/` |

```bash
git checkout master && git pull

cmake --preset release
cmake --build build-release -j"$(nproc)"
ctest --test-dir build-release --output-on-failure
```

Both presets come from [`CMakePresets.json`](../CMakePresets.json) plus a local
`CMakeUserPresets.json` that supplies the vcpkg toolchain, so `VCPKG_ROOT` must be
set. Copy `CMakeUserPresets.example.json` if you do not have one yet.

> **Release the binary you are about to tag, and do it in `build-release/`.**
> A bare `cmake -S . -B build ...` bypasses the presets, and
> [`CMakeLists.txt`](../CMakeLists.txt) then defaults to `Debug` — roughly 4× slower,
> and it leaves `build/` holding something other than what the `debug` preset
> expects. Any timing measured from a Debug binary is meaningless.

**And check that the release can be signed**, before you tag rather than after:

```bash
.github/scripts/release-sign.sh signing-key
```

It prints the key CI will sign with, or tells you what is missing. The release job runs the
same code and **fails the release** if it cannot sign - there is no unsigned fallback - so a
missing key found here costs a minute and found after tagging costs a re-tag. See
[Release integrity](#release-integrity-checksums-and-signatures).

If the change touches rules or the match engine, also confirm findings did not move
against a known-good binary — see [Verifying detection did not
change](#verifying-detection-did-not-change). Whatever it moved on purpose is what the
changelog entry has to say, so the two steps feed each other.

### 2. Close out the changelog

**This page is about the `v*` scanner tags only.** The corpus has its own tag series,
`corpus-YYYY.MM.N`, cut per review round rather than per rule, and its own changelog at
[`corpus/CHANGELOG.md`](../corpus/CHANGELOG.md). Nothing in this workflow builds or publishes
a corpus release — `corpus/release-assets.sh` does that — and a corpus tag does not trigger
`.github/workflows/build.yml`, which only matches `v*`. Close out the changelog that matches
the tag you are cutting; closing out both is how one round ends up described twice.

**The corpus series closes out the same way, and before its tag for a different reason.**
Rename the `## Unreleased` heading in [`corpus/CHANGELOG.md`](../corpus/CHANGELOG.md) to
`## [corpus-YYYY.MM.N] - <date>`, open a fresh empty one above it, and add the compare link
at the foot beside the others:

```markdown
## Unreleased

## [corpus-2026.09.3] - 2026-09-14
```
```markdown
[Unreleased]: https://github.com/LytraX/lyxbosa/compare/corpus-2026.09.3...HEAD
[corpus-2026.09.3]: https://github.com/LytraX/lyxbosa/compare/corpus-2026.09.2...corpus-2026.09.3
```

No CI job reads that file, so the reason is not the release body. A corpus tag publishes
shards that a stranger downloads and re-runs, and its section is where the counts those
shards assert are written down — which shard is new, which figure moved, and what moved it.
Push the tag first and the same section can only be written as history about something
already public, by somebody who has to reconstruct which side of the tag each entry fell on.

`corpus/release-assets.sh --print-upload <tag>` refuses to print the tag and upload commands
while `corpus/CHANGELOG.md` has no closed section for that tag, so the ordering is a
precondition of cutting the release rather than a step to remember.

[`CHANGELOG.md`](../CHANGELOG.md) carries an `## Unreleased` section that is written as
the work lands, not at release time. Closing it out means renaming that heading to the
version and the date, and opening a fresh empty one above it:

```markdown
## Unreleased

## [1.2.0] - 2026-09-14
```

Two things to check before you do:

- **Every user-visible change since the last tag has an entry.**
  `git log --no-merges v1.1.0..HEAD` is the list to read against. CI already publishes
  the commit subjects in the release notes, so the changelog is not a second copy of
  them — it is the part a commit subject cannot carry: what a scan now reports on the
  same input, and what a configuration or a calling script has to do differently.
- **Anything under *Compatibility* agrees with the number you are about to pick.**
  That section exists so the bump is not a guess; see
  [Choosing the number](#choosing-the-number).

The README is not the place for this. It describes what the tool does now; the history
of how it got there lives here.

For a `v*` tag this step comes before tagging for a mechanical reason, not a tidiness
one: CI reads the section for the tagged version out of the file *as it exists at the
tag*, so an entry written afterwards never reaches the release body. See
[What CI produces](#what-ci-produces). That mechanism is `v*`-only, which is why the
corpus series above states its own reason and is gated by its own script.

### 3. Tag

Use an **annotated** tag with a one-line summary; the tag message is what shows in
`git tag -n` and in the GitHub tag list. Take it from the changelog headline for that
version, so the tag and the entry do not drift apart.

```bash
git tag -a v1.2.0 -m "Literal prefilter, 6x faster scans"
```

> `v1.0.0` was created as a lightweight tag and `v1.1.0` as an annotated one. Use
> annotated from here on.

### 4. Push the tag

```bash
git push origin v1.2.0
```

**`git push` alone does not push tags.** Pushing master will not start a release;
the tag ref has to be pushed explicitly.

### 5. Watch the build

```bash
gh run watch
```

Seven jobs. `test-linux` (amd64 and arm64 matrix), `test-linux-musl` (the same matrix,
in the Alpine image) and `test-windows` build the tree with `BUILD_TESTS=ON` and run
`ctest`; they are the same jobs a pull request to `master` runs, and a tag runs them too.
They also run on a push to `master`, where they build nothing anyone downloads: a cache
saved during a pull request is scoped to that pull request, so only a run on the default
branch leaves one the next pull request can restore. `build-linux` (amd64 and arm64
matrix), `build-linux-musl` (the same matrix, static musl) and `build-windows` produce
the binaries, with the tests off — a release build compiles only what it ships, which is
why the test build is a separate configure in `docker/build/Linux/test-inside.sh`,
`docker/build/Linux-musl/test-inside.sh` and `docker/build/Windows/test.ps1` rather than
a flag on the release scripts. Then `release`, which only runs
`if: startsWith(github.ref, 'refs/tags/v')` and needs all three builds to succeed. If any
build fails, no release is published and the tag is left pointing at a commit with
nothing attached — see [If a release goes
wrong](#if-a-release-goes-wrong). A test job failing does not stop the release; it is
reported on the run, and gating on it is a decision to take once the jobs have been seen
to pass.

---

## What CI produces

| Artifact | From |
|---|---|
| `lyxbosa-linux-amd64` | `ubuntu-latest`, built in the container in `docker/build/Linux/` |
| `lyxbosa-linux-arm64` | `ubuntu-24.04-arm`, same container |
| `lyxbosa-linux-amd64-portable` | `ubuntu-latest`, built in the Alpine container in `docker/build/Linux-musl/` |
| `lyxbosa-linux-arm64-portable` | `ubuntu-24.04-arm`, same container |
| `lyxbosa-windows-*.exe` | `windows-latest`, static vcpkg triplet (amd64 and arm64) |
| `SHA256SUMS` | the release job, over the six binaries |
| `SHA256SUMS.minisig` | the release job, signing `SHA256SUMS` with the release key |

The last two are [release integrity](#release-integrity-checksums-and-signatures) and they
are not optional: the job fails rather than publishing a release without them.

**Two Linux binaries per architecture, and the difference is the C library.**
`lyxbosa-linux-<arch>` is dynamically linked against the glibc of `almalinux:8` and needs
glibc 2.28 and a libstdc++ from GCC 6 or newer on the host; older hosts refuse to load it.
`lyxbosa-linux-<arch>-portable` is statically linked against musl and needs nothing from
the host at all, which is what makes it run on the older shared hosting where compromised
sites tend to live. It is musl rather than a static glibc because glibc's resolver loads
the host's NSS modules even from a static binary, and a binary that segfaults on
`update --check` there is worse than one that refuses. `lyxbosa update` never crosses
between the two: the standard binary fetches the standard asset and the portable binary
the portable one, and swapping is done once, by hand, by installing the other. The suffix
is the contract — `src-lib/cpp/update/ReleaseAssets.cpp` appends `-portable` for a musl
build and nothing for glibc, so the names here and the names there have to move together.

**The asset says `portable`; the build says `musl`.** The asset name is read by whoever is
choosing a download, and the thing they are choosing is a binary that runs on an older
host. The CI job (`build-linux-musl`), its caches, the container directory
(`docker/build/Linux-musl/`) and the CMake option (`LYXBOSA_LIBC_MUSL`) all keep `musl`,
because each of those is read by somebody who needs to know which C library is involved —
the CMake option is checked against `__GLIBC__` by a test, where it is a claim about the C
library and nothing else. README.md under *System support* is what a user reads about
choosing.

Release notes are the union of three things, in this order:

- the **[CHANGELOG.md](../CHANGELOG.md) section for the tagged version**, matched on
  `## [1.2.0]` or `## 1.2.0` and taken up to the next `##` heading. This is why the
  changelog is closed out *before* tagging — the tag is what makes CI look for the
  section, so an entry added afterwards never reaches the release body. A tag with no
  matching section still releases, with the commit list alone;
- a **Commits** section the workflow builds itself, from
  `git log --no-merges` between the previous tag and this one;
- GitHub's own `generate_release_notes: true` output.

The step logs which of the first two it found, so a release published without its
changelog entry says so in the job output rather than only in the body.

The previous tag is found with:

```bash
git describe --tags --abbrev=0 "${GITHUB_REF_NAME}^"
```

which means **the new tag must be a descendant of the previous one**. Tagging a
commit that is not on top of the last release produces an empty or wrong commit
list. The checkout uses `fetch-depth: 0` so the full history and all tags are
available.

---

## Release integrity: checksums and signatures

Every `v*` release publishes two files beside the binaries:

| File | What it is |
|---|---|
| `SHA256SUMS` | one line per binary, `<hash>  <name>`, bare names in byte order |
| `SHA256SUMS.minisig` | a [minisign](https://jedisct1.github.io/minisign/) signature over `SHA256SUMS` |

The checksum file alone defends against a corrupted or truncated download. It does **not**
defend against anyone who can write to the release, because they can rewrite it too - which
is what the signature is for. This matters more here than for most tools: `lyxbosa` is run as
root, on compromised hosts, during incident response, and a download nobody can verify is a
bad thing to hand somebody in that position.

What it does not do is make **Windows** trust the binary. That is Authenticode with an EV
certificate, it is not owned here, and a browser download still shows an unknown-publisher
warning exactly as it did before. The two answer different questions; see
[`docs/tasks/UPDATE_PLAN.md`](tasks/UPDATE_PLAN.md) §3. A binary that `lyxbosa update`
installs is the one case where the certificate's absence costs nothing: SmartScreen raises
that warning for a file carrying a Mark of the Web, which a browser attaches to what it
downloads, and the updater writes the file itself and attaches none. Defender's real-time
scan of a new executable is a separate matter and is unaffected either way.

### It fails rather than skipping

The signing step runs **before** `softprops/action-gh-release`, so a failure to sign stops the
job and nothing is published. That ordering is the guarantee, and a release job that quietly
published without a signature when signing broke would have removed the whole defence at the
moment it was needed while looking identical to one that worked. Do not add
`continue-on-error`, and do not make the step conditional on the secret being present.

Both scripts carry their own controls and CI runs them on every release, before the files they
defend are written:

```bash
.github/scripts/release-checksums.sh --selftest
.github/scripts/release-sign.sh --selftest
```

### The updater checks the same two files

`lyxbosa update` verifies the signature over `SHA256SUMS` against the keys compiled into it,
checks that the signature's trusted comment names the release being installed, and only then
hashes the download against its line in that verified list. So the properties this section
describes are not only for a person following the commands below: the release job writing a
list that omits an asset, or a signature whose trusted comment does not carry the tag, makes
every installed binary refuse to update. `README.md` under *Updating* is what a user reads.

To watch the whole chain - a real download, a real verification, a real replacement, and each
refusal - without cutting a release, run `docs/local/demo-update-apply.sh`. It builds against a
throwaway key and a local HTTPS origin, and restores `build/` afterwards.

### Provisioning the signing key

**One-time, per signing key.** A release refuses to publish unless
`keys/minisign-trusted.txt` names a signing key and the CI secret holding its private half
exists, so this is done before the first release that uses a given key. Generate the keypair
**on your own machine and never in CI**:

```bash
minisign -G -W -p minisign.pub -s minisign.key
```

`-W` leaves the secret key unencrypted. A password would be stored in the same secret store as
the key it protects, which buys nothing; if you use one anyway, put it in a second repository
secret `MINISIGN_KEY_PASSWORD` and the signing step will use it.

Then:

1. Copy the **second** line of `minisign.pub` - `RW` followed by 54 base64 characters - into
   `keys/minisign-trusted.txt` as `signing <key>`, and commit it.
2. Put the **whole** of `minisign.key` into the repository secret `MINISIGN_SECRET_KEY`
   (*Settings → Secrets and variables → Actions*), comment line and all.
3. Keep `minisign.key` offline. It is the only copy; there is no recovery, and losing it means
   a rotation rather than a re-issue.
4. Delete it from anywhere it does not belong - and note that
   `corpus/pre-push-check.py` refuses a push carrying a minisign secret key by shape, in a
   tracked file or in a commit message, the same way it refuses a customer identifier.

### Rotating the key

`keys/minisign-trusted.txt` holds a **list** rather than one key, from the first release
onwards, because a verifier that accepts exactly one key cannot survive that key being
compromised. The file's own header carries the full reasoning; the procedure is:

| Release | Change |
|---|---|
| N | add the new key as `trusted`; the old key keeps signing |
| N+1 | swap the roles - new key `signing`, old key `trusted` |
| N+2 | delete the old key's line |

A **compromised** key gets no overlap: delete its line in the next release, announce the new
key wherever the old one was published, and accept that older installs can no longer verify.

**The rotation now has a consumer inside the binary.** `lyxbosa update` verifies a release
against the keys compiled into it, and CMake generates that list from this file, so a binary
built at release N carries the keys this file named at N. A release signed by a key added
later is refused by every earlier binary, which is why the new key ships as `trusted` one
release before it starts signing. Skipping that step does not break verification quietly - it
sends everybody to a manual download.

## Verifying detection did not change

Rule and engine changes must not move findings unless that is the point of the
change. Keep a known-good binary and compare against it:

```bash
mkdir -p .baseline
cp build-release/lyxbosa .baseline/lyxbosa-baseline
git rev-parse --short HEAD > .baseline/COMMIT
```

Capture reference reports before the change, then after it compare everything except
the timing field:

```bash
for corpus in trail-data/CMS trail-data/Sites trail-data/Infected/<name>; do
  ./.baseline/lyxbosa-baseline scan -r --force --dry-run -s \
      -o json -O .baseline/ref.json "$corpus"
  ./build-release/lyxbosa scan -r --force --dry-run -s \
      -o json -O /tmp/new.json "$corpus"
  diff <(jq -S 'del(.durationMs)' .baseline/ref.json) \
       <(jq -S 'del(.durationMs)' /tmp/new.json) && echo "IDENTICAL: $corpus"
done
```

`.baseline/` and `trail-data/` are both gitignored, so neither the binaries nor the
malware corpus can be committed by accident.

---

## After the release

```bash
gh release view v1.2.0
```

Eight assets, not six: the six binaries, `SHA256SUMS` and `SHA256SUMS.minisig`.

**Verify them the way a user would**, from a fresh download directory rather than from the
build tree:

```bash
key="$(.github/scripts/release-sign.sh signing-key)"     # from the checkout, before leaving it
gh release download v1.2.0 -D /tmp/v1.2.0 && cd /tmp/v1.2.0

# 1. the signature FIRST. The checksums are only worth reading if this passes: they are
#    published beside the files they describe, and anyone who can write to the release can
#    rewrite them.
minisign -Vm SHA256SUMS -P "$key"

# 2. then the checksums, in the directory the assets were downloaded into.
sha256sum -c SHA256SUMS
```

`minisign -Vm` prints the **trusted comment**, which is covered by the signature and names the
tag: `LyxBoSa v1.2.0 SHA256SUMS (LytraX/LyxBoSa)`. Read it. A `SHA256SUMS` and
`SHA256SUMS.minisig` pair lifted wholesale from an older release verifies perfectly well and
describes the wrong binaries; the tag in that line is what says which release you are holding.

Anyone without a checkout takes the key from
[`keys/minisign-trusted.txt`](../keys/minisign-trusted.txt) on GitHub and passes it to `-P`
directly.

Then check the version is the tag, not `0.0.0`:

```bash
./lyxbosa-linux-amd64 --version
2.3.0 (standard build, lyxbosa-linux-amd64)
```

The version is the first token; what follows names the build, so the same command on the
portable asset reads `2.3.0 (portable build, lyxbosa-linux-amd64-portable)`. That is worth
reading too: an asset whose name and whose banner disagree was renamed after it was built.

If the version is `0.0.0`, it did not reach CMake — check that the tag matched `v*` and
that the "Extract version from tag" step ran.

---

## If a release goes wrong

**The build failed; nothing was published.** Fix the problem on master, then move the
tag:

```bash
git tag -d v1.2.0
git push origin :refs/tags/v1.2.0     # delete the remote tag
git tag -a v1.2.0 -m "..."            # re-tag the fixed commit
git push origin v1.2.0
```

**A release was already published.** Do not move a tag people may have downloaded —
binaries would silently change under a version that is already out. Cut the next
patch version instead:

```bash
git tag -a v1.2.1 -m "Fix ..."
git push origin v1.2.1
```

If the published artifacts are actively harmful, mark the GitHub release as a
draft or delete it, then ship the replacement version — but the tag stays.

---

## Choosing the number

The tag is the version users see and quote in bug reports, so it should say
something about compatibility.

| Bump | When |
|---|---|
| **Major** | CLI flags, config schema, exit codes or report format change in a way that breaks existing use |
| **Minor** | New rules, new detection capability, new flags — anything additive |
| **Patch** | Fixes and performance work that leave behaviour unchanged |

A change in *what gets detected* is worth calling out in the tag message even when it
is a patch, because it changes what a scan reports on the same input.

The **Compatibility** section of the unreleased changelog entry is what decides between
minor and major: if it is empty, nothing breaks and the bump is minor at most. Rule
removals and default changes belong there too, not only flags and formats — a removed
rule is a silent no-op for anyone who named it in `builtin_rules`, and a changed default
alters coverage for everyone who never set it.

---

## Pre-releases

The version parse rejects `-rc` suffixes (see the table at the top), so a pre-release
needs one of:

- tag a normal patch version from a branch and mark the GitHub release as a
  pre-release afterwards; or
- run the workflow manually via `workflow_dispatch`, which builds every target and
  uploads artifacts without publishing a release. Its one input, `version`, is what
  the binaries report; left empty they report `0.0.0`, which makes them fine for
  testing a build and unsuitable for distribution. Given a version older than the
  newest release - `2.2.0`, say - the artefact is a binary that believes an update
  exists, which is how `lyxbosa update` is proved against the live release without
  cutting one. A leading `v` is accepted and anything that is not three dot-separated
  numbers stops the job before the Windows resource compile would.

Supporting real `-rc` tags means making the version parse tolerate a suffix and
stripping it before the Windows resource is generated. Worth doing if pre-releases
become routine; not needed for the current flow.
