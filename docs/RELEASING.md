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

If the change touches rules or the match engine, also confirm findings did not move
against a known-good binary — see [Verifying detection did not
change](#verifying-detection-did-not-change).

### 2. Tag

Use an **annotated** tag with a one-line summary; the tag message is what shows in
`git tag -n` and in the GitHub tag list.

```bash
git tag -a v1.2.0 -m "Literal prefilter, 6x faster scans"
```

> `v1.0.0` was created as a lightweight tag and `v1.1.0` as an annotated one. Use
> annotated from here on.

### 3. Push the tag

```bash
git push origin v1.2.0
```

**`git push` alone does not push tags.** Pushing master will not start a release;
the tag ref has to be pushed explicitly.

### 4. Watch the build

```bash
gh run watch
```

Three jobs: `build-linux` (amd64 and arm64 matrix), `build-windows`, then `release`,
which only runs `if: startsWith(github.ref, 'refs/tags/v')` and needs both builds to
succeed. If either fails, no release is published and the tag is left pointing at a
commit with nothing attached — see [If a release goes
wrong](#if-a-release-goes-wrong).

---

## What CI produces

| Artifact | From |
|---|---|
| `lyxbosa-linux-amd64` | `ubuntu-latest`, built in the container in `docker/build/Linux/` |
| `lyxbosa-linux-arm64` | `ubuntu-24.04-arm`, same container |
| `lyxbosa-windows-*.exe` | `windows-latest`, static vcpkg triplet |

Release notes are the union of two things:

- a **Commits** section the workflow builds itself, from
  `git log --no-merges` between the previous tag and this one;
- GitHub's own `generate_release_notes: true` output.

The previous tag is found with:

```bash
git describe --tags --abbrev=0 "${GITHUB_REF_NAME}^"
```

which means **the new tag must be a descendant of the previous one**. Tagging a
commit that is not on top of the last release produces an empty or wrong commit
list. The checkout uses `fetch-depth: 0` so the full history and all tags are
available.

---

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

Download one binary per platform and check the version is the tag, not `0.0.0`:

```bash
./lyxbosa-linux-amd64 --version
```

If it prints `0.0.0`, the version did not reach CMake — check that the tag matched
`v*` and that the "Extract version from tag" step ran.

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

---

## Pre-releases

The version parse rejects `-rc` suffixes (see the table at the top), so a pre-release
needs one of:

- tag a normal patch version from a branch and mark the GitHub release as a
  pre-release afterwards; or
- run the workflow manually via `workflow_dispatch`, which builds every target and
  uploads artifacts without publishing a release. The binaries report `0.0.0`
  because no tag is involved, which makes them fine for testing and unsuitable for
  distribution.

Supporting real `-rc` tags means making the version parse tolerate a suffix and
stripping it before the Windows resource is generated. Worth doing if pre-releases
become routine; not needed for the current flow.
