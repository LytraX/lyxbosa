# Building LyxBoSa

LyxBoSa is a CMake + vcpkg (manifest mode) project built with Ninja. Everything below
assumes you run commands from the repository root.

## Prerequisites

| Requirement | Notes |
|---|---|
| C++20 compiler | GCC 12+, Clang 15+, or MSVC 2022. GCC 11 and older cannot build this. |
| CMake | 3.25 or newer to use the presets (`CMakePresets.json` is format version 6). The bare `CMakeLists.txt` still works with 3.16+ if you configure manually. |
| Ninja | Generator used by every preset. |
| vcpkg | Cloned and bootstrapped, with `VCPKG_ROOT` exported. |

Dependencies (`fmt`, `argparse`, `yaml-cpp`, `reflectcpp`, `re2`, `xxhash`, `gtest`,
`zlib`, `libzip`)
are declared in [`vcpkg.json`](../vcpkg.json) and installed automatically at configure
time, pinned to the registry baseline in
[`vcpkg-configuration.json`](../vcpkg-configuration.json). The first configure of a
fresh build directory compiles those ports and can take several minutes; later
configures reuse the vcpkg binary cache.

```bash
export VCPKG_ROOT=/path/to/vcpkg   # add to ~/.bashrc so presets can find it
```

## First-time setup

`CMakePresets.json` deliberately contains no toolchain path — the vcpkg location is
per-machine. Copy the example user presets once:

```bash
cp CMakeUserPresets.example.json CMakeUserPresets.json
```

That file is gitignored and defines the `debug` and `release` configure presets, each
inheriting the shared hidden presets from `CMakePresets.json` and adding
`CMAKE_TOOLCHAIN_FILE=$env{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake`. It also holds
the matching build presets: CMake refuses a build preset that points at a hidden
configure preset, and `CMakePresets.json` cannot reference presets defined in the user
file, so both must live together there.

Without this file you have no presets at all — configure manually instead (see
[Common variations](#common-variations)).

Verify the presets are visible:

```bash
cmake --list-presets          # configure presets: debug, release
cmake --list-presets=build    # build presets:     debug, release
```

## Debug build

```bash
cmake --preset debug          # configure into ./build
cmake --build --preset debug  # or: cmake --build build
```

- Output: `build/lyxbosa` and `build/lyxbosa_tests`
- `CMAKE_BUILD_TYPE=Debug`, defines `LYXBOSA_DEBUG`
- Tests are built (`BUILD_TESTS=ON` by default)

## Release build

```bash
cmake --preset release          # configure into ./build-release
cmake --build --preset release  # or: cmake --build build-release
```

- Output: `build-release/lyxbosa` and `build-release/lyxbosa_tests`
- `CMAKE_BUILD_TYPE=Release`, defines `LYXBOSA_RELEASE`

### Build options

| Option | Default | Effect |
|--------|---------|--------|
| `BUILD_TESTS` | `ON` | Build `lyxbosa_tests` |
| `LYXBOSA_TUI` | `ON` | Build the full-screen scan UI (FTXUI). `OFF` drops the dependency and the binary falls back to the plain stderr progress line |
| `LYXBOSA_VERSION_OVERRIDE` | unset | Stamp a version into the binary (see "Versioning") |

Both build directories are independent and gitignored, so you can keep a debug and a
release tree side by side without reconfiguring. `cmake --build <dir>` is equivalent to
`cmake --build --preset <name>` and works even without the user presets file.

## Common variations

```bash
# Build one target only (faster than the whole tree)
cmake --build build --target lyxbosa
cmake --build build --target lyxbosa_tests

# Parallel build with an explicit job count (Ninja already parallelises by default)
cmake --build build -j 8

# Skip building the test executable
cmake --preset release -DBUILD_TESTS=OFF

# Build without the full-screen terminal UI, dropping the ftxui dependency.
# The binary then always uses the plain stderr progress line.
cmake --preset release -DLYXBOSA_TUI=OFF

# Stamp a version into the binary (see "Versioning" below)
cmake --preset release -DLYXBOSA_VERSION_OVERRIDE=1.1.0

# Configure without presets (equivalent to the debug preset)
cmake -B build -S . -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build
```

Reconfiguring is only needed when you change `CMakeLists.txt`, a cache variable, or
`vcpkg.json`; otherwise `cmake --build` is enough. To start over, delete the build
directory (`rm -rf build`) rather than editing the cache.

## Running the tests

```bash
cd build && ctest --output-on-failure    # or: ctest --test-dir build --output-on-failure
```

Tests are registered individually through `gtest_discover_tests`, so `ctest -R <name>`
filters by test name. You can also run the binary directly for gtest flags:

```bash
./build/lyxbosa_tests --gtest_filter='StringAssembly*'
```

## Versioning

The version is baked in at configure time as the `LYXBOSA_VERSION` macro, which feeds
`--version`, the `--help` header, and the Windows resource in
[`src-cli/lyxbosa.rc.in`](../src-cli/lyxbosa.rc.in).

- Default: `PROJECT_VERSION` from `project(LyxBoSa VERSION ...)` in `CMakeLists.txt`.
- Override: `-DLYXBOSA_VERSION_OVERRIDE=<x.y.z>` wins when defined.

A plain local build therefore reports the project default (currently `0.0.0`), not the
released tag. CI
passes the git tag (minus the leading `v`) as the override, so release binaries carry
the real version. Pass the override yourself when you need a locally built binary to
report a specific version.

## Updating vcpkg

vcpkg is a plain git clone, so updating it is `git pull` plus a re-bootstrap. Do this
wherever `VCPKG_ROOT` points.

**Linux / macOS**

```bash
cd "$VCPKG_ROOT"
git pull
./bootstrap-vcpkg.sh -disableMetrics
vcpkg version   # confirm the new tool version
```

**Windows (PowerShell)**

```powershell
cd $env:VCPKG_ROOT      # or .\vcpkg in the repo, if build.ps1 cloned it there
git pull
.\bootstrap-vcpkg.bat -disableMetrics
.\vcpkg version
```

If `VCPKG_ROOT` points inside a Visual Studio installation
(`...\Microsoft Visual Studio\<year>\<edition>\VC\vcpkg`), that copy is managed by
the VS Installer — update Visual Studio instead of pulling, or clone your own vcpkg
somewhere else and repoint `VCPKG_ROOT` at it.

### Updating the tool does not update the dependencies

This project uses manifest mode with a pinned registry baseline in
[`vcpkg-configuration.json`](../vcpkg-configuration.json). Port versions are resolved
from that baseline commit, not from your clone's `HEAD`, so pulling vcpkg changes the
tool but leaves `fmt`, `re2`, `yaml-cpp` and friends exactly where they were — which is
what keeps local builds and CI reproducible.

To actually move the dependencies forward, update the baseline from the project root
after pulling vcpkg:

```bash
cd /path/to/LyxBoSa
"$VCPKG_ROOT/vcpkg" x-update-baseline     # rewrites the baseline to your clone's HEAD
rm -rf vcpkg_installed build/vcpkg_installed build-release/vcpkg_installed
cmake --preset debug && cmake --build --preset debug
ctest --test-dir build --output-on-failure
```

The baseline change is a tracked edit to `vcpkg-configuration.json` — commit it only
once a clean rebuild and the test suite pass, since it moves every dependency at once.

### Reclaiming disk space

Intermediate port build output is safe to delete; vcpkg re-creates what it needs.

```bash
rm -rf "$VCPKG_ROOT/buildtrees" "$VCPKG_ROOT/packages"   # per-port build scratch
rm -rf "$VCPKG_ROOT/downloads"                           # cached source tarballs
```

Keep the binary cache (`~/.cache/vcpkg/archives` on Linux,
`%LOCALAPPDATA%\vcpkg\archives` on Windows) — it is what makes reconfiguring a fresh
build directory fast. Deleting it only costs rebuild time.

## Distribution builds

These produce the standalone binaries published on releases — they are not needed for
day-to-day development.

### Linux (Docker, AlmaLinux 8 + GCC 12)

Builds against an old glibc so the binary runs on older distributions:

```bash
docker/build/Linux/build.sh [amd64|arm64|all] [output-dir] [version]

# examples
docker/build/Linux/build.sh amd64 dist
docker/build/Linux/build.sh all dist 1.1.0
```

Requires Docker with buildx (and qemu for cross-arch builds). Output is
`dist/lyxbosa-linux-<arch>`.

### Windows (PowerShell, static MSVC runtime)

```powershell
$env:LYXBOSA_VERSION = "1.1.0"   # optional
docker\build\Windows\build.ps1 dist
```

Builds x64 and ARM64 with the `*-windows-static` triplets, `BUILD_TESTS=OFF` and
`CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded`, producing
`dist\lyxbosa-windows-<arch>.exe`. Clones and bootstraps vcpkg into the repo if
`VCPKG_ROOT` is unset.

### CI

[`.github/workflows/build.yml`](../.github/workflows/build.yml) runs both of the above
on a `v*` tag push (Linux amd64/arm64 and Windows), then publishes a GitHub release
with the binaries. `workflow_dispatch` builds artifacts without releasing.

## Build directories at a glance

| Path | Produced by | Tracked |
|---|---|---|
| `build/` | `cmake --preset debug` | no (gitignored) |
| `build-release/` | `cmake --preset release` | no (gitignored) |
| `build-win-release-<arch>/` | `docker/build/Windows/build.ps1` | no |
| `dist/` | distribution scripts | no (gitignored) |

Because these are gitignored, binaries left over from an earlier checkout can linger
and report an old version. When a binary's `--version` looks wrong, rebuild rather
than trusting the artifact.

## Troubleshooting

**`Could not read presets ... version 6 not supported`** — CMake is older than 3.25.
Upgrade, or configure manually with the explicit `cmake -B build -S .` command above.

**`No such preset: debug`** — `CMakeUserPresets.json` is missing. Copy it from
`CMakeUserPresets.example.json`.

**`CMAKE_TOOLCHAIN_FILE ... does not exist`, or `find_package(fmt)` fails** —
`VCPKG_ROOT` is unset or points at a vcpkg clone that was never bootstrapped
(`$VCPKG_ROOT/bootstrap-vcpkg.sh -disableMetrics`).

**Compiler errors on `<format>`, concepts, or ranges** — the compiler predates C++20
support. On EL-family distributions use `gcc-toolset-12` as the Docker build does.

**IDE / clangd sees no includes** — every preset sets
`CMAKE_EXPORT_COMPILE_COMMANDS=ON`; point your tooling at
`build/compile_commands.json`, or symlink it to the repo root.
