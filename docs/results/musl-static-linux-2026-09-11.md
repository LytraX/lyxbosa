# A static musl Linux binary — spike, 2026-09-11

**Question.** The released Linux binary is built on `almalinux:8` and needs `GLIBC_2.28`
and `GLIBCXX_3.4.22` from the host. On `centos:7` (glibc 2.17) and `ubuntu:16.04` (glibc
2.23) it does not start, and that is the hosting where compromised sites live. A glibc
binary linked with `-static` starts there and scans correctly, then dies with SIGSEGV in
`update --check` on `centos:7`, because glibc's resolver `dlopen`s the host's NSS modules
even from a static binary. The hypothesis this round tested: a static **musl** binary has
no NSS and no `dlopen`, so it should not have that failure at all.

**Answer.** Both gates pass. The musl binary builds with every dependency and no
warnings, completes `update --check` on `centos:7` without crashing, and reports the same
findings as the glibc build byte for byte. It is published beside the glibc binary as
`lyxbosa-linux-<arch>-musl`.

## Gate one: the dependency graph builds

Built inside `alpine:3.24` (musl natively, so the system gcc rather than a cross
toolchain), with vcpkg at the manifest's pinned baseline. What it took:

| what | why |
|---|---|
| `VCPKG_FORCE_SYSTEM_BINARIES=1` | vcpkg downloads prebuilt cmake and ninja for Linux, and they are glibc binaries. With the variable it uses Alpine's own. Bootstrap fetched vcpkg's own `vcpkg-muslc` tool on amd64 and compiled the tool from source on arm64, where upstream publishes none |
| `perl` | OpenSSL's Configure. Alpine's core `perl` package carries `IPC::Cmd`, so there is no second package to name as there is on AlmaLinux |
| `ninja-build` + `ninja-is-really-ninja` | Alpine's `ninja-build` installs `/usr/bin/ninja-build`; the second package is the symlink that makes it answer to `ninja` |
| `linux-headers`, `file` | kernel headers for abseil and libzip; `file` for the script's own check that its output is statically linked |
| `-DCMAKE_EXE_LINKER_FLAGS=-static` | every vcpkg library is already static; this makes musl and libstdc++ static too |

All eighteen ports built - the twelve named in `vcpkg.json` and six transitive or helper
ports - with **zero warnings** in the build log, and no `getaddrinfo` warning on the link,
which is the warning the static glibc build prints. Nothing fought. OpenSSL took 28 s,
the whole dependency graph about four minutes on 56 cores, and the project 38 ninja steps
with `BUILD_TESTS=OFF`.

CMake reported what it configured: `Update verification: OpenSSL 3.6.4 (Ed25519,
BLAKE2b-512)`, `Full-screen UI: enabled (FTXUI)`, and the new line `Linux C library: musl
(x86_64-alpine-linux-musl); release asset lyxbosa-linux-<arch>-musl`. libzip and zlib are
in the link, and the archive tests pass under it (below).

Both architectures built. amd64 was built here; arm64 was built natively on an Apple M4,
because this machine is x86-64 and the emulated arm64 build was still inside OpenSSL after
25 minutes. Natively it took **2 minutes 52 seconds** end to end, image included. CI needs
no emulation either: the workflow puts the arm64 job on the `ubuntu-24.04-arm` runner, which
is native, exactly as the glibc arm64 job already is.

The arm64 build reported the same configuration - `Linux C library: musl
(aarch64-alpine-linux-musl)`, OpenSSL 3.6.4, FTXUI enabled - and the same 38 build steps.
The only warnings in either log are one CMake developer warning from vcpkg's own bootstrap;
the project build emits none, and neither emits the `getaddrinfo` warning that the static
glibc link does.

### Sizes

| binary | unstripped | stripped |
|---|---|---|
| released `lyxbosa-linux-amd64` 2.3.0, dynamic glibc | 11,003 KB | 9,429 KB |
| static glibc, amd64 (`build-static/`) | 14,170 KB | 12,107 KB |
| **static musl, amd64** | **15,056 KB** | **11,946 KB** |
| **static musl, arm64** | **14,430 KB** | **11,101 KB** |

Stripped, the amd64 musl binary is 161 KB smaller than the static glibc one and 2,517 KB
larger than the dynamic glibc one. The release publishes unstripped binaries, so what a user
downloads is about a third larger than the glibc asset.

## Gate two: it fixes the thing it exists to fix, and still detects

### The crash test

The binary was built with `LYXBOSA_VERSION=2.2.0` so that `update --check` reaches the
network: a `0.0.0` build refuses as a development build before any request. Each container
ran `--version`, `init-config`, `check` on a webshell, and `update --check` twice - once with
nothing mounted, once with the host's CA bundle mounted and `SSL_CERT_FILE` pointed at it.
The published glibc 2.3.0 asset ran the same matrix as the comparator. The whole matrix was
then run again on arm64, on the M4, against the arm64 images of the same three distributions
- native there, so the arm64 result is a measurement and not an emulation artefact.

| host | glibc | musl `--version` | musl `check` | musl `update --check`, no bundle | musl `update --check`, bundle | glibc 2.3.0 asset |
|---|---|---|---|---|---|---|
| `centos:7` | 2.17 | `2.2.0`, exit 0 | exit 2 | **exit 2, "A newer release is available: 2.3.0"** | exit 2, same | does not load: `GLIBC_2.27' not found`, exit 1 on every command |
| `ubuntu:16.04` | 2.23 | `2.2.0`, exit 0 | exit 2 | exit 1, "no certificate store was found on this host" | exit 2, "A newer release is available" | does not load, exit 1 on every command |
| `ubuntu:24.04` | 2.39 | `2.2.0`, exit 0 | exit 2 | exit 1, "no certificate store was found on this host" | exit 2, "A newer release is available" | works: `2.3.0`, `check` exit 2, `update --check` exit 0 with the bundle |

The `centos:7` result verbatim, with nothing mounted:

```
--- update --check, no CA bundle
A newer release is available: 2.3.0 (this is 2.2.0).
Run 'lyxbosa update' to install it, or fetch it from
https://github.com/LytraX/lyxbosa/releases
exit=2
```

**arm64 behaved identically on all three**, cell for cell: `2.2.0` and exit 0 for
`--version`, exit 2 for `check`, and `update --check` reaching GitHub - exit 2 with no bundle
on `arm64v8/centos:7`, and exit 2 with the bundle on the two Ubuntu images.

No segfault, on either architecture. Exit 2 is the documented "a newer release exists"
answer, which means DNS, TCP, TLS and the GitHub API all completed. It completed without the bundle because
`centos:7` ships one at `/etc/pki/tls/certs/ca-bundle.crt`; the two Ubuntu images ship
none, and there the bundle-less run is a certificate error and not a DNS error - the
message says which, and the same command with the bundle mounted succeeds.

### What the updater did before the asset name carried the C library

Run for real, `update --yes`, from the musl 2.2.0 binary against the live 2.3.0 release,
which publishes only glibc assets:

- **`centos:7`**: fetched the checksum list, verified the signature, downloaded
  `lyxbosa-linux-amd64`, hashed it, ran it once - and refused: *"it did not start when
  asked for its version, so it has not been installed - the most likely cause is a C
  library older here than on the build host"*. The musl binary was left in place. That is
  the smoke test doing its job.
- **`ubuntu:24.04`**: the same steps, and the glibc binary started, so it was installed.
  `Updated 2.2.0 -> 2.3.0`; the file was now a dynamically linked glibc executable. The C
  library had been swapped under the user without a word.

That second result is why `platformAssetName()` now appends `-musl` for a musl build. With
the suffix, the same command on `ubuntu:24.04` refuses before downloading anything:
*"SHA256SUMS names 4 file(s) and none of them is lyxbosa-linux-amd64-musl"*, and the
binary is unchanged. A release that carries the musl asset will be fetched by name.

### Detection

`corpus/verify.py` with `LYXBOSA_BIN` pointed at the musl binary, against a reference run of
`build-release/lyxbosa` made the same morning on the same index:

| figure | glibc reference | musl |
|---|---|---|
| detection | 730 / 1,299 | 730 / 1,299 |
| regression | 131 / 131 | 131 / 131 |
| false positives | 44 in 197,559 benign files read | 44 in 197,559 |
| rule-exact | 131 / 131 | 131 / 131 |
| known misses re-run | 36, 0 newly detected | 36, 0 newly detected |

The suite's whole output was identical with only the timings normalised - no line differed.
**What that claim is over:** the suite re-ran `check` on the 131 shipped malicious samples
and 36 known misses, and re-scanned all 197,559 benign files; the 599 held-local-only
malicious rows in the 730 stand on their recorded result and were not re-run by the suite.
To cover their bytes, the whole-tree comparison from `docs/RELEASING.md` was run as well:
both binaries scanned each `trail-data` tree in JSON mode and the reports were diffed with
only `durationMs` removed.

| tree | files scanned | files with matches | result |
|---|---|---|---|
| `trail-data/CMS` | 51,404 | 0 | identical |
| `trail-data/Sites` | 48,950 | 8 | identical |
| `trail-data/Infected` | 9,633 | 505 | identical |

Every finding, every skipped file and every archive member in those reports is the same
from both binaries.

### The test suite under musl

`docker/build/Linux-musl/test-inside.sh`, a static `-static` test binary, run as an
unprivileged user in the Alpine image: **579 of 579 passed on amd64 and 579 of 579 on
arm64** (Windows-only cases skipped, as on any Linux). The same suite on the host's debug
build, `ctest -j1`, also 579 of 579. The archive cases, the update-apply cases including the
staged binary's smoke test, and the new cross-check that the asset name agrees with
`__GLIBC__` are in that count on all three.

## Decisions

**Asset names.** `lyxbosa-linux-amd64-musl` and `lyxbosa-linux-arm64-musl`, beside the
unchanged glibc names. The suffix keeps the existing name as a stem, so the pair sorts
together and the workflow's existing globs still match; the libc last follows the Rust and
Zig target-triple convention (`x86_64-unknown-linux-musl`). `platformAssetName()` builds the
same name from `LYXBOSA_LIBC_MUSL`, which CMake sets from the compiler's `-dumpmachine`
triple, and a test asserts that against `__GLIBC__` so the two detections cannot disagree
quietly.

**What the updater prefers.** Neither. A binary updates to the asset of its own C
library and never crosses: glibc to glibc, musl to musl. Crossing is a decision for
whoever runs the host, made once by installing the other asset by hand. The smoke test
remains the safety net under that rule, and a glibc build refused by it now names the
`-musl` asset in its message.

**`--expect`.** 4 becomes 6 in the release job, and its comment says why.

**arm64 gets the same treatment, not an exception.** The reason to consider excluding it
would have been build cost, and that turned out to be an artefact of this machine rather
than of arm64: built natively it is under three minutes, and the workflow already has a
native arm64 runner for the glibc job. Everything measured on amd64 was measured on arm64
too - the build, the 579 tests, and the full three-distribution matrix - and no result
differed. An arm64 host running an old glibc has exactly the problem this asset fixes, so
shipping amd64 only would have left half the affected hosts with nothing.

## Observations worth keeping

- `docker/build/Linux/build-inside.sh` does not pass `BUILD_TESTS=OFF`, so the glibc
  release container compiles and links `lyxbosa_tests` as well (86 ninja steps, the last
  one the test link) although the workflow's comments say a release build compiles only
  what it ships. The musl script passes it. Left unchanged this round.
- `centos:7` ships a CA bundle; the Ubuntu base images do not. A "no certificate store"
  message from the scanner on a bare image is the image, not the scanner.
- vcpkg publishes a musl build of its own tool for amd64 only. On arm64 the bootstrap
  compiles it from source: about eight minutes under emulation here, and part of the
  sub-three-minute total natively.
- This host's Docker engine had no arm64 `binfmt_misc` handler registered even though
  `buildx ls` listed `linux/arm64`; `tonistiigi/binfmt --install arm64` registered it. Even
  then, emulated arm64 is roughly an order of magnitude slower and is not the way to measure
  anything about that architecture.
- `.github/scripts/release-checksums.sh`'s control fixture now uses the six real asset
  names. The musl pair introduced the first case where one asset name is a strict prefix of
  another (`lyxbosa-linux-amd64` and `lyxbosa-linux-amd64-musl`), which the fixture had
  never exercised. Two mutants confirm the extended expectation is load-bearing: dropping
  one line from the expected list, and making `--expect` accept any count, are both caught.
