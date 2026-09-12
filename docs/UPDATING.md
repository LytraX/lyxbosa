# Updating

How `lyxbosa update` replaces the binary you are running, what it verifies before it does,
what it refuses to do, and when a scan checks on its own. The command's own options and exit
codes are in [docs/CLI.md](CLI.md#update--install-the-newest-release).

```bash
lyxbosa update
```

It downloads the newest release, checks it, and replaces the binary you are running. Or
fetch it yourself from [the releases page](https://github.com/LytraX/lyxbosa/releases):
every release publishes `SHA256SUMS` and a `minisign` signature over it, and verifying both
by hand is written out in [docs/INSTALL.md](INSTALL.md#by-hand).

## Which Linux binary

[System support](../README.md#system-support) is where to choose one. Two things about that
choice are the updater's rather than yours:

**`update` never crosses between the two.** The standard binary fetches the standard
asset and the portable binary the portable asset, so the build you installed is the one
you keep. To move, install the other asset once by hand; updates stay on it from then on.

**The portable build is a static musl binary**, not a static glibc one. glibc's resolver
loads the host's own name-service modules even from a statically linked binary, and on a
host old enough to need this build that crashes the network path — so `update --check`
would segfault on exactly the systems the build exists for. musl resolves names itself.
This is why the build container and the CMake option say `musl` while the asset says
`portable`: the asset name is for whoever is choosing a download, and the rest is for
whoever is maintaining the build.

## What `update` checks, in this order

1. The **signature** over the release's `SHA256SUMS` is verified against a list of keys
   compiled into this binary.
2. The **global signature** is verified too. That is what covers the *trusted comment* — the
   line naming the release — so the tag printed at the end is signed rather than asserted.
3. That comment must name **this** release. A `SHA256SUMS` and signature pair lifted from an
   older release verifies perfectly well and describes the wrong binaries.
4. Only then is the download hashed and compared to its line in that verified list.

The order is the point. A hash checked against an unverified list defends against a
corrupted transfer and nothing else, because whoever can rewrite the asset can rewrite the
list published beside it.

The new file is written **beside** the old one, given the old one's permissions, run once to
confirm it starts on this host, flushed to disk, and only then renamed over the old binary.
The rename is atomic, so a failure at any point leaves the binary you are running exactly
where it was.

On Windows a running `.exe` cannot be overwritten, but it can be renamed, so the last step
is two moves inside the install directory: the running `lyxbosa.exe` is moved aside to
`lyxbosa.exe.old` and the verified download is moved into its place. If the second move
fails the first is undone, so there is a `lyxbosa.exe` at the end either way. The `.old`
is removed the next time `lyxbosa` starts, once nothing is running from it. A file that
something else has open - a real-time scanner reading a freshly written executable is the
usual case - is retried for a few seconds and then refused with the reason. The binary the
updater installs carries no Mark of the Web, so SmartScreen does not raise the
unknown-publisher warning on it that a browser download gets.

## What it refuses to do

| situation | what happens |
|---|---|
| the newest release is **older** than what you run | refused: a signed old release is still signed, and rolling you backwards into a known defect needs no forgery |
| signed by a key this binary does not carry | refused, with instructions to download and verify by hand |
| the binary sits under a path a package manager owns | declined: an updater fighting `apt` leaves its database describing a file that is not there |
| you cannot write the install directory | refused, with the reason. It never re-runs itself under `sudo` |
| the download will not start on this host | refused before anything is replaced; the standard build names the `-portable` asset as the way forward |
| on Windows, the install directory needs elevation to write | refused, with the reason. It never relaunches itself as administrator |
| macOS and other platforms | refused: a release publishes Linux and Windows binaries only |

There is no `--to VERSION`. It is the one option that would put a hole in the downgrade
rule by construction, and it is not worth having in the same release that first taught this
program to replace itself.

**The keys are frozen at build time.** A binary from an earlier release has never seen a key
introduced later and cannot verify a release signed by it. It refuses and tells you to
download the release yourself rather than proceeding unverified —
[`keys/minisign-trusted.txt`](../keys/minisign-trusted.txt) describes the three-release rotation
that keeps that gap from opening in normal operation.

**The trust boundary.** A verified update proves the bytes were signed by whoever holds the
release key. It defends against a tampered asset, a hostile mirror and a MITM on the
download. It does not defend against a compromise of this repository or its CI, because the
signing key lives there, and no self-updater can do better without a separate offline
signing step.

**What narrows it is rebuilding.** The four Linux assets are built so that the same tagged
source produces the same bytes: build the tag in the release container and the SHA256 you
get is the one in that release's `SHA256SUMS`. Anyone can do that without holding any key,
which turns the signature from the only evidence into one of two.
[docs/RELEASING.md](RELEASING.md#rebuilding-a-release) is the procedure, and it is
also where the limits are - what a rebuild does and does not pin, and why the two Windows
assets are outside it.

## `update --check` — ask without downloading

```bash
lyxbosa update --check
```

Exits **0** when up to date and **2** when a newer release exists, so a monitoring script
can use it without reading the text — the same discipline as the scan exit codes. Anything
else is **1**: the request failed, or the binary is a development build, which reports
version `0.0.0` and has no released version to compare against.

## Checking during a scan

A scan may also check on its own, and the rules are narrow on purpose:

| when | checks? |
|---|---|
| `lyxbosa update --check`, typed | always |
| `scan`, stdout is a terminal, no `--quiet`/`--silent`/`--force` | at most once per interval |
| `check` | **never** |
| `--quiet`, `--silent`, `--force`, redirected output, CI | **never** |
| a development build (`0.0.0`) | **never** |
| no writable state file | never, silently |

`check` never checks because it is called from scripts — this repository's own harness runs
it 167 times in one suite run — and a network call per invocation would break that.

The check is asynchronous with a hard timeout of about two seconds, and **it cannot fail a
scan, change an exit code, or delay output**: a result that has not arrived by the time the
report is printed is discarded rather than waited for. The answer is cached, so one scan a
day asks and the rest of that day's scans can repeat what it learned without asking again.

Configure it beside `scan`, `archives`, `builtin_rules` and `actions`:

```yaml
updates:
  check: periodic      # off | on-demand | periodic
  interval: 24h        # 24h, 7d, 90m, or a bare number of seconds
```

- **`periodic`** (the default) — at most one check per `interval`, under the rules above.
- **`on-demand`** — a scan never checks; only `lyxbosa update --check` does.
- **`off`** — the same, spelled for an operator who wants the file to say it.

> **Privacy.** A version check tells whoever serves it **your IP address, which version of
> this scanner you are running, and when you ran it**. On an incident-response engagement
> that is telemetry about the investigation, and on a scheduled fleet it is a pattern of when
> your hosts are scanned. `off` and `on-demand` both mean the binary never opens a socket
> unless `lyxbosa update --check` is typed. There is no other network access anywhere in this
> tool.
>
> The check asks the GitHub releases API over HTTPS, with certificate verification against
> your system trust store. It sends no path, no finding, no hostname and nothing about what
> was scanned. `lyxbosa update` reaches the same API and then the release download; it makes
> no request at all until you ask it to.

**Certificates.** Verification is always on and there is no flag to turn it off. The system
trust store is found at run time — a released binary is built on one distribution and run on
others, and the path its TLS library was configured with often does not exist on the host.
To point it somewhere else, set `SSL_CERT_FILE` (a bundle), `CURL_CA_BUNDLE` (the same), or
`SSL_CERT_DIR` (a hashed directory); whichever you set is used in place of the probe for
that kind.
