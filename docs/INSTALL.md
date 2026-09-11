# Installing LyxBoSa

One command per platform. Both scripts are release assets, covered by the release's
`SHA256SUMS` and by the minisign signature over that list.

**Linux**

```bash
curl -fsSL https://github.com/LytraX/lyxbosa/releases/latest/download/install.sh | sh
```

**Windows (PowerShell)**

```powershell
irm https://github.com/LytraX/lyxbosa/releases/latest/download/install.ps1 | iex
```

`releases/latest/download/` always resolves to the newest release, so neither line names a
version.

---

## What piping a script into a shell does and does not give you

It runs bytes chosen by whoever controls the release, on your machine, before you have read
them. That is the same trust you extend to the binary itself — and `lyxbosa` is a program
you are about to run as root on a compromised host, so it is trust you are extending either
way. What it adds over downloading the binary by hand is a window between fetching the
script and running it, during which nothing you can check has happened yet.

What it does not give you is any guarantee that the bytes your shell is executing are the
bytes in the signed list. The script re-fetches its own published copy and checks it, and
that is worth exactly what [Verification](#verification) says it is worth and no more: a
script that had been tampered with in flight would simply not do the check, or would print
that it had. **No script can establish its own integrity.**

Everything the one-liner does is written out under [By hand](#by-hand). If you would rather
read before you run, download `install.sh`, verify it against `SHA256SUMS` the way you would
verify a binary, and then run it as a file — run that way, it also compares its own bytes on
disk against the signed list and says whether they match.

## What the script does, in order

1. Refuses a platform or architecture the release publishes no asset for.
2. Refuses a destination under a prefix a package manager owns, and checks the destination
   is writable — both **before** anything is downloaded.
3. Downloads `SHA256SUMS`, and `SHA256SUMS.minisig` if minisign is installed.
4. Verifies the signature over that list, or says plainly that it could not.
5. Re-fetches its own published copy and checks it against the list.
6. Picks the asset, downloads it, and checks its SHA-256 against the list.
7. Runs the verified download once to confirm it starts on this host.
8. Moves it into place with a rename, which is atomic.

A failure at any step leaves nothing behind: no partial download, and the binary you already
had exactly where it was.

## Which Linux binary it picks

A release publishes two Linux binaries per architecture and they differ in the C library.
[System support](../README.md#system-support) describes the choice; the script makes it
without asking.

**Architecture** comes from `uname -m`. `x86_64` means `amd64` and `aarch64` means `arm64`.
Anything else is refused rather than guessed at, because there is no asset to fall back on.

**C library** is read the way the binary itself reads it. The script looks for the dynamic
loader at the path the ABI fixes for the architecture — `/lib64/ld-linux-x86-64.so.2` on
x86_64, `/lib/ld-linux-aarch64.so.1` on aarch64 — and then reads the highest `GLIBC_2.N`
symbol version out of the first readable `libc.so.6` among four standard locations. At 2.28
or above it installs the standard build.

There are three answers and only one of them is acted on:

| answer | what it means | what gets installed |
|---|---|---|
| yes | a loader is present and a glibc at or above 2.28 was read | standard |
| no | there is no loader at all, or the glibc found is older | portable |
| unknown | a loader is present and no glibc could be read or parsed | portable |

**A host that cannot be read gets the portable build.** It runs everywhere, so being wrong
in that direction costs a few percent on a scan; being wrong in the other costs a binary
that will not start.

**The standard build also needs a libstdc++ from GCC 6**, which neither the script nor the
binary's own check looks at. Every distribution shipping glibc 2.28 ships a newer libstdc++,
so it is a gap rather than a case — and it is closed by observation rather than by a second
opinion about libraries: the verified download is run once before it is installed, and a
standard build that will not start here is replaced by the portable one with the reason
printed.

### Already running the portable build on a host that could run the standard one

`lyxbosa update` never crosses between the two builds, so the installer is the only thing
that can move you — and it will not do it on its own. Running it again on a host that
already has `lyxbosa` keeps the build that is there and tells you the faster one is
available. To cross:

```bash
curl -fsSL https://github.com/LytraX/lyxbosa/releases/latest/download/install.sh | sh -s -- --standard
```

`--portable` goes the other way. From then on updates stay on whichever you chose.

## Where it installs

| you are | destination | why |
|---|---|---|
| root on Linux | `/usr/local/bin` | outside every prefix a package manager owns, so `update` can replace the binary |
| a user on Linux | `~/.local/bin` | needs no elevation, and leaves `update` working without `sudo` |
| on Windows | `%LOCALAPPDATA%\Programs\lyxbosa` | per-user and writable, so nothing needs elevation and `update` works |

**`/usr/bin` and the eleven other prefixes `lyxbosa update` declines to touch are refused.**
The updater declines them because a package manager owns them, and an updater fighting `apt`
or `dnf` leaves the package database describing a file that is not there. An installer that
could write into one would be manufacturing exactly the state the updater refuses to be in:
a binary that can never update itself. Pass `--dir` and the same refusal applies to it.

**Program Files is refused on Windows for the matching reason.** `update` refuses an install
directory it cannot write as the user running it, and it never relaunches itself as
administrator.

Because there is no conventional per-user directory already on PATH on Windows, the
PowerShell script adds the install directory to the user PATH. On Linux, `~/.local/bin` is
conventional but not universal, and the script says how to add it when it is missing.

## Verification

Every download is checked against the release's `SHA256SUMS`. Whether that *list* is checked
depends on whether [minisign](https://jedisct1.github.io/minisign/) is installed, and the
script says which of the two you got rather than implying the stronger one.

| minisign | what is checked | what it defends against |
|---|---|---|
| installed | the signature over `SHA256SUMS` against keys pinned in the script, then the SHA-256 of each download against that verified list | a tampered asset, a hostile mirror, a rewritten release |
| not installed | the SHA-256 of each download against `SHA256SUMS` | a corrupted or truncated download, and nothing more |

The weaker level is not a failure and the script proceeds, because a checked download is
better than an unchecked one and refusing would send people to a browser. But `SHA256SUMS`
is published beside the files it describes, so **anyone who can write to the release can
rewrite the list too** — which is the entire reason the signature exists. Install minisign
and run it again for the stronger check:

```bash
sudo apt-get install minisign      # or: apk add minisign, brew install minisign
```

With minisign present, the script also prints the release named in the signature's *trusted
comment*. That comment is covered by the signature, so it is the only signed statement of
which release you are holding — a `SHA256SUMS` and signature pair lifted from an older
release verifies perfectly well and describes the wrong binaries.

**The keys are pinned in the script**, the same way `lyxbosa update` compiles its keyring in.
A key fetched from the same place as the thing it verifies is not a check. They are the keys
in [`keys/minisign-trusted.txt`](../keys/minisign-trusted.txt), and that file describes the
three-release rotation.

**What none of this defends against** is a compromise of this repository or its CI, because
the signing key lives there. That is the same boundary `lyxbosa update` has, and no
self-installing script can do better without a separate offline signing step.

## Options

```
--dir <path>     where to install
--standard       install the standard (glibc) build whatever this host looks like
--portable       install the portable (static) build, which runs on any Linux
--help
```

Through a pipe, options go after `-s --`:

```bash
curl -fsSL .../install.sh | sh -s -- --dir /opt/bin
```

On Windows, `iex` cannot forward arguments, so build the script block instead:

```powershell
& ([scriptblock]::Create((irm https://github.com/LytraX/lyxbosa/releases/latest/download/install.ps1))) -Dir D:\tools
```

`-SkipPath` leaves the user PATH alone.

## By hand

The same steps, written out. Substitute your architecture and, on Linux, the `-portable`
suffix if this host's glibc is older than 2.28 — `ldd --version` says which it has.

```bash
cd "$(mktemp -d)"
base=https://github.com/LytraX/lyxbosa/releases/latest/download

curl -fsSLO "$base/lyxbosa-linux-amd64"
curl -fsSLO "$base/SHA256SUMS"
curl -fsSLO "$base/SHA256SUMS.minisig"

# 1. the signature FIRST. The checksums are only worth reading if this passes.
#    The key is the `signing` line of keys/minisign-trusted.txt.
minisign -Vm SHA256SUMS -P RWQ3sDWqcTt8R0jVErMgIrRfrzCVlwuU4cFCUaEVGH2WqhYeiuL343eS

# 2. then the checksum of what you downloaded. `-c` on the whole list would fail on the
#    assets you did not fetch, so check the one line you care about.
grep ' lyxbosa-linux-amd64$' SHA256SUMS | sha256sum -c -

# 3. and install it somewhere update can replace it.
chmod +x lyxbosa-linux-amd64
install -m 0755 lyxbosa-linux-amd64 ~/.local/bin/lyxbosa      # or /usr/local/bin as root
```

`minisign -Vm` prints the trusted comment, which names the release. Read it.

Anyone without a checkout takes the key from
[`keys/minisign-trusted.txt`](../keys/minisign-trusted.txt) on GitHub.

## Uninstalling

```bash
rm ~/.local/bin/lyxbosa          # or /usr/local/bin/lyxbosa
```

```powershell
Remove-Item "$env:LOCALAPPDATA\Programs\lyxbosa" -Recurse
```

Nothing else is written. Configuration, if you made any, is wherever you put it; the update
check's state file is under the usual per-user state directory and is safe to delete.

## If two copies end up installed

The script never overwrites a `lyxbosa` found somewhere else on PATH. It reports the one it
found, installs into the destination it was given, and says that PATH now decides which name
wins. Remove the one you do not want, or reorder PATH.

## Building instead

[docs/BUILDING.md](BUILDING.md). A release publishes Linux and Windows binaries only, so
macOS and the BSDs are a source build.
