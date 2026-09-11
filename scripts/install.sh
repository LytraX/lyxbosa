#!/bin/sh
# install.sh - install lyxbosa on Linux, in one command.
#
#   curl -fsSL https://github.com/LytraX/lyxbosa/releases/latest/download/install.sh | sh
#
# WHY THIS FILE IS PUBLISHED AS A RELEASE ASSET AND NOT SERVED FROM A BRANCH
# --------------------------------------------------------------------------
# The release job hashes everything in its artifacts directory into SHA256SUMS and signs
# that list with minisign. A script staged there is covered by the same list and the same
# signature as the binaries. A script served from raw.githubusercontent.com is a mutable
# branch path: it is covered by no list, signed by no key, and it is the one artefact that
# runs with the most privilege while being the only one nobody can check. So this is an
# asset, it is fetched from releases/latest/download/, and `--expect` in the release
# workflow counts it.
#
# WHAT PIPING THIS INTO A SHELL DOES AND DOES NOT GIVE YOU
# --------------------------------------------------------
# It gives you: bytes chosen by whoever controls the release, run by your shell, before
# you have read them. That is the same trust you extend to the binary itself, and it is
# the honest framing - no amount of checking inside a script can make the script's own
# origin safer than the release it comes from.
#
# It does not give you: any guarantee that the bytes your shell is running right now are
# the bytes in the signed list. See `self_check` below, which states exactly what it
# catches and exactly what it cannot.
#
# If you would rather not pipe, docs/INSTALL.md writes out the same steps by hand.
#
# WHAT IT REFUSES
# ---------------
#   * a platform or architecture no release publishes an asset for
#   * a destination under a prefix a package manager owns - the same twelve
#     src-lib/cpp/update/InstallPath.cpp refuses, so an install can always update itself
#   * a destination that is not writable, asked before anything is downloaded
#   * a download whose SHA-256 is not the one in the release's SHA256SUMS
#   * a signature that does not verify, when minisign is installed
#   * crossing between the standard and the portable build without being asked
#
# SHELL
# -----
# POSIX sh, no bashisms, so `| sh` works under dash, ash/busybox, bash and zsh. `local` is
# not in POSIX but is implemented by every one of those.
set -eu

# ---------------------------------------------------------------------------------------
# What a release publishes, and where.
# ---------------------------------------------------------------------------------------

REPO="LytraX/lyxbosa"

# `latest` always resolves to the newest release, so the one-liner never names a version
# and never goes stale. LYXBOSA_INSTALL_ORIGIN exists so the control suite can serve a
# fabricated release from a local directory; a non-default origin is announced loudly
# rather than used quietly.
DEFAULT_ORIGIN="https://github.com/${REPO}/releases/latest/download"
ORIGIN="${LYXBOSA_INSTALL_ORIGIN:-$DEFAULT_ORIGIN}"

SUMS="SHA256SUMS"
SIG="SHA256SUMS.minisig"
SELF_ASSET="install.sh"

# The minisign public keys a release may be signed by, copied from keys/minisign-trusted.txt
# with both roles kept - `signing` signs, `trusted` is a key on its way in or out, and a
# verifier accepts either. Pinned here rather than fetched, for the same reason the binary
# compiles its keyring in: a key fetched from the same place as the thing it verifies is
# not a check. corpus/install-scripts.sh asserts this list against that file, so a rotation
# that forgets this script fails a pre-report command rather than a release.
#
# LYXBOSA_INSTALL_KEYS replaces the list so that the control suite can sign a fabricated
# release with a throwaway key and watch a real verification both accept it and refuse a
# mutated one - the same override release-sign.sh takes for LYXBOSA_KEYRING, and for the
# same reason: a verification nobody has watched refuse anything is not a verification.
# It is announced as loudly as a changed origin.
BUILTIN_KEYS="RWQ3sDWqcTt8R0jVErMgIrRfrzCVlwuU4cFCUaEVGH2WqhYeiuL343eS"
TRUSTED_KEYS="${LYXBOSA_INSTALL_KEYS:-$BUILTIN_KEYS}"

# Every prefix src-lib/cpp/update/InstallPath.cpp declines to write under, because a
# package manager owns it. /usr/local/bin is deliberately NOT among them, which is what
# makes it the right destination for root: an install under /usr/bin is a binary that can
# never update itself, so an installer that could write there would be manufacturing the
# exact state the updater refuses to be in.
#
# It is a copy, and it is a copy under duress: this script is fetched on its own and has no
# repository to read the list out of. What keeps it from drifting is not good intentions -
# corpus/install-scripts.sh parses the array in InstallPath.cpp and fails if these two
# lists are not the same set.
OWNED_PREFIXES="/usr/bin
/usr/sbin
/bin
/sbin
/usr/lib
/usr/libexec
/usr/share
/snap
/var/lib/flatpak
/nix/store
/usr/local/Cellar
/opt/homebrew"

# The glibc the standard build needs, and where to look for the answer. Both are
# src-lib/cpp/update/BuildIdentity.cpp's, asserted equal to it by the control suite: a
# second opinion about which build a host can run is worse than no opinion, because the
# binary goes on printing its own.
GLIBC_MIN_MINOR=28

MINISIGN="${MINISIGN:-minisign}"

# ---------------------------------------------------------------------------------------
# Saying things.
# ---------------------------------------------------------------------------------------

say()  { printf '%s\n' "$*"; }
note() { printf '  %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

WORK=""
cleanup() { [ -n "${WORK:-}" ] && rm -rf "$WORK"; return 0; }

usage() {
  cat <<'USAGE'
usage: install.sh [options]

  --dir <path>     where to install. Defaults to /usr/local/bin as root and
                   ~/.local/bin otherwise. Refused under a package manager's prefix.
  --standard       install the standard (glibc) build, whatever this host looks like.
  --portable       install the portable (static) build, which runs on any Linux.
  --help           this.

With neither --standard nor --portable, an existing install keeps the build it already
has, and a fresh install gets the standard build on a host that can run it.
USAGE
}

# ---------------------------------------------------------------------------------------
# The host.
# ---------------------------------------------------------------------------------------

# amd64, arm64, or a refusal. Anything else is refused rather than guessed at: there is no
# asset to fall back to, and downloading one that cannot run is worse than stopping.
detect_arch() {
  local machine
  machine="$(uname -m 2>/dev/null || echo unknown)"
  case "$machine" in
    x86_64|amd64)  printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *) die "no release asset for this architecture ($machine). A release publishes Linux
   and Windows binaries for x86_64 and aarch64 only. Building from source is
   docs/BUILDING.md." ;;
  esac
}

# The dynamic loader's path, which the ABI fixes per architecture rather than leaving to
# the distribution. A dynamically linked binary carries it as its PT_INTERP, so its absence
# is not a hint: no such binary can start at all.
loader_path() {
  case "$1" in
    amd64) printf '/lib64/ld-linux-x86-64.so.2\n' ;;
    arm64) printf '/lib/ld-linux-aarch64.so.1\n' ;;
  esac
}

libc_paths() {
  case "$1" in
    amd64) printf '%s\n' /lib/x86_64-linux-gnu/libc.so.6 /lib64/libc.so.6 \
                         /usr/lib/x86_64-linux-gnu/libc.so.6 /usr/lib64/libc.so.6 ;;
    arm64) printf '%s\n' /lib/aarch64-linux-gnu/libc.so.6 /lib64/libc.so.6 \
                         /usr/lib/aarch64-linux-gnu/libc.so.6 /usr/lib64/libc.so.6 ;;
  esac
}

# The highest N in any `GLIBC_2.N` string in an ELF file, or nothing.
#
# HOW THIS AGREES WITH THE BINARY, which is the property that matters more than the method:
# src-lib/cpp/update/BuildIdentity.cpp walks the NUL-separated strings of the .dynstr
# section and keeps the highest `GLIBC_2.<digits>` whose digits are digits all the way to
# the end - so `GLIBC_2.2.5` and `GLIBC_PRIVATE` are skipped rather than half-parsed. `tr`
# turns every run of non-printable bytes into a line break, which produces exactly that
# NUL-separated walk, and the anchored pattern below is that same "digits to the end" rule.
#
# Where the two are not identical: this reads the whole file, not only .dynstr. A version
# name that appears in some other section would be seen here and not there. Nothing in a
# glibc puts one anywhere else - the `.gnu.version_d` entries point into .dynstr rather
# than carrying their own copies, and the release banner in .rodata is prose - so the two
# cannot disagree on a real C library, and on a file that is not one the ELF magic below
# refuses first, exactly as the C++ does.
highest_glibc_minor() {
  local file magic
  file="$1"
  [ -r "$file" ] || return 1
  # An ELF, or nothing. Same first refusal as the C++ reader, and it is what keeps "read
  # the whole file" from becoming "believe any file that has the right letters in it".
  magic="$(od -An -tx1 -N4 "$file" 2>/dev/null | tr -d ' \n')" || return 1
  [ "$magic" = "7f454c46" ] || return 1
  LC_ALL=C tr -c '[:print:]' '\n' < "$file" 2>/dev/null \
    | LC_ALL=C sed -n 's/^GLIBC_2\.\([0-9][0-9]*\)$/\1/p' \
    | LC_ALL=C sort -n | tail -1
}

# yes | no | unknown - would the standard build load on a host with this loader and these
# C libraries?
#
# The three answers are BuildIdentity.h's and mean what it says they mean. Only `yes` is
# acted on. `no` and `unknown` both lead to the portable build, which is the safe
# direction: the portable build runs everywhere, so being wrong that way costs a few
# percent on a scan, and being wrong the other way costs a binary that will not start.
#
# It takes the paths rather than reading the ABI's, for the same reason
# standardBuildHereAt() in BuildIdentity.h does: none of the three answers is observable on
# a developer's machine, which can only ever demonstrate one of them, and an answer nobody
# has watched the check give is not an answer the check is known to be able to give.
# corpus/install-scripts.sh presents all three.
standard_build_here_at() {
  local loader path answer
  loader="$1"
  shift

  # No loader, no dynamically linked binary, whatever else is true of this host. The Alpine
  # case and every other musl-only one, and the only answer here that needs nothing parsed.
  [ -n "$loader" ] && [ -e "$loader" ] || { printf 'no\n'; return 0; }

  # Every tool the read needs. Missing one is `unknown`, not an excuse to guess.
  command -v od >/dev/null 2>&1 && command -v tr >/dev/null 2>&1 \
    && command -v sed >/dev/null 2>&1 && command -v sort >/dev/null 2>&1 \
    || { printf 'unknown\n'; return 0; }

  # The FIRST readable glibc decides, rather than the highest across all of them - the
  # same rule as the C++, so a host with several is answered the same way by both.
  # `break` and not `return`: the loop body runs in a subshell of the pipeline, where a
  # `return` is not this function's to make.
  printf '%s\n' "$@" | while IFS= read -r path; do
    answer="$(highest_glibc_minor "$path" 2>/dev/null || true)"
    [ -n "$answer" ] || continue
    if [ "$answer" -ge "$GLIBC_MIN_MINOR" ]; then printf 'yes\n'; else printf 'no\n'; fi
    break
  done | head -1 | grep . || printf 'unknown\n'
}

# The same answer with the paths the ABI and the distributions fix.
standard_build_here() {
  local arch
  arch="$1"
  # Unquoted on purpose: libc_paths prints one path per line and they become the argument
  # list. No path here contains whitespace or a glob character.
  # shellcheck disable=SC2046
  standard_build_here_at "$(loader_path "$arch")" $(libc_paths "$arch")
}

# WHICH BUILD, as a function of the three things that decide it, and the ORDER of the rules
# is the whole decision.
#
# An explicit flag wins. Otherwise an existing install keeps the build it has: `lyxbosa
# update` deliberately never crosses between the two, so this script is the only thing that
# can move somebody, and somebody who chose the portable build on purpose should not be
# moved by an installer they ran to get a newer version. Only a fresh install is decided by
# what the host can run, and only a proven `yes` gets the standard build.
choose_build() {
  local forced existing capable
  forced="$1"; existing="$2"; capable="$3"
  if [ -n "$forced" ]; then
    printf '%s\n' "$forced"
  elif [ "$existing" = "portable" ] || [ "$existing" = "standard" ]; then
    printf '%s\n' "$existing"
  elif [ "$capable" = "yes" ]; then
    printf 'standard\n'
  else
    printf 'portable\n'
  fi
}

# ---------------------------------------------------------------------------------------
# Fetching and hashing.
# ---------------------------------------------------------------------------------------

DOWNLOADER=""
CURL_PROTO="=https"
choose_downloader() {
  if command -v curl >/dev/null 2>&1; then DOWNLOADER=curl
  elif command -v wget >/dev/null 2>&1; then DOWNLOADER=wget
  else
    die "neither curl nor wget is installed, so nothing can be downloaded.
   Install one - 'apt-get install curl', 'yum install curl', 'apk add curl' - or follow
   the manual steps in docs/INSTALL.md."
  fi
}

# Into a file, refusing on any HTTP error rather than saving an error page under the name
# of a binary. `--fail` and `--tries=1` are what make a 404 a failure here.
fetch() {
  local url dest
  url="$1"; dest="$2"
  case "$DOWNLOADER" in
    curl) curl -fsSL --proto "$CURL_PROTO" --retry 2 -o "$dest" "$url" 2>/dev/null ;;
    wget) wget -q --tries=2 -O "$dest" "$url" 2>/dev/null ;;
  esac
}

fetch_required() {
  fetch "$1" "$2" || die "could not download $1
   Check the network, or take the assets from ${DEFAULT_ORIGIN%/download} by hand -
   docs/INSTALL.md has the manual steps."
}

HASHER=""
choose_hasher() {
  if command -v sha256sum >/dev/null 2>&1; then HASHER=sha256sum
  elif command -v shasum >/dev/null 2>&1; then HASHER=shasum
  else
    die "no sha256sum and no shasum, so a download cannot be checked - and this script
   does not install anything it has not checked. Install coreutils (or perl's shasum)
   and run it again."
  fi
}

sha256_of() {
  case "$HASHER" in
    sha256sum) sha256sum "$1" | cut -d' ' -f1 ;;
    shasum)    shasum -a 256 "$1" | cut -d' ' -f1 ;;
  esac
}

# The hash SHA256SUMS records for one asset, or nothing. Whole-field match on the name, so
# `lyxbosa-linux-amd64` cannot pick up `lyxbosa-linux-amd64-portable`'s line - the two are
# in a prefix relation and a looser match would silently verify the wrong file.
sum_for() {
  local name
  name="$1"
  LC_ALL=C awk -v want="$name" '$2 == want { print $1; found = 1 } END { exit !found }' \
    "$WORK/$SUMS" 2>/dev/null || return 1
}

# ---------------------------------------------------------------------------------------
# Verification.
# ---------------------------------------------------------------------------------------

VERIFICATION=""      # "signature" or "checksum"
RELEASE_TAG=""       # read out of the signed trusted comment when there is one

# Both levels are acceptable and the user is told which they got. What is NOT acceptable is
# reporting the strong one when the weak one happened, so the level is a variable set in
# exactly one place and printed verbatim at the end.
verify_sums() {
  local key out
  fetch_required "$ORIGIN/$SUMS" "$WORK/$SUMS"

  if ! command -v "$MINISIGN" >/dev/null 2>&1; then
    VERIFICATION="checksum"
    return 0
  fi
  if ! fetch "$ORIGIN/$SIG" "$WORK/$SIG"; then
    VERIFICATION="checksum"
    warn "the release publishes no $SIG, so the checksum list could not be verified."
    return 0
  fi

  for key in $TRUSTED_KEYS; do
    if out="$("$MINISIGN" -V -m "$WORK/$SUMS" -x "$WORK/$SIG" -P "$key" 2>&1)"; then
      VERIFICATION="signature"
      # The trusted comment is covered by the signature; the untrusted one is not. It
      # names the release, which is the only signed statement of WHICH release this is -
      # a SHA256SUMS and signature pair lifted from an older release verifies perfectly
      # well and describes the wrong binaries.
      RELEASE_TAG="$(printf '%s\n' "$out" \
        | sed -n 's/^Trusted comment: *LyxBoSa \(v[0-9][0-9.]*\) .*/\1/p' | head -1)"
      return 0
    fi
  done

  die "$SUMS is published with a signature and it does not verify under any key this
   script carries. That is either a release signed by a newer key than this script knows
   about - take a newer install.sh from the releases page - or bytes that were changed
   between the release and here. Nothing has been downloaded or installed."
}

# Re-fetch this script from the release and check it against the signed list.
#
# WHAT IT IS WORTH, stated rather than implied. It catches a corrupted download, a
# truncated transfer and a bad mirror, which are the failures that actually happen. It
# does NOT prove that the bytes your shell is running right now are the bytes in the list:
# a script that had been tampered with in flight would simply not do this, or would print
# that it had. Nothing a script says about itself can establish its own integrity, and no
# arrangement of this check ever will. It also cannot protect anybody from a compromised
# release, because the list and the signing key both live there.
#
# The one case where it is more than that is an install.sh somebody saved to disk and ran
# as a file: then $0 is readable and its bytes are compared too, which does catch a local
# copy that has been edited or has gone stale.
self_check() {
  local published local_sum want
  want="$(sum_for "$SELF_ASSET")" || {
    warn "$SUMS has no line for $SELF_ASSET, so this script could not be checked against
   the release. Continuing: the binary below is checked on its own."
    return 0
  }

  published="$WORK/$SELF_ASSET"
  fetch "$ORIGIN/$SELF_ASSET" "$published" || {
    warn "the published $SELF_ASSET could not be re-fetched, so it was not compared
   against the release. Continuing: the binary below is checked on its own."
    return 0
  }
  [ "$(sha256_of "$published")" = "$want" ] \
    || die "the published $SELF_ASSET does not match its line in $SUMS. Nothing has been
   installed. Take the assets from the releases page and check them by hand -
   docs/INSTALL.md."

  if [ -n "${0:-}" ] && [ -f "$0" ] && [ -r "$0" ]; then
    local_sum="$(sha256_of "$0")"
    if [ "$local_sum" != "$want" ]; then
      warn "the copy of this script being run ($0) is not the one in the release's
   $SUMS. That is expected for a modified or older copy and worth knowing about for any
   other reason."
    else
      note "this script: matches the release's $SUMS"
    fi
  fi
}

# ---------------------------------------------------------------------------------------
# The destination.
# ---------------------------------------------------------------------------------------

# Component-wise, so that /usr/binary-thing is not inside /usr/bin. A plain string prefix
# would say it is, and the difference is a directory nobody owns being refused as if a
# package manager did. Same rule as isUnder() in InstallPath.cpp.
is_under() {
  local path prefix
  path="$1"; prefix="$2"
  case "$path" in
    "$prefix") return 0 ;;
    "$prefix"/*) return 0 ;;
    *) return 1 ;;
  esac
}

owner_of() {
  local dir prefix
  dir="$1"
  printf '%s\n' "$OWNED_PREFIXES" | while IFS= read -r prefix; do
    [ -n "$prefix" ] || continue
    if is_under "$dir" "$prefix"; then printf '%s\n' "$prefix"; break; fi
  done | head -1
}

# An absolute, symlink-resolved, `..`-free spelling of a destination.
#
# The resolution is the load-bearing half and not tidiness. The owned-prefix test below is
# component-wise, so it answers about the path it is handed: `--dir /usr/local/bin/../../bin`
# IS /bin and would be accepted on its typed spelling, and `--dir bin` would be a relative
# path no prefix can match. Resolving first means the refusal is about where the file
# actually lands. It resolves symlinks too, so a /usr/local/bin that is a link into /usr/bin
# is refused for what it is.
normalise_dir() {
  local d base parent
  d="$1"
  while :; do
    case "$d" in
      */) d="${d%/}" ;;
      */.) d="${d%/.}" ;;
      *) break ;;
    esac
    [ -n "$d" ] || { d="/"; break; }
  done
  if [ -d "$d" ]; then
    ( cd "$d" 2>/dev/null && pwd -P ) || printf '%s\n' "$d"
    return 0
  fi
  # It does not exist yet, which is the ~/.local/bin case. Resolve the parent - which
  # does - and put the last component back on.
  base="${d##*/}"
  parent="${d%/*}"
  [ "$parent" = "$d" ] && parent="."
  [ -n "$parent" ] || parent="/"
  if parent="$( cd "$parent" 2>/dev/null && pwd -P )"; then
    case "$parent" in
      /) printf '/%s\n' "$base" ;;
      *) printf '%s/%s\n' "$parent" "$base" ;;
    esac
  else
    printf '%s\n' "$d"
  fi
}

check_destination() {
  local dir owner
  dir="$1"
  owner="$(owner_of "$dir")"
  if [ -n "$owner" ]; then
    die "$dir is under $owner, which a package manager owns.

   'lyxbosa update' refuses to replace a binary under that prefix - an updater fighting
   apt or dnf leaves the package database describing a file that is not there - so
   installing there produces a binary that can never update itself. Install to
   /usr/local/bin (as root) or ~/.local/bin (as a user); both are deliberately outside
   that list."
  fi

  # Asked by writing, and asked BEFORE anything is downloaded. A stat cannot see a
  # read-only mount, a full filesystem or a container's restrictions, and every one of
  # those decides whether the install below can happen.
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir" 2>/dev/null \
      || die "$dir does not exist and could not be created."
  fi
  local probe="$dir/.lyxbosa-install-probe.$$"
  if ! (: > "$probe") 2>/dev/null; then
    rm -f "$probe" 2>/dev/null || true
    if [ "$(id -u)" != "0" ]; then
      die "$dir is not writable by this user. Either run this as root, which installs to
   /usr/local/bin, or pass --dir ~/.local/bin, which needs no elevation and leaves
   'lyxbosa update' working without sudo."
    fi
    die "$dir is not writable."
  fi
  rm -f "$probe" 2>/dev/null || true
}

on_path() {
  local dir entry
  dir="$1"
  # The literal spelling first, which is the common case and costs nothing.
  case ":${PATH:-}:" in
    *":$dir:"*|*":$dir/:"*) return 0 ;;
  esac
  # Then each entry resolved the way the destination was, so that a PATH carrying
  # /usr/local/bin and a destination resolved through a symlink are seen to be the same
  # directory rather than reported as a missing one.
  printf '%s\n' "${PATH:-}" | tr ':' '\n' | while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    [ -d "$entry" ] || continue
    [ "$( normalise_dir "$entry" )" = "$dir" ] && printf 'yes\n' && break
  done | grep -q yes
}

# ---------------------------------------------------------------------------------------
# What is already here.
# ---------------------------------------------------------------------------------------

EXISTING_PATH=""
EXISTING_VERSION=""
EXISTING_BUILD=""     # standard | portable | unknown

# `lyxbosa --version` prints "2.3.0 (portable build, lyxbosa-linux-amd64-portable)". The
# version is the first whitespace-delimited token and stays that way by design, so reading
# it here is reading a documented contract rather than scraping a banner.
read_existing() {
  local out
  EXISTING_PATH="$(command -v lyxbosa 2>/dev/null || true)"
  [ -n "$EXISTING_PATH" ] || return 0
  out="$("$EXISTING_PATH" --version 2>/dev/null || true)"
  [ -n "$out" ] || { EXISTING_BUILD="unknown"; return 0; }
  EXISTING_VERSION="$(printf '%s\n' "$out" | head -1 | cut -d' ' -f1)"
  case "$out" in
    *"portable build"*) EXISTING_BUILD="portable" ;;
    *"standard build"*) EXISTING_BUILD="standard" ;;
    *) EXISTING_BUILD="unknown" ;;
  esac
}

asset_for() {
  local arch build
  arch="$1"; build="$2"
  if [ "$build" = "portable" ]; then
    printf 'lyxbosa-linux-%s-portable\n' "$arch"
  else
    printf 'lyxbosa-linux-%s\n' "$arch"
  fi
}

# Download one asset and check it against the verified list. Nothing downstream is ever
# handed a file that failed this: the failure removes it rather than leaving it for a
# later step to be trusted to notice.
fetch_asset() {
  local name dest want got
  name="$1"; dest="$2"
  want="$(sum_for "$name")" \
    || die "$SUMS has no line for $name, so this release does not publish it or the list
   does not cover it. Refusing to install an asset the signed list says nothing about."
  fetch_required "$ORIGIN/$name" "$dest"
  got="$(sha256_of "$dest")"
  if [ "$got" != "$want" ]; then
    rm -f "$dest"
    die "$name does not match its SHA-256 in $SUMS.
     expected $want
     got      $got
   Nothing has been installed and the download has been removed. This is a corrupted or
   truncated transfer, or bytes that are not the release's."
  fi
  chmod 0755 "$dest" 2>/dev/null || true
}

# A liveness check, not a source of information: output goes nowhere, because a version
# banner in the middle of an install reads as part of the install. It is the same smoke
# test UpdateApply.cpp runs before a replace, and it is what closes the one gap the glibc
# read above leaves open - the standard build also needs a libstdc++ from GCC 6, which
# neither this script nor the binary's own check looks at. A host that somehow has the
# glibc and not the C++ runtime lands here, and is moved to the portable build by
# observation rather than by a second opinion about libraries.
runs_here() {
  "$1" --version >/dev/null 2>&1
}

# ---------------------------------------------------------------------------------------
main() {
  local arch dir want_build capable asset staged version_line new_version shadow
  local requested_dir="" forced=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --dir) [ $# -ge 2 ] || die "--dir needs a path"; requested_dir="$2"; shift 2 ;;
      --dir=*) requested_dir="${1#--dir=}"; shift ;;
      --standard) forced="standard"; shift ;;
      --portable) forced="portable"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1 (try --help)" ;;
    esac
  done

  [ "$(uname -s 2>/dev/null || echo unknown)" = "Linux" ] \
    || die "this script installs the Linux binaries. A release publishes Linux and
   Windows only; on Windows use install.ps1, and on macOS or a BSD there is no asset to
   install - build from source, see docs/BUILDING.md."

  arch="$(detect_arch)"
  choose_downloader
  choose_hasher

  if [ -n "$requested_dir" ]; then
    dir="$(normalise_dir "$requested_dir")"
  elif [ "$(id -u)" = "0" ]; then
    dir="/usr/local/bin"
  else
    dir="$HOME/.local/bin"
  fi
  check_destination "$dir"

  read_existing

  capable="$(standard_build_here "$arch")"
  want_build="$(choose_build "$forced" "$EXISTING_BUILD" "$capable")"

  WORK="$(mktemp -d "${TMPDIR:-/tmp}/lyxbosa-install.XXXXXX")" \
    || die "could not create a temporary directory"
  trap cleanup EXIT INT TERM

  if [ "$ORIGIN" != "$DEFAULT_ORIGIN" ]; then
    # Announced rather than used quietly, and this is the only thing that widens the
    # protocol list: with the release origin, nothing but https is ever fetched.
    say "origin: $ORIGIN  (NOT the release origin)"
    case "$ORIGIN" in file://*) CURL_PROTO="=file" ;; esac
  fi
  [ "$TRUSTED_KEYS" = "$BUILTIN_KEYS" ] \
    || say "keys:   NOT the keys this script ships with"

  verify_sums
  self_check

  asset="$(asset_for "$arch" "$want_build")"
  staged="$WORK/lyxbosa"
  fetch_asset "$asset" "$staged"

  # Verified, then run. A binary that will not start on this host is not installed over a
  # working one, and when it is the standard build there is a published asset that will.
  if ! runs_here "$staged"; then
    if [ "$want_build" = "standard" ]; then
      warn "$asset does not start on this host, so the portable build is being installed
   instead. This host's C or C++ runtime is older than the standard build needs."
      want_build="portable"
      asset="$(asset_for "$arch" "$want_build")"
      fetch_asset "$asset" "$staged"
      runs_here "$staged" || die "$asset does not start here either. Nothing has been
   installed. Please report this with the output of 'uname -a'."
    else
      die "$asset does not start on this host, and it is the build that needs nothing
   from the host at all. Nothing has been installed. Please report this with the output
   of 'uname -a'."
    fi
  fi

  version_line="$("$staged" --version 2>/dev/null | head -1)"
  new_version="$(printf '%s\n' "$version_line" | cut -d' ' -f1)"

  # Staged inside the destination so the move is a rename within one filesystem, which is
  # atomic: an interrupted install leaves either the old binary or the new one, never half.
  cp "$staged" "$dir/.lyxbosa.install.$$" \
    || die "could not write into $dir"
  chmod 0755 "$dir/.lyxbosa.install.$$"
  mv -f "$dir/.lyxbosa.install.$$" "$dir/lyxbosa" \
    || { rm -f "$dir/.lyxbosa.install.$$"; die "could not move the new binary into $dir"; }

  # ------------------------------------------------------------------- what just happened
  say ""
  say "installed lyxbosa $new_version to $dir/lyxbosa"
  note "build:    $want_build ($asset)"
  if [ "$VERIFICATION" = "signature" ]; then
    note "verified: minisign signature over $SUMS, then SHA-256 of the download"
    [ -n "$RELEASE_TAG" ] && note "release:  $RELEASE_TAG (from the signed trusted comment)"
  else
    note "verified: SHA-256 against $SUMS only"
    note "          minisign is not installed, so the list ITSELF was not verified - and"
    note "          the list is published beside the files it describes, so this catches a"
    note "          corrupted download and not a rewritten release. 'apt-get install"
    note "          minisign' (or 'apk add minisign'), then run this again, for the"
    note "          stronger check."
  fi

  # ------------------------------------------------------------------- and what to know
  if [ -n "$EXISTING_PATH" ] && [ "$EXISTING_PATH" != "$dir/lyxbosa" ]; then
    shadow="$EXISTING_PATH"
    say ""
    warn "there was already a lyxbosa at $shadow ($EXISTING_VERSION, $EXISTING_BUILD build)
   and it has been left alone. Two copies are now installed, and PATH decides which one
   'lyxbosa' means."
    if on_path "$dir" && command -v lyxbosa >/dev/null 2>&1; then
      note "right now 'lyxbosa' is $(command -v lyxbosa)"
    fi
    note "remove the other one, or put $dir earlier in PATH."
  fi

  if ! on_path "$dir"; then
    say ""
    warn "$dir is not on PATH, so typing 'lyxbosa' will not find it yet."
    note "add it for future shells:"
    note "    echo 'export PATH=\"$dir:\$PATH\"' >> ~/.profile"
    note "and for this one:"
    note "    export PATH=\"$dir:\$PATH\""
  fi

  # The one case the updater cannot handle and this script can. It is an offer and not an
  # action: `update` never crosses between the builds, so a switch only ever happens
  # because somebody asked for it.
  if [ "$want_build" = "portable" ] && [ "$capable" = "yes" ] && [ -z "$forced" ]; then
    say ""
    say "This host can run the standard build, which is faster on the same scan and finds"
    say "exactly the same things. You have the portable one, and nothing will move you off"
    say "it - 'lyxbosa update' never crosses between the two. To switch:"
    note "curl -fsSL $DEFAULT_ORIGIN/$SELF_ASSET | sh -s -- --standard"
  fi
}

# Sourced by corpus/install-scripts.sh, which calls the functions above one at a time.
# Running is the default; nothing a user does sets this.
if [ "${LYXBOSA_INSTALL_NO_MAIN:-0}" != "1" ]; then
  main "$@"
fi
