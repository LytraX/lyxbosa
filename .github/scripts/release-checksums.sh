#!/usr/bin/env bash
# Write SHA256SUMS over a directory of release assets, and prove in the same file that it
# can also say no.
#
#   release-checksums.sh write <dir> [--expect N]   hash every asset in <dir> into SHA256SUMS
#   release-checksums.sh --selftest                 the controls, both directions, then exit
#
# WHY THIS IS A FILE AND NOT FOUR LINES OF YAML
# ----------------------------------------------
# The release job cannot be rehearsed. Any `v*` tag publishes a real release to the public,
# `docs/RELEASING.md` records that a non-numeric tag such as `v0.0.1-rc1` breaks the Windows
# build outright, and the job is gated on the ref being a `v*` tag so `workflow_dispatch`
# never reaches it. Shell written inside a `run:` block is therefore code that ships without
# ever having been executed. In a file it runs here, on a fabricated directory, and its
# controls run again in CI on every release - before the file they defend is published.
#
# THE FOUR PROPERTIES A CONSUMER DEPENDS ON
# ------------------------------------------
# A consumer downloads the assets into one directory and runs `sha256sum -c SHA256SUMS`
# there. That single sentence decides the whole format:
#
#   basenames, not paths     `sha256sum artifacts/x` writes `artifacts/x` into the file, and
#                            `-c` then looks for a directory the consumer does not have. The
#                            hashing runs from inside <dir> so the names are bare.
#   it must not list itself  a file cannot carry its own hash, and `-c` would report
#                            SHA256SUMS: FAILED on a list that tried. Its signature is
#                            excluded for the same reason one level out: the .minisig is
#                            written after the list, so a list naming it can never be true.
#   stable ordering          two releases of the same bytes must produce the same file.
#                            Directory order is readdir order, which is neither sorted nor
#                            stable; the sort is `LC_ALL=C` because a locale collation can
#                            reorder the same names on a different runner.
#   every asset is in it     a list missing one binary looks done, which is worse than no
#                            list at all - the same argument that puts `fail_on_unmatched_files`
#                            on the release step. `--expect N` is how the caller says how
#                            many assets a release of this project has.
#
# It writes through a temp file OUTSIDE <dir> and moves it in. A `SHA256SUMS.tmp` left in the
# artifacts directory by a half-finished run would be picked up by the `artifacts/*` glob and
# published as an asset.
set -euo pipefail

SUMS="SHA256SUMS"
SIG="SHA256SUMS.minisig"

die() { echo "error: $*" >&2; exit 1; }

# The asset names in <dir>, in the order they will be written: every regular file, minus the
# list and its signature, in byte order.
#
# The enumeration is `find` rather than a glob, and that is not a style choice. Bash sorts
# glob results itself, using the AMBIENT LOCALE - so with a glob the `LC_ALL=C sort` below
# had nothing left to do, and a mutant with the sort deleted passed every control in this
# file. The sort was correct and its control was blind, which is the shape AGENTS.md is
# about. `find` returns readdir order, measured scrambled on tmpfs, so the sort is now
# load-bearing and a control can see it disappear.
enumerate_assets() {
  local dir="$1" f base
  while IFS= read -r -d '' f; do
    base="${f##*/}"
    case "$base" in
      "$SUMS"|"$SIG") continue ;;
    esac
    printf '%s\n' "$base"
  done < <(find "$dir" -maxdepth 1 -type f -print0)
}

# Byte order, not the runner's collation. C and en_US disagree about case and punctuation,
# and two runners hashing the same assets have to produce the same file.
sort_names() { LC_ALL=C sort; }

asset_names() { enumerate_assets "$1" | sort_names; }

cmd_write() {
  local dir="" expect=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --expect) expect="${2:-}"; shift 2 ;;
      -*) die "unknown option: $1" ;;
      *) [ -n "$dir" ] && die "one directory, not two"; dir="$1"; shift ;;
    esac
  done
  [ -n "$dir" ] || die "usage: release-checksums.sh write <dir> [--expect N]"
  [ -d "$dir" ] || die "no such directory: $dir"

  local names=()
  while IFS= read -r line; do names+=("$line"); done < <(asset_names "$dir")

  [ ${#names[@]} -eq 0 ] && die "no assets in $dir - refusing to write an empty $SUMS"
  if [ -n "$expect" ] && [ "${#names[@]}" -ne "$expect" ]; then
    die "$dir holds ${#names[@]} asset(s), expected $expect. Either a build produced nothing
       or the release gained an asset and the --expect in the workflow was not updated.
       Names found: ${names[*]}"
  fi

  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/SHA256SUMS.XXXXXX")"
  ( cd "$dir" && LC_ALL=C sha256sum -- "${names[@]}" ) > "$tmp"
  mv -f "$tmp" "$dir/$SUMS"

  # A positive control on the real release, not only in --selftest: the list is checked
  # against the files it was just derived from, in the same directory a consumer would.
  ( cd "$dir" && sha256sum -c --quiet -- "$SUMS" ) \
    || die "the $SUMS just written does not check out against $dir"

  echo "wrote $dir/$SUMS  (${#names[@]} asset(s), hashed in this run, verified in this run)"
  echo
  cat "$dir/$SUMS"
}

# ---------------------------------------------------------------------------------------
# Controls.
# ---------------------------------------------------------------------------------------

# The four names are the four assets a release actually publishes, and they are CREATED in an
# order that is neither the sorted order nor its reverse, so a run that simply echoed readdir
# order would fail the expected-bytes case rather than pass it by luck.
FIXTURE_NAMES=(lyxbosa-windows-arm64.exe lyxbosa-linux-amd64 lyxbosa-windows-amd64.exe lyxbosa-linux-arm64)

fixture() {
  local dir="$1"
  mkdir -p "$dir"
  printf ''     > "$dir/lyxbosa-windows-arm64.exe"
  printf 'abc'  > "$dir/lyxbosa-linux-amd64"
  printf 'a'    > "$dir/lyxbosa-windows-amd64.exe"
  printf 'z\n'  > "$dir/lyxbosa-linux-arm64"
}

# Known answers, not a re-derivation. The first two are the published SHA-256 test vectors
# for the empty string and for "abc", so half of this expectation can be checked against
# FIPS 180-4 rather than against this repository.
expected_sums() {
  cat <<'EXPECTED'
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  lyxbosa-linux-amd64
c865f6c5ab8d1b0bcd383a5e1e3879d22681c96bf462c269b7581d523fbe70ab  lyxbosa-linux-arm64
ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb  lyxbosa-windows-amd64.exe
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  lyxbosa-windows-arm64.exe
EXPECTED
}

_ok=0
say()  { printf '  %-62s %s\n' "$1" "$2"; }
pass() { say "$1" "correct"; }
fail() { say "$1" "WRONG"; _ok=1; }

selftest() {
  local work a b
  work="$(mktemp -d "${TMPDIR:-/tmp}/release-checksums-selftest.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" EXIT
  a="$work/a"; b="$work/b"

  fixture "$a"
  cmd_write "$a" --expect 4 >/dev/null

  # 1. exact bytes: order, two-space separator, bare names, known hashes.
  if diff -u <(expected_sums) "$a/$SUMS" >/dev/null; then
    pass "the file is exactly the four known hashes, in byte order"
  else
    fail "the file is exactly the four known hashes, in byte order"
    diff -u <(expected_sums) "$a/$SUMS" | sed 's/^/      /' || true
  fi

  # 2. bare names. Asserted separately from the bytes because it is the property that
  #    decides whether `sha256sum -c` works at all in the consumer's download directory,
  #    and a future change to the fixture must not be able to quietly lose it.
  if grep -q '/' "$a/$SUMS"; then
    fail "no path separator anywhere in the list"
  else
    pass "no path separator anywhere in the list"
  fi

  # 3. `sha256sum -c` in that directory, which is the consumer's command.
  if ( cd "$a" && sha256sum -c --quiet -- "$SUMS" >/dev/null 2>&1 ); then
    pass "sha256sum -c passes on the assets it was written from"
  else
    fail "sha256sum -c passes on the assets it was written from"
  fi

  # 4. the other direction: one byte changed in one asset.
  printf 'X' >> "$a/lyxbosa-linux-amd64"
  local out rc
  out="$( cd "$a" && sha256sum -c -- "$SUMS" 2>&1 )" && rc=0 || rc=$?
  if [ "$rc" -ne 0 ]; then
    pass "sha256sum -c fails after a one-byte change"
  else
    fail "sha256sum -c fails after a one-byte change"
  fi
  if printf '%s' "$out" | grep -q 'lyxbosa-linux-amd64: FAILED'; then
    pass "...and it names the asset that changed"
  else
    fail "...and it names the asset that changed"
  fi
  printf 'abc' > "$a/lyxbosa-linux-amd64"

  # 5. the same bytes, created in a different order, produce the same file. This is the
  #    reproducibility claim, tested rather than asserted: b writes its four files in the
  #    reverse order and in a different directory.
  mkdir -p "$b"
  printf 'z\n' > "$b/lyxbosa-linux-arm64"
  printf 'a'   > "$b/lyxbosa-windows-amd64.exe"
  printf 'abc' > "$b/lyxbosa-linux-amd64"
  printf ''    > "$b/lyxbosa-windows-arm64.exe"
  cmd_write "$b" >/dev/null
  if cmp -s "$a/$SUMS" "$b/$SUMS"; then
    pass "same assets, different creation order, identical file"
  else
    fail "same assets, different creation order, identical file"
  fi

  # 6. self-exclusion, on the second run - the first cannot list a file that does not exist
  #    yet, so a check that only ever ran once would pass while being blind.
  cmd_write "$a" --expect 4 >/dev/null
  if grep -q "  $SUMS\$" "$a/$SUMS"; then
    fail "a second run does not list $SUMS in itself"
  else
    pass "a second run does not list $SUMS in itself"
  fi
  if cmp -s "$a/$SUMS" "$b/$SUMS"; then
    pass "...and re-running over its own output changes nothing"
  else
    fail "...and re-running over its own output changes nothing"
  fi

  # 7. the signature is excluded too. It is written after the list, so a list naming it
  #    could never be true, and `sha256sum -c` would report it FAILED for every consumer.
  printf 'not a real signature\n' > "$a/$SIG"
  cmd_write "$a" --expect 4 >/dev/null
  if grep -q "  $SIG\$" "$a/$SIG" 2>/dev/null || grep -q "  $SIG\$" "$a/$SUMS"; then
    fail "$SIG is not listed either"
  else
    pass "$SIG is not listed either"
  fi
  rm -f "$a/$SIG"

  # 8. a subdirectory is not an asset. download-artifact without merge-multiple leaves one
  #    directory per artifact, and hashing a directory is an error, not a checksum.
  mkdir -p "$a/lyxbosa-linux-amd64-dir"
  if ( cmd_write "$a" --expect 4 >/dev/null 2>&1 ); then
    pass "a subdirectory beside the assets is ignored"
  else
    fail "a subdirectory beside the assets is ignored"
  fi
  rmdir "$a/lyxbosa-linux-amd64-dir"

  # 9. an empty directory is refused rather than written empty. An empty SHA256SUMS passes
  #    `sha256sum -c` - zero lines, zero failures - which is the "no findings reads as
  #    green" shape this repository has already been bitten by.
  mkdir -p "$work/empty"
  if ( cmd_write "$work/empty" >/dev/null 2>&1 ); then
    fail "an empty directory is refused"
  else
    pass "an empty directory is refused"
  fi
  if [ -e "$work/empty/$SUMS" ]; then
    fail "...and nothing was written"
  else
    pass "...and nothing was written"
  fi

  # 10. --expect, both directions. The count that matters is the one that is wrong.
  if ( cmd_write "$a" --expect 4 >/dev/null 2>&1 ); then
    pass "--expect 4 accepts four assets"
  else
    fail "--expect 4 accepts four assets"
  fi
  if ( cmd_write "$a" --expect 5 >/dev/null 2>&1 ); then
    fail "--expect 5 refuses four assets"
  else
    pass "--expect 5 refuses four assets"
  fi

  # 11. the ordering itself, fed a scrambled list directly rather than through a directory.
  #     Deterministic: it does not depend on what order a filesystem hands back. Mixed case
  #     is the point - C sorts every uppercase name before every lowercase one, an en_US
  #     collation interleaves them, and two runners must not disagree.
  local got want
  got="$(printf '%s\n' lyxbosa-linux-arm64 SHA256SUMS.txt lyxbosa-linux-amd64 Lyxbosa.exe \
         | sort_names | tr '\n' ' ')"
  want="Lyxbosa.exe SHA256SUMS.txt lyxbosa-linux-amd64 lyxbosa-linux-arm64 "
  if [ "$got" = "$want" ]; then
    pass "a scrambled, mixed-case list sorts into byte order"
  else
    fail "a scrambled, mixed-case list sorts into byte order"
    say "  got: $got" ""
  fi

  # 11b. that the collation is PINNED rather than inherited. This one is asserted on the
  #      source and not observed, and the distinction is the point: dropping `LC_ALL=C` and
  #      leaving a bare `sort` behaves identically on any machine whose only locales are C
  #      variants, which is this one and may well be the runner. A control that cannot fire
  #      here would report green forever, so it says what it is instead of pretending.
  if declare -f sort_names | grep -q 'LC_ALL=C'; then
    say "the sort pins LC_ALL=C (asserted on the source, not observed)" "correct"
  else
    fail "the sort pins LC_ALL=C (asserted on the source, not observed)"
  fi

  # 12. and the real path sorts what it enumerates. This case states its own power: if the
  #     filesystem happened to hand the names back already sorted it proves nothing, and it
  #     says so rather than reporting a pass.
  local raw
  raw="$(enumerate_assets "$a" | tr '\n' ' ')"
  if [ "$raw" = "$(enumerate_assets "$a" | sort_names | tr '\n' ' ')" ]; then
    say "directory order was already sorted - case 12 proves nothing here" "NOT EXERCISED"
  elif [ "$(asset_names "$a" | tr '\n' ' ')" = "$(printf '%s\n' "${FIXTURE_NAMES[@]}" | sort_names | tr '\n' ' ')" ]; then
    pass "the write path sorts the directory order it was handed"
  else
    fail "the write path sorts the directory order it was handed"
  fi

  echo
  if [ $_ok -eq 0 ]; then
    echo "controls: the list is exactly right, and every way of being wrong was caught"
  else
    echo "controls: AT LEAST ONE CONTROL FAILED"
  fi
  return $_ok
}

case "${1:-}" in
  write)      shift; cmd_write "$@" ;;
  --selftest) selftest ;;
  *) echo "usage: release-checksums.sh write <dir> [--expect N] | --selftest" >&2; exit 2 ;;
esac
