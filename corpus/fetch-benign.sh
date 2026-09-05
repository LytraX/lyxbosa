#!/usr/bin/env bash
# Fetch and verify the pinned benign corpus.
#
# Reads corpus/benign/sources.jsonl, downloads each entry, checks its sha256 against the
# lockfile, and unpacks it. The downloads are NOT committed: the lockfile plus this script
# are what make the benign half reproducible, which is what turns "it worked on my server"
# into a number someone else can regenerate.
#
# Usage:
#   corpus/fetch-benign.sh [DEST]        default DEST: trail-data/CMS-ext
#   VERIFY_ONLY=1 corpus/fetch-benign.sh # re-check hashes of what is already downloaded
#   corpus/fetch-benign.sh --inject      # positive control, see below
#
# THE ARCHIVE FORMAT COMES FROM THE URL, AND AN UNKNOWN ONE IS A HARD FAILURE
# ---------------------------------------------------------------------------
# Every source was a wordpress.org .zip until rendered page content had to be pinned, and
# the only immutable bulk source of that is a .tar.gz. The format is therefore read off the
# URL rather than added as a lockfile field, which keeps the 86 existing rows untouched -
# but a suffix this script does not recognise must FAIL rather than fall through to unzip.
# CORPUS_PLAN section 8: a silent fallback is how two artefacts that claim to be the same
# thing stop being the same thing.
#
# Dependencies are tested ONE AT A TIME and only for the formats the lockfile actually
# uses. `command -v a b c` is not an all-present test - it reported success while zstd was
# absent - and that failure is why this is written out longhand.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK="${LOCK:-$HERE/benign/sources.jsonl}"
: "${VERIFY_ONLY:=0}"

# Return the archive kind for a URL, or fail. Never guesses.
archive_kind() {
  case "$1" in
    *.zip)            echo zip ;;
    *.tar.gz|*.tgz)   echo tar.gz ;;
    *) echo "error: unrecognised archive suffix, refusing to guess: $1" >&2; return 1 ;;
  esac
}

fetch_all() {
  local DEST="$1" ARCHIVES ok failed skipped
  ARCHIVES="$DEST/_archives"

  command -v jq >/dev/null || { echo "error: jq is required" >&2; exit 1; }
  command -v sha256sum >/dev/null || { echo "error: sha256sum is required" >&2; exit 1; }
  command -v curl >/dev/null || { echo "error: curl is required" >&2; exit 1; }
  [ -f "$LOCK" ] || { echo "error: lockfile not found: $LOCK" >&2; exit 1; }

  # Only demand an unpacker for a format this lockfile actually contains.
  if jq -re 'select(.url | test("\\.zip$")) | .url' "$LOCK" >/dev/null 2>&1; then
    command -v unzip >/dev/null || { echo "error: unzip is required" >&2; exit 1; }
  fi
  if jq -re 'select(.url | test("\\.(tar\\.gz|tgz)$")) | .url' "$LOCK" >/dev/null 2>&1; then
    command -v tar >/dev/null || { echo "error: tar is required" >&2; exit 1; }
    command -v gzip >/dev/null || { echo "error: gzip is required" >&2; exit 1; }
  fi

  mkdir -p "$ARCHIVES"
  ok=0; failed=0; skipped=0

  while IFS=$'\t' read -r name kind version url want size; do
    local akind file out got
    if ! akind="$(archive_kind "$url")"; then failed=$((failed+1)); continue; fi
    file="$ARCHIVES/${name}-${version}.${akind}"

    if [ ! -f "$file" ]; then
      if [ "$VERIFY_ONLY" = "1" ]; then
        echo "MISSING  $name $version"; failed=$((failed+1)); continue
      fi
      echo "fetching $name $version"
      if ! curl -fsSL --retry 3 --retry-delay 2 -o "$file.part" "$url"; then
        echo "FAILED   $name $version (download)" >&2; failed=$((failed+1)); rm -f "$file.part"; continue
      fi
      mv "$file.part" "$file"
    fi

    got="$(sha256sum "$file" | cut -d' ' -f1)"
    if [ "$got" != "$want" ]; then
      # A hash mismatch is never "just a new version" - upstream may have been replaced.
      echo "FAILED   $name $version" >&2
      echo "         expected $want" >&2
      echo "         got      $got" >&2
      failed=$((failed+1)); continue
    fi

    if [ "$VERIFY_ONLY" = "1" ]; then ok=$((ok+1)); continue; fi

    out="$DEST/$kind/$name-$version"
    if [ -d "$out" ]; then skipped=$((skipped+1)); ok=$((ok+1)); continue; fi
    mkdir -p "$out"
    case "$akind" in
      zip)
        if ! unzip -qq -o "$file" -d "$out"; then
          echo "FAILED   $name $version (unpack)" >&2; failed=$((failed+1)); rmdir "$out" 2>/dev/null || true; continue
        fi ;;
      tar.gz)
        if ! tar xzf "$file" -C "$out"; then
          echo "FAILED   $name $version (unpack)" >&2; failed=$((failed+1)); rmdir "$out" 2>/dev/null || true; continue
        fi ;;
    esac
    ok=$((ok+1))
  done < <(jq -r '[.name,.kind,.version,.url,.sha256,(.size|tostring)] | @tsv' "$LOCK")

  echo
  echo "verified $ok, already unpacked $skipped, failed $failed"
  [ "$failed" -eq 0 ] || return 1
}

# ---------------------------------------------------------------------------------------
# Positive control.
#
# The hash gate here has never been observed to fail: every run in this project's history
# has verified 86 of 86. AGENTS.md - a check that has never been observed to fail is not
# yet a check. So --inject builds a throwaway lockfile over file:// URLs and asserts this
# script says the OTHER thing on each of five cases, including the two new tar.gz paths.
# It touches neither the real lockfile nor the real download cache.
# ---------------------------------------------------------------------------------------
inject() {
  local tmp pass fail
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/src/pkg" "$tmp/lock"
  echo "hello" > "$tmp/src/pkg/a.txt"
  (cd "$tmp/src" && zip -qr "$tmp/good.zip" pkg && tar czf "$tmp/good.tar.gz" pkg)
  cp "$tmp/good.zip" "$tmp/bad.zip"; printf 'x' | dd of="$tmp/bad.zip" bs=1 seek=3 conv=notrunc status=none
  cp "$tmp/good.tar.gz" "$tmp/bad.tar.gz"; printf 'x' | dd of="$tmp/bad.tar.gz" bs=1 seek=9 conv=notrunc status=none

  mk() { # name url-file expected-hash-file
    printf '{"kind":"control","name":"%s","note":"","sha256":"%s","size":%s,"url":"file://%s","version":"1"}\n' \
      "$1" "$(sha256sum "$3" | cut -d' ' -f1)" "$(stat -c%s "$2")" "$2"
  }
  pass=0; fail=0
  run_case() { # label lockfile want(ok|fail)
    local out rc
    set +e
    out="$(LOCK="$2" VERIFY_ONLY=0 bash "${BASH_SOURCE[0]}" "$tmp/dest-$RANDOM" 2>&1)"; rc=$?
    set -e
    if { [ "$3" = ok ] && [ $rc -eq 0 ]; } || { [ "$3" = fail ] && [ $rc -ne 0 ]; }; then
      echo "  PASS  $1"; pass=$((pass+1))
    else
      echo "  FAIL  $1 (exit $rc, wanted $3)"; echo "$out" | sed 's/^/        /'; fail=$((fail+1))
    fi
  }

  mk zip-good      "$tmp/good.zip"    "$tmp/good.zip"    > "$tmp/lock/1"
  mk zip-bad       "$tmp/bad.zip"     "$tmp/good.zip"    > "$tmp/lock/2"
  mk targz-good    "$tmp/good.tar.gz" "$tmp/good.tar.gz" > "$tmp/lock/3"
  mk targz-bad     "$tmp/bad.tar.gz"  "$tmp/good.tar.gz" > "$tmp/lock/4"
  printf '{"kind":"control","name":"weird","note":"","sha256":"%s","size":1,"url":"file://%s","version":"1"}\n' \
    "$(sha256sum "$tmp/good.zip" | cut -d' ' -f1)" "$tmp/good.rar" > "$tmp/lock/5"

  echo "fetch-benign.sh positive control"
  run_case "a zip whose hash matches verifies and unpacks"          "$tmp/lock/1" ok
  run_case "a zip whose hash does NOT match is refused"             "$tmp/lock/2" fail
  run_case "a tar.gz whose hash matches verifies and unpacks"       "$tmp/lock/3" ok
  run_case "a tar.gz whose hash does NOT match is refused"          "$tmp/lock/4" fail
  run_case "an unrecognised archive suffix is refused, not guessed" "$tmp/lock/5" fail
  echo
  echo "control: $pass passed, $fail failed"
  [ "$fail" -eq 0 ]
}

if [ "${1:-}" = "--inject" ]; then
  command -v zip >/dev/null || { echo "error: zip is required for --inject" >&2; exit 1; }
  inject; exit $?
fi

fetch_all "${1:-$(cd "$HERE/.." && pwd)/trail-data/CMS-ext}"
