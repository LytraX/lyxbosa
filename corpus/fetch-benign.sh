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
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK="$HERE/benign/sources.jsonl"
DEST="${1:-$(cd "$HERE/.." && pwd)/trail-data/CMS-ext}"
ARCHIVES="$DEST/_archives"
: "${VERIFY_ONLY:=0}"

command -v jq >/dev/null || { echo "error: jq is required" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "error: sha256sum is required" >&2; exit 1; }
[ -f "$LOCK" ] || { echo "error: lockfile not found: $LOCK" >&2; exit 1; }

mkdir -p "$ARCHIVES"
ok=0; failed=0; skipped=0

while IFS=$'\t' read -r name kind version url want size; do
  file="$ARCHIVES/${name}-${version}.zip"

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
  if ! unzip -qq -o "$file" -d "$out"; then
    echo "FAILED   $name $version (unpack)" >&2; failed=$((failed+1)); continue
  fi
  ok=$((ok+1))
done < <(jq -r '[.name,.kind,.version,.url,.sha256,(.size|tostring)] | @tsv' "$LOCK")

echo
echo "verified $ok, already unpacked $skipped, failed $failed"
[ "$failed" -eq 0 ] || exit 1
