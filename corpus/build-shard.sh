#!/usr/bin/env bash
# Build a corpus shard.
#
# §7 specifies .tar.zst. zstd is REQUIRED and its absence is a hard failure, not a reason to
# fall back to another format: a format decision should not be rewritten by a missing
# dependency, and a silent fallback is how two artefacts that claim to be the same thing stop
# being the same thing. Same standard fetch-benign.sh applies to jq and sha256sum.
#
# Usage: corpus/build-shard.sh <stage-dir> <shard-name>
set -euo pipefail

for tool in zstd tar sha256sum; do
  command -v "$tool" >/dev/null || {
    echo "error: required tool '$tool' not found" >&2
    [ "$tool" = zstd ] && echo "       install it: sudo apt install zstd" >&2
    exit 1
  }
done

STAGE="${1:?usage: build-shard.sh <stage-dir> <shard-name>}"
NAME="${2:?usage: build-shard.sh <stage-dir> <shard-name>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/shards"
: "${SHARD_PASSPHRASE:=infected}"

[ -d "$STAGE" ] || { echo "error: stage dir not found: $STAGE" >&2; exit 1; }
[ -f "$STAGE/MANIFEST.json" ] || { echo "error: stage has no MANIFEST.json" >&2; exit 1; }
mkdir -p "$OUT"

tar -C "$STAGE" -cf - . | zstd -19 -q -o "$OUT/$NAME.tar.zst" -f
echo "built  $OUT/$NAME.tar.zst  ($(stat -c%s "$OUT/$NAME.tar.zst") bytes)"

# §7.1: the passphrase stops AV and repository scanners flagging the archive. It is NOT
# confidentiality - CI must be able to open it, so anyone can. Masking is the control.
if command -v zip >/dev/null; then
  rm -f "$OUT/$NAME.tar.zst.zip"
  zip -q -P "$SHARD_PASSPHRASE" -j "$OUT/$NAME.tar.zst.zip" "$OUT/$NAME.tar.zst"
  echo "wrapped $OUT/$NAME.tar.zst.zip (passphrase is public by design; see SOURCES.md §7.1)"
else
  echo "note: zip not found, skipping the AV-noise wrapper" >&2
fi
sha256sum "$OUT/$NAME".tar.zst*
