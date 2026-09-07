#!/usr/bin/env bash
# Build a corpus shard.
#
# §7 specifies .tar.zst. zstd is REQUIRED and its absence is a hard failure, not a reason to
# fall back to another format: a format decision should not be rewritten by a missing
# dependency, and a silent fallback is how two artefacts that claim to be the same thing stop
# being the same thing. Same standard fetch-benign.sh applies to jq and sha256sum.
#
# THE BUILD IS REPRODUCIBLE, AND IT WAS NOT
# ------------------------------------------
# A stranger fetching a shard and a person rebuilding it must get the same bytes, or the
# sha256 in a release note certifies nothing. `tar -cf - .` gave neither:
#
#   * member ORDER was readdir order. Rebuilt from an extraction of the shipped archives,
#     all eight differed from what shipped - same bytes, same mtimes, same ownership, same
#     permissions, different order. Sorted order is not even the order that shipped: the
#     shipped archives carry samples/ before carriers/ before MANIFEST.json, which is a
#     directory's creation order and nothing else.
#   * MTIMES were whatever the staging pass happened to leave. Control: identical bytes with
#     one file touched produced a different archive hash.
#   * OWNERSHIP was the building user's name and numeric id.
#   * PERMISSIONS were inconsistent across shards that shipped from the same script - 117 of
#     142 samples at 0400, 25 at 0644 across three shards. That is stage state, not a
#     decision, and it lands in the archive bytes either way.
#
# `--sort=name`, a pinned `--mtime`, `--owner=0 --group=0 --numeric-owner` and a normalised
# permission set remove all four. `--selftest` is the control and asserts they are removed:
# it builds the same content twice through perturbed mtimes, ownership-visible order and
# permissions, and requires one hash.
#
# SOURCE_DATE_EPOCH pins the timestamp. It defaults to 0 rather than to `now`, because a
# default that moves is the defect this is fixing.
#
# Usage: corpus/build-shard.sh <stage-dir> <shard-name>
#        corpus/build-shard.sh --selftest
set -euo pipefail

for tool in zstd tar sha256sum; do
  command -v "$tool" >/dev/null || {
    echo "error: required tool '$tool' not found" >&2
    [ "$tool" = zstd ] && echo "       install it: sudo apt install zstd" >&2
    exit 1
  }
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${SHARD_PASSPHRASE:=infected}"
: "${SOURCE_DATE_EPOCH:=0}"

# tar's reproducibility flags, in one place so the selftest cannot drift from the build.
# --sort=name needs GNU tar 1.28+; it is checked rather than assumed, because without it
# this script silently goes back to emitting readdir order.
tar --sort=name --version >/dev/null 2>&1 || {
  echo "error: this tar does not support --sort=name (needs GNU tar 1.28+)" >&2
  echo "       without it the member order is readdir order and the build is not reproducible" >&2
  exit 1
}
TAR_REPRO=(--sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH")

# Normalise into a scratch copy rather than in place: a build step that chmods the caller's
# staging tree changes the thing it was asked to read, and the next run would be measuring
# the previous one.
#
# 0400 on every file is the convention 5 of the 8 shipped shards already used and the one §7
# argues for - the corpus is live malware and nothing here should be executable or casually
# editable after extraction. Directories keep 0755 so the tree can be walked.
build_tar() {
  local stage="$1" out="$2" work
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN
  cp -a "$stage/." "$work/"
  find "$work" -type d -exec chmod 0755 {} +
  find "$work" -type f -exec chmod 0400 {} +
  tar -C "$work" "${TAR_REPRO[@]}" -cf - . | zstd -19 -q -o "$out" -f
}

selftest() {
  local work a b rc=0
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN
  # Two stages with identical CONTENT and deliberately different everything else.
  for v in one two; do
    mkdir -p "$work/$v/samples" "$work/$v/carriers"
    printf '<?php eval($_POST[0]);' > "$work/$v/samples/a.php"
    printf 'GIF89a' > "$work/$v/carriers/c.gif"
    printf '[{"file":"samples/a.php"}]' > "$work/$v/MANIFEST.json"
  done
  # Perturb stage "two": different mtimes and different permissions on every member.
  find "$work/two" -exec touch -d '2019-03-04T05:06:07' {} +
  chmod 0644 "$work/two/samples/a.php"
  chmod 0666 "$work/two/carriers/c.gif"
  chmod 0700 "$work/two/samples"
  build_tar "$work/one" "$work/one.tar.zst"
  build_tar "$work/two" "$work/two.tar.zst"
  a="$(sha256sum "$work/one.tar.zst" | cut -d' ' -f1)"
  b="$(sha256sum "$work/two.tar.zst" | cut -d' ' -f1)"
  if [ "$a" = "$b" ]; then
    echo "  mtimes, permissions and stage identity do not reach the archive   caught"
  else
    echo "  mtimes, permissions and stage identity do not reach the archive   MISSED"
    rc=1
  fi
  # The other direction: a real content change MUST change the hash, or the normalisation
  # above would be flattening the payload rather than the metadata.
  printf 'x' >> "$work/two/samples/a.php"
  build_tar "$work/two" "$work/two-changed.tar.zst"
  if [ "$(sha256sum "$work/two-changed.tar.zst" | cut -d' ' -f1)" != "$b" ]; then
    echo "  a one-byte content change still changes the archive               correct"
  else
    echo "  a one-byte content change still changes the archive               WRONG"
    rc=1
  fi
  # And member order must be sorted, not readdir order.
  if [ "$(zstd -dc "$work/one.tar.zst" | tar -tf - | sed 's|^\./||' | grep -v '^$' | sort -c && echo sorted)" = "sorted" ]; then
    echo "  members are emitted in sorted order                               correct"
  else
    echo "  members are emitted in sorted order                               WRONG"
    rc=1
  fi
  # The zip's non-reproducibility is a measured property, not an assumption, so it is
  # asserted here too: if a future zip ever DOES reproduce, this line says so and the
  # comment above needs rewriting rather than quietly becoming false.
  if command -v zip >/dev/null; then
    local z1 z2
    touch -d "@$SOURCE_DATE_EPOCH" "$work/one.tar.zst"
    TZ=UTC zip -q -X -P "$SHARD_PASSPHRASE" -j "$work/z1.zip" "$work/one.tar.zst"
    TZ=UTC zip -q -X -P "$SHARD_PASSPHRASE" -j "$work/z2.zip" "$work/one.tar.zst"
    z1="$(sha256sum "$work/z1.zip" | cut -d' ' -f1)"
    z2="$(sha256sum "$work/z2.zip" | cut -d' ' -f1)"
    if [ "$z1" != "$z2" ]; then
      echo "  the encrypted .zip does NOT reproduce (ZipCrypto random header)     as documented"
    else
      echo "  the encrypted .zip reproduced - the comment above is now wrong       REVIEW"
      rc=1
    fi
  fi
  [ $rc -eq 0 ] && echo "controls: the .tar.zst is reproducible; the .zip is not, by construction" \
                || echo "controls: AT LEAST ONE CONTROL MISSED"
  return $rc
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
  exit $?
fi

STAGE="${1:?usage: build-shard.sh <stage-dir> <shard-name>  |  build-shard.sh --selftest}"
NAME="${2:?usage: build-shard.sh <stage-dir> <shard-name>  |  build-shard.sh --selftest}"
OUT="$HERE/shards"

[ -d "$STAGE" ] || { echo "error: stage dir not found: $STAGE" >&2; exit 1; }
[ -f "$STAGE/MANIFEST.json" ] || { echo "error: stage has no MANIFEST.json" >&2; exit 1; }
mkdir -p "$OUT"

build_tar "$STAGE" "$OUT/$NAME.tar.zst"
echo "built  $OUT/$NAME.tar.zst  ($(stat -c%s "$OUT/$NAME.tar.zst") bytes)"

# §7.1: the passphrase stops AV and repository scanners flagging the archive. It is NOT
# confidentiality - CI must be able to open it, so anyone can. Masking is the control.
#
# THE .zip IS NOT REPRODUCIBLE AND CANNOT BE MADE SO. Measured: three encrypted zips of one
# byte-identical input, built one after another with -X and a pinned mtime, gave three
# hashes; the same three runs without -P gave one. ZipCrypto prefixes each entry with a
# 12-byte randomised encryption header, so the bytes differ by construction and no flag
# removes it.
#
# That is acceptable only because of what the wrapper is for (§7.1: AV noise, not
# confidentiality) and it decides which hash a release note may quote: **the .tar.zst hash
# is the one that certifies anything.** A consumer verifies the shard by unwrapping the zip
# and hashing the .tar.zst inside it, which reproduces; hashing the .zip proves only that
# the file arrived intact from one particular upload.
#
# -X and the pinned mtime stay: they remove the two sources of drift that are removable, so
# the residue is exactly the encryption header and nothing else has to be argued about.
if command -v zip >/dev/null; then
  rm -f "$OUT/$NAME.tar.zst.zip"
  touch -d "@$SOURCE_DATE_EPOCH" "$OUT/$NAME.tar.zst"
  TZ=UTC zip -q -X -P "$SHARD_PASSPHRASE" -j "$OUT/$NAME.tar.zst.zip" "$OUT/$NAME.tar.zst"
  echo "wrapped $OUT/$NAME.tar.zst.zip (passphrase is public by design; see SOURCES.md §7.1)"
else
  echo "note: zip not found, skipping the AV-noise wrapper" >&2
fi
sha256sum "$OUT/$NAME".tar.zst*
