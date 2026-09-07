#!/usr/bin/env bash
# Prepare and verify the release assets for a corpus tag. Derives the checksum file in the
# SAME run that verifies it, and never reads one written earlier.
#
# WHY THAT IS THE WHOLE POINT
# ----------------------------
# A release note quoting a hash from a list somebody generated in a previous round certifies
# the previous round. This repository has already published a figure taken on the wrong side
# of a write, and the shard hashes are the version of that mistake that a stranger would
# inherit: every one of the eight changed when the shards were rebuilt reproducibly, and two
# changed again when a sample was dropped. A stale SHA256SUMS would have been internally
# consistent and wrong about every file.
#
# So there is no stored list. `--verify` recomputes each inner `.tar.zst` hash from the file
# on disk, unwraps each `.zip` into a temp directory and asserts the tar inside it is the
# same file, rebuilds each shard from its own extracted contents and asserts the rebuild is
# byte-identical, and only then writes SHA256SUMS. If any of that fails, no list is written.
#
# WHAT IS CHECKSUMMED, AND WHY IT IS NOT THE .zip
# ------------------------------------------------
# The `.tar.zst` is reproducible; the `.zip` is not and cannot be. ZipCrypto prefixes every
# entry with a randomised 12-byte encryption header, so wrapping one byte-identical input
# twice gives two hashes. A `.zip` hash attests that one upload arrived intact and nothing
# more, so the list covers the inner tars - which is also what a consumer can re-derive.
#
# Usage:
#   corpus/release-assets.sh --verify            check everything, write SHA256SUMS
#   corpus/release-assets.sh --selftest          controls, then exit
#   corpus/release-assets.sh --print-upload TAG  the gh command, printed and never run
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARDS="$HERE/shards"
: "${SHARD_PASSPHRASE:=infected}"
: "${SOURCE_DATE_EPOCH:=0}"

for tool in zstd tar sha256sum unzip; do
  command -v "$tool" >/dev/null || { echo "error: required tool '$tool' not found" >&2; exit 1; }
done

# The same recipe build-shard.sh uses, restated here ONLY to rebuild for comparison. It is
# deliberately not sourced: this is an independent re-derivation, and a check that calls the
# thing it is checking proves that the thing agrees with itself.
# Cleanup is one EXIT trap over a list rather than a `trap ... RETURN` per function. A
# RETURN trap set inside a function survives into its caller, and `selftest` calls `verify`
# four times - which under `set -u` fired the caller's return on an unset variable and made
# a green control run exit non-zero. Found by the controls, which is what they are for.
# `scratch` assigns to a global instead of printing, because `d="$(scratch)"` runs the
# function in a SUBSHELL and the array append is lost with it - which left the list empty,
# every temp directory on disk, and `_cleanup` exiting non-zero on the empty expansion. A
# control run in which every case passed still exited 1, which is how it was found.
_SCRATCH=()
_LAST_SCRATCH=""
_cleanup() {
  local d
  for d in ${_SCRATCH+"${_SCRATCH[@]}"}; do
    [ -n "$d" ] && rm -rf "$d"
  done
  return 0
}
trap _cleanup EXIT

scratch() {
  _LAST_SCRATCH="$(mktemp -d)"
  _SCRATCH+=("$_LAST_SCRATCH")
}

rebuild() {
  local stage="$1" out="$2" work
  work="$(mktemp -d)"
  cp -a "$stage/." "$work/"
  find "$work" -type d -exec chmod 0755 {} +
  find "$work" -type f -exec chmod 0400 {} +
  tar -C "$work" --sort=name --owner=0 --group=0 --numeric-owner \
      --mtime="@$SOURCE_DATE_EPOCH" -cf - . | zstd -19 -q -o "$out" -f
  rm -rf "$work"
}

verify() {
  local rc=0 tmp
  scratch; tmp="$_LAST_SCRATCH"
  local lines=()
  local n=0

  shopt -s nullglob
  for tar in "$SHARDS"/*.tar.zst; do
    n=$((n + 1))
    local name h zip zh
    name="$(basename "$tar")"
    h="$(sha256sum "$tar" | cut -d' ' -f1)"

    # 1. the .zip must contain exactly this file.
    zip="$tar.zip"
    if [ ! -f "$zip" ]; then
      echo "  $(printf '%-34s' "${name%.tar.zst}") NO ZIP WRAPPER" >&2
      rc=1
      continue
    fi
    mkdir -p "$tmp/unz/$name"
    unzip -q -o -P "$SHARD_PASSPHRASE" "$zip" -d "$tmp/unz/$name"
    zh="$(sha256sum "$tmp/unz/$name/$name" | cut -d' ' -f1)"
    if [ "$zh" != "$h" ]; then
      echo "  $(printf '%-34s' "${name%.tar.zst}") ZIP HOLDS DIFFERENT BYTES ${zh:0:12} != ${h:0:12}" >&2
      rc=1
      continue
    fi

    # 2. it must rebuild to itself from its own contents. That is the property the
    #    checksum is worth quoting for: a consumer can re-derive it.
    mkdir -p "$tmp/stage/$name"
    zstd -dc "$tar" | tar -x -C "$tmp/stage/$name"
    rebuild "$tmp/stage/$name" "$tmp/rebuilt-$name"
    local rh
    rh="$(sha256sum "$tmp/rebuilt-$name" | cut -d' ' -f1)"
    if [ "$rh" != "$h" ]; then
      echo "  $(printf '%-34s' "${name%.tar.zst}") DOES NOT REPRODUCE ${rh:0:12} != ${h:0:12}" >&2
      rc=1
      continue
    fi

    echo "  $(printf '%-34s' "${name%.tar.zst}") ${h:0:12}  zip holds it · rebuilds to it"
    lines+=("$h  $name")
  done
  shopt -u nullglob

  if [ "$n" -eq 0 ]; then
    echo "error: no shards in $SHARDS" >&2
    return 1
  fi
  if [ $rc -ne 0 ]; then
    echo >&2
    echo "REFUSING to write SHA256SUMS: $n shard(s) examined and at least one failed." >&2
    return 1
  fi
  printf '%s\n' "${lines[@]}" > "$SHARDS/SHA256SUMS"
  echo
  echo "wrote $SHARDS/SHA256SUMS  ($n inner .tar.zst, hashed in this run)"
  return 0
}

selftest() {
  local work rc=0
  scratch; work="$_LAST_SCRATCH"
  # A shard-shaped tree, wrapped correctly, must verify; and each of the three ways it can
  # be wrong must be caught. Without these the verify path could return success forever.
  mkdir -p "$work/s/samples"
  printf '<?php eval($_POST[0]);' > "$work/s/samples/a.php"
  printf '[{"file":"samples/a.php"}]' > "$work/s/MANIFEST.json"
  local OLD="$SHARDS"
  SHARDS="$work/out"; mkdir -p "$SHARDS"
  rebuild "$work/s" "$SHARDS/t.tar.zst"
  ( cd "$SHARDS" && TZ=UTC zip -q -X -P "$SHARD_PASSPHRASE" t.tar.zst.zip t.tar.zst )

  if verify >/dev/null 2>&1; then
    echo "  a correctly wrapped, reproducible shard verifies                  correct"
  else
    echo "  a correctly wrapped, reproducible shard verifies                  WRONG"; rc=1
  fi
  if [ -f "$SHARDS/SHA256SUMS" ] \
     && [ "$(cut -d' ' -f1 < "$SHARDS/SHA256SUMS")" = "$(sha256sum "$SHARDS/t.tar.zst" | cut -d' ' -f1)" ]; then
    echo "  the list it wrote is the hash of the file on disk                 correct"
  else
    echo "  the list it wrote is the hash of the file on disk                 WRONG"; rc=1
  fi

  # (a) the zip holds something else.
  rm -f "$SHARDS/SHA256SUMS"
  cp "$SHARDS/t.tar.zst" "$work/keep.tar.zst"
  printf 'x' >> "$SHARDS/t.tar.zst"
  if verify >/dev/null 2>&1; then
    echo "  a zip holding different bytes than the tar beside it              MISSED"; rc=1
  else
    echo "  a zip holding different bytes than the tar beside it              caught"
  fi
  [ -f "$SHARDS/SHA256SUMS" ] && { echo "  ...and no list was written                                       MISSED"; rc=1; } \
                              || echo "  ...and no list was written                                       correct"
  cp "$work/keep.tar.zst" "$SHARDS/t.tar.zst"

  # (b) no wrapper at all.
  mv "$SHARDS/t.tar.zst.zip" "$work/away.zip"
  if verify >/dev/null 2>&1; then
    echo "  a shard with no zip wrapper                                       MISSED"; rc=1
  else
    echo "  a shard with no zip wrapper                                       caught"
  fi
  mv "$work/away.zip" "$SHARDS/t.tar.zst.zip"

  # (c) a tar that does not rebuild to itself - built the OLD way, with real mtimes and
  #     the building user's ownership, which is exactly how all eight shipped before.
  rm -f "$SHARDS/SHA256SUMS"
  tar -C "$work/s" -cf - . | zstd -19 -q -o "$SHARDS/t.tar.zst" -f
  rm -f "$SHARDS/t.tar.zst.zip"
  ( cd "$SHARDS" && TZ=UTC zip -q -X -P "$SHARD_PASSPHRASE" t.tar.zst.zip t.tar.zst )
  if verify >/dev/null 2>&1; then
    echo "  a tar that does not rebuild to its own bytes                      MISSED"; rc=1
  else
    echo "  a tar that does not rebuild to its own bytes                      caught"
  fi

  SHARDS="$OLD"
  [ $rc -eq 0 ] && echo "controls: every planted defect was caught, and the good case still passes" \
                || echo "controls: AT LEAST ONE CONTROL MISSED"
  return $rc
}

case "${1:-}" in
  --selftest)
    selftest
    ;;
  --verify)
    echo "=== each shard: hashed now, not read from a list ==="
    verify
    ;;
  --print-upload)
    TAG="${2:?usage: --print-upload <tag>}"
    HEAD_SHA="$(git rev-parse HEAD)"
    # Read from the API rather than assumed: there is no repo-level 'latest' pin to check,
    # so what a new release would displace is whatever GitHub computes today.
    LATEST_TAG="$(gh api repos/:owner/:repo/releases/latest --jq .tag_name 2>/dev/null \
                  || echo '(could not read; check before publishing)')"
    # Printed, never run. Creating a release is irreversible in the way that matters: an
    # asset can be fetched, cached and indexed within minutes of going up, and this
    # repository's own history records that deleting the objects afterwards did not remove
    # them. So the tool that prepares the assets does not publish them.
    echo "# 1. Re-derive and verify. This writes SHA256SUMS from the artefacts as they are;"
    echo "#    a list from an earlier round would certify the earlier round."
    echo "corpus/release-assets.sh --verify"
    echo
    echo "# 2. Its own tag, on the commit that produced these bytes - never retrofitted onto"
    echo "#    a scanner release, which would change what an already-published release holds."
    echo "#    The commit is named rather than implied: 'git tag -a $TAG' alone tags whatever"
    echo "#    HEAD happens to be, and the tag has to name the index state that was gated."
    echo "git tag -a $TAG -m 'LyxBoSa malware corpus, $TAG' $HEAD_SHA"
    echo "git push origin $TAG"
    echo
    echo "# 3. Upload the wrappers plus the checksum file of the inner tars."
    echo "#"
    echo "#    --latest=false is REQUIRED, not tidiness. GitHub has no repository setting for"
    echo "#    which release is latest; it computes it per release, and every existing release"
    echo "#    here is draft=false prerelease=false, so a release created today takes the"
    echo "#    label from $LATEST_TAG. /releases/latest is what a stranger and most install"
    echo "#    scripts fetch, and it would hand them malware shards instead of the scanner."
    echo "#"
    echo "#    --verify-tag makes step 3 depend on step 2 having worked. Without it, a typo in"
    echo "#    the tag name creates a SECOND tag and a release nobody meant to publish, and a"
    echo "#    published release is the one thing here that cannot be taken back."
    echo "gh release create $TAG \\"
    echo "  --latest=false \\"
    echo "  --verify-tag \\"
    echo "  --title '$TAG' \\"
    echo "  --notes-file docs/corpus-release-notes.md \\"
    echo "  corpus/shards/SHA256SUMS \\"
    files=()
    shopt -s nullglob
    for z in "$SHARDS"/*.tar.zst.zip; do files+=("corpus/shards/$(basename "$z")"); done
    shopt -u nullglob
    last=$(( ${#files[@]} - 1 ))
    for i in "${!files[@]}"; do
      if [ "$i" -eq "$last" ]; then echo "  ${files[$i]}"
      else echo "  ${files[$i]} \\"; fi
    done
    ;;
  *)
    echo "usage: release-assets.sh --verify | --selftest | --print-upload <tag>" >&2
    exit 2
    ;;
esac
