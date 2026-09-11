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
CHANGELOG="$HERE/CHANGELOG.md"
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

# Is corpus/CHANGELOG.md closed out for the tag about to be cut?
#
# WHY A CHANGELOG CHECK BELONGS IN A RELEASE SCRIPT
# --------------------------------------------------
# The section for a tag is where the counts that tag's shards assert are written down: which
# shard is new, which figure moved and what moved it. A tag cannot be rewritten once it is
# pushed, and a section written afterwards is history about something already public, by
# somebody reconstructing which side of the tag each entry fell on. So the ordering is worth
# enforcing, and "close out the changelog first" written in a document is the instruction
# that has already failed - the note explaining it was in the file the second time.
#
# It gates `--print-upload` because printing is as far as this script goes by design, and a
# gate is worth exactly what the step it stands in front of is worth. The commands to tag and
# to publish come out of here; refusing to print them is refusing to cut the release.
#
# CLOSED OUT IS FOUR THINGS, EACH REFUSED BY NAME
# ------------------------------------------------
#   1. `## [<tag>] - <date>` exists, exactly once.
#   2. It has at least one entry under it. A heading with nothing beneath satisfies a check
#      for the heading and ships a release whose section says nothing - the check that
#      passes while blind.
#   3. `## Unreleased` is still above it. Rename it without opening a fresh one and the next
#      round writes into a released section, which is this defect one round later.
#   4. A `[<tag>]:` link definition exists, or the bracketed heading renders as brackets.
changelog_closed() {
  local tag="$1" rc=0 tag_re body tag_line unrel_line n
  tag_re="${tag//./\\.}"

  if [ ! -f "$CHANGELOG" ]; then
    echo "  there is no changelog at $CHANGELOG" >&2
    return 1
  fi

  n="$(command grep -c "^## \[$tag_re\] - [0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\$" "$CHANGELOG" || true)"
  if [ "$n" -eq 0 ]; then
    echo "  NO SECTION: the changelog has no '## [$tag] - <date>', so it still says" >&2
    echo "  Unreleased about whatever this tag would publish." >&2
    return 1
  fi
  if [ "$n" -ne 1 ]; then
    echo "  $n sections are headed '## [$tag]'; there can be one." >&2
    return 1
  fi

  # 2. the section is not empty.
  body="$(awk -v t="## [$tag] - " 'index($0, t) == 1 { inx = 1; next }
                                   inx && /^## / { exit }
                                   inx { print }' "$CHANGELOG")"
  # A here-string and not `printf ... | grep -q`. Under `set -o pipefail` that pipeline
  # reports the LEFT side: `grep -q` exits on the first match and closes the pipe, `printf`
  # takes SIGPIPE and exits 141, and pipefail hands back the 141. It reads as "no entries"
  # on exactly the sections big enough for printf to still be writing - which is every real
  # one. Caught by running this against the repository's own changelog; the fixture below
  # is twenty lines and won the race every time.
  if ! command grep -q '^- ' <<<"$body"; then
    echo "  EMPTY SECTION: '## [$tag]' has no entries under it." >&2
    rc=1
  fi

  # 3. a fresh Unreleased is still above it.
  # `grep -m1` rather than `grep | head -1`, for the reason above: `head` exiting first
  # SIGPIPEs grep and pipefail hands back the 141. One match each today, so it would not
  # fire yet - which is the version of this that gets found much later.
  tag_line="$(command grep -n -m1 "^## \[$tag_re\] - " "$CHANGELOG" | cut -d: -f1)"
  unrel_line="$(command grep -n -m1 '^## Unreleased$' "$CHANGELOG" | cut -d: -f1 || true)"
  if [ -z "$unrel_line" ] || [ "$unrel_line" -gt "$tag_line" ]; then
    echo "  NO UNRELEASED: there is no '## Unreleased' heading above '## [$tag]', so the" >&2
    echo "  next round has nowhere to write and lands inside a released section." >&2
    rc=1
  fi

  # 4. the bracketed heading resolves.
  if ! command grep -q "^\[$tag_re\]: " "$CHANGELOG"; then
    echo "  NO LINK: no '[$tag]:' definition at the foot, so the heading renders as" >&2
    echo "  literal brackets." >&2
    rc=1
  fi

  return $rc
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

  # --- the changelog gate ---------------------------------------------------------
  # Five ways to be not closed out. Each must be caught AND must say which one, because a
  # function that returned 1 unconditionally would pass every refusal case here and refuse
  # every real release. The good case is asserted first and again last, so a refusal that
  # crept in is the failure and not the silence.
  local OLDCL="$CHANGELOG" T="corpus-2026.09.9" good="$work/good.md"
  cat > "$good" <<'EOF'
# Corpus changelog

## Unreleased

### Fixed

- **Something that landed after the tag.** Words.

## [corpus-2026.09.9] - 2026-09-14

### Added

- **Something the tag published.** Words.

## [corpus-2026.09.1] - 2026-09-07

### Added

- **Earlier.** Words.

---

[Unreleased]: https://example.invalid/compare/corpus-2026.09.9...HEAD
[corpus-2026.09.9]: https://example.invalid/compare/corpus-2026.09.1...corpus-2026.09.9
[corpus-2026.09.1]: https://example.invalid/releases/tag/corpus-2026.09.1
EOF

  _cl_case() {  # label, expected reason ('' = must pass), changelog, tag
    local label="$1" want="$2" out
    CHANGELOG="$3"
    if out="$(changelog_closed "$4" 2>&1)"; then
      if [ -z "$want" ]; then echo "  $(printf '%-64s' "$label") correct"
      else echo "  $(printf '%-64s' "$label") MISSED"; rc=1; fi
    elif [ -z "$want" ]; then
      echo "  $(printf '%-64s' "$label") WRONG, refused a closed changelog"; rc=1
    elif [[ "$out" == *"$want"* ]]; then
      echo "  $(printf '%-64s' "$label") caught"
    else
      echo "  $(printf '%-64s' "$label") caught, BUT NOT BY THE STATED RULE"; rc=1
    fi
  }

  echo
  _cl_case "a changelog closed out for the tag is accepted" "" "$good" "$T"

  # And against the repository's OWN changelog, which is the case a fixture cannot stand in
  # for. The fixture above is twenty lines; the real sections are several hundred, and the
  # emptiness test read every one of them as empty until that was fixed. A good case small
  # enough to win a race has not been observed. The tag is read out of the file rather than
  # named here, so this does not need editing at each release.
  local real_tag
  real_tag="$(command grep -m1 -o '^## \[[^]]*\] - [0-9][0-9-]*' "$OLDCL" \
              | sed 's/^## \[//; s/\] - .*//' || true)"
  if [ -n "$real_tag" ]; then
    _cl_case "corpus/CHANGELOG.md itself, closed out for $real_tag" "" "$OLDCL" "$real_tag"
  else
    echo "  $(printf '%-64s' "corpus/CHANGELOG.md carries a closed section") WRONG, none found"
    rc=1
  fi

  command grep -v "^## \[$T\] - " "$good"                  > "$work/nosection.md"
  _cl_case "the tag's work still sitting under Unreleased" \
           "NO SECTION" "$work/nosection.md" "$T"

  command grep -v '^- \*\*Something the tag published\.\*\*' "$good" > "$work/empty.md"
  _cl_case "a heading closed over an empty section" \
           "EMPTY SECTION" "$work/empty.md" "$T"

  command grep -v '^## Unreleased$' "$good"                > "$work/nounrel.md"
  _cl_case "Unreleased renamed without a fresh one opened above" \
           "NO UNRELEASED" "$work/nounrel.md" "$T"

  command grep -v "^\[$T\]: " "$good"                      > "$work/nolink.md"
  _cl_case "a bracketed heading with no link to resolve to" \
           "NO LINK" "$work/nolink.md" "$T"

  # The recurrence shape, and the one this gate exists for: the PREVIOUS tag is closed out
  # and the current one is not, which is what a changelog looks like every time this has
  # gone wrong. A check that asked only "does this file contain any closed section" would
  # pass here, and it is the case a reader is least likely to think of.
  _cl_case "the previous tag closed out, and not the one being cut" \
           "NO SECTION" "$good" "corpus-2026.09.10"

  _cl_case "...and the closed changelog is still accepted afterwards" "" "$good" "$T"
  CHANGELOG="$OLDCL"

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
    # Before anything is printed. A refusal that arrives under the commands it is refusing
    # is a warning, and a warning at the bottom of a block somebody is about to paste is
    # not a gate.
    if ! changelog_closed "$TAG"; then
      echo >&2
      echo "REFUSING to print the tag and upload commands for $TAG." >&2
      echo "Close out corpus/CHANGELOG.md first - docs/RELEASING.md, 'Close out the" >&2
      echo "changelog'. The tag cannot be rewritten once it is pushed, which is the" >&2
      echo "whole reason the section is written before it rather than after." >&2
      exit 1
    fi
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
