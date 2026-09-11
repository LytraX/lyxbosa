#!/usr/bin/env bash
# Build one Linux asset twice and say whether the two runs produced the same file.
#
#   verify-reproducible.sh <glibc|musl> [amd64|arm64]   build twice, compare, report
#   verify-reproducible.sh --control <glibc|musl> [arch] build twice at DIFFERENT epochs;
#                                                        they must differ
#   verify-reproducible.sh --selftest                    the controls that need no compiler
#
# WHAT A COMPARISON OF TWO BUILDS CAN FAIL TO MEASURE
# ---------------------------------------------------
# Two builds a second apart in one directory against one binary cache match for reasons
# that have nothing to do with any pin: the second restores the first's dependency
# artifacts and relinks the same inputs. So the two runs here are given a vcpkg binary
# cache each, and the second is refused outright if it was handed the first's - a shared
# cache is the way this check goes blind, and it goes blind reporting success.
#
# The comparison is also not the only thing asserted. Equal bytes cannot distinguish "the
# epoch reached OpenSSL" from "both builds happened inside the same second", so each
# binary is separately required to carry the banner gmtime(SOURCE_DATE_EPOCH) writes. That
# one is cheap, it observes the mechanism rather than its consequence, and it is what
# notices if the pin is ever quietly dropped.
#
# --control is the other direction, and it costs two more builds: the same two runs at two
# deliberately different epochs, which MUST produce different files. If they do not, the
# variable is reaching nothing and every green run above is meaningless.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
EPOCH_FILE="${SCRIPT_DIR}/source-date-epoch"

# OpenSSL's util/mkbuildinf.pl writes `gmtime($ENV{SOURCE_DATE_EPOCH})` in Perl's scalar
# form - "Fri Sep 11 20:11:10 2026" - with the day of the month space-padded, which is
# what %e gives and what %d does not.
banner_for_epoch() { date -u -d "@$1" '+built on: %a %b %e %H:%M:%S %Y UTC'; }

# The banner a built binary actually carries, or the empty string. `grep` here is the real
# grep: this file is read by people whose shell wraps it in something that skips ignored
# trees, and a binary in a scratch directory is exactly what such a wrapper cannot see.
banner_in() {
    [ -r "$1" ] || return 1
    strings -a "$1" 2>/dev/null | command grep -m1 '^built on: ' || true
}

# Both halves of the verdict, each returning 0 for ok. Split out from the building so the
# selftest can drive them on fabricated files and watch them say no.
same_bytes() { cmp -s "$1" "$2"; }

banner_is() {
    local bin="$1" want="$2" got
    got="$(banner_in "$bin")" || return 1
    # An absent banner is not a pass. A check that reads "nothing found" as "nothing
    # wrong" is the shape that reported ten objects present when every one was gone.
    [ -n "$got" ] || return 1
    [ "$got" = "$want" ]
}

# ---------------------------------------------------------------- selftest

selftest() {
    local tmp rc=0 n=0 bad=0
    # Cleaned up explicitly rather than by a RETURN trap: bash does not scope one to the
    # function that set it, so the trap fired again when main returned and tripped over a
    # $tmp that no longer existed.
    tmp="$(mktemp -d)"

    check() {  # check <expectation:ok|no> <description> <command...>
        local want="$1" desc="$2"; shift 2
        n=$((n+1))
        if "$@"; then rc=ok; else rc=no; fi
        if [ "$rc" = "$want" ]; then
            printf '  ok    %-58s (said %s)\n' "$desc" "$rc"
        else
            printf '  FAIL  %-58s (said %s, wanted %s)\n' "$desc" "$rc" "$want"
            bad=$((bad+1))
        fi
    }

    local want_epoch=1789157470
    local want_banner; want_banner="$(banner_for_epoch "$want_epoch")"

    printf 'x%.0s' $(seq 1 64) > "$tmp/a"
    cp "$tmp/a" "$tmp/b"
    cp "$tmp/a" "$tmp/c"; printf 'y' | dd of="$tmp/c" bs=1 seek=31 conv=notrunc status=none

    echo "verify-reproducible.sh --selftest"
    echo
    echo "the byte comparison, both directions:"
    check ok "two identical files compare equal"                 same_bytes "$tmp/a" "$tmp/b"
    check no "one byte in sixty-four is enough to be unequal"     same_bytes "$tmp/a" "$tmp/c"
    check no "a missing file is not a match"                      same_bytes "$tmp/a" "$tmp/nope"

    echo
    echo "the banner assertion, both directions:"
    printf 'padding\0%s\0more padding\n' "$want_banner" > "$tmp/good"
    printf 'padding\0%s\0more padding\n' "$(banner_for_epoch 1500000000)" > "$tmp/wrong"
    printf 'padding\0no banner at all\0\n' > "$tmp/none"
    check ok "the expected banner is accepted"                    banner_is "$tmp/good"  "$want_banner"
    check no "a banner from another epoch is refused"             banner_is "$tmp/wrong" "$want_banner"
    check no "a binary carrying no banner is refused, not passed" banner_is "$tmp/none"  "$want_banner"
    check no "a file that does not exist is refused"              banner_is "$tmp/gone"  "$want_banner"

    echo
    echo "the epoch the banner is formed from:"
    check ok "the day of the month is space-padded, as gmtime writes it" \
          test "$(banner_for_epoch 1000000000)" = "built on: Sun Sep  9 01:46:40 2001 UTC"
    check no "two different epochs do not form the same banner" \
          test "$(banner_for_epoch 1000000000)" = "$(banner_for_epoch 1500000000)"

    echo
    echo "the shared-cache refusal, which is how this check would go blind:"
    check no "two runs handed one cache directory are refused"    distinct_caches "$tmp/k" "$tmp/k"
    check ok "two runs with a cache each are allowed"             distinct_caches "$tmp/k" "$tmp/j"

    echo
    echo "the epoch file this repository ships:"
    check ok "it exists and is a whole number of seconds" \
          bash -c '[ -r "$1" ] && [[ "$(tr -d "[:space:]" < "$1")" =~ ^[0-9]+$ ]]' _ "$EPOCH_FILE"

    rm -rf "$tmp"
    echo
    if [ "$bad" -eq 0 ]; then
        echo "$n cases, all ok"
        return 0
    fi
    echo "$n cases, $bad NOT ok"
    return 1
}

distinct_caches() { [ "$1" != "$2" ]; }

# ---------------------------------------------------------------- the real thing

build_once() {  # build_once <libc> <arch> <outdir> <cachedir> <epoch>
    local libc="$1" arch="$2" out="$3" cache="$4" epoch="$5" script
    case "$libc" in
        glibc) script="${SCRIPT_DIR}/Linux/build.sh" ;;
        musl)  script="${SCRIPT_DIR}/Linux-musl/build.sh" ;;
        *) echo "unknown libc: $libc" >&2; return 2 ;;
    esac
    mkdir -p "$out" "$cache"
    SOURCE_DATE_EPOCH="$epoch" VCPKG_BINARY_CACHE="$cache" \
        "$script" "$arch" "$out" 1>&2
}

run_pair() {  # run_pair <libc> <arch> <epoch-a> <epoch-b>; prints the two binary paths
    local libc="$1" arch="$2" ea="$3" eb="$4"
    local work; work="$(mktemp -d)"
    echo "$work" > "$WORK_MARKER"
    local ca="$work/cache-a" cb="$work/cache-b"
    distinct_caches "$ca" "$cb" || { echo "the two runs share a cache directory" >&2; return 1; }
    build_once "$libc" "$arch" "$work/a" "$ca" "$ea"
    build_once "$libc" "$arch" "$work/b" "$cb" "$eb"
    local name
    case "$libc" in
        glibc) name="lyxbosa-linux-${arch}" ;;
        musl)  name="lyxbosa-linux-${arch}-portable" ;;
    esac
    # build.sh names the file; if it ever renames it, find out here rather than reporting
    # a comparison of two things that are not there.
    [ -f "$work/a/$name" ] || name="$(cd "$work/a" && ls | head -1)"
    echo "$work/a/$name" "$work/b/$name"
}

usage() { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; }

main() {
    local mode=verify
    case "${1:-}" in
        --selftest) selftest; return $? ;;
        --control)  mode=control; shift ;;
        -h|--help|"") usage; return 2 ;;
    esac

    local libc="${1:-}" arch="${2:-amd64}"
    case "$libc" in glibc|musl) ;; *) usage; return 2 ;; esac

    local pinned; pinned="$(tr -d '[:space:]' < "$EPOCH_FILE")"
    WORK_MARKER="$(mktemp)"
    local ea eb pair a b
    if [ "$mode" = control ]; then
        # Deliberately different, and neither is the shipped value, so a run that somehow
        # ignored both would not accidentally land on it.
        ea=1000000000; eb=1500000000
        echo "=== control: $libc $arch, two builds at DIFFERENT epochs; they must differ ==="
    else
        ea="$pinned"; eb="$pinned"
        echo "=== $libc $arch, two builds at SOURCE_DATE_EPOCH=$pinned ==="
    fi

    pair="$(run_pair "$libc" "$arch" "$ea" "$eb")"
    read -r a b <<<"$pair"

    echo
    echo "a: $a"
    echo "b: $b"
    echo "   $(stat -c%s "$a") and $(stat -c%s "$b") bytes"
    echo "   banner a: $(banner_in "$a")"
    echo "   banner b: $(banner_in "$b")"

    local ok=0
    if [ "$mode" = control ]; then
        if same_bytes "$a" "$b"; then
            echo
            echo "CONTROL FAILED: two epochs produced the same file, so nothing is reading the pin"
            ok=1
        else
            echo
            echo "control ok: $(cmp -l "$a" "$b" | wc -l) bytes differ between the two epochs"
        fi
    else
        banner_is "$a" "$(banner_for_epoch "$pinned")" \
            || { echo "the first binary does not carry gmtime($pinned)"; ok=1; }
        banner_is "$b" "$(banner_for_epoch "$pinned")" \
            || { echo "the second binary does not carry gmtime($pinned)"; ok=1; }
        if same_bytes "$a" "$b"; then
            echo
            [ "$ok" -eq 0 ] && echo "REPRODUCIBLE: the two builds are the same file"
        else
            echo
            echo "NOT REPRODUCIBLE: $(cmp -l "$a" "$b" | wc -l) bytes differ"
            cmp -l "$a" "$b" | head -40
            ok=1
        fi
    fi

    echo
    # Not removed here: a failing comparison is worth looking at, and the binaries are
    # what there is to look at. The container writes them as root, so removing the tree
    # needs the same privilege that wrote it.
    echo "the two trees are at $(cat "$WORK_MARKER"), written by the container as root"
    rm -f "$WORK_MARKER"
    return "$ok"
}

main "$@"
