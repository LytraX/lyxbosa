#!/bin/bash
# Refuse a Linux binary that needs more from a host than the published floor.
#
#   abi-floor.sh <binary>     assert it needs nothing above the floor
#   abi-floor.sh --selftest   the controls, both directions, no compiler needed
#
# WHAT THE FLOOR IS AND WHY IT IS CHECKED HERE
# --------------------------------------------
# README.md, under "System support", tells a person which of six downloads to take, and
# for the glibc pair it says what their host must have: glibc 2.28 or newer and a
# libstdc++ from GCC 6 or newer. Those two sentences are the only thing standing between
# a user on an older distribution and a binary that will never start. What makes them
# true is the builder image - AlmaLinux 8 - and nothing else.
#
# So the day somebody bumps that base image to a newer distribution, the published floor
# is wrong, every affected host gets `version GLIBC_2.34 not found`, and the first report
# comes from a user. This runs on the binary that is about to be copied out, in the
# container that produced it, and refuses it. It is the constraint checked where it is
# decided, rather than a sentence in a document hoping somebody read it.
#
# THE VERSION COMPARISON IS THE PART THAT LOOKS RIGHT AND IS NOT
# --------------------------------------------------------------
# GLIBC_2.9 is not above GLIBC_2.28 and every string comparison says it is. The sort is
# -V for that reason and --selftest asserts it on exactly that pair, because a floor check
# that refuses correct binaries gets switched off and a floor check that accepts wrong ones
# is not a check.
set -euo pipefail

# The floor, in one place. Raising either of these is a release-note change - see README.md
# under "System support", where a user reads it before downloading.
FLOOR_GLIBC="GLIBC_2.28"
FLOOR_GLIBCXX="GLIBCXX_3.4.22"

# The symbol versions a binary requires. ABI_FLOOR_SYMBOLS_FROM names a file holding
# pre-captured objdump output and exists so --selftest can drive the whole comparison,
# including the sort, against inputs nothing on the host has to be able to produce. A
# build never sets it.
symbols_of() {
    if [ -n "${ABI_FLOOR_SYMBOLS_FROM:-}" ]; then
        cat "${ABI_FLOOR_SYMBOLS_FROM}"
        return 0
    fi
    objdump -T "$1" 2>/dev/null || true
}

# The highest version of one family, or the empty string. `grep` is spelled with `command`
# because the shell some readers of this file use wraps it in a tool that skips ignored
# trees, and a binary in a scratch directory is exactly what such a wrapper cannot see.
#
# The `|| true` is load-bearing under `set -o pipefail`: a family with no matches makes
# grep exit 1, which fails the pipeline, which fails the command substitution, which under
# `set -e` ends the script with status 1 and NOT ONE LINE of output. Run against a C
# binary - no GLIBCXX anywhere in it - that is exactly what this did, and "refused" and
# "died before it could say anything" are the same exit code and different facts.
highest() {  # highest <family> <text>
    printf '%s\n' "$2" | { command grep -oE "$1"'_[0-9][0-9.]*' || true; } | sort -uV | tail -1
}

# 0 when got is at or below want. An empty got is ACCEPTED here and refused one level up:
# a binary that needs nothing at all from libstdc++ is a legitimate binary, while a read
# that produced no symbols whatsoever is blindness. Those are two different facts and
# check_binary keeps them apart - one family being silent is not the same as the object
# file being unreadable.
at_or_below() {  # at_or_below <got> <want>
    [ -n "$1" ] || return 0
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$2" ]
}

check_binary() {  # check_binary <path>
    local bin="$1" syms glibc glibcxx rc=0
    syms="$(symbols_of "$bin")"
    if [ -z "${syms}" ]; then
        echo "abi-floor: read no dynamic symbols from ${bin}" >&2
        return 1
    fi
    glibc="$(highest GLIBC "$syms")"
    glibcxx="$(highest GLIBCXX "$syms")"

    # A glibc-linked binary always requires some GLIBC_ version, so reading none of them
    # out of a file that produced other text means the file was not what was expected -
    # and every version comparison below would then be vacuously satisfied. The libstdc++
    # family is different: needing nothing from it is a real answer, so only this one is
    # required to be present.
    if [ -z "${glibc}" ]; then
        echo "abi-floor: read no GLIBC_ version requirement out of ${bin}" >&2
        echo "abi-floor: that is not what a dynamically linked release binary looks like." >&2
        return 1
    fi

    if ! at_or_below "${glibc}" "${FLOOR_GLIBC}"; then
        echo "abi-floor: ${bin} needs ${glibc}, above the published floor ${FLOOR_GLIBC}" >&2
        rc=1
    fi
    if ! at_or_below "${glibcxx}" "${FLOOR_GLIBCXX}"; then
        echo "abi-floor: ${bin} needs ${glibcxx}, above the published floor ${FLOOR_GLIBCXX}" >&2
        rc=1
    fi
    if [ "$rc" -ne 0 ]; then
        echo "abi-floor: README.md states the floor under \"System support\"; moving it is a" >&2
        echo "abi-floor: release-note change and not something a build quietly does." >&2
        return 1
    fi
    echo "ABI floor: needs ${glibc:-no glibc symbols} and ${glibcxx:-no libstdc++ symbols}, at or below the published ${FLOOR_GLIBC} / ${FLOOR_GLIBCXX}"
}

# ---------------------------------------------------------------- selftest

selftest() {
    local tmp n=0 bad=0 rc
    tmp="$(mktemp -d)"

    check() {  # check <expectation:ok|no> <description> <command...>
        local want="$1" desc="$2"; shift 2
        n=$((n+1))
        if "$@" >/dev/null 2>&1; then rc=ok; else rc=no; fi
        if [ "$rc" = "$want" ]; then
            printf '  ok    %-62s (said %s)\n' "$desc" "$rc"
        else
            printf '  FAIL  %-62s (said %s, wanted %s)\n' "$desc" "$rc" "$want"
            bad=$((bad+1))
        fi
    }

    # Each file below is objdump -T output in the only shape this reads: version tags.
    printf '0000 g DF .text 0000 GLIBC_2.2.5 fopen\n0000 g DF .text 0000 GLIBC_2.28 statx\n0000 g DF .text 0000 GLIBCXX_3.4.22 _ZSt1x\n' > "$tmp/at-floor"
    printf '0000 g DF .text 0000 GLIBC_2.2.5 fopen\n0000 g DF .text 0000 GLIBC_2.34 pthread_create\n0000 g DF .text 0000 GLIBCXX_3.4.22 _ZSt1x\n' > "$tmp/glibc-high"
    printf '0000 g DF .text 0000 GLIBC_2.28 statx\n0000 g DF .text 0000 GLIBCXX_3.4.29 _ZSt1y\n' > "$tmp/glibcxx-high"
    printf '0000 g DF .text 0000 GLIBC_2.9 foo\n0000 g DF .text 0000 GLIBCXX_3.4.9 bar\n' > "$tmp/two-nine"
    : > "$tmp/empty"
    printf 'this is not an object file at all\n' > "$tmp/garbage"
    printf '0000 g DF .text 0000 GLIBC_2.28 statx\n' > "$tmp/no-cxx"
    printf '0000 g DF .text 0000 GLIBC_2.34 pthread_create\n' > "$tmp/c-only-high"

    at() { ABI_FLOOR_SYMBOLS_FROM="$tmp/$1" check_binary "planted:$1"; }

    echo "abi-floor.sh --selftest"
    echo
    echo "the verdict, both directions:"
    check ok "a binary exactly at the published floor is accepted"        at at-floor
    check no "one needing GLIBC_2.34 is refused"                          at glibc-high
    check no "one needing GLIBCXX_3.4.29 is refused"                      at glibcxx-high

    echo
    echo "the comparison itself, which a string sort gets wrong:"
    check ok "GLIBC_2.9 is BELOW GLIBC_2.28 and is accepted"              at two-nine
    check ok "and the sort agrees when asked directly" \
          test "$(printf 'GLIBC_2.9\nGLIBC_2.28\n' | sort -V | tail -1)" = "GLIBC_2.28"
    check no "a lexical sort would have said otherwise, and does" \
          test "$(printf 'GLIBC_2.9\nGLIBC_2.28\n' | sort | tail -1)" = "GLIBC_2.28"

    echo
    echo "reading nothing is not passing, which is how this check would go blind:"
    check no "an empty symbol list is refused, not accepted"              at empty
    check no "a file with text but no version symbols is refused"         at garbage
    check no "a path that does not exist is refused"                      check_binary "$tmp/absent"

    echo
    echo "one silent family is not blindness, and the two are told apart:"
    check ok "a binary needing nothing from libstdc++ is accepted"        at no-cxx
    check no "a C-only binary above the glibc floor is still refused"     at c-only-high

    echo
    echo "the floor this file ships is the one README.md states:"
    check ok "the glibc floor is GLIBC_2.28"    test "$FLOOR_GLIBC" = "GLIBC_2.28"
    check ok "the libstdc++ floor is GLIBCXX_3.4.22" test "$FLOOR_GLIBCXX" = "GLIBCXX_3.4.22"

    echo
    echo "the real extractor runs, rather than only the planted path:"
    check ok "objdump reads dynamic symbols out of this machine's /bin/sh" \
          bash -c 'command -v objdump >/dev/null && [ -n "$(objdump -T /bin/sh 2>/dev/null | command grep -oE "GLIBC_[0-9][0-9.]*" | head -1)" ]'

    rm -rf "$tmp"
    echo
    if [ "$bad" -eq 0 ]; then
        echo "$n cases, all ok"
        return 0
    fi
    echo "$n cases, $bad NOT ok"
    return 1
}

case "${1:-}" in
    --selftest) selftest ;;
    "" | -h | --help) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
    *) check_binary "$1" ;;
esac
