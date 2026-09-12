#!/bin/sh
# Point AlmaLinux's repositories at the origin instead of the mirror network, and refuse
# the image if that did not actually happen.
#
#   almalinux-repos.sh [dir]     rewrite (default /etc/yum.repos.d), then assert
#   almalinux-repos.sh --selftest  the controls, both directions, no container needed
#
# WHY NOT THE MIRROR NETWORK
# --------------------------
# The base image ships repository files that ask mirrors.almalinux.org for a list of hosts
# and then fetch from whichever come back. Those hosts sync independently, so dnf can be
# handed a repomd.xml by one mirror naming checksummed files the others have not received
# yet - and then every one of them answers 404. On 2026-09-12 that failed both glibc build
# jobs thirteen seconds in, eleven minutes after the identical source tree had passed, and
# a plain re-run passed again. Nothing in this repository chose those hosts.
#
# repo.almalinux.org is one name, served from a CDN, holding one tree that cannot disagree
# with itself. The trade is deliberate and it is not free: an outage of that one name fails
# every build at once, where the mirror network fails a fraction of builds intermittently
# and forever. retry.sh covers the first. Nothing covers the second.
#
# WHY THE ASSERTION IS HALF THE FILE
# ----------------------------------
# A substitution that matches nothing leaves the mirror list in place, exits 0, and leaves
# every comment above describing something that is not happening. That is a check which has
# never been observed to fail. So the rewrite is asserted afterwards - no repository may
# still resolve through a mirror list or a metalink, and the one this build depends on must
# name the origin - and --selftest drives both directions against planted files.
set -eu

ORIGIN="https://repo.almalinux.org/almalinux"
# 8.10 is the last AlmaLinux 8 minor, so writing it out pins the only thing $releasever
# could still resolve to differently.
RELEASE="8.10"

rewrite() {  # rewrite <dir>
    dir="$1"
    [ -d "$dir" ] || { echo "almalinux-repos: no such directory: $dir" >&2; return 1; }

    # A directory with no repository files in it is not a directory that was rewritten.
    # Refusing here is what keeps the assertions below from passing vacuously.
    if [ -z "$(find "$dir" -maxdepth 1 -name 'almalinux*.repo' -print -quit)" ]; then
        echo "almalinux-repos: no almalinux*.repo in $dir" >&2
        return 1
    fi

    sed -i -e 's|^mirrorlist=|#mirrorlist=|' \
           -e 's|^# *baseurl=|baseurl=|' \
           -e "s|\$releasever|${RELEASE}|g" \
           "$dir"/almalinux*.repo

    if command grep -REq '^[[:space:]]*(mirrorlist|metalink)=' "$dir"; then
        echo "almalinux-repos: a repository still resolves through a mirror list." >&2
        echo "almalinux-repos: the substitution above matched nothing, which happens when the" >&2
        echo "almalinux-repos: base image digest is bumped and the repository files change shape." >&2
        command grep -REn '^[[:space:]]*(mirrorlist|metalink)=' "$dir" >&2
        return 1
    fi

    if ! command grep -q "^baseurl=${ORIGIN}/${RELEASE}/BaseOS/" "$dir/almalinux.repo" 2>/dev/null; then
        echo "almalinux-repos: BaseOS does not name ${ORIGIN}/${RELEASE} after the rewrite" >&2
        command grep -E '^\[|^baseurl' "$dir/almalinux.repo" >&2 2>/dev/null || true
        return 1
    fi

    echo "repositories: ${ORIGIN}/${RELEASE}, one origin, no mirror list"
}

# ---------------------------------------------------------------- selftest

selftest() {
    tmp="$(mktemp -d)"
    n=0
    bad=0

    check() {  # check <expectation:ok|no> <description> <command...>
        want="$1"; desc="$2"; shift 2
        n=$((n+1))
        if "$@" >/dev/null 2>&1; then rc=ok; else rc=no; fi
        if [ "$rc" = "$want" ]; then
            printf '  ok    %-62s (said %s)\n' "$desc" "$rc"
        else
            printf '  FAIL  %-62s (said %s, wanted %s)\n' "$desc" "$rc" "$want"
            bad=$((bad+1))
        fi
    }

    # The shape almalinux:8 actually ships, reduced to the two lines that matter.
    plant_stock() {
        mkdir -p "$1"
        cat > "$1/almalinux.repo" <<'REPO'
[baseos]
name=AlmaLinux $releasever - BaseOS
mirrorlist=https://mirrors.almalinux.org/mirrorlist/$releasever/baseos
# baseurl=https://repo.almalinux.org/almalinux/$releasever/BaseOS/$basearch/os/
enabled=1

[appstream]
name=AlmaLinux $releasever - AppStream
mirrorlist=https://mirrors.almalinux.org/mirrorlist/$releasever/appstream
# baseurl=https://repo.almalinux.org/almalinux/$releasever/AppStream/$basearch/os/
enabled=1
REPO
    }

    # The same file with the shape changed, which is what a future base digest could do.
    plant_metalink() {
        mkdir -p "$1"
        cat > "$1/almalinux.repo" <<'REPO'
[baseos]
name=AlmaLinux $releasever - BaseOS
metalink=https://mirrors.almalinux.org/metalink?repo=baseos-$releasever
# baseurl=https://repo.almalinux.org/almalinux/$releasever/BaseOS/$basearch/os/
enabled=1
REPO
    }

    # A file with a mirror list and NO commented baseurl to uncomment: the substitution
    # half-succeeds and the repository is still resolved through mirrors.
    plant_no_baseurl() {
        mkdir -p "$1"
        cat > "$1/almalinux.repo" <<'REPO'
[baseos]
name=AlmaLinux $releasever - BaseOS
mirrorlist=https://mirrors.almalinux.org/mirrorlist/$releasever/baseos
enabled=1
REPO
    }

    echo "almalinux-repos.sh --selftest"
    echo
    echo "the rewrite, on the shape this base image ships:"
    plant_stock "$tmp/stock"
    check ok "a stock repository file is rewritten and accepted"           rewrite "$tmp/stock"
    check ok "and BaseOS now names the origin at 8.10" \
          sh -c "command grep -q '^baseurl=https://repo.almalinux.org/almalinux/8.10/BaseOS/' '$tmp/stock/almalinux.repo'"
    check ok "and \$releasever is gone from every line that had it" \
          sh -c "! command grep -q 'releasever' '$tmp/stock/almalinux.repo'"
    check no "no mirrorlist= line is left uncommented" \
          sh -c "command grep -q '^mirrorlist=' '$tmp/stock/almalinux.repo'"

    echo
    echo "the assertion, which is the half that can fail silently:"
    plant_metalink "$tmp/metalink"
    check no "a file using metalink= is REFUSED rather than half-rewritten"  rewrite "$tmp/metalink"
    plant_no_baseurl "$tmp/nobase"
    check no "a file with no baseurl to uncomment is refused"                rewrite "$tmp/nobase"
    mkdir -p "$tmp/empty"
    check no "a directory holding no repository files is refused"            rewrite "$tmp/empty"
    check no "a directory that does not exist is refused"                    rewrite "$tmp/absent"

    echo
    echo "the rewrite is idempotent, because a layer may be rebuilt:"
    check ok "running it twice on the same directory is still accepted"      rewrite "$tmp/stock"

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
    -h|--help) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
    *) rewrite "${1:-/etc/yum.repos.d}" ;;
esac
