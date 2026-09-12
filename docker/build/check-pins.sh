#!/usr/bin/env bash
# Prove that the pins in the builder images can refuse.
#
#   check-pins.sh --selftest          every --selftest under docker/build/, no compiler
#   check-pins.sh --images glibc      plant a bad pin in the glibc image, watch it fail
#   check-pins.sh --images musl       the same for the musl image
#
# WHY THIS EXISTS SEPARATELY FROM THE PINS
# ----------------------------------------
# A pin that has never been watched refuse is indistinguishable from a comment. Every
# failure it is supposed to catch is also what a passing build looks like: a digest that
# quietly fell back to a tag, a compiler that resolved to something else, a vcpkg checkout
# that did not happen. So each one is planted here and the build is required to fail.
#
# THE TWO HALVES COST DIFFERENT THINGS AND RUN IN DIFFERENT PLACES
# -----------------------------------------------------------------
# --selftest runs the suites that need nothing but a shell. It is under a second and
# belongs in every job.
#
# --images builds images with a pin deliberately broken, which needs docker and costs
# tens of seconds per plant. It belongs in the job that just built that image, where the
# layers it does not invalidate are already warm - and in the amd64 leg only, because the
# arm64 leg would pay the same cost to learn the same thing.
#
# DISCOVERY RATHER THAN A LIST
# ----------------------------
# --selftest finds its suites by reading docker/build/*.sh for a --selftest in a DISPATCH
# position - a case pattern - rather than anywhere in the text, because a file explaining
# somebody else's --selftest is not a suite. A list here would be a list somebody has to
# remember to add to, and the suite added without it would be the one that breaks. It
# refuses rather than reporting a result when discovery finds fewer suites than this
# repository is known to have: a discovery that finds nothing reports no failures, and no
# failures reads as green.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIN_SUITES=4

# ---------------------------------------------------------------- the hermetic half

discover() {
    for f in "${SCRIPT_DIR}"/*.sh; do
        [ -r "$f" ] || continue
        [ "$(basename "$f")" = "check-pins.sh" ] && continue
        if command grep -Eq '^[[:space:]]*(-[a-z-]+\|)*--selftest\)' "$f"; then
            printf '%s\n' "$f"
        fi
    done
}

run_selftests() {
    local suites failed=0 total=0 name
    mapfile -t suites < <(discover)

    if [ "${#suites[@]}" -lt "$MIN_SUITES" ]; then
        echo "check-pins: discovery found ${#suites[@]} suites under ${SCRIPT_DIR}, fewer than the ${MIN_SUITES} this repository has."
        echo "check-pins: REFUSING to report a result - a discovery that finds nothing reports no failures."
        return 2
    fi

    echo "=== ${#suites[@]} suites discovered under docker/build/ ==="
    echo
    for f in "${suites[@]}"; do
        name="$(basename "$f")"
        total=$((total + 1))
        if bash "$f" --selftest; then
            echo "--- ${name}: ok"
        else
            echo "--- ${name}: FAILED"
            failed=$((failed + 1))
        fi
        echo
    done

    echo "=== ${total} suites, $((total - failed)) ok, ${failed} not ok ==="
    [ "$failed" -eq 0 ]
}

# ---------------------------------------------------------------- the planted half

# A build context holding this directory's files, so a plant can replace one of them
# without touching anything tracked. AGENTS.md records three separate occasions on which a
# harness that mutated tracked files and restored them with `git checkout --` destroyed a
# round's uncommitted work; a copy costs nothing and cannot do that.
plant_context() {  # plant_context <destdir>
    mkdir -p "$1/Linux" "$1/Linux-musl"
    cp "${SCRIPT_DIR}"/*.sh "${SCRIPT_DIR}/vcpkg-commit" "$1/"
    cp "${SCRIPT_DIR}/Linux/Dockerfile" "${SCRIPT_DIR}/Linux/build-inside.sh" "$1/Linux/"
    cp "${SCRIPT_DIR}/Linux-musl/Dockerfile" "${SCRIPT_DIR}/Linux-musl/build-inside.sh" "$1/Linux-musl/"
}

PLANT_N=0
PLANT_BAD=0

# A build that MUST fail, and must fail with the message the pin is supposed to print.
# Asserting the message as well as the exit code is what keeps this from passing because
# the build broke for some other reason - which is the same failure as a check that cannot
# tell "it did not happen" from "it happened and found nothing".
#
# The expected text names the planted value rather than a phrase like "not found", for the
# same reason one level down: a network outage, a full disk and a syntax error in this
# repository all produce a failed build with plausible words in it.
must_refuse() {  # must_refuse <description> <expected-text> <docker-build-args...>
    local desc="$1" want="$2"; shift 2
    local log status
    PLANT_N=$((PLANT_N + 1))
    log="$(mktemp)"
    if docker buildx build "$@" >"$log" 2>&1; then
        status=built
    else
        status=refused
    fi
    if [ "$status" != refused ]; then
        printf '  FAIL  %-58s (the build SUCCEEDED)\n' "$desc"
        PLANT_BAD=$((PLANT_BAD + 1))
    elif ! command grep -qF "$want" "$log"; then
        printf '  FAIL  %-58s (refused, but not for the planted reason)\n' "$desc"
        echo "        wanted to see: ${want}"
        tail -15 "$log" | sed 's/^/        /'
        PLANT_BAD=$((PLANT_BAD + 1))
    else
        printf '  ok    %-58s (refused: %s)\n' "$desc" "$want"
    fi
    rm -f "$log"
}

plants_glibc() {
    local ctx; ctx="$(mktemp -d)"
    plant_context "$ctx"

    echo "planted pins in the glibc image:"

    # A digest nothing can resolve. The requirement is that the build STOPS, rather than
    # falling back to the `almalinux:8` tag that is written beside it for a reader.
    must_refuse "a base digest that does not resolve is not a fallback" \
        "almalinux@sha256:0000000000000000000000000000000000000000000000000000000000000000: not found" \
        --platform linux/amd64 -f "$ctx/Linux/Dockerfile" \
        --build-arg BASE_IMAGE=almalinux@sha256:0000000000000000000000000000000000000000000000000000000000000000 \
        "$ctx"

    # A compiler release that was never built. dnf resolving nothing is the loud failure
    # the Dockerfile's comment promises.
    must_refuse "a compiler release that does not exist stops the image" \
        "gcc-toolset-12-gcc-c++-0.0.0-0.el8" \
        --platform linux/amd64 -f "$ctx/Linux/Dockerfile" \
        --build-arg GCC_TOOLSET=gcc-toolset-12-gcc-c++-0.0.0-0.el8 \
        "$ctx"

    # A vcpkg commit that is not in the repository. This is the plant that needs a context
    # of its own: the commit is read from a file rather than passed as an argument, so that
    # the two Linux images and the Windows script cannot disagree about it.
    printf '%s\n' "0123456789abcdef0123456789abcdef01234567" > "$ctx/vcpkg-commit"
    must_refuse "a vcpkg commit that is not in the repository stops the image" \
        "0123456789abcdef0123456789abcdef01234567" \
        --platform linux/amd64 -f "$ctx/Linux/Dockerfile" "$ctx"

    rm -rf "$ctx"
}

plants_musl() {
    local ctx; ctx="$(mktemp -d)"
    plant_context "$ctx"

    echo "planted pins in the musl image:"

    must_refuse "a base digest that does not resolve is not a fallback" \
        "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000: not found" \
        --platform linux/amd64 -f "$ctx/Linux-musl/Dockerfile" \
        --build-arg BASE_IMAGE=alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000 \
        "$ctx"

    # Alpine's branch serves only current versions, so the compiler is asserted rather than
    # requested. This is that assertion being watched to fire.
    must_refuse "a compiler version this image does not have is refused" \
        "this image expects gcc 0.0.0-r0" \
        --platform linux/amd64 -f "$ctx/Linux-musl/Dockerfile" \
        --build-arg EXPECT_GCC=0.0.0-r0 \
        "$ctx"

    printf '%s\n' "0123456789abcdef0123456789abcdef01234567" > "$ctx/vcpkg-commit"
    must_refuse "a vcpkg commit that is not in the repository stops the image" \
        "0123456789abcdef0123456789abcdef01234567" \
        --platform linux/amd64 -f "$ctx/Linux-musl/Dockerfile" "$ctx"

    rm -rf "$ctx"
}

run_plants() {  # run_plants <glibc|musl>
    case "${1:-}" in
        glibc) plants_glibc ;;
        musl)  plants_musl ;;
        *) echo "usage: check-pins.sh --images <glibc|musl>" >&2; return 2 ;;
    esac
    echo
    echo "=== ${PLANT_N} planted pins, $((PLANT_N - PLANT_BAD)) refused as they must, ${PLANT_BAD} did not ==="
    [ "$PLANT_BAD" -eq 0 ]
}

case "${1:-}" in
    --selftest) run_selftests ;;
    --images)   run_plants "${2:-}" ;;
    *) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
