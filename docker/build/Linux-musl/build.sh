#!/bin/bash
set -e

# The static musl build of the Linux binary, beside docker/build/Linux/build.sh and
# with the same arguments:
#
#   docker/build/Linux-musl/build.sh [amd64|arm64|all] [output-dir] [version]
#
# Same shape as the glibc script deliberately, so the workflow calls the two the same
# way: one configure with the tests in it, the tests run when this machine can execute
# the architecture being built, and the binary that passed them copied out. What differs
# is the image (Dockerfile in this directory says why it exists), the tag, and the name
# the binary is given: lyxbosa-linux-<arch>-portable, the suffix being what
# src-lib/cpp/update/ReleaseAssets.cpp appends for a musl build, so that the updater
# fetches the asset this script produced and not the glibc one.
#
# The asset says `portable` and this directory says `musl` on purpose. The asset name is
# read by somebody choosing what to download, and what they are choosing is a binary that
# runs on an older host; everything in here - Alpine, the system gcc, -static - is how
# that is delivered, and is exactly what a maintainer opening this file needs told.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

ARCH="${1:-all}"
OUTPUT_DIR="${2:-./dist}"
VERSION="${3:-}"

if [ "${ARCH}" = "all" ]; then
    ARCHES=(amd64 arm64)
else
    ARCHES=("${ARCH}")
fi

case "$(uname -m)" in
    aarch64|arm64) HOST_ARCH=arm64 ;;
    *)             HOST_ARCH=amd64 ;;
esac

# The verdict goes to the log and, under Actions, to the run summary page. The glibc
# script's header says why.
announce() {
    echo "$1"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        echo "$1" >> "${GITHUB_STEP_SUMMARY}"
    fi
}

# The build timestamp, pinned, so the same source produces the same bytes.
#
# vcpkg builds OpenSSL from source and its util/mkbuildinf.pl stamps the build time into
# the version banner libcrypto carries; the GNU build ID, a hash over the link inputs,
# then moves with it. Two builds of one commit minutes apart differ in exactly those 24
# bytes and nowhere else - .text is identical. SOURCE_DATE_EPOCH replaces the clock, and
# with it held the two builds are byte for byte the same file.
#
# The value is a constant in the repository rather than the commit date of HEAD, and that
# is deliberate. The overlay triplets put it in vcpkg's ABI hash - which is what stops a
# cached dependency built under another epoch from being restored and silently undoing the
# pin - so an epoch that moved with every commit would miss every cache entry on every
# run and rebuild all of them. A constant is the same pin with a warm cache. Bump it when
# there is a reason to; nothing breaks if nobody does.
#
# An exported SOURCE_DATE_EPOCH wins, so a rebuilder can reproduce a release whose pinned
# value differs from the one in the tree they happen to be holding.
EPOCH_FILE="${SCRIPT_DIR}/../source-date-epoch"
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    [ -r "${EPOCH_FILE}" ] || { echo "no epoch at ${EPOCH_FILE}" >&2; exit 1; }
    SOURCE_DATE_EPOCH="$(tr -d '[:space:]' < "${EPOCH_FILE}")"
fi
case "${SOURCE_DATE_EPOCH}" in
    ''|*[!0-9]*) echo "SOURCE_DATE_EPOCH is not a whole number of seconds: '${SOURCE_DATE_EPOCH}'" >&2; exit 1 ;;
esac
echo "SOURCE_DATE_EPOCH: ${SOURCE_DATE_EPOCH} ($(date -u -d "@${SOURCE_DATE_EPOCH}" 2>/dev/null || true))"

VERSION_ENV=""
if [ -n "${VERSION}" ]; then
    VERSION_ENV="-e LYXBOSA_VERSION=${VERSION}"
fi

# Optional vcpkg binary cache, shared with the host, exactly as the glibc script mounts
# it. A separate directory from the glibc build's is the caller's business - the
# workflow keys them apart - but sharing one would be safe too: vcpkg keys every entry
# by an ABI hash that covers the compiler, and Alpine's gcc is not AlmaLinux's.
CACHE_MOUNT=""
if [ -n "${VCPKG_BINARY_CACHE:-}" ]; then
    mkdir -p "${VCPKG_BINARY_CACHE}"
    CACHE_DIR="$(cd "${VCPKG_BINARY_CACHE}" && pwd)"
    CACHE_MOUNT="-v ${CACHE_DIR}:/vcpkg-cache -e VCPKG_DEFAULT_BINARY_CACHE=/vcpkg-cache"
    echo "vcpkg binary cache: ${CACHE_DIR}"
fi

# Resolved to an absolute path once, for the reason the glibc script gives: docker -v
# needs one, and "$(pwd)/${OUTPUT_DIR}" produced nonsense for an absolute argument.
mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"

for CURRENT_ARCH in "${ARCHES[@]}"; do
    PLATFORM="linux/${CURRENT_ARCH}"
    TAG_NAME="lyxbosa-build-linux-musl-${CURRENT_ARCH}"
    BINARY_NAME="lyxbosa-linux-${CURRENT_ARCH}-portable"

    if [ "${CURRENT_ARCH}" = "${HOST_ARCH}" ]; then
        RUN_TESTS=1
        SKIP_REASON=""
    else
        RUN_TESTS=0
        SKIP_REASON="this machine is ${HOST_ARCH} and would run a ${CURRENT_ARCH} suite under emulation"
    fi

    echo "=== Building LyxBoSa for Linux (${CURRENT_ARCH}, static musl) ==="

    # The build context is docker/build/ rather than this directory: retry.sh and
    # vcpkg-commit are shared by both Linux images and by the Windows script, and a copy
    # of each in every directory is three files that agree today. The Dockerfile's COPY
    # lines are written against that root.
    echo "Building Docker image..."
    docker buildx build \
        --platform "${PLATFORM}" \
        -t "${TAG_NAME}" \
        --load \
        -f "${SCRIPT_DIR}/Dockerfile" \
        "${SCRIPT_DIR}/.."

    echo "Running build inside container..."
    docker run --rm \
        --platform "${PLATFORM}" \
        -v "${PROJECT_ROOT}:/src:ro" \
        -v "${OUTPUT_DIR}:/output" \
        ${CACHE_MOUNT} \
        ${VERSION_ENV} \
        -e "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
        -e "LYXBOSA_RUN_TESTS=${RUN_TESTS}" \
        -e "LYXBOSA_TESTS_SKIPPED_BECAUSE=${SKIP_REASON}" \
        "${TAG_NAME}"

    mv -f "${OUTPUT_DIR}/lyxbosa" "${OUTPUT_DIR}/${BINARY_NAME}"

    echo ""
    if [ "${RUN_TESTS}" = "1" ]; then
        announce "- \`linux ${CURRENT_ARCH} musl\` built **and tested** - ctest ran in the Alpine release container"
    else
        announce "- \`linux ${CURRENT_ARCH} musl\` built, **not tested** - ${SKIP_REASON}"
    fi
    file "${OUTPUT_DIR}/${BINARY_NAME}"
    echo ""
done
