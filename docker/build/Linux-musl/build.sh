#!/bin/bash
set -e

# The static musl build of the Linux binary, beside docker/build/Linux/build.sh and
# with the same arguments:
#
#   docker/build/Linux-musl/build.sh [amd64|arm64|all] [output-dir] [version]
#
# Same shape as the glibc script deliberately, so the workflow calls the two the same
# way; what differs is the image (Dockerfile in this directory says why it exists), the
# tag, and the name the binary is given: lyxbosa-linux-<arch>-portable, the suffix being
# what src-lib/cpp/update/ReleaseAssets.cpp appends for a musl build, so that the
# updater fetches the asset this script produced and not the glibc one.
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

    echo "=== Building LyxBoSa for Linux (${CURRENT_ARCH}, static musl) ==="

    echo "Building Docker image..."
    docker buildx build \
        --platform "${PLATFORM}" \
        -t "${TAG_NAME}" \
        --load \
        -f "${SCRIPT_DIR}/Dockerfile" \
        "${SCRIPT_DIR}"

    echo "Running build inside container..."
    docker run --rm \
        --platform "${PLATFORM}" \
        -v "${PROJECT_ROOT}:/src:ro" \
        -v "${OUTPUT_DIR}:/output" \
        ${CACHE_MOUNT} \
        ${VERSION_ENV} \
        "${TAG_NAME}"

    mv -f "${OUTPUT_DIR}/lyxbosa" "${OUTPUT_DIR}/${BINARY_NAME}"

    echo ""
    echo "=== Build complete: ${OUTPUT_DIR}/${BINARY_NAME} ==="
    file "${OUTPUT_DIR}/${BINARY_NAME}"
    echo ""
done
