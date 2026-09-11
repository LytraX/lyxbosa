#!/bin/bash
set -e

# Build the tests and run them, in the musl release container.
#
#   docker/build/Linux-musl/test.sh [amd64|arm64]
#
# docker/build/Linux/test.sh for the glibc image, with the same rules: one architecture
# per call, defaulting to this machine's, because the tests have to execute; the same
# image, triplets and binary cache as build.sh, so a test build restores what the
# release build stored; nothing written to the source tree and nothing copied out.
# That file's header and test-inside.sh's carry the reasoning and are not repeated.
#
# What this proves that the glibc job cannot: that the static musl binary - a different
# C library, a different allocator, a different resolver, and the release build's own
# -static link on the test executable - passes the same suite. A musl asset whose tests
# only ever ran on glibc would be shipping on an assumption.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

case "$(uname -m)" in
    aarch64|arm64) HOST_ARCH=arm64 ;;
    *)             HOST_ARCH=amd64 ;;
esac
ARCH="${1:-${HOST_ARCH}}"

CACHE_MOUNT=""
if [ -n "${VCPKG_BINARY_CACHE:-}" ]; then
    mkdir -p "${VCPKG_BINARY_CACHE}"
    CACHE_DIR="$(cd "${VCPKG_BINARY_CACHE}" && pwd)"
    CACHE_MOUNT="-v ${CACHE_DIR}:/vcpkg-cache -e VCPKG_DEFAULT_BINARY_CACHE=/vcpkg-cache"
    echo "vcpkg binary cache: ${CACHE_DIR}"
fi

PLATFORM="linux/${ARCH}"
TAG_NAME="lyxbosa-build-linux-musl-${ARCH}"

echo "=== Building and running LyxBoSa tests for Linux (${ARCH}, static musl) ==="

echo "Building Docker image..."
docker buildx build \
    --platform "${PLATFORM}" \
    -t "${TAG_NAME}" \
    --load \
    -f "${SCRIPT_DIR}/Dockerfile" \
    "${SCRIPT_DIR}"

# The test script is taken from the mounted source rather than baked into the image,
# so that it does not rotate the cache key the workflow derives from the Dockerfile.
echo "Running tests inside container..."
docker run --rm \
    --platform "${PLATFORM}" \
    -v "${PROJECT_ROOT}:/src:ro" \
    ${CACHE_MOUNT} \
    --entrypoint /src/docker/build/Linux-musl/test-inside.sh \
    "${TAG_NAME}"

echo ""
echo "=== Tests passed: Linux (${ARCH}, static musl) ==="
