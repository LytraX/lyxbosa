#!/bin/bash
set -e

# Build the tests and run them, in the release container.
#
#   docker/build/Linux/test.sh [amd64|arm64]
#
# One architecture per call and it defaults to the one this machine is: the tests
# have to EXECUTE, and a runner can only execute its own. build.sh's "all" has no
# meaning here.
#
# This is a second entry point into the same image, not a second way of building the
# project. The Dockerfile, the compiler, the overlay triplets and the vcpkg binary
# cache are exactly build.sh's - the image is even tagged the same, so a machine that
# has run one has the image for the other - and the only thing that differs is the
# script run inside it: test-inside.sh instead of build-inside.sh. That file's header
# says why those two are deliberately not one script with a flag.
#
# Nothing is written to the source tree, which is mounted read-only, and nothing is
# copied out: this produces a verdict, not an artefact.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

case "$(uname -m)" in
    aarch64|arm64) HOST_ARCH=arm64 ;;
    *)             HOST_ARCH=amd64 ;;
esac
ARCH="${1:-${HOST_ARCH}}"

# Optional vcpkg binary cache, shared with the host, exactly as build.sh mounts it.
# Same directory, same key: the dependencies a release build restored are the ones
# this build wants.
CACHE_MOUNT=""
if [ -n "${VCPKG_BINARY_CACHE:-}" ]; then
    mkdir -p "${VCPKG_BINARY_CACHE}"
    CACHE_DIR="$(cd "${VCPKG_BINARY_CACHE}" && pwd)"
    CACHE_MOUNT="-v ${CACHE_DIR}:/vcpkg-cache -e VCPKG_DEFAULT_BINARY_CACHE=/vcpkg-cache"
    echo "vcpkg binary cache: ${CACHE_DIR}"
fi

PLATFORM="linux/${ARCH}"
TAG_NAME="lyxbosa-build-linux-${ARCH}"

echo "=== Building and running LyxBoSa tests for Linux (${ARCH}) ==="

echo "Building Docker image..."
docker buildx build \
    --platform "${PLATFORM}" \
    -t "${TAG_NAME}" \
    --load \
    -f "${SCRIPT_DIR}/Dockerfile" \
    "${SCRIPT_DIR}"

# The test script is taken from the mounted source rather than baked into the image,
# so that adding it did not change the Dockerfile and therefore did not rotate the
# cache key the workflow derives from it.
echo "Running tests inside container..."
docker run --rm \
    --platform "${PLATFORM}" \
    -v "${PROJECT_ROOT}:/src:ro" \
    ${CACHE_MOUNT} \
    --entrypoint /src/docker/build/Linux/test-inside.sh \
    "${TAG_NAME}"

echo ""
echo "=== Tests passed: Linux (${ARCH}) ==="
