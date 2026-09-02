#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Default values
ARCH="${1:-all}"
OUTPUT_DIR="${2:-./dist}"
VERSION="${3:-}"

if [ "${ARCH}" = "all" ]; then
    ARCHES=(amd64 arm64)
else
    ARCHES=("${ARCH}")
fi

# Build version args for docker run
VERSION_ENV=""
if [ -n "${VERSION}" ]; then
    VERSION_ENV="-e LYXBOSA_VERSION=${VERSION}"
fi

# Optional vcpkg binary cache, shared with the host so CI can persist it between
# runs. vcpkg keys every entry by an ABI hash covering the port version, triplet,
# compiler and dependency hashes, so a stale or partial cache can only cause a
# rebuild - never a wrong binary.
CACHE_MOUNT=""
if [ -n "${VCPKG_BINARY_CACHE:-}" ]; then
    mkdir -p "${VCPKG_BINARY_CACHE}"
    CACHE_DIR="$(cd "${VCPKG_BINARY_CACHE}" && pwd)"
    CACHE_MOUNT="-v ${CACHE_DIR}:/vcpkg-cache -e VCPKG_DEFAULT_BINARY_CACHE=/vcpkg-cache"
    echo "vcpkg binary cache: ${CACHE_DIR}"
fi

# Create the output directory and resolve it to an absolute path.
#
# docker -v needs an absolute source, and the default "./dist" is relative, so this
# used to be spelled "$(pwd)/${OUTPUT_DIR}" at the mount. That silently produced
# nonsense for an absolute argument - "/out" became "$(pwd)//out". Resolving once
# here keeps relative paths behaving exactly as before, relative to the working
# directory, and makes absolute ones work too.
mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"

for CURRENT_ARCH in "${ARCHES[@]}"; do
    PLATFORM="linux/${CURRENT_ARCH}"
    TAG_NAME="lyxbosa-build-linux-${CURRENT_ARCH}"
    BINARY_NAME="lyxbosa-linux-${CURRENT_ARCH}"

    echo "=== Building LyxBoSa for Linux (${CURRENT_ARCH}) ==="

    # Build the Docker image
    echo "Building Docker image..."
    docker buildx build \
        --platform "${PLATFORM}" \
        -t "${TAG_NAME}" \
        --load \
        -f "${SCRIPT_DIR}/Dockerfile" \
        "${SCRIPT_DIR}"

    # Run the build
    echo "Running build inside container..."
    docker run --rm \
        --platform "${PLATFORM}" \
        -v "${PROJECT_ROOT}:/src:ro" \
        -v "${OUTPUT_DIR}:/output" \
        ${CACHE_MOUNT} \
        ${VERSION_ENV} \
        "${TAG_NAME}"

    # Rename binary with target suffix
    mv -f "${OUTPUT_DIR}/lyxbosa" "${OUTPUT_DIR}/${BINARY_NAME}"

    echo ""
    echo "=== Build complete: ${OUTPUT_DIR}/${BINARY_NAME} ==="
    file "${OUTPUT_DIR}/${BINARY_NAME}"
    echo ""
done
