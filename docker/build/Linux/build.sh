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

# Create output directory
mkdir -p "${OUTPUT_DIR}"

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
        -v "$(pwd)/${OUTPUT_DIR}:/output" \
        ${VERSION_ENV} \
        "${TAG_NAME}"

    # Rename binary with target suffix
    mv -f "${OUTPUT_DIR}/lyxbosa" "${OUTPUT_DIR}/${BINARY_NAME}"

    echo ""
    echo "=== Build complete: ${OUTPUT_DIR}/${BINARY_NAME} ==="
    file "${OUTPUT_DIR}/${BINARY_NAME}"
    echo ""
done
