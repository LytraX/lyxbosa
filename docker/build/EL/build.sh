#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Default values
EL_VERSION="${1:-8}"
ARCH="${2:-all}"
OUTPUT_DIR="${3:-./dist}"

if [ "${ARCH}" = "all" ]; then
    ARCHES=(amd64 arm64)
else
    ARCHES=("${ARCH}")
fi

# Create output directory
mkdir -p "${OUTPUT_DIR}"

for CURRENT_ARCH in "${ARCHES[@]}"; do
    PLATFORM="linux/${CURRENT_ARCH}"
    TAG_NAME="lyxbosa-build-el${EL_VERSION}-${CURRENT_ARCH}"
    BINARY_NAME="lyxbosa-el${EL_VERSION}-${CURRENT_ARCH}"

    echo "=== Building LyxBoSa for EL ${EL_VERSION} (${CURRENT_ARCH}) ==="

    # Build the Docker image
    echo "Building Docker image..."
    docker buildx build \
        --platform "${PLATFORM}" \
        --build-arg EL_VERSION="${EL_VERSION}" \
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
        "${TAG_NAME}"

    # Rename binary with target suffix
    mv -f "${OUTPUT_DIR}/lyxbosa" "${OUTPUT_DIR}/${BINARY_NAME}"

    echo ""
    echo "=== Build complete: ${OUTPUT_DIR}/${BINARY_NAME} ==="
    file "${OUTPUT_DIR}/${BINARY_NAME}"
    echo ""
done
