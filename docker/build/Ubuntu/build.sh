#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Default values
UBUNTU_VERSION="${1:-20.04}"
OUTPUT_DIR="${2:-./dist}"

# Create output directory
mkdir -p "${OUTPUT_DIR}"

for ARCH in amd64 arm64; do
    PLATFORM="linux/${ARCH}"
    TAG_NAME="lyxbosa-build-ubuntu${UBUNTU_VERSION//./}-${ARCH}"
    BINARY_NAME="lyxbosa-ubuntu${UBUNTU_VERSION//./}-${ARCH}"

    echo "=== Building LyxBoSa for Ubuntu ${UBUNTU_VERSION} (${ARCH}) ==="

    # Build the Docker image
    echo "Building Docker image..."
    docker buildx build \
        --platform "${PLATFORM}" \
        --build-arg UBUNTU_VERSION="${UBUNTU_VERSION}" \
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
