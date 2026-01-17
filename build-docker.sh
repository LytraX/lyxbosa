#!/bin/bash
set -e

# Default values
UBUNTU_VERSION="${1:-22.04}"
OUTPUT_DIR="${2:-./dist}"

# Derive tag name from version (e.g., "22.04" -> "ubuntu2204")
TAG_NAME="lyxbosa-build-ubuntu${UBUNTU_VERSION//./}"

echo "=== Building LyxBoSa for Ubuntu ${UBUNTU_VERSION} ==="

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Build the Docker image
echo "Building Docker image..."
docker build \
    --build-arg UBUNTU_VERSION="${UBUNTU_VERSION}" \
    -t "${TAG_NAME}" \
    -f docker/Dockerfile.ubuntu \
    .

# Run the build
echo "Running build inside container..."
docker run --rm \
    -v "$(pwd):/src:ro" \
    -v "$(pwd)/${OUTPUT_DIR}:/output" \
    "${TAG_NAME}"

# Rename binary with target suffix
BINARY_NAME="lyxbosa-ubuntu${UBUNTU_VERSION//./}"
mv "${OUTPUT_DIR}/lyxbosa" "${OUTPUT_DIR}/${BINARY_NAME}"

echo ""
echo "=== Build complete ==="
echo "Binary: ${OUTPUT_DIR}/${BINARY_NAME}"
file "${OUTPUT_DIR}/${BINARY_NAME}"
