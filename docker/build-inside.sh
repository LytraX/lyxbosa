#!/bin/bash
set -e

# Configure with vcpkg toolchain
cmake -B /build -S /src \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake

# Build
cmake --build /build

# Copy binary to output
cp /build/lyxbosa /output/lyxbosa

echo "Build complete: /output/lyxbosa"
