#!/bin/bash
set -e

# Enable GCC 12 for C++20 support
source /opt/rh/gcc-toolset-12/enable

# Build version override arg
VERSION_ARG=""
if [ -n "${LYXBOSA_VERSION}" ]; then
    VERSION_ARG="-DLYXBOSA_VERSION_OVERRIDE=${LYXBOSA_VERSION}"
fi

# Configure with vcpkg toolchain
cmake -B /build -S /src \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake \
    ${VERSION_ARG}

# Build
cmake --build /build

# Copy binary to output
cp /build/lyxbosa /output/lyxbosa

echo "Build complete: /output/lyxbosa"
