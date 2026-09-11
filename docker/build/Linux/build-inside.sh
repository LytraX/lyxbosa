#!/bin/bash
set -e

# Enable GCC 12 for C++20 support
source /opt/rh/gcc-toolset-12/enable

# Build version override arg
VERSION_ARG=""
if [ -n "${LYXBOSA_VERSION}" ]; then
    VERSION_ARG="-DLYXBOSA_VERSION_OVERRIDE=${LYXBOSA_VERSION}"
fi

# Configure with vcpkg toolchain.
#
# The overlay triplets in /src/triplets are the stock ones plus
# VCPKG_BUILD_TYPE=release, so vcpkg does not also build a debug copy of every
# dependency that this release build would never link.
#
# BUILD_TESTS=OFF because a release build compiles only what it ships. It defaults to
# ON, so without this the release container built and linked the test binary on every
# release and pulled gtest into the graph to do it, for an artefact nobody downloads.
# The Windows script and the musl container both already pass it; this one was the odd
# one out. The test build is a separate configure - see the test jobs in
# .github/workflows/build.yml - so that a test-only switch can never leak into what is
# published.
cmake -B /build -S /src \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=OFF \
    -DVCPKG_OVERLAY_TRIPLETS=/src/triplets \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake \
    ${VERSION_ARG}

# Build
cmake --build /build

# Copy binary to output
cp /build/lyxbosa /output/lyxbosa

echo "Build complete: /output/lyxbosa"
