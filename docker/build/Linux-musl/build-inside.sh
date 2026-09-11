#!/bin/bash
set -e

# Build version override arg
VERSION_ARG=""
if [ -n "${LYXBOSA_VERSION}" ]; then
    VERSION_ARG="-DLYXBOSA_VERSION_OVERRIDE=${LYXBOSA_VERSION}"
fi

# Configure with the vcpkg toolchain and the same release-only overlay triplets the
# glibc build uses. What this configure adds is -static on the executable link: every
# vcpkg dependency is already a static library, and this makes the C and C++ runtimes
# static too, so the binary carries musl and libstdc++ inside it and needs nothing from
# the host it runs on.
#
# BUILD_TESTS=OFF because a release build compiles only what it ships; the test build
# is test-inside.sh, a separate configure, for the reasons its header gives.
cmake -B /build -S /src \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=OFF \
    -DCMAKE_EXE_LINKER_FLAGS=-static \
    -DVCPKG_OVERLAY_TRIPLETS=/src/triplets \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake \
    ${VERSION_ARG}

cmake --build /build

# The claim this image exists to make, checked where it is made: a binary that still
# has a dynamic section is not the thing described above, whatever the flags said.
if file /build/lyxbosa | grep -q "dynamically linked"; then
    echo "ERROR: /build/lyxbosa is dynamically linked" >&2
    file /build/lyxbosa >&2
    exit 1
fi

cp /build/lyxbosa /output/lyxbosa

echo "Build complete: /output/lyxbosa"
file /output/lyxbosa
