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
# And the allocator. musl's is deliberately small and simple, and a scan is malloc-heavy
# enough for that to cost about 40% of the throughput the glibc build of the same commit
# gets on the same tree - which is the whole reason there are still two Linux assets.
# mimalloc replaces it. Two flags rather than one because they act at different times:
# VCPKG_MANIFEST_FEATURES puts mimalloc in the dependency graph before the toolchain
# resolves anything, and LYXBOSA_BUNDLED_ALLOCATOR is what CMakeLists.txt reads
# afterwards to link it. Neither is inferred from the C library; the check below is what
# makes sure they were both actually passed.
#
# BUILD_TESTS=OFF because a release build compiles only what it ships; the test build
# is test-inside.sh, a separate configure, for the reasons its header gives.
cmake -B /build -S /src \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=OFF \
    -DCMAKE_EXE_LINKER_FLAGS=-static \
    -DVCPKG_OVERLAY_TRIPLETS=/src/triplets \
    -DVCPKG_MANIFEST_FEATURES=bundled-allocator \
    -DLYXBOSA_BUNDLED_ALLOCATOR=ON \
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

# The other claim, checked the same way and for a sharper reason. A static override of
# malloc is a link-order property: mimalloc can be in the dependency graph, compile, link
# and export its symbols while every allocation in the binary still goes to musl's
# allocator, and nothing about that build fails. The binary would then be shipped as the
# fast one and be the slow one. So the allocator is observed running rather than found
# linked: MIMALLOC_VERBOSE makes mimalloc announce itself during its own initialisation,
# which only happens if it is the allocator this process is using.
if ! MIMALLOC_VERBOSE=1 /build/lyxbosa --version 2>&1 | grep -q "mimalloc"; then
    echo "ERROR: /build/lyxbosa does not run on mimalloc - malloc was not overridden" >&2
    MIMALLOC_VERBOSE=1 /build/lyxbosa --version >&2 2>&1 || true
    exit 1
fi
echo "Allocator: mimalloc, observed announcing itself under MIMALLOC_VERBOSE"

cp /build/lyxbosa /output/lyxbosa

echo "Build complete: /output/lyxbosa"
file /output/lyxbosa
