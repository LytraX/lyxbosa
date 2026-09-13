#!/bin/bash
set -e

# The build, inside the musl release container: one configure, the tests built with it,
# the tests run, and the binary that passed them copied out.
#
# The same shape as docker/build/Linux/build-inside.sh and for the same reasons; that
# file's header carries the measurement showing a test-only switch changes nothing in the
# published bytes, and the contract for LYXBOSA_RUN_TESTS. What differs here is the
# platform: a different C library, a different allocator and a different resolver, so a
# musl asset whose suite only ever ran on glibc would be shipping on an assumption.
#
# The test binary is linked -static and carries mimalloc, exactly as the shipped one is,
# because it IS the same configure: the update tests run the staged binary's smoke test
# for real, and a dynamically linked cousin of the release binary would not prove a static
# build passes that.

# What this image is, printed before anything is built - the same record the glibc
# container prints, and for the same reason: the base layer, the compiler and vcpkg are
# pinned, every other package is whatever the branch served on the day the image was built,
# and a rebuilder comparing two binaries needs somewhere to diff.
#
# No ABI floor is asserted here and that is not an omission: this binary is linked -static
# and needs nothing from any host, which is the whole reason it exists. What stands in its
# place is the dynamic-section check further down, which refuses a binary that acquired one.
if [ -r /etc/lyxbosa-builder-manifest ]; then
    head -3 /etc/lyxbosa-builder-manifest
    # The package lines are the indented ones. Counted rather than derived by subtracting
    # a header length, which would go quietly wrong the day the header gains a line.
    echo "packages: $(command grep -c '^  ' /etc/lyxbosa-builder-manifest) recorded in /etc/lyxbosa-builder-manifest"
else
    echo "no builder manifest in this image" >&2
    exit 1
fi

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
cmake -B /build -S /src \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=ON \
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

if [ "${LYXBOSA_RUN_TESTS:-1}" != "0" ]; then
    # Unprivileged, for the reason docker/build/Linux/build-inside.sh gives: root ignores
    # permission bits, so every case about an unreadable file would skip rather than run.
    # BusyBox's adduser and su, since Alpine ships neither useradd nor runuser.
    adduser -D -h /home/tester tester
    chown tester /build

    # One test process per CPU this container may use, for the reasons and on the condition
    # docker/build/Linux/build-inside.sh gives.
    TEST_JOBS="$(nproc)"
    echo "=== Running tests as $(id -un tester) (uid $(id -u tester)), ${TEST_JOBS} at a time ==="
    su tester -c "HOME=/home/tester ctest --test-dir /build --output-on-failure --timeout 300 --parallel ${TEST_JOBS}"
else
    echo "=== Tests not run in this container: ${LYXBOSA_TESTS_SKIPPED_BECAUSE:-caller asked for a build only} ==="
fi

# After the tests and never before: a binary whose suite failed must not reach the
# directory the release job collects from.
cp /build/lyxbosa /output/lyxbosa

echo "Build complete: /output/lyxbosa"
file /output/lyxbosa
