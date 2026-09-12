#!/bin/bash
set -e

# The build, inside the release container: one configure, the tests built with it, the
# tests run, and the binary that passed them copied out.
#
# ONE CONFIGURE, NOT TWO
# ----------------------
# The flag this deliberately does not pass is BUILD_TESTS=OFF, and the reason is measured
# rather than argued. The same commit, built at the same version in this container with
# the tests ON and with them OFF, produces binaries differing by 24 bytes out of
# 11,282,152, and .text is byte-identical. Twenty of those bytes are the GNU build ID and
# four a timestamp inside OpenSSL's own version banner, which the vcpkg-built libcrypto
# embeds and from which the build ID then derives - two builds at different times differ
# the same way with the flag held constant. Nothing a test-only switch does reaches the
# published bytes.
#
# So compiling the tree twice bought build time, not isolation, and it bought it at the
# price of shipping a binary that no suite had ever been run against. Built this way the
# binary that is tested is the binary that ships, and a suite that fails stops the copy
# below rather than being reported beside a release that went out anyway.
#
# WHETHER THE TESTS RUN
# ---------------------
# LYXBOSA_RUN_TESTS decides, and build.sh sets it: 0 when the caller asked for an
# architecture this machine cannot execute without emulation, 1 otherwise. It changes
# nothing about how the binary is built - that is the same configure either way - only
# whether this container can run what it just produced. Unset means run, so a caller that
# forgets the variable gets a slow suite rather than a silent skip.

# What this image is, printed before anything is built. The Dockerfile pins the base layer
# by digest, the compiler by its exact release and vcpkg by commit; every other package is
# whatever dnf resolved on the day the image was built, and the manifest is the record of
# that. Two builds that disagree have somewhere to be diffed, and a rebuilder reading a log
# can see which toolchain produced the file they are holding.
if [ -r /etc/lyxbosa-builder-manifest ]; then
    head -3 /etc/lyxbosa-builder-manifest
    # The package lines are the indented ones. Counted rather than derived by subtracting
    # a header length, which would go quietly wrong the day the header gains a line.
    echo "packages: $(command grep -c '^  ' /etc/lyxbosa-builder-manifest) recorded in /etc/lyxbosa-builder-manifest"
else
    echo "no builder manifest in this image" >&2
    exit 1
fi

source /opt/rh/gcc-toolset-12/enable

# Build version override arg
VERSION_ARG=""
if [ -n "${LYXBOSA_VERSION}" ]; then
    VERSION_ARG="-DLYXBOSA_VERSION_OVERRIDE=${LYXBOSA_VERSION}"
fi

# Configure with vcpkg toolchain.
#
# The overlay triplets in /src/triplets are the stock ones plus VCPKG_BUILD_TYPE=release,
# so vcpkg does not also build a debug copy of every dependency that this release build
# would never link. Release rather than Debug for the same reason: a Debug configure wants
# the debug halves of every dependency, which the overlay triplets do not build and the
# binary cache does not hold.
cmake -B /build -S /src \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=ON \
    -DVCPKG_OVERLAY_TRIPLETS=/src/triplets \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake \
    ${VERSION_ARG}

# The CLI and the test binary in one build.
cmake --build /build

# The floor README.md publishes, asserted on the binary that is about to be copied out.
# AlmaLinux 8 is the only reason "glibc 2.28 or newer" is true, and a base image bumped to
# a newer distribution would strand every host the standard build exists for without one
# line of this build failing. See docker/build/abi-floor.sh for both directions of it.
abi-floor /build/lyxbosa

if [ "${LYXBOSA_RUN_TESTS:-1}" != "0" ]; then
    # The tests run as an unprivileged user. The container is root, and root ignores
    # permission bits, so every case about an unreadable file or directory would print
    # "running as root ... no refusal can be observed" and skip - the exact cases this
    # run exists to exercise, passing while blind. See tests/PlatformSkips.h.
    #
    # ctest writes Testing/ under the build directory, so the user running it needs to own
    # that directory; nothing else in the build tree is written to.
    useradd --create-home --home-dir /home/tester tester
    chown tester /build

    # Serial, and not because the machine is small. tests/scan_root_test.cpp names its
    # scratch directory from a per-process counter and a hash of the temp directory, both
    # of which are the same in every test process, so two of its cases running at once
    # share a directory and one removes it under the other. Measured 2026-09-10: 4 of 284
    # fail under --parallel 56 and 284 of 284 pass serially, in 8 seconds. There is
    # nothing here worth buying with a flaky run.
    echo "=== Running tests as $(id -un tester) (uid $(id -u tester)) ==="
    runuser -u tester -- env HOME=/home/tester \
        ctest --test-dir /build \
              --output-on-failure \
              --timeout 300
else
    echo "=== Tests not run in this container: ${LYXBOSA_TESTS_SKIPPED_BECAUSE:-caller asked for a build only} ==="
fi

# After the tests and never before: a binary whose suite failed must not reach the
# directory the release job collects from.
cp /build/lyxbosa /output/lyxbosa

echo "Build complete: /output/lyxbosa"
