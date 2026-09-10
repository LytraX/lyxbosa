#!/bin/bash
set -e

# The test build, inside the same container the release is built in.
#
# This is deliberately NOT build-inside.sh with BUILD_TESTS added. The two answer
# different questions and share everything except the configure:
#
#   build-inside.sh   "produce the binary that ships" - builds only what the release
#                     contains, copies one file out, and is what a v* tag runs.
#   test-inside.sh    "does this tree pass its tests" - builds the test target too,
#                     runs it, and ships nothing.
#
# Keeping them as two configures means a test-only switch can never leak into what
# is published, and a test failure can never be "fixed" by editing the release path.
# What they share on purpose is the part that costs money: the same image, the same
# GCC 12, the same overlay triplets and therefore the same vcpkg binary-cache
# entries. A test build configured any other way would miss the cache the release
# build filled and rebuild every dependency from source on every pull request.
#
# The tests run as an unprivileged user. The container is root, and root ignores
# permission bits, so every case about an unreadable file or directory would print
# "running as root ... no refusal can be observed" and skip - the exact cases this
# job exists to run, passing while blind. See tests/PlatformSkips.h.

source /opt/rh/gcc-toolset-12/enable

# Configure with the vcpkg toolchain and the release-only overlay triplets, exactly as
# build-inside.sh does, plus the tests. Release rather than Debug for the same cache
# reason: a Debug configure would want the debug halves of every dependency, which
# the overlay triplets do not build and the cache does not hold.
cmake -B /build-tests -S /src \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=ON \
    -DVCPKG_OVERLAY_TRIPLETS=/src/triplets \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake

# The CLI as well as the tests: on a pull request this is the only compile of
# src-cli/lyxbosa.cpp anywhere, and a main() that no longer builds is worth knowing
# before the tag.
cmake --build /build-tests

# ctest writes Testing/ under the build directory, so the user running it needs to
# own that directory; nothing else in the build tree is written to.
useradd --create-home --home-dir /home/tester tester
chown tester /build-tests

# Serial, and not because the machine is small. tests/scan_root_test.cpp names its
# scratch directory from a per-process counter and a hash of the temp directory,
# both of which are the same in every test process, so two of its cases running at
# once share a directory and one removes it under the other. Measured 2026-09-10:
# 4 of 284 fail under --parallel 56 and 284 of 284 pass serially, in 8 seconds.
# There is nothing here worth buying with a flaky run.
echo "=== Running tests as $(id -un tester) (uid $(id -u tester)) ==="
runuser -u tester -- env HOME=/home/tester \
    ctest --test-dir /build-tests \
          --output-on-failure \
          --timeout 300
