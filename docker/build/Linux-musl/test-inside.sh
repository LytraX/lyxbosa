#!/bin/bash
set -e

# The test build, inside the same container the musl release is built in.
#
# The same shape as docker/build/Linux/test-inside.sh, and for the same reasons: a second
# configure of the same tree in the same image, with BUILD_TESTS=ON, run as an
# unprivileged user so that the cases about unreadable files are observed rather than
# skipped as root. That file's header carries the argument for keeping the test build
# and the release build as two configures; it is not repeated here.
#
# What differs from the glibc one is what differs about the platform. -static on the
# link, exactly as build-inside.sh passes it, because the test binary should be the
# thing being shipped and not a dynamically linked cousin of it: the update tests run
# the staged binary's smoke test for real, and a static test binary is what proves a
# static build passes that. And the unprivileged user is made with BusyBox's adduser
# and run with its su, since Alpine ships neither useradd nor runuser.

cmake -B /build-tests -S /src \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXE_LINKER_FLAGS=-static \
    -DBUILD_TESTS=ON \
    -DVCPKG_OVERLAY_TRIPLETS=/src/triplets \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake

cmake --build /build-tests

adduser -D -h /home/tester tester
chown tester /build-tests

# Serial, for the reason docker/build/Linux/test-inside.sh gives: scan_root_test names
# its scratch directory the same way in every process, so two of its cases running at
# once share a directory.
echo "=== Running tests as $(id -un tester) (uid $(id -u tester)) ==="
su tester -c "HOME=/home/tester ctest --test-dir /build-tests --output-on-failure --timeout 300"
