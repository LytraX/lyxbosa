set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_PROVIDED_FORTRAN ON)

# Release-only: nothing here links the debug halves. See README.md.
set(VCPKG_BUILD_TYPE release)

# SOURCE_DATE_EPOCH reaches the port builds, and its value is part of vcpkg's ABI hash.
#
# Both halves are needed and they are separate facts. On Linux the variable already
# reaches a port build without being declared - but untracked, so a cache entry built
# under one epoch is restored for a request at another and the pin never touches the
# bytes: measured, an epoch-B build handed back the epoch-A artifact. Declaring it here
# puts the VALUE in the hash, so changing the epoch rebuilds and returning to an earlier
# one restores. On Windows vcpkg scrubs the environment, so this line is also what lets
# the variable through at all.
#
# What reads it is OpenSSL: util/mkbuildinf.pl stamps gmtime(SOURCE_DATE_EPOCH) into the
# version banner that libcrypto carries, and the GNU build ID then moves because it is a
# hash over the link inputs. docs/RELEASING.md, under "Rebuilding a release", is the
# procedure and the measurements.
set(VCPKG_ENV_PASSTHROUGH SOURCE_DATE_EPOCH)
