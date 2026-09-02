set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_PROVIDED_FORTRAN ON)

# Release-only: nothing here links the debug halves. See README.md.
set(VCPKG_BUILD_TYPE release)
