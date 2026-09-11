# Overlay triplets

These mirror vcpkg's built-in triplets of the same name and add two lines:

```cmake
set(VCPKG_BUILD_TYPE release)
set(VCPKG_ENV_PASSTHROUGH SOURCE_DATE_EPOCH)
```

Without the first, vcpkg builds a **debug and a release** copy of every dependency. The
release builds here never link the debug halves, so on the CI runners that was
277s of 742s on Windows and 105s of 234s on Linux spent producing artifacts that
are then thrown away.

They are applied only by the container and Windows build scripts, via
`VCPKG_OVERLAY_TRIPLETS`. Local development through the CMake presets keeps the
stock triplets, so a local debug build still gets debug dependencies.

The second is what makes a release rebuildable byte for byte. It puts the value of
`SOURCE_DATE_EPOCH` into vcpkg's ABI hash, so a dependency built under one epoch is
never restored for a request at another, and on Windows - where vcpkg scrubs the build
environment - it is also what lets the variable through at all. Each triplet file says
so at length. The value lives in `docker/build/source-date-epoch` and the procedure is
in `docs/RELEASING.md` under *Rebuilding a release*.

Keep these in step with upstream if the built-in definitions change; the rest of
each file is copied verbatim from `vcpkg/triplets/`.
