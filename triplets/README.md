# Overlay triplets

These mirror vcpkg's built-in triplets of the same name and add one line:

```cmake
set(VCPKG_BUILD_TYPE release)
```

Without it vcpkg builds a **debug and a release** copy of every dependency. The
release builds here never link the debug halves, so on the CI runners that was
277s of 742s on Windows and 105s of 234s on Linux spent producing artifacts that
are then thrown away.

They are applied only by the container and Windows build scripts, via
`VCPKG_OVERLAY_TRIPLETS`. Local development through the CMake presets keeps the
stock triplets, so a local debug build still gets debug dependencies.

Keep these in step with upstream if the built-in definitions change; the rest of
each file is copied verbatim from `vcpkg/triplets/`.
