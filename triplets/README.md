# Overlay triplets

Four of these five mirror vcpkg's built-in triplets of the same name and add two lines
(`x64-linux-fuzz.cmake` is the exception, described at the end):

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

`x64-linux-fuzz.cmake` mirrors nothing: vcpkg has no built-in triplet of that name. It is
`x64-linux` plus AddressSanitizer, UndefinedBehaviorSanitizer and SanitizerCoverage on the
parsers alone — zlib, libzip, re2, abseil and the compression ports under them — because ASan
reports an out-of-bounds access only when the code performing it was instrumented, and
libFuzzer cannot steer through a parser whose coverage it cannot see. It carries no
`VCPKG_ENV_PASSTHROUGH`, because nothing about a fuzz build is reproduced byte for byte. It
is used only by `docker/fuzz/`; see `docs/FUZZING.md`.

Keep the other four in step with upstream if the built-in definitions change; the rest of
each of those files is copied verbatim from `vcpkg/triplets/`.
