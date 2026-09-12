# x64-linux-fuzz - the dependency triplet for the sanitizer/fuzzer build.
#
# Same as x64-linux, plus one thing: the C parsers this project hands attacker-controlled
# bytes to are compiled WITH the sanitizers and with SanitizerCoverage.
#
# Both halves of that matter and they are separate facts. AddressSanitizer only reports an
# out-of-bounds access when the code performing the access was instrumented - the redzone
# around an allocation is checked by the instrumented load, not by the allocator - so an
# uninstrumented libzip can read off the end of a heap buffer and ASan will say nothing
# unless the read happens to reach an unmapped page. And libFuzzer steers by coverage, so
# an uninstrumented parser is a black box: the fuzzer gets no signal for finding a new
# branch inside the very code it is aimed at.
#
# Only the parsers, and deliberately. OpenSSL and curl are in this graph for `update`,
# which no fuzz target calls; instrumenting them costs build time and buys nothing, and
# OpenSSL's Configure is the port most likely to object to injected flags. The PORT
# variable is set by vcpkg while each port is built, which is what makes a per-port
# decision expressible here at all.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_CMAKE_SYSTEM_NAME Linux)

set(VCPKG_BUILD_TYPE release)

if(PORT MATCHES "^(zlib|libzip|re2|abseil|bzip2|liblzma|zstd)$")
  set(_lyxbosa_fuzz_flags
      "-fsanitize=address,undefined -fsanitize=fuzzer-no-link -fno-omit-frame-pointer -fno-sanitize-recover=undefined -g -O1")
  set(VCPKG_C_FLAGS "${_lyxbosa_fuzz_flags}")
  set(VCPKG_CXX_FLAGS "${_lyxbosa_fuzz_flags}")
  set(VCPKG_LINKER_FLAGS "-fsanitize=address,undefined")
endif()
