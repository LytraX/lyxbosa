cmake_minimum_required(VERSION 3.16)

project(LyxBoSa VERSION 0.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set default build type if not specified
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose the type of build" FORCE)
endif()

# Define build type macros
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_definitions(LYXBOSA_DEBUG)
else()
  add_compile_definitions(LYXBOSA_RELEASE)
endif()

# Version: use LYXBOSA_VERSION_OVERRIDE if provided (e.g., from CI tag), otherwise PROJECT_VERSION
if(DEFINED LYXBOSA_VERSION_OVERRIDE)
  set(LYXBOSA_VER_STRING "${LYXBOSA_VERSION_OVERRIDE}")
else()
  set(LYXBOSA_VER_STRING "${PROJECT_VERSION}")
endif()

add_compile_definitions(LYXBOSA_VERSION="${LYXBOSA_VER_STRING}")
message(STATUS "Version: ${LYXBOSA_VER_STRING}")

# Parse version components for Windows resource file
string(REPLACE "." ";" _VERSION_LIST "${LYXBOSA_VER_STRING}")
list(GET _VERSION_LIST 0 LYXBOSA_VER_MAJOR)
list(GET _VERSION_LIST 1 LYXBOSA_VER_MINOR)
list(GET _VERSION_LIST 2 LYXBOSA_VER_PATCH)

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Prevent Windows.h min/max macros from breaking std::min/std::max
if(MSVC)
  add_compile_definitions(NOMINMAX)
endif()

# Find vcpkg packages
find_package(fmt CONFIG REQUIRED)
find_package(argparse CONFIG REQUIRED)
find_package(yaml-cpp CONFIG REQUIRED)
find_package(reflectcpp CONFIG REQUIRED)
find_package(re2 CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(libzip CONFIG REQUIRED)
find_package(Threads REQUIRED)
# HTTPS for `update --check`. vcpkg.json pins the feature set to `ssl` with
# default-features off - see src-lib/cpp/update/HttpTransport.cpp for why that is the
# whole of the dependency, and what it costs.
find_package(CURL CONFIG REQUIRED)

# Ed25519, BLAKE2b-512 and SHA-256 for `lyxbosa update`: the signature over SHA256SUMS,
# and the hash of the asset that list describes.
#
# REQUIRED on every platform, and not optional anywhere. On Linux and macOS the `ssl`
# feature of curl above already builds OpenSSL, so this finds a library that is in the
# build either way. On Windows curl uses Schannel for TLS and would build no OpenSSL of
# its own, so vcpkg.json names openssl as a dependency in its own right there: libcrypto
# only, for the three primitives above, linked statically like everything else. The TLS
# stack and the certificate store on Windows stay the OS's - HttpTransport.cpp says why -
# and the verifier is the same Minisign.cpp on every platform rather than a second crypto
# path nobody exercises.
#
# A quiet find that silently disabled verification would be the worst outcome: it would
# ship a binary whose updater refuses for a reason nobody chose, and nothing would say so.
# LYXBOSA_UPDATE_VERIFY is therefore always ON; the `#ifndef` arms it guards in
# Minisign.cpp and Checksums.cpp are what a build without a verifier owes - refuse,
# never accept - and no configuration this file produces is one.
find_package(OpenSSL REQUIRED)
set(LYXBOSA_UPDATE_VERIFY ON)
message(STATUS "Update verification: OpenSSL ${OPENSSL_VERSION} (Ed25519, BLAKE2b-512)")

# Which C library a Linux binary is built against decides which release asset it is,
# and so which asset `lyxbosa update` fetches: a glibc build publishes as
# lyxbosa-linux-<arch> and a musl build as lyxbosa-linux-<arch>-musl, and
# ReleaseAssets.cpp says why neither ever fetches the other. The compiler's target
# triple is what says which - Alpine's gcc reports x86_64-alpine-linux-musl, AlmaLinux's
# x86_64-redhat-linux - and it is read here and handed to the code as a definition
# rather than sniffed from a macro in the source, because musl deliberately defines no
# macro of its own. tests/update_apply_test.cpp checks the result against __GLIBC__, so
# a build where this detection and the headers disagree fails its tests rather than
# naming the wrong asset.
set(LYXBOSA_LIBC_MUSL OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  execute_process(
    COMMAND ${CMAKE_CXX_COMPILER} -dumpmachine
    OUTPUT_VARIABLE LYXBOSA_TARGET_TRIPLE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE _dumpmachine_result
  )
  if(NOT _dumpmachine_result EQUAL 0)
    message(FATAL_ERROR "${CMAKE_CXX_COMPILER} -dumpmachine failed; the C library of a "
                        "Linux build decides its release asset name and cannot be guessed")
  endif()
  if(LYXBOSA_TARGET_TRIPLE MATCHES "musl")
    set(LYXBOSA_LIBC_MUSL ON)
    message(STATUS "Linux C library: musl (${LYXBOSA_TARGET_TRIPLE}); "
                   "release asset lyxbosa-linux-<arch>-musl")
  else()
    message(STATUS "Linux C library: glibc (${LYXBOSA_TARGET_TRIPLE}); "
                   "release asset lyxbosa-linux-<arch>")
  endif()
endif()

# The allocator the binary carries, if it carries one.
#
# musl's allocator is deliberately small and simple, and a scan is malloc-heavy: over
# 53,977 files the static musl build ran about 40% slower than the glibc build of the
# same commit, on the same tree, with the cache warm. That difference is the allocator
# and not the C library in general, and it is the only thing that stops one Linux binary
# from being the binary everybody gets. mimalloc carries its own free lists and heaps, is
# built with MI_OVERRIDE so the ordinary malloc, free, new and delete entry points are
# its own, and links into a static binary with nothing to load at run time.
#
# OFF by default and never inferred from the C library. The C library is detected here,
# but the vcpkg feature that puts mimalloc in the dependency graph has to be selected on
# the configure command line before this file runs at all, so a build that turned this on
# by itself would fail to find a package nobody asked vcpkg to build.
# docker/build/Linux-musl/build-inside.sh passes both halves together, and checks the
# binary it produced actually runs on the allocator rather than trusting that it linked.
option(LYXBOSA_BUNDLED_ALLOCATOR
       "Link mimalloc into the binary in place of the C library's allocator" OFF)

if(LYXBOSA_BUNDLED_ALLOCATOR)
  find_package(mimalloc CONFIG REQUIRED)
  # The port builds whichever of the two linkages the triplet asks for and exports the
  # matching target; every triplet here is static, so mimalloc-static is what exists.
  if(TARGET mimalloc-static)
    set(LYXBOSA_ALLOCATOR_TARGET mimalloc-static)
  elseif(TARGET mimalloc)
    set(LYXBOSA_ALLOCATOR_TARGET mimalloc)
  else()
    message(FATAL_ERROR "mimalloc was found but exports neither mimalloc-static nor "
                        "mimalloc: nothing would be linked and the binary would quietly "
                        "keep the C library's allocator")
  endif()
  message(STATUS "Allocator: mimalloc (${LYXBOSA_ALLOCATOR_TARGET}), overriding malloc")
endif()

# Link the bundled allocator into an executable, if there is one. A function for the
# same reason lyxbosa_configure_update is one: the CLI and the test binary must not
# drift apart on it, because a test suite running on a different allocator from the
# shipped binary is a suite that cannot see an allocator's effects at all.
function(lyxbosa_configure_allocator target)
  if(LYXBOSA_BUNDLED_ALLOCATOR)
    target_link_libraries(${target} PRIVATE ${LYXBOSA_ALLOCATOR_TARGET})
  endif()
endfunction()

# The keys a released binary trusts, compiled in from the one file that
# keys/minisign-trusted.txt's header, docs/RELEASING.md and release-sign.sh all describe.
# A verifier that read its keyring from disk at run time would be a verifier an attacker
# with write access to that disk can edit.
set(LYXBOSA_KEYRING_FILE "${CMAKE_SOURCE_DIR}/keys/minisign-trusted.txt"
    CACHE FILEPATH "minisign keys compiled into the binary")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${LYXBOSA_KEYRING_FILE}")
if(NOT EXISTS "${LYXBOSA_KEYRING_FILE}")
  message(FATAL_ERROR "no keyring at ${LYXBOSA_KEYRING_FILE}")
endif()
file(READ "${LYXBOSA_KEYRING_FILE}" LYXBOSA_KEYRING_TEXT)
# The text is embedded in a raw string literal; a file containing the closing delimiter
# would end the literal early and compile as something else entirely.
if(LYXBOSA_KEYRING_TEXT MATCHES "\\)LYXBOSAKEYS\"")
  message(FATAL_ERROR "${LYXBOSA_KEYRING_FILE} contains the raw-string delimiter")
endif()
configure_file(
  ${CMAKE_SOURCE_DIR}/cmake/EmbeddedKeyring.h.in
  ${CMAKE_BINARY_DIR}/generated/update/EmbeddedKeyring.h
  @ONLY
)

# Point both update origins at a server on this machine, so docs/local/demo-update.sh can
# show a real download, a real verification and a real replacement without a release being
# cut. OFF everywhere a release is built, and the code that reads the variable is not
# compiled at all when it is off. It cannot make an unverified binary install - the
# keyring is compiled in - and src-lib/cpp/update/ReleaseAssets.h says why at length.
option(LYXBOSA_UPDATE_TEST_ORIGIN "Honour $LYXBOSA_UPDATE_ORIGIN (local demos only)" OFF)
if(LYXBOSA_UPDATE_TEST_ORIGIN)
  message(WARNING "LYXBOSA_UPDATE_TEST_ORIGIN is ON: this build reads "
                  "$LYXBOSA_UPDATE_ORIGIN instead of github.com. Never release it.")
endif()

# The full-screen terminal UI. Off-switch for minimal/static builds (docker/,
# dist/), which then fall back to the plain stderr progress line.
option(LYXBOSA_TUI "Build the full-screen terminal UI (FTXUI)" ON)
if(LYXBOSA_TUI)
  find_package(ftxui CONFIG REQUIRED)
  message(STATUS "Full-screen UI: enabled (FTXUI)")
else()
  message(STATUS "Full-screen UI: disabled")
endif()

# Rule sources
set(RULE_SOURCES
    src-lib/cpp/rules/webshell.cpp
    src-lib/cpp/rules/code_exec.cpp
    src-lib/cpp/rules/obfuscation.cpp
    src-lib/cpp/rules/backdoor.cpp
    src-lib/cpp/rules/phishing.cpp
    src-lib/cpp/rules/credential_theft.cpp
    src-lib/cpp/rules/dropper.cpp
    src-lib/cpp/rules/exploit.cpp
    src-lib/cpp/rules/seo_spam.cpp
    src-lib/cpp/rules/defacement.cpp
    src-lib/cpp/rules/perl.cpp
    src-lib/cpp/rules/archive.cpp
)

# Collect library sources from src-lib
set(LIB_SOURCES
    src-lib/cpp/infrastructure/Console.cpp
    src-lib/cpp/analysis/StringAssembly.cpp
    src-lib/cpp/config/Config.cpp
    src-lib/cpp/patterns/StringPattern.cpp
    src-lib/cpp/patterns/RegexPattern.cpp
    src-lib/cpp/patterns/HeuristicPattern.cpp
    src-lib/cpp/core/Rule.cpp
    src-lib/cpp/core/FileWalker.cpp
    src-lib/cpp/core/MatchEngine.cpp
    src-lib/cpp/core/Scanner.cpp
    src-lib/cpp/archive/ArchiveFormat.cpp
    src-lib/cpp/archive/ArchiveIndex.cpp
    src-lib/cpp/archive/ArchiveScanner.cpp
    src-lib/cpp/archive/TarReader.cpp
    src-lib/cpp/archive/ZipReader.cpp
    ${RULE_SOURCES}
)

# The update check. Deliberately not in LIB_SOURCES: the regex benchmark builds that
# list and has no reason to link an HTTP client.
set(UPDATE_SOURCES
    src-lib/cpp/update/UpdateState.cpp
    src-lib/cpp/update/UpdateCheck.cpp
    src-lib/cpp/update/HttpTransport.cpp
    src-lib/cpp/update/HttpVersionSource.cpp
    src-lib/cpp/update/Minisign.cpp
    src-lib/cpp/update/Checksums.cpp
    src-lib/cpp/update/InstallPath.cpp
    src-lib/cpp/update/ReleaseAssets.cpp
    src-lib/cpp/update/UpdateApply.cpp
)

# Everything the update sources need beyond the library's own dependencies, in one place
# so the CLI and the test binary cannot drift apart on it.
function(lyxbosa_configure_update target)
  target_include_directories(${target} PRIVATE ${CMAKE_BINARY_DIR}/generated)
  target_link_libraries(${target} PRIVATE CURL::libcurl)
  if(LYXBOSA_UPDATE_VERIFY)
    target_link_libraries(${target} PRIVATE OpenSSL::Crypto)
    target_compile_definitions(${target} PRIVATE LYXBOSA_UPDATE_VERIFY)
  endif()
  if(LYXBOSA_UPDATE_TEST_ORIGIN)
    target_compile_definitions(${target} PRIVATE LYXBOSA_UPDATE_TEST_ORIGIN)
  endif()
  if(LYXBOSA_LIBC_MUSL)
    target_compile_definitions(${target} PRIVATE LYXBOSA_LIBC_MUSL)
  endif()
endfunction()

# Windows version resource
if(WIN32)
  configure_file(
    ${CMAKE_SOURCE_DIR}/src-cli/lyxbosa.rc.in
    ${CMAKE_BINARY_DIR}/lyxbosa.rc
    @ONLY
  )
  set(WIN_RC_FILE ${CMAKE_BINARY_DIR}/lyxbosa.rc)
endif()

# Windows application manifest.
#
# A process opens a path at or past MAX_PATH (260) with the ordinary Win32 calls that
# std::filesystem and std::ifstream make only if Windows has been told twice: the
# LongPathsEnabled value in the registry, which is the machine's to set, and a
# longPathAware entry in the executable's manifest, which is ours. Without the manifest
# the scanner could not open fifteen files in the stock CMS trees, at 260 to 271
# characters, on a machine whose registry value was on - while Python, which ships the
# entry, opened every one of them.
#
# One function for every executable, the way lyxbosa_configure_update is, so the release
# binary and the test binary cannot drift apart on it: a manifest present in only one of
# them is a fix nobody can test. CMake merges a `.manifest` source into the
# linker-generated manifest with mt.exe (release notes, 3.4) under the Visual Studio
# generator that build.ps1 and test.ps1 use and under Ninja alike. Nothing here reaches
# a non-MSVC build: the source is not even listed.
set(LYXBOSA_WIN_MANIFEST ${CMAKE_SOURCE_DIR}/cmake/lyxbosa.manifest)
function(lyxbosa_configure_windows_exe target)
  if(MSVC)
    target_sources(${target} PRIVATE ${LYXBOSA_WIN_MANIFEST})
  endif()
endfunction()

# Create the CLI executable
add_executable(lyxbosa
    src-cli/lyxbosa.cpp
    ${LIB_SOURCES}
    ${UPDATE_SOURCES}
    ${WIN_RC_FILE}
)
lyxbosa_configure_windows_exe(lyxbosa)

target_include_directories(lyxbosa PRIVATE
    ${CMAKE_SOURCE_DIR}/src-lib/cpp
    ${CMAKE_SOURCE_DIR}/src-cli
)

target_link_libraries(lyxbosa
  PRIVATE
    fmt::fmt
    argparse::argparse
    yaml-cpp::yaml-cpp
    reflectcpp::reflectcpp
    re2::re2
    libzip::zip
    ZLIB::ZLIB
    Threads::Threads
)
lyxbosa_configure_update(lyxbosa)
lyxbosa_configure_allocator(lyxbosa)

if(LYXBOSA_TUI)
  target_link_libraries(lyxbosa PRIVATE ftxui::screen ftxui::dom ftxui::component)
  target_compile_definitions(lyxbosa PRIVATE LYXBOSA_TUI_ENABLED)
endif()

# Benchmarks (opt-in). Compares the regex engines against the live rule set;
# see docs/results/regex-engine-benchmark-2026-09-02.md.
#
# Hyperscan is not a project dependency - it is x86-only, pulls ~88 transitive
# ports, and the scanner does not need it to run. If it happens to be available
# the benchmark picks it up, otherwise it builds with RE2 and RE2::Set only.
option(LYXBOSA_BENCHMARKS "Build the regex engine benchmark" OFF)
if(LYXBOSA_BENCHMARKS)
  add_executable(lyxbosa_bench_regex benchmarks/regex_engines.cpp ${LIB_SOURCES})
  lyxbosa_configure_windows_exe(lyxbosa_bench_regex)
  target_include_directories(lyxbosa_bench_regex PRIVATE
    ${CMAKE_SOURCE_DIR}/src-lib/cpp
    ${CMAKE_SOURCE_DIR}/src-cli
  )
  target_link_libraries(lyxbosa_bench_regex PRIVATE
    fmt::fmt yaml-cpp::yaml-cpp re2::re2 libzip::zip ZLIB::ZLIB Threads::Threads
  )
  find_path(HYPERSCAN_INCLUDE_DIR hs/hs.h)
  find_library(HYPERSCAN_LIBRARY NAMES hs libhs)
  if(HYPERSCAN_INCLUDE_DIR AND HYPERSCAN_LIBRARY)
    target_include_directories(lyxbosa_bench_regex PRIVATE ${HYPERSCAN_INCLUDE_DIR})
    target_link_libraries(lyxbosa_bench_regex PRIVATE ${HYPERSCAN_LIBRARY})
    target_compile_definitions(lyxbosa_bench_regex PRIVATE LYXBOSA_HAVE_HYPERSCAN)
    message(STATUS "Regex benchmark: RE2, RE2::Set and Hyperscan")
  else()
    message(STATUS "Regex benchmark: RE2 and RE2::Set (Hyperscan not found)")
  endif()
endif()

# Testing
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
  enable_testing()
  find_package(GTest CONFIG REQUIRED)

  # tests/test_main.cpp rather than GTest::gtest_main: the test binary answers --version
  # like the scanner does, so that the smoke test in InstallPath.cpp has a real
  # executable to run on a platform where a shell script is not one, and it can hold
  # its own image open so that replacing a RUNNING binary is observed rather than
  # reasoned about. The file says which arguments do what.
  add_executable(lyxbosa_tests
    tests/test_main.cpp
    tests/rules_test.cpp
    tests/path_filter_test.cpp
    tests/location_prior_test.cpp
    tests/annotation_test.cpp
    tests/progress_model_test.cpp
    tests/archive_test.cpp
    tests/scan_root_test.cpp
    tests/file_walker_test.cpp
    tests/long_path_test.cpp
    tests/update_test.cpp
    tests/update_apply_test.cpp
    ${LIB_SOURCES}
    ${UPDATE_SOURCES}
  )
  lyxbosa_configure_windows_exe(lyxbosa_tests)

  target_include_directories(lyxbosa_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src-lib/cpp
    ${CMAKE_SOURCE_DIR}/src-cli
  )

  target_link_libraries(lyxbosa_tests
    PRIVATE
      fmt::fmt
      argparse::argparse
      yaml-cpp::yaml-cpp
      reflectcpp::reflectcpp
      re2::re2
      libzip::zip
      ZLIB::ZLIB
      Threads::Threads
      GTest::gtest
  )
  lyxbosa_configure_update(lyxbosa_tests)
  lyxbosa_configure_allocator(lyxbosa_tests)

  # The keyring is compiled into the binary from this file. The test that asserts the
  # two are byte-identical needs to know where the file is, and it is given the path
  # here rather than baked into the shipped binary - a released executable has no
  # business carrying the absolute path of the machine that built it.
  target_compile_definitions(lyxbosa_tests PRIVATE
    LYXBOSA_KEYRING_FILE_PATH="${LYXBOSA_KEYRING_FILE}")

  include(GoogleTest)
  gtest_discover_tests(lyxbosa_tests)
endif()
