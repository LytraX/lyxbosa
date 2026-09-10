$ErrorActionPreference = "Stop"

# Build the tests and run them, on Windows.
#
#   docker/build/Windows/test.ps1
#
# This is deliberately NOT build.ps1 with -DBUILD_TESTS=ON. The two answer different
# questions and share everything except the configure:
#
#   build.ps1   "produce the binaries that ship" - both architectures, tests off, one
#               .exe copied out per architecture. What a v* tag runs.
#   test.ps1    "does this tree pass its tests" - the architecture this machine can
#               execute, tests on, nothing copied out.
#
# build.ps1 passing -DBUILD_TESTS=OFF is correct and stays: a release build should
# compile only what it ships. It is also exactly why a test target that could not
# compile on Windows shipped release after release with every build green - nothing
# ever asked. Keeping the two as separate configures means a test-only switch can
# never leak into what is published, and a test failure can never be "fixed" by
# editing the release path.
#
# What they share on purpose is the part that costs time: the same vcpkg, the same
# static triplet, the same overlay triplets and the same MSVC runtime, and therefore
# the same binary-cache entries. A test build configured any other way would miss
# the cache the release build filled and rebuild every dependency from source.
#
# x64 only. The arm64 binary is cross-compiled on an x64 runner and cannot be run
# there, and a test target that is compiled but never executed is half a check -
# the same sources compile for both, so the half that can run is the one worth
# paying for.

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\..\..\.."

# Ensure vcpkg is available - the same resolution build.ps1 uses.
if (-not $env:VCPKG_ROOT) {
    if (Test-Path "$ProjectRoot\vcpkg\vcpkg.exe") {
        $env:VCPKG_ROOT = "$ProjectRoot\vcpkg"
    } else {
        Write-Host "VCPKG_ROOT not set. Cloning vcpkg..."
        git clone https://github.com/microsoft/vcpkg.git "$ProjectRoot\vcpkg"
        & "$ProjectRoot\vcpkg\bootstrap-vcpkg.bat" -disableMetrics
        $env:VCPKG_ROOT = "$ProjectRoot\vcpkg"
    }
}

Write-Host "Using vcpkg at: $env:VCPKG_ROOT"

# A native command's exit code does not stop a PowerShell script on its own, and a
# ctest that failed must fail the job: every step checks.
function Assert-LastExitCode($What) {
    if ($LASTEXITCODE -ne 0) {
        Write-Host "=== $What failed (exit $LASTEXITCODE) ===" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

$BuildDir = Join-Path $ProjectRoot "build-win-tests-x64"

Write-Host ""
Write-Host "=== Building LyxBoSa tests for Windows (x64) ===" -ForegroundColor Cyan

Write-Host "Configuring..."
cmake -B "$BuildDir" -S "$ProjectRoot" `
    -A x64 `
    -DCMAKE_BUILD_TYPE=Release `
    -DBUILD_TESTS=ON `
    -DVCPKG_TARGET_TRIPLET=x64-windows-static `
    "-DVCPKG_OVERLAY_TRIPLETS=$ProjectRoot\triplets" `
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
    "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake"
Assert-LastExitCode "Configure"

# The CLI as well as the tests: on a pull request this is the only Windows compile
# of src-cli anywhere, and a main() that no longer builds there is worth knowing
# before the tag.
Write-Host "Building..."
cmake --build "$BuildDir" --config Release
Assert-LastExitCode "Build"

# -C Release because the Visual Studio generator is multi-config and ctest has to
# be told which one was built. A ctest run without it finds no tests and, worse,
# reports that as success.
#
# Serial, for the reason docker/build/Linux/test-inside.sh gives: the scan-root
# cases share a scratch directory name across processes and collide under
# --parallel. The whole run is seconds either way.
Write-Host "Running tests..."
ctest --test-dir "$BuildDir" `
    -C Release `
    --output-on-failure `
    --timeout 300
Assert-LastExitCode "Tests"

Write-Host "=== Tests passed: Windows (x64) ===" -ForegroundColor Green
