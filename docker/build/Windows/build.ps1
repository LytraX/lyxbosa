$ErrorActionPreference = "Stop"

# Build the Windows binary for one architecture, run its tests if this machine can
# execute them, and copy the binary out.
#
#   docker\build\Windows\build.ps1 <amd64|arm64> [output-dir]
#
# ONE ARCHITECTURE PER CALL
# -------------------------
# This script used to loop over both architectures inside one invocation, which made the
# Windows job the only build in the pipeline without a matrix and the only one that could
# not overlap with itself. One architecture per call is what lets the workflow run the two
# as parallel jobs, the way the Linux scripts already are called.
#
# ONE CONFIGURE, NOT TWO
# ----------------------
# The tests are built here rather than by a second configure of the same tree, so the
# binary that ships is the binary the suite ran against. docker/build/Linux/build-inside.sh
# carries the measurement that says a test-only switch changes nothing in the published
# bytes.
#
# WHETHER THE TESTS RUN
# ---------------------
# When the architecture being built is this machine's, and not otherwise. An ARM64 binary
# is cross-compiled on an x64 runner and cannot be executed there, so that job builds and
# does not test - and says so, on the run summary as well as in the log, because "built"
# and "built and tested" are different results and reporting the second for the first is
# how a suite that never ran gets counted as green.
#
# The test target is still compiled and linked for ARM64. That is not the half-check it
# would be if it were also expected to run: a test source that no longer builds for ARM64
# is exactly the failure that let a Windows test target ship broken release after release
# with every build green, and it costs one compile of sources vcpkg has already built the
# dependencies for. CMakeLists.txt asks gtest to enumerate the cases at ctest time rather
# than at link time for this reason - the default would run the freshly linked ARM64
# binary on the x64 host and fail the build.

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\..\..\.."

$Arch = $args[0]
$OutputDir = if ($args[1]) { $args[1] } else { "dist" }

$Targets = @{
    "amd64" = @{ CmakeArch = "x64";   Triplet = "x64-windows-static" }
    "arm64" = @{ CmakeArch = "ARM64"; Triplet = "arm64-windows-static" }
}

if (-not $Arch -or -not $Targets.ContainsKey($Arch)) {
    Write-Host "usage: build.ps1 <amd64|arm64> [output-dir]" -ForegroundColor Red
    exit 2
}

$CmakeArch = $Targets[$Arch].CmakeArch
$VcpkgTriplet = $Targets[$Arch].Triplet

# What this machine can execute. OSArchitecture rather than PROCESSOR_ARCHITECTURE
# because the latter answers for the process and reports x86 from a 32-bit one. An
# ARM64 host would test its own ARM64 build here, which is the answer that makes this a
# determination rather than a hardcoded "ARM64 is never tested".
$HostArch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
    "X64"   { "amd64" }
    "Arm64" { "arm64" }
    default { "unknown" }
}
$RunTests = ($Arch -eq $HostArch)

# WHICH VCPKG
# -----------
# vcpkg-configuration.json pins the registry baseline, which pins the port VERSIONS. The
# tool that builds them comes from the clone, and cloning the default branch means whatever
# was on it that morning. docker/build/vcpkg-commit holds the commit, and it is the same
# file the two Linux images read - one value rather than three that agree today.
#
# The pin applies to a clone this script makes. It deliberately does NOT check out that
# commit inside a VCPKG_ROOT somebody else provided: on a GitHub runner that variable
# points at the image's own vcpkg, shared with every other job on the machine, and moving
# its HEAD would be this script reaching outside its own build.
#
# So a Windows release is not reproducible the way a Linux one is, and this pin does not
# make it so - the MSVC toolchain, the Windows SDK and that preinstalled vcpkg all come
# from the runner image, which rolls. What this does is make the local path deterministic
# and make the remote one REPORTED: the commit actually in use is printed below, so a log
# says which tool built the artefact instead of leaving it to be guessed.
$VcpkgCommit = (Get-Content (Join-Path $ScriptDir "..\vcpkg-commit") -Raw).Trim()

if (-not $env:VCPKG_ROOT) {
    if (Test-Path "$ProjectRoot\vcpkg\vcpkg.exe") {
        $env:VCPKG_ROOT = "$ProjectRoot\vcpkg"
    } else {
        Write-Host "VCPKG_ROOT not set. Cloning vcpkg at $VcpkgCommit..."
        git clone https://github.com/microsoft/vcpkg.git "$ProjectRoot\vcpkg"
        if ($LASTEXITCODE -ne 0) { Write-Host "=== vcpkg clone failed ===" -ForegroundColor Red; exit $LASTEXITCODE }
        git -C "$ProjectRoot\vcpkg" checkout --detach $VcpkgCommit
        if ($LASTEXITCODE -ne 0) { Write-Host "=== vcpkg is not at $VcpkgCommit ===" -ForegroundColor Red; exit $LASTEXITCODE }
        & "$ProjectRoot\vcpkg\bootstrap-vcpkg.bat" -disableMetrics
        if ($LASTEXITCODE -ne 0) { Write-Host "=== vcpkg bootstrap failed ===" -ForegroundColor Red; exit $LASTEXITCODE }
        $env:VCPKG_ROOT = "$ProjectRoot\vcpkg"
    }
}

# Whatever it turned out to be, said out loud. An unreadable HEAD is reported as unknown
# rather than left blank: a missing line and a line nobody wrote look the same in a log.
$VcpkgAt = (git -C $env:VCPKG_ROOT rev-parse HEAD 2>$null)
if (-not $VcpkgAt) { $VcpkgAt = "unknown - not a git checkout" }
Write-Host "Using vcpkg at: $env:VCPKG_ROOT"
Write-Host "vcpkg commit:   $VcpkgAt (this repository pins $VcpkgCommit for clones it makes)"

# A native command's exit code does not stop a PowerShell script on its own, and a cmake
# or ctest that failed must fail the job: every step checks.
function Assert-LastExitCode($What) {
    if ($LASTEXITCODE -ne 0) {
        Write-Host "=== $What failed (exit $LASTEXITCODE) ===" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

# The verdict goes to the log and, under Actions, to the run summary page, because a
# result nobody opens a log to find is a result nobody reads.
function Announce($Line) {
    Write-Host $Line -ForegroundColor Green
    if ($env:GITHUB_STEP_SUMMARY) {
        Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value $Line
    }
}

# The build timestamp, pinned, so the same source produces the same bytes.
#
# vcpkg builds OpenSSL from source here too - for the update verifier rather than for curl,
# which uses Schannel on Windows - and its util/mkbuildinf.pl stamps the build time into the
# banner libcrypto carries. On Linux that is measured: two builds of one commit minutes
# apart differ in the banner and in the GNU build ID derived from it, and holding
# SOURCE_DATE_EPOCH makes them the same file. Windows has a second clock this does not
# touch, in the PE header the linker writes, so the Windows assets are not claimed to
# reproduce - docs/RELEASING.md says which platforms the claim covers and why this is set
# anyway: whatever else is left, it is one fewer thing, and it costs a variable.
#
# vcpkg scrubs the build environment on Windows, so the variable reaches a port build only
# because the overlay triplets name it in VCPKG_ENV_PASSTHROUGH.
#
# An exported SOURCE_DATE_EPOCH wins, so a rebuilder can reproduce a release whose pinned
# value differs from the one in the tree they happen to be holding.
if (-not $env:SOURCE_DATE_EPOCH) {
    $EpochFile = Join-Path $ScriptDir "..\source-date-epoch"
    if (-not (Test-Path $EpochFile)) {
        Write-Host "no epoch at $EpochFile" -ForegroundColor Red
        exit 1
    }
    $env:SOURCE_DATE_EPOCH = (Get-Content $EpochFile -Raw).Trim()
}
if ($env:SOURCE_DATE_EPOCH -notmatch '^[0-9]+$') {
    Write-Host "SOURCE_DATE_EPOCH is not a whole number of seconds: '$($env:SOURCE_DATE_EPOCH)'" -ForegroundColor Red
    exit 1
}
$EpochUtc = [DateTimeOffset]::FromUnixTimeSeconds([long]$env:SOURCE_DATE_EPOCH).UtcDateTime
Write-Host "SOURCE_DATE_EPOCH: $($env:SOURCE_DATE_EPOCH) ($EpochUtc UTC)"

# Version override from environment
$VersionArg = @()
if ($env:LYXBOSA_VERSION) {
    $VersionArg = @("-DLYXBOSA_VERSION_OVERRIDE=$env:LYXBOSA_VERSION")
    Write-Host "Version override: $env:LYXBOSA_VERSION"
}

# Create output directory
$AbsOutputDir = Join-Path (Get-Location) $OutputDir
New-Item -ItemType Directory -Force -Path $AbsOutputDir | Out-Null

Write-Host ""
Write-Host "=== Building LyxBoSa for Windows ($Arch) ===" -ForegroundColor Cyan

# Configure (static linking for standalone binary)
$BuildDir = Join-Path $ProjectRoot "build-win-release-$Arch"
Write-Host "Configuring..."
# The overlay triplets are the stock ones plus VCPKG_BUILD_TYPE=release, so
# vcpkg does not also build a debug copy of every dependency that this
# release build would never link.
cmake -B "$BuildDir" -S "$ProjectRoot" `
    -A "$CmakeArch" `
    -DCMAKE_BUILD_TYPE=Release `
    -DBUILD_TESTS=ON `
    "-DVCPKG_TARGET_TRIPLET=$VcpkgTriplet" `
    "-DVCPKG_OVERLAY_TRIPLETS=$ProjectRoot\triplets" `
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
    "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
    @VersionArg
Assert-LastExitCode "Configure"

# The CLI and the test binary in one build.
#
# No --parallel, and that is measured rather than overlooked. CMakeLists.txt sets /MP, so
# each project already compiles on every processor the machine has; --parallel adds
# MSBuild's /m, which runs the two projects at once on top of that. On a 2-core, 4-thread
# affinity mask with /MP4, standing in for a hosted runner, a clean build took 142.0 and
# 141.5 s with it and 142.5 and 141.5 s without, while the cl.exe processes alive at once
# went from 5 to 10 and their peak working set from 1.5 to 2.4 GiB. Overlapping projects
# pays only where processors would otherwise sit idle - 16.5 s against 22 s on 56 threads -
# and a runner has none to spare.
Write-Host "Building..."
cmake --build "$BuildDir" --config Release
Assert-LastExitCode "Build"

if ($RunTests) {
    # -C Release because the Visual Studio generator is multi-config and ctest has to
    # be told which one was built. A ctest run without it finds no tests and, worse,
    # reports that as success.
    #
    # Serial, for the reason docker/build/Linux/build-inside.sh gives: the scan-root
    # cases share a scratch directory name across processes and collide under
    # --parallel. The whole run is seconds either way.
    Write-Host "Running tests..."
    ctest --test-dir "$BuildDir" `
        -C Release `
        --output-on-failure `
        --timeout 300
    Assert-LastExitCode "Tests"
} else {
    Write-Host "Tests not run: this machine is $HostArch and cannot execute an $Arch binary" -ForegroundColor Yellow
}

# After the tests and never before: a binary whose suite failed must not reach the
# directory the release job collects from.
$ExePath = Join-Path $BuildDir "Release\lyxbosa.exe"
if (-not (Test-Path $ExePath)) {
    # Some generators put it directly in the build dir
    $ExePath = Join-Path $BuildDir "lyxbosa.exe"
}

$BinaryName = "lyxbosa-windows-$Arch.exe"
Copy-Item $ExePath (Join-Path $AbsOutputDir $BinaryName) -Force

if ($RunTests) {
    Announce "- ``windows $Arch`` built **and tested** - ctest ran on this runner"
} else {
    Announce "- ``windows $Arch`` built, **not tested** - this runner is $HostArch and cannot execute an $Arch binary"
}
Write-Host "=== Build complete: $OutputDir\$BinaryName ===" -ForegroundColor Green
