$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\..\..\.."
$OutputDir = if ($args[0]) { $args[0] } else { "dist" }

Write-Host "=== Building LyxBoSa for Windows ===" -ForegroundColor Cyan

# Ensure vcpkg is available
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

# Create output directory
$AbsOutputDir = Join-Path (Get-Location) $OutputDir
New-Item -ItemType Directory -Force -Path $AbsOutputDir | Out-Null

# Configure (static linking for standalone binary)
$BuildDir = Join-Path $ProjectRoot "build-win-release"
Write-Host "Configuring..."
cmake -B $BuildDir -S $ProjectRoot `
    -DCMAKE_BUILD_TYPE=Release `
    -DBUILD_TESTS=OFF `
    -DVCPKG_TARGET_TRIPLET=x64-windows-static `
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
    -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake"

# Build
Write-Host "Building..."
cmake --build $BuildDir --config Release

# Copy binary to output
$ExePath = Join-Path $BuildDir "Release\lyxbosa.exe"
if (-not (Test-Path $ExePath)) {
    # Some generators put it directly in the build dir
    $ExePath = Join-Path $BuildDir "lyxbosa.exe"
}

$BinaryName = "lyxbosa-windows.exe"
Copy-Item $ExePath (Join-Path $AbsOutputDir $BinaryName) -Force

Write-Host ""
Write-Host "=== Build complete ===" -ForegroundColor Green
Write-Host "Binary: $OutputDir\$BinaryName"
