<#
.SYNOPSIS
  Install lyxbosa on Windows, in one command.

.DESCRIPTION
  irm https://github.com/LytraX/lyxbosa/releases/latest/download/install.ps1 | iex

  To pass an option, create the script block rather than piping into iex, because `iex`
  has no way to forward arguments:

    & ([scriptblock]::Create((irm https://github.com/LytraX/lyxbosa/releases/latest/download/install.ps1))) -Dir D:\tools

  WHY THIS FILE IS PUBLISHED AS A RELEASE ASSET AND NOT SERVED FROM A BRANCH

  The release job hashes everything in its artifacts directory into SHA256SUMS and signs
  that list with minisign. A script staged there is covered by the same list and the same
  signature as the binaries. A script served from a branch URL is a mutable path: covered
  by no list, signed by no key, and the one artefact that runs with the most privilege
  while being the only one nobody can check.

  WHAT PIPING THIS INTO A SHELL DOES AND DOES NOT GIVE YOU

  It gives you bytes chosen by whoever controls the release, run by PowerShell, before you
  have read them - the same trust you extend to the binary itself. It does not give you any
  guarantee that the bytes running right now are the bytes in the signed list; see
  Invoke-SelfCheck, which says exactly what it catches and what it cannot. docs/INSTALL.md
  writes the same steps out by hand for anyone who would rather not pipe.

  WHERE IT INSTALLS, AND WHY NOT PROGRAM FILES

  %LOCALAPPDATA%\Programs\lyxbosa. It is per-user and writable, so nothing needs elevation
  and `lyxbosa update` can replace the binary in place. Program Files is the wrong answer
  for exactly that reason: the updater refuses a directory it cannot write unelevated, and
  it refuses deliberately rather than relaunching itself as administrator. Installing there
  produces a binary that can never update itself.

  Unlike the Linux case there is no conventional per-user directory already on PATH, so
  this adds the install directory to the user PATH.

.PARAMETER Dir
  Where to install. Defaults to %LOCALAPPDATA%\Programs\lyxbosa.

.PARAMETER SkipPath
  Do not touch the user PATH.

.PARAMETER SelfTest
  Run the control cases and exit. Used by the Windows CI job, which is the only place in
  this project that can execute PowerShell.
#>
[CmdletBinding()]
param(
    [string] $Dir,
    [switch] $SkipPath,
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Repo          = 'LytraX/lyxbosa'
$DefaultOrigin = "https://github.com/$Repo/releases/latest/download"
$Origin        = if ($env:LYXBOSA_INSTALL_ORIGIN) { $env:LYXBOSA_INSTALL_ORIGIN } else { $DefaultOrigin }
$SumsName      = 'SHA256SUMS'
$SigName       = 'SHA256SUMS.minisig'
$SelfAsset     = 'install.ps1'

# The minisign public keys a release may be signed by, copied from keys/minisign-trusted.txt
# with both roles kept: `signing` signs, `trusted` is a key on its way in or out, and a
# verifier accepts either. Pinned rather than fetched - a key taken from the same place as
# the thing it verifies is not a check. corpus/install-scripts.sh asserts this list against
# that file, so a rotation that forgets this script fails a pre-report command.
$BuiltinKeys = @('RWQ3sDWqcTt8R0jVErMgIrRfrzCVlwuU4cFCUaEVGH2WqhYeiuL343eS')
$TrustedKeys = if ($env:LYXBOSA_INSTALL_KEYS) { $env:LYXBOSA_INSTALL_KEYS -split '\s+' } else { $BuiltinKeys }

# Directories an installer must not write into on Windows.
#
# The twelve prefixes src-lib/cpp/update/InstallPath.cpp refuses are POSIX paths a package
# manager owns, and none of them can occur here - packageManagerOwning() is compiled out on
# Windows. The Windows version of the same rule is not ownership but elevation: `update`
# asks whether it can WRITE the install directory and refuses when it cannot, without ever
# relaunching itself as administrator. So the list that matters here is the directories a
# normal user cannot write, and installing into one produces the same broken state the
# POSIX list exists to prevent - a binary that can never update itself.
$RefusedRoots = @(
    ${env:ProgramFiles},
    ${env:ProgramFiles(x86)},
    ${env:ProgramW6432},
    ${env:SystemRoot}
) | Where-Object { $_ }

$script:Verification = ''
$script:ReleaseTag   = ''

function Write-Note { param([string] $Text) Write-Host "  $Text" }
function Fail { param([string] $Text) throw $Text }

# ---------------------------------------------------------------------------- the host

# amd64, arm64, or a refusal. Anything else is refused rather than guessed at: there is no
# asset to fall back to, and downloading one that cannot run is worse than stopping.
function Get-Arch {
    $a = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ("$a") {
        'X64'   { return 'amd64' }
        'Arm64' { return 'arm64' }
        default {
            Fail "no release asset for this architecture ($a). A release publishes Windows binaries for x64 and arm64 only. Building from source is docs/BUILDING.md."
        }
    }
}

# ------------------------------------------------------------------------- destinations

# Absolute, with `..` and a trailing separator resolved away, so that the refusal below
# answers about where the file actually lands rather than about how the path was spelled.
# GetFullPath does not require the directory to exist, which the default one may not.
function Resolve-Destination {
    param([string] $Path)
    if (-not $Path) { return $Path }
    return [System.IO.Path]::GetFullPath($Path.TrimEnd('\', '/'))
}

function Test-IsUnder {
    param([string] $Path, [string] $Prefix)
    # Component-wise, so that C:\Program Files Extra is not inside C:\Program Files. A
    # plain string prefix would say it is - the same trap isUnder() avoids in InstallPath.cpp.
    $p = (Resolve-Destination $Path).TrimEnd('\')
    $r = (Resolve-Destination $Prefix).TrimEnd('\')
    if ($p -ieq $r) { return $true }
    return $p.StartsWith($r + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Test-Destination {
    param([string] $Path)
    foreach ($root in $RefusedRoots) {
        if (Test-IsUnder -Path $Path -Prefix $root) {
            Fail @"
$Path is under $root, which needs elevation to write.

   'lyxbosa update' refuses an install directory it cannot write as the user running it,
   and it never relaunches itself as administrator - so installing there produces a binary
   that can never update itself. The default, %LOCALAPPDATA%\Programs\lyxbosa, is per-user
   and writable, which is what makes updates work with nothing elevated.
"@
        }
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
    # Asked by writing, and asked BEFORE anything is downloaded. An ACL read cannot see a
    # read-only volume, a full disk or a policy that denies writes, and each of those
    # decides whether the install can happen.
    $probe = Join-Path $Path (".lyxbosa-install-probe." + [System.Diagnostics.Process]::GetCurrentProcess().Id)
    try {
        [System.IO.File]::WriteAllText($probe, 'probe')
        Remove-Item -LiteralPath $probe -Force
    } catch {
        Fail "$Path is not writable by this user. Pass -Dir with a directory you can write, or use the default %LOCALAPPDATA%\Programs\lyxbosa."
    }
}

# ------------------------------------------------------------------ fetching and hashing

function Get-Asset {
    param([string] $Name, [string] $Destination)
    $url = "$Origin/$Name"
    try {
        Invoke-WebRequest -Uri $url -OutFile $Destination -UseBasicParsing
    } catch {
        Fail "could not download $url`n   $($_.Exception.Message)"
    }
}

function Try-Asset {
    param([string] $Name, [string] $Destination)
    try { Get-Asset -Name $Name -Destination $Destination; return $true } catch { return $false }
}

function Get-Sha256 {
    param([string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# The hash SHA256SUMS records for one asset, or $null. Whole-field match on the name, so a
# name that is a prefix of another asset's cannot pick up the wrong line.
function Get-SumFor {
    param([string] $SumsPath, [string] $Name)
    foreach ($line in [System.IO.File]::ReadAllLines($SumsPath)) {
        $parts = $line.Trim() -split '\s+', 2
        if ($parts.Count -eq 2 -and $parts[1].Trim() -ceq $Name) { return $parts[0].ToLowerInvariant() }
    }
    return $null
}

# ------------------------------------------------------------------------- verification

# Both levels are acceptable and the user is told which they got. What is not acceptable is
# reporting the strong one when the weak one happened, so the level is set in exactly one
# place and printed verbatim at the end.
function Invoke-VerifySums {
    param([string] $Work)
    $sums = Join-Path $Work $SumsName
    Get-Asset -Name $SumsName -Destination $sums

    $minisign = Get-Command minisign -ErrorAction SilentlyContinue
    if (-not $minisign) { $script:Verification = 'checksum'; return }

    $sig = Join-Path $Work $SigName
    if (-not (Try-Asset -Name $SigName -Destination $sig)) {
        $script:Verification = 'checksum'
        Write-Warning "the release publishes no $SigName, so the checksum list could not be verified."
        return
    }

    foreach ($key in $TrustedKeys) {
        $out = & $minisign.Source -V -m $sums -x $sig -P $key 2>&1
        if ($LASTEXITCODE -eq 0) {
            $script:Verification = 'signature'
            # The trusted comment is covered by the signature; the untrusted one is not. It
            # is the only signed statement of WHICH release this is - a SHA256SUMS and
            # signature pair lifted from an older release verifies perfectly well and
            # describes the wrong binaries.
            $m = [regex]::Match(($out -join "`n"), 'Trusted comment:\s*LyxBoSa\s+(v[0-9][0-9.]*)\s')
            if ($m.Success) { $script:ReleaseTag = $m.Groups[1].Value }
            return
        }
    }
    Fail @"
$SumsName is published with a signature and it does not verify under any key this script
   carries. That is either a release signed by a newer key than this script knows about -
   take a newer install.ps1 from the releases page - or bytes that were changed between the
   release and here. Nothing has been downloaded or installed.
"@
}

# Re-fetch this script from the release and check it against the signed list.
#
# WHAT IT IS WORTH, stated rather than implied. It catches a corrupted download, a truncated
# transfer and a bad mirror, which are the failures that actually happen. It does NOT prove
# that the bytes running right now are the bytes in the list: a script tampered with in
# flight would simply not do this, or would print that it had. Nothing a script says about
# itself can establish its own integrity. It also cannot protect anybody from a compromised
# release, because the list and the signing key both live there.
#
# The one case where it is more than that is a copy saved to disk and run as a file: then
# $PSCommandPath is readable and its bytes are compared too, which does catch a local copy
# that has been edited or has gone stale.
function Invoke-SelfCheck {
    param([string] $Work)
    $sums = Join-Path $Work $SumsName
    $want = Get-SumFor -SumsPath $sums -Name $SelfAsset
    if (-not $want) {
        Write-Warning "$SumsName has no line for $SelfAsset, so this script was not checked against the release. Continuing: the binary below is checked on its own."
        return
    }
    $published = Join-Path $Work $SelfAsset
    if (-not (Try-Asset -Name $SelfAsset -Destination $published)) {
        Write-Warning "the published $SelfAsset could not be re-fetched, so it was not compared against the release. Continuing: the binary below is checked on its own."
        return
    }
    if ((Get-Sha256 $published) -ne $want) {
        Fail "the published $SelfAsset does not match its line in $SumsName. Nothing has been installed. Take the assets from the releases page and check them by hand - docs/INSTALL.md."
    }
    if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) {
        if ((Get-Sha256 $PSCommandPath) -ne $want) {
            Write-Warning "the copy of this script being run ($PSCommandPath) is not the one in the release's $SumsName. That is expected for a modified or older copy and worth knowing about for any other reason."
        } else {
            Write-Note "this script: matches the release's $SumsName"
        }
    }
}

# Download one asset and check it against the verified list. Nothing downstream is handed a
# file that failed this: the failure removes it rather than leaving it for a later step to
# be trusted to notice.
function Get-VerifiedAsset {
    param([string] $Work, [string] $Name, [string] $Destination)
    $want = Get-SumFor -SumsPath (Join-Path $Work $SumsName) -Name $Name
    if (-not $want) {
        Fail "$SumsName has no line for $Name, so this release does not publish it or the list does not cover it. Refusing to install an asset the signed list says nothing about."
    }
    Get-Asset -Name $Name -Destination $Destination
    $got = Get-Sha256 $Destination
    if ($got -ne $want) {
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
        Fail @"
$Name does not match its SHA-256 in $SumsName.
     expected $want
     got      $got
   Nothing has been installed and the download has been removed. This is a corrupted or
   truncated transfer, or bytes that are not the release's.
"@
    }
}

# ------------------------------------------------------------------------------ the PATH

# The user PATH, with the install directory added once. Idempotent by construction: an
# installer run twice must not leave two copies, and a PATH that grows every run is a real
# way to break a machine.
function Add-ToUserPath {
    param([string] $Path)
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $current) { $current = '' }
    $entries = $current -split ';' | Where-Object { $_ -ne '' }
    foreach ($e in $entries) {
        if ($e.TrimEnd('\') -ieq $Path.TrimEnd('\')) { return $false }
    }
    $updated = (@($entries) + $Path) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
    # And this session, so the install is usable without opening a new window. The process
    # copy is not what SetEnvironmentVariable('User') changes.
    $env:Path = "$env:Path;$Path"
    return $true
}

# --------------------------------------------------------------------------- what is here

function Get-Existing {
    $cmd = Get-Command lyxbosa -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    $version = ''
    try { $version = (& $cmd.Source --version 2>$null | Select-Object -First 1) } catch { }
    return [pscustomobject]@{
        Path    = $cmd.Source
        Version = if ($version) { ($version -split '\s+')[0] } else { 'unknown' }
    }
}

# A liveness check, not a source of information: output goes nowhere, because a version
# banner in the middle of an install reads as part of the install. Same smoke test
# UpdateApply.cpp runs before a replace.
function Test-Runs {
    param([string] $Binary)
    $out = Join-Path ([System.IO.Path]::GetTempPath()) 'lyxbosa-probe.out'
    $err = Join-Path ([System.IO.Path]::GetTempPath()) 'lyxbosa-probe.err'
    try {
        $p = Start-Process -FilePath $Binary -ArgumentList '--version' -Wait -PassThru `
                           -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err
        return $p.ExitCode -eq 0
    } catch {
        return $false
    } finally {
        Remove-Item -LiteralPath $out, $err -Force -ErrorAction SilentlyContinue
    }
}

# A running .exe cannot be overwritten on Windows, but it can be renamed. Two moves inside
# the install directory, exactly as InstallPath.cpp does it: the old binary aside, the new
# one into the name that just came free, and the first move undone if the second fails - so
# there is a lyxbosa.exe at the end either way.
function Install-Binary {
    param([string] $Staged, [string] $Target)
    $aside = "$Target.old"
    if (Test-Path -LiteralPath $aside) {
        Remove-Item -LiteralPath $aside -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $Target) {
        try {
            Move-Item -LiteralPath $Target -Destination $aside -Force
        } catch {
            Fail "the existing $Target could not be moved aside, which usually means it is running. Close it and try again. Nothing was changed."
        }
        try {
            Move-Item -LiteralPath $Staged -Destination $Target -Force
        } catch {
            Move-Item -LiteralPath $aside -Destination $Target -Force
            Fail "the new binary could not be moved into place; the old one was put back and is unchanged."
        }
        Remove-Item -LiteralPath $aside -Force -ErrorAction SilentlyContinue
    } else {
        Move-Item -LiteralPath $Staged -Destination $Target -Force
    }
}

# ----------------------------------------------------------------------------- controls
#
# They live in the script because this is the only file in the project that the Windows CI
# job can execute, and a control nothing runs is not a control. They need no network: every
# case below is a refusal or a pure function.
function Invoke-SelfTest {
    function Assert-Case {
        param([string] $Label, [bool] $Ok)
        $script:cases++
        Write-Host ("  {0,-62} {1}" -f $Label, $(if ($Ok) { 'correct' } else { 'WRONG' }))
        if (-not $Ok) { $script:failed += $Label }
    }
    $script:cases = 0
    $script:failed = @()

    function Refuses { param([scriptblock] $Block) try { & $Block; return $false } catch { return $true } }

    Write-Host '=== destinations ==='
    foreach ($root in $RefusedRoots) {
        $under = Join-Path $root 'lyxbosa'
        Assert-Case "$root is refused"            (Refuses { Test-Destination -Path (Resolve-Destination $under) })
    }
    # The direction that matters as much: the default destination is NOT refused, or the
    # refusal above would be a script that can never install anything.
    $default = Resolve-Destination (Join-Path $env:LOCALAPPDATA 'Programs\lyxbosa')
    Assert-Case 'the per-user default is accepted' (-not (Refuses { Test-Destination -Path $default }))

    # A sibling whose name merely starts the same way is not inside it. A plain string
    # prefix would say it is.
    Assert-Case 'C:\Program Files Extra is not inside C:\Program Files' `
        (-not (Test-IsUnder -Path 'C:\Program Files Extra\x' -Prefix 'C:\Program Files'))
    Assert-Case 'C:\Program Files\x IS inside C:\Program Files' `
        (Test-IsUnder -Path 'C:\Program Files\x' -Prefix 'C:\Program Files')
    # And a spelling that walks back out of an accepted directory into a refused one.
    Assert-Case 'a ..-spelled path back into a refused root is still refused' `
        (Refuses { Test-Destination -Path (Resolve-Destination (Join-Path $env:ProgramFiles 'somewhere\..\lyxbosa')) })

    Write-Host ''
    Write-Host '=== the checksum list ==='
    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("lyxbosa-selftest-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    try {
        $sums = Join-Path $work $SumsName
        # A name that is a strict prefix of another, which is the shape that makes a loose
        # match verify the wrong file.
        [System.IO.File]::WriteAllText($sums, @"
1111111111111111111111111111111111111111111111111111111111111111  lyxbosa-windows-amd64.exe
2222222222222222222222222222222222222222222222222222222222222222  lyxbosa-windows-amd64.exe.sig
"@)
        Assert-Case 'a whole-name match finds its own line' `
            ((Get-SumFor -SumsPath $sums -Name 'lyxbosa-windows-amd64.exe') -eq ('1' * 64))
        Assert-Case '  ...and does not pick up the longer name' `
            ((Get-SumFor -SumsPath $sums -Name 'lyxbosa-windows-amd64.exe.sig') -eq ('2' * 64))
        Assert-Case 'an asset with no line is not found' `
            ($null -eq (Get-SumFor -SumsPath $sums -Name 'lyxbosa-windows-arm64.exe'))

        $file = Join-Path $work 'payload'
        [System.IO.File]::WriteAllText($file, 'abc')
        Assert-Case 'SHA-256 of "abc" is the published vector' `
            ((Get-Sha256 $file) -eq 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        Assert-Case 'a download whose hash is not in the list is refused' `
            (Refuses { Get-VerifiedAsset -Work $work -Name 'lyxbosa-windows-arm64.exe' -Destination $file })
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host ''
    Write-Host '=== the architecture ==='
    Assert-Case 'this runner resolves to a published architecture' `
        (@('amd64', 'arm64') -contains (Get-Arch))

    Write-Host ''
    if ($script:failed.Count -eq 0) {
        Write-Host "controls: $($script:cases) cases, every one correct"
        return 0
    }
    Write-Host "controls: AT LEAST ONE CONTROL FAILED"
    foreach ($f in $script:failed) { Write-Host "FAIL: $f" }
    return 1
}

# --------------------------------------------------------------------------------- main

function Invoke-Install {
    $arch = Get-Arch

    $destination = if ($Dir) { Resolve-Destination $Dir }
                   else { Resolve-Destination (Join-Path $env:LOCALAPPDATA 'Programs\lyxbosa') }
    Test-Destination -Path $destination

    $existing = Get-Existing

    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("lyxbosa-install-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    try {
        if ($Origin -ne $DefaultOrigin) { Write-Host "origin: $Origin  (NOT the release origin)" }
        if (($TrustedKeys -join ' ') -ne ($BuiltinKeys -join ' ')) {
            Write-Host 'keys:   NOT the keys this script ships with'
        }

        Invoke-VerifySums -Work $work
        Invoke-SelfCheck  -Work $work

        $asset  = "lyxbosa-windows-$arch.exe"
        $staged = Join-Path $work 'lyxbosa.exe'
        Get-VerifiedAsset -Work $work -Name $asset -Destination $staged

        # Verified, then run. A binary that will not start on this host is not installed
        # over a working one.
        if (-not (Test-Runs $staged)) {
            Fail "$asset does not start on this host. Nothing has been installed. Please report this with the output of 'systeminfo'."
        }
        $versionLine = (& $staged --version 2>$null | Select-Object -First 1)
        $newVersion  = if ($versionLine) { ($versionLine -split '\s+')[0] } else { 'unknown' }

        $target = Join-Path $destination 'lyxbosa.exe'
        Install-Binary -Staged $staged -Target $target

        Write-Host ''
        Write-Host "installed lyxbosa $newVersion to $target"
        Write-Note "build:    $asset"
        if ($script:Verification -eq 'signature') {
            Write-Note "verified: minisign signature over $SumsName, then SHA-256 of the download"
            if ($script:ReleaseTag) { Write-Note "release:  $($script:ReleaseTag) (from the signed trusted comment)" }
        } else {
            Write-Note "verified: SHA-256 against $SumsName only"
            Write-Note '          minisign is not installed, so the list ITSELF was not verified - and'
            Write-Note '          the list is published beside the files it describes, so this catches a'
            Write-Note '          corrupted download and not a rewritten release. "winget install'
            Write-Note '          jedisct1.minisign", then run this again, for the stronger check.'
        }

        if ($existing -and $existing.Path -ine $target) {
            Write-Host ''
            Write-Warning "there was already a lyxbosa at $($existing.Path) ($($existing.Version)) and it has been left alone. Two copies are now installed, and PATH decides which one 'lyxbosa' means. Remove the other one, or put $destination earlier in PATH."
        }

        if ($SkipPath) {
            Write-Host ''
            Write-Note "PATH was left alone; $destination may not be on it."
        } elseif (Add-ToUserPath -Path $destination) {
            Write-Host ''
            Write-Note "added $destination to your user PATH."
            Write-Note 'Open a new terminal for other programs to see it; this one already can.'
        }
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($SelfTest) { exit (Invoke-SelfTest) }
Invoke-Install
