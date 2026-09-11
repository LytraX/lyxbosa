#pragma once

// Why a case cannot observe what it is about, on this platform, as a sentence.
//
// Several cases in this suite need a path the current user is not allowed to read or
// write, and set that up with std::filesystem::permissions. There are two ways a
// platform cannot produce one:
//
//   root ignores the permission bits, so a mode-000 file is still readable
//   Windows has no POSIX mode bits at all for permissions() to clear
//
// Either way the case cannot fail, and a case that cannot fail is the shape AGENTS.md
// records five earlier instances of - a check that passed while blind. So it says
// which of the two it hit and skips, rather than passing without having observed
// anything. Written once here so that no case can quietly ask a weaker question than
// its neighbours, and so that adding the Windows arm was one edit rather than four.

#include <filesystem>
#include <optional>
#include <string>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace lyxbosa::test {

// The current process id, spelled once. Only used to keep two concurrent test binaries
// from colliding on a probe path.
inline unsigned long getpid_portable() {
#ifdef _WIN32
    return static_cast<unsigned long>(::GetCurrentProcessId());
#else
    return static_cast<unsigned long>(::getpid());
#endif
}

// Nullopt when this platform can deny the current user access to a path it owns.
inline std::optional<std::string> whyCannotDenyOwnAccess() {
#ifdef _WIN32
    return "Windows has no POSIX permission bits, so std::filesystem::permissions "
           "cannot make a path this user may not read and no refusal can be observed";
#else
    if (::geteuid() == 0) {
        return "running as root - the permission bits this case sets are ignored, so "
               "no refusal can be observed";
    }
    return std::nullopt;
#endif
}

// Nullopt when this machine lets a process that declares longPathAware open a path at
// or past MAX_PATH. Windows needs two things for that and only one of them is the
// binary's to provide: the manifest CMakeLists.txt attaches to every executable, and
// the LongPathsEnabled value under HKLM\SYSTEM\CurrentControlSet\Control\FileSystem.
// With the value off the path is refused however the binary was built, so a case about
// the manifest cannot observe anything and says which half it could not meet. The
// manifest's absence is never a reason to skip: that is the defect, and the case fails.
inline std::optional<std::string> whyCannotObserveLongPaths() {
#ifdef _WIN32
    DWORD enabled = 0;
    DWORD size = sizeof(enabled);
    const LSTATUS status = RegGetValueW(
        HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\FileSystem",
        L"LongPathsEnabled", RRF_RT_REG_DWORD, nullptr, &enabled, &size);
    if (status != ERROR_SUCCESS) {
        return "LongPathsEnabled is not set under HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
               "FileSystem (RegGetValueW returned " + std::to_string(status) + "), so Windows "
               "refuses a path at MAX_PATH whatever this binary's manifest declares";
    }
    if (enabled != 1) {
        return "LongPathsEnabled is " + std::to_string(enabled) + " under HKLM\\SYSTEM\\"
               "CurrentControlSet\\Control\\FileSystem, so Windows refuses a path at "
               "MAX_PATH whatever this binary's manifest declares";
    }
    return std::nullopt;
#else
    // PATH_MAX is 4096 here and the case stays well inside it; the property is observed.
    return std::nullopt;
#endif
}

// Nullopt when this process can create a symbolic link. POSIX lets any user create one;
// Windows needs SeCreateSymbolicLinkPrivilege or Developer Mode, and without it the
// cases about symlink handling would set up a plain directory and then "observe" that
// the walk descended into it - passing while blind, which is the shape AGENTS.md
// records five earlier instances of. So the answer is taken from the host rather than
// assumed: one link is created in a temporary directory and the error is reported.
inline std::optional<std::string> whyCannotCreateSymlinks() {
    namespace fs = std::filesystem;

    std::error_code ec;
    const fs::path probe = fs::temp_directory_path() /
                           ("lyxbosa-symlink-probe-" + std::to_string(getpid_portable()));
    fs::remove(probe, ec);
    fs::create_directory_symlink(fs::temp_directory_path(), probe, ec);
    if (ec) {
        return "this process may not create a symbolic link (" + ec.message() +
               "), so the walk's symlink handling cannot be observed";
    }
    fs::remove(probe, ec);
    return std::nullopt;
}

}  // namespace lyxbosa::test
