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

#include "infrastructure/PathUtils.h"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

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

// Nullopt when this platform can hand a program a destination that opens for writing
// and then refuses the bytes - which is what a full disk is, and what a case about a
// report that could not be delivered has to have.
//
// On POSIX that destination is /dev/full, and it is probed rather than assumed: a
// container built without the standard device set does not have one, and a case that
// wrote to a path that quietly accepted everything would be asserting that a failure
// nobody caused was not reported. The probe writes, flushes and checks, because those
// are the three moments a stream can fail at and only the flush fails here.
//
// Windows has no equivalent. There is no /dev/full, and the other route - denying
// access to the directory - does not reach a handle that is already open, which is the
// whole point: the open has to succeed for the write to be the thing that fails. So the
// case says that rather than passing on a write that worked.
inline std::optional<std::string> whyCannotFailAWrite(std::string& sink) {
#ifdef _WIN32
    (void)sink;
    return "Windows has no /dev/full, and an ACL tightened after the fact does not reach "
           "a handle that is already open, so no path here opens for writing and then "
           "refuses the bytes";
#else
    const char* candidate = "/dev/full";
    std::ofstream probe(candidate, std::ios::out | std::ios::binary);
    if (!probe) {
        return std::string("this host has no writable ") + candidate +
               ", so a write that fails after a successful open cannot be set up here";
    }
    probe << "probe";
    probe.flush();
    if (!probe.fail()) {
        return std::string(candidate) + " accepted a write on this host, so it cannot "
               "stand in for a destination that refuses one";
    }
    sink = candidate;
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

// Nullopt when the bytes just written to `path` are the bytes on disk now.
//
// A fixture that is a real webshell is a real webshell to resident antivirus as well:
// Microsoft Defender takes one out of `%TEMP%` between the write and the scan. The case
// then fails with the file missing, or a quarantine that moved nothing, or an exit code
// of 0 where a finding should have made it 2 - each of which reads as a defect in the
// scanner, and costs an hour of looking in the wrong place. It is an environmental fact,
// so a case asks this after writing each such fixture and before the scan that reads it,
// and skips with the sentence. A fixture that survives changes nothing: the case goes on
// to assert exactly what it always asserted.
inline std::optional<std::string> whyTheFixtureIsNotOnDisk(const std::filesystem::path& path,
                                                           std::string_view expected) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return "another program removed the webshell fixture at " + pathForDisplay(path) +
               " between writing it and scanning it - resident antivirus does this to a "
               "real signature - so this case cannot observe what the scanner does with it";
    }
    std::ifstream in(path, std::ios::binary);
    const std::string actual((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
    if (!in.good() && !in.eof()) {
        return "the webshell fixture at " + pathForDisplay(path) + " could not be read back "
               "- another program holds it or has blocked it - so this case cannot observe "
               "what the scanner does with it";
    }
    if (actual != expected) {
        return "the webshell fixture at " + pathForDisplay(path) + " is not the bytes that "
               "were written to it - something on this host rewrote or emptied it - so this "
               "case cannot observe what the scanner does with it";
    }
    return std::nullopt;
}

// Nullopt when a file holding `text` survives in the temporary directory.
//
// For a case that captures a command's output, when that output quotes a webshell: gtest
// captures into a file in the temporary directory, and on a host whose resident antivirus
// takes that file the capture cannot be read back and gtest aborts the whole test binary -
// every case after this one goes with it, reported as nothing. The fixture itself may be
// a compressed container that no scanner of the host's reads, so asking about the fixture
// would say nothing; asked here instead, of a probe holding the same text, before the
// capture begins.
inline std::optional<std::string> whyTheTemporaryDirectoryWillNotHold(std::string_view text) {
    const std::filesystem::path probe =
        std::filesystem::temp_directory_path() /
        ("lyxbosa-capture-probe-" + std::to_string(getpid_portable()) + ".txt");
    {
        std::ofstream out(probe, std::ios::binary | std::ios::trunc);
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
    }
    const bool held = !whyTheFixtureIsNotOnDisk(probe, text).has_value();
    std::error_code ec;
    std::filesystem::remove(probe, ec);
    if (!held) {
        return "a file holding the webshell text this case prints did not survive in " +
               pathForDisplay(std::filesystem::temp_directory_path()) + " - resident "
               "antivirus takes it - and gtest captures the output into a file there, so "
               "the capture would abort the test binary rather than fail this case";
    }
    return std::nullopt;
}

}  // namespace lyxbosa::test
