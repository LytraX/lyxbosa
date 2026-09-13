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
#include <winioctl.h>
#include <cstring>
#include <cwchar>
#include <vector>
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

// Directory junctions and volume mount points, made from code.
//
// Both are an NTFS reparse point with the tag IO_REPARSE_TAG_MOUNT_POINT on an empty
// directory, and they differ only in what the reparse data stores: a junction stores a
// directory path, a volume mount point stores the root of a volume. So one writer makes
// both, with FSCTL_SET_REPARSE_POINT, rather than running `mklink /J`: there is no command
// line to quote a path through, the failure comes back as an error number a skip can
// name, and `mklink` has no way to make the second kind at all.
//
// Neither exists anywhere but Windows, so on every other platform each answers with the
// sentence that says so and a case skips on it. On Windows the answer is taken from the
// host - the reparse point is written and the error reported - never assumed.
#ifdef _WIN32
namespace detail {

inline std::string windowsError(DWORD code) {
    return "error " + std::to_string(code);
}

// Writes an IO_REPARSE_TAG_MOUNT_POINT reparse point storing `substitute` onto a new,
// empty directory at `link`. The layout is ntifs.h's MountPointReparseBuffer, which user
// mode has no header for.
inline std::optional<std::string> writeMountPointReparse(const std::filesystem::path& link,
                                                         const std::wstring& substitute) {
    std::error_code ec;
    std::filesystem::create_directory(link, ec);
    if (ec) {
        return "the directory for the reparse point could not be created (" + ec.message() + ")";
    }
    const HANDLE handle =
        ::CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD error = ::GetLastError();
        std::filesystem::remove(link, ec);
        return "the directory for the reparse point would not open for writing (" +
               windowsError(error) + ")";
    }

    // The substitute name, then the print name - the same string, as the mount manager
    // writes them - each NUL-terminated, after eight bytes of offsets and lengths. Nothing
    // the walk asks reads the print name.
    const size_t nameBytes = (substitute.size() + 1) * 2 * sizeof(wchar_t);
    std::vector<unsigned char> data(16 + nameBytes, 0);
    const ULONG tag = IO_REPARSE_TAG_MOUNT_POINT;
    const auto dataLength = static_cast<USHORT>(8 + nameBytes);
    const auto nameLength = static_cast<USHORT>(substitute.size() * sizeof(wchar_t));
    const auto printOffset = static_cast<USHORT>(nameLength + sizeof(wchar_t));
    const USHORT zero = 0;
    std::memcpy(data.data(), &tag, sizeof(tag));
    std::memcpy(data.data() + 4, &dataLength, sizeof(dataLength));
    std::memcpy(data.data() + 8, &zero, sizeof(zero));          // substitute name offset
    std::memcpy(data.data() + 10, &nameLength, sizeof(nameLength));
    std::memcpy(data.data() + 12, &printOffset, sizeof(printOffset));
    std::memcpy(data.data() + 14, &nameLength, sizeof(nameLength));
    std::memcpy(data.data() + 16, substitute.data(), nameLength);
    std::memcpy(data.data() + 16 + printOffset, substitute.data(), nameLength);

    DWORD returned = 0;
    const BOOL written = ::DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, data.data(),
                                           static_cast<DWORD>(data.size()), nullptr, 0,
                                           &returned, nullptr);
    const DWORD error = ::GetLastError();
    ::CloseHandle(handle);
    if (!written) {
        std::filesystem::remove(link, ec);
        return "FSCTL_SET_REPARSE_POINT was refused (" + windowsError(error) + ")";
    }
    return std::nullopt;
}

// The root of the volume holding `path`, as a reparse point stores it -
// \??\Volume{...}\ - and the rest of `path` below that root. Nullopt on success.
inline std::optional<std::string> volumeGuidRootOf(const std::filesystem::path& path,
                                                   std::wstring& root, std::wstring& rest) {
    std::wstring absolute = std::filesystem::absolute(path).native();
    if (absolute.rfind(L"\\\\?\\", 0) == 0) {
        absolute.erase(0, 4);
    }
    wchar_t volumePath[MAX_PATH + 1] = {};
    if (!::GetVolumePathNameW(absolute.c_str(), volumePath, MAX_PATH)) {
        return "the volume holding the temporary directory would not name its root (" +
               windowsError(::GetLastError()) + ")";
    }
    wchar_t volumeName[MAX_PATH + 1] = {};
    if (!::GetVolumeNameForVolumeMountPointW(volumePath, volumeName, MAX_PATH)) {
        return "the volume holding the temporary directory has no volume GUID path (" +
               windowsError(::GetLastError()) + ")";
    }
    // \\?\Volume{...}\ as the API spells it.
    root = volumeName;
    if (root.rfind(L"\\\\?\\", 0) != 0) {
        return "the volume GUID path came back in an unexpected form";
    }
    root.replace(0, 4, L"\\??\\");
    const size_t prefix = std::wcslen(volumePath);
    rest = absolute.size() > prefix ? absolute.substr(prefix) : std::wstring();
    return std::nullopt;
}

}  // namespace detail
#endif

// Nullopt when a directory junction now stands at `link`, leading to the directory
// `target`.
inline std::optional<std::string> whyCannotCreateJunction(const std::filesystem::path& link,
                                                          const std::filesystem::path& target) {
#ifdef _WIN32
    // An absolute path in the NT namespace, without the \\?\ a long path may carry.
    std::wstring absolute = std::filesystem::absolute(target).native();
    if (absolute.rfind(L"\\\\?\\", 0) == 0) {
        absolute.erase(0, 4);
    }
    if (const auto why = detail::writeMountPointReparse(link, L"\\??\\" + absolute)) {
        return "this host would not let this process make a directory junction - " + *why +
               " - so the walk's handling of one cannot be observed";
    }
    return std::nullopt;
#else
    (void)link;
    (void)target;
    return "a directory junction is an NTFS reparse point and exists only on Windows, so "
           "there is none here for the walk to be asked about";
#endif
}

// Nullopt when a volume mount point now stands at `link`, attaching the root of the volume
// that holds `onVolumeOf` - which, for a case, is the volume holding its temporary tree.
//
// The case that uses this must never read far into what it attaches: it is a whole volume.
// It carries the reparse data the mount manager writes for one, put straight onto the file
// system, so nothing is registered with the mount manager and there is nothing to undo but
// the reparse point itself - which removeReparsePoint() below does, before the directory
// is deleted.
inline std::optional<std::string> whyCannotCreateVolumeMountPoint(
    const std::filesystem::path& link, const std::filesystem::path& onVolumeOf) {
#ifdef _WIN32
    std::wstring root;
    std::wstring rest;
    if (const auto why = detail::volumeGuidRootOf(onVolumeOf, root, rest)) {
        return *why + ", so no volume mount point can be made to observe";
    }
    if (const auto why = detail::writeMountPointReparse(link, root)) {
        return "this host would not let this process make a volume mount point - " + *why +
               " - so the walk's handling of one cannot be observed";
    }
    return std::nullopt;
#else
    (void)link;
    (void)onVolumeOf;
    return "a volume mount point in a folder is an NTFS reparse point and exists only on "
           "Windows, so there is none here for the walk to be asked about";
#endif
}

// Nullopt when a directory junction now stands at `link`, leading to the directory `target`
// but spelled through the volume's GUID path - \??\Volume{...}\path\to\target - which is
// what a volume mount point stores with a path after it. It is a junction and not a mount
// point, and this is the fixture that lets a case say so.
inline std::optional<std::string> whyCannotCreateJunctionThroughVolumeGuid(
    const std::filesystem::path& link, const std::filesystem::path& target) {
#ifdef _WIN32
    std::wstring root;
    std::wstring rest;
    if (const auto why = detail::volumeGuidRootOf(target, root, rest)) {
        return *why + ", so no junction through it can be made to observe";
    }
    if (rest.empty()) {
        return "the target is the root of its volume, which would make a mount point and "
               "not the junction this case is about";
    }
    if (const auto why = detail::writeMountPointReparse(link, root + rest)) {
        return "this host would not let this process make a directory junction - " + *why +
               " - so the walk's handling of one cannot be observed";
    }
    return std::nullopt;
#else
    (void)link;
    (void)target;
    return "a directory junction is an NTFS reparse point and exists only on Windows, so "
           "there is none here for the walk to be asked about";
#endif
}

// Removes the reparse point at `link` and then the empty directory it was on. For a mount
// point this is the only safe order: whatever deletes the directory then sees a directory
// and nothing it could lead into.
inline void removeReparsePoint(const std::filesystem::path& link) {
#ifdef _WIN32
    const HANDLE handle =
        ::CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle != INVALID_HANDLE_VALUE) {
        // A Microsoft tag is deleted by naming it in a header with no data after it.
        unsigned char header[8] = {};
        const ULONG tag = IO_REPARSE_TAG_MOUNT_POINT;
        std::memcpy(header, &tag, sizeof(tag));
        DWORD returned = 0;
        ::DeviceIoControl(handle, FSCTL_DELETE_REPARSE_POINT, header, sizeof(header), nullptr,
                          0, &returned, nullptr);
        ::CloseHandle(handle);
    }
#endif
    std::error_code ec;
    std::filesystem::remove(link, ec);
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
