#pragma once

#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <string_view>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace lyxbosa::test {

// A temporary directory that no other test, in this process or another, is handed.
//
// ctest runs every case as its own process, many at once, so a directory name only has to
// collide once for two cases to scan, overwrite and delete each other's fixtures, and they
// then fail in ways that have nothing to do with the code under test. A name alone cannot
// promise uniqueness: a steady_clock tick is not unique across processes - two workers on
// a Windows runner read the same tick and built the same name - a random number is
// unlikely rather than impossible to repeat, and a counter restarts in every process.
//
// So uniqueness is decided by the filesystem, not by the name. The name carries the process
// id, a tick and a process-wide counter, and std::filesystem::create_directory() creates it
// or reports that it already exists; a name that exists is never used, only replaced by the
// next one. The parent is created first, since create_directory() makes one level only.
inline std::filesystem::path makeUniqueTempDir(
    std::string_view prefix,
    const std::filesystem::path& parent = std::filesystem::temp_directory_path()) {
    static std::atomic<unsigned long long> counter{0};
#ifdef _WIN32
    const long long pid = ::_getpid();
#else
    const long long pid = ::getpid();
#endif
    std::filesystem::create_directories(parent);
    for (;;) {
        const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
        std::filesystem::path candidate =
            parent / (std::string(prefix) + "-" + std::to_string(pid) + "-" +
                      std::to_string(tick) + "-" + std::to_string(counter++));
        if (std::filesystem::create_directory(candidate)) {
            return candidate;
        }
    }
}

}  // namespace lyxbosa::test
