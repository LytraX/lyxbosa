#include "update/InstallPath.h"

#include <fmt/format.h>

#include <array>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

namespace lyxbosa {

namespace {

// Component-wise, so that /usr/binary-thing is not inside /usr/bin. A plain string
// prefix would say it is, and the difference is a directory nobody owns being refused
// as if a package manager did.
bool isUnder(const std::filesystem::path& path, std::string_view prefix) {
    const std::filesystem::path root(prefix);
    auto p = path.begin();
    auto r = root.begin();
    for (; r != root.end(); ++r, ++p) {
        if (p == path.end()) return false;
        if (*p != *r) return false;
    }
    return true;
}

}  // namespace

std::filesystem::path runningExecutablePath() {
#if defined(__linux__)
    std::error_code ec;
    // /proc/self/exe is the kernel's own answer and it is already fully resolved, which
    // is what makes it right here: an install at /usr/local/bin/lyxbosa that is a
    // symlink into /opt must have the real file replaced, not the link.
    auto resolved = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (!ec) return resolved;
    return {};
#elif defined(_WIN32)
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(),
                                            static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) return {};
    return std::filesystem::path(std::wstring(buffer.data(), length));
#else
    // macOS and the BSDs. `update` refuses on them before this is reached, because a
    // release publishes no asset they could install; answering "unknown" is honest
    // rather than adding a path nothing exercises.
    return {};
#endif
}

std::string_view packageManagerOwning(const std::filesystem::path& path) {
    struct Owner {
        std::string_view prefix;
        std::string_view name;
    };
    // Every entry is somewhere a package manager writes and an administrator does not.
    static constexpr std::array<Owner, 12> kOwned{{
        {"/usr/bin", "the system package manager"},
        {"/usr/sbin", "the system package manager"},
        {"/bin", "the system package manager"},
        {"/sbin", "the system package manager"},
        {"/usr/lib", "the system package manager"},
        {"/usr/libexec", "the system package manager"},
        {"/usr/share", "the system package manager"},
        {"/snap", "snap"},
        {"/var/lib/flatpak", "flatpak"},
        {"/nix/store", "nix"},
        {"/usr/local/Cellar", "homebrew"},
        {"/opt/homebrew", "homebrew"},
    }};

    for (const auto& owner : kOwned) {
        if (isUnder(path, owner.prefix)) return owner.name;
    }
    return {};
}

std::optional<uint32_t> fileMode(const std::filesystem::path& path) {
#ifdef _WIN32
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || ec) return std::nullopt;
    return uint32_t{0};  // Windows has no mode bits to carry across
#else
    struct stat info{};
    if (::stat(path.string().c_str(), &info) != 0) return std::nullopt;
    return static_cast<uint32_t>(info.st_mode & 07777);
#endif
}

std::filesystem::path stagingPathFor(const std::filesystem::path& target) {
    // Beside the target, so the rename below stays inside one filesystem. A rename
    // across filesystems is not atomic and, on Linux, is not permitted at all - which
    // is why /tmp is not used for this however convenient it looks.
    //
    // The pid is in the name so two updates running at once do not write the same
    // staging file. They still race at the rename, and that is fine: rename is atomic,
    // so the loser's file is simply replaced by the winner's, and both were verified.
#ifdef _WIN32
    const auto pid = static_cast<long>(GetCurrentProcessId());
#else
    const auto pid = static_cast<long>(::getpid());
#endif
    auto name = target.filename().string() + fmt::format(".update-{}", pid);
    return target.parent_path() / name;
}

ReplaceAccess canReplace(const std::filesystem::path& target) {
    ReplaceAccess out;
    const auto directory = target.parent_path();
    if (directory.empty()) {
        out.reason = "the install directory could not be worked out";
        return out;
    }

    std::error_code ec;
    if (!std::filesystem::is_directory(directory, ec) || ec) {
        out.reason = fmt::format("{} is not a directory", directory.string());
        return out;
    }

    // Asked by writing. A stat cannot see a read-only mount, a full filesystem, an
    // immutable attribute or a container's restrictions, and every one of those decides
    // whether the replace below can happen.
    const auto probe = stagingPathFor(target).string() + ".probe";
    std::FILE* file = std::fopen(probe.c_str(), "wb");
    if (file == nullptr) {
        const int error = errno;
        out.reason = fmt::format("{} is not writable by this user ({})", directory.string(),
                                 std::strerror(error));
        return out;
    }
    std::fclose(file);
    std::error_code removeEc;
    std::filesystem::remove(probe, removeEc);

    out.ok = true;
    return out;
}

std::string adoptTargetOwnership(const std::filesystem::path& staged,
                                 const std::filesystem::path& target) {
#ifdef _WIN32
    (void)staged;
    (void)target;
    return {};  // Windows carries no mode bits across
#else
    // The mode the old binary had, carried over. A release download arrives 0644 from
    // the umask of whoever ran the update, and installing a scanner nobody can execute
    // is a broken update that reports success.
    const uint32_t mode = fileMode(target).value_or(0755);

    struct stat targetInfo{};
    const bool haveTargetOwner = ::stat(target.string().c_str(), &targetInfo) == 0;

    const int fd = ::open(staged.string().c_str(), O_RDONLY);
    if (fd < 0) {
        return fmt::format("the downloaded file could not be reopened ({})",
                           std::strerror(errno));
    }
    if (::fchmod(fd, static_cast<mode_t>(mode)) != 0) {
        const int error = errno;
        ::close(fd);
        return fmt::format("the downloaded file could not be given the old binary's "
                           "permissions ({})", std::strerror(error));
    }
    // Best effort, and only meaningful when this process is root: an install owned by a
    // service account must not silently become root-owned. A failure here is not fatal
    // because the common case - a user replacing their own file - cannot chown at all
    // and does not need to.
    if (haveTargetOwner) {
        (void)::fchown(fd, targetInfo.st_uid, targetInfo.st_gid);
    }
    ::close(fd);
    return {};
#endif
}

std::string replaceAtomically(const std::filesystem::path& staged,
                              const std::filesystem::path& target) {
#ifdef _WIN32
    (void)staged;
    (void)target;
    return "a running executable cannot be replaced on Windows";
#else
    if (const std::string failure = adoptTargetOwnership(staged, target); !failure.empty()) {
        return failure;
    }

    const int fd = ::open(staged.string().c_str(), O_RDONLY);
    if (fd < 0) {
        return fmt::format("the downloaded file could not be reopened ({})",
                           std::strerror(errno));
    }

    // Before the rename, not after. The point of the rename is that it publishes a file
    // that is already complete on the disk.
    if (::fsync(fd) != 0) {
        const int error = errno;
        ::close(fd);
        return fmt::format("the downloaded file could not be flushed to disk ({})",
                           std::strerror(error));
    }
    ::close(fd);

    if (::rename(staged.string().c_str(), target.string().c_str()) != 0) {
        return fmt::format("the new binary could not be moved into place ({})",
                           std::strerror(errno));
    }

    // And the directory, so the rename itself survives a power failure that the file's
    // own fsync survived. Not fatal if it fails - the rename has already happened and
    // the new binary is in place - so this reports success either way rather than
    // telling a user an update failed when it did not.
    const int dirFd = ::open(target.parent_path().string().c_str(), O_RDONLY | O_DIRECTORY);
    if (dirFd >= 0) {
        (void)::fsync(dirFd);
        ::close(dirFd);
    }
    return {};
#endif
}

bool stagedBinaryRuns(const std::filesystem::path& binary) {
#ifdef _WIN32
    (void)binary;
    return false;
#else
    const std::string path = binary.string();

    const pid_t pid = ::fork();
    if (pid < 0) return false;

    if (pid == 0) {
        // Output goes nowhere: this is a liveness check, not a source of information,
        // and a version banner printed into the middle of an update reads like part of
        // the update's own output.
        const int devNull = ::open("/dev/null", O_RDWR);
        if (devNull >= 0) {
            ::dup2(devNull, STDIN_FILENO);
            ::dup2(devNull, STDOUT_FILENO);
            ::dup2(devNull, STDERR_FILENO);
            if (devNull > STDERR_FILENO) ::close(devNull);
        }
        char argv0[] = "lyxbosa";
        char argv1[] = "--version";
        char* const argv[] = {argv0, argv1, nullptr};
        ::execv(path.c_str(), argv);
        ::_exit(127);  // execv only returns on failure
    }

    // Bounded, because a binary that hangs on --version must not hang the update. Ten
    // seconds is far more than a version banner needs and short enough that a person
    // watching does not conclude the tool is wedged.
    constexpr int kSliceMs = 20;
    constexpr int kSlices = 10 * 1000 / kSliceMs;
    for (int slice = 0; slice < kSlices; ++slice) {
        int status = 0;
        const pid_t done = ::waitpid(pid, &status, WNOHANG);
        if (done == pid) {
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
        if (done < 0) return false;
        struct timespec pause {
            0, kSliceMs * 1000L * 1000L
        };
        ::nanosleep(&pause, nullptr);
    }

    ::kill(pid, SIGKILL);
    int status = 0;
    ::waitpid(pid, &status, 0);
    return false;
#endif
}

}  // namespace lyxbosa
