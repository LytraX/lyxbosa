#include "Quarantine.h"

#include <string>

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#endif

namespace lyxbosa::quarantine {

namespace fs = std::filesystem;

namespace {

using Char = fs::path::value_type;
using Str = fs::path::string_type;

constexpr Char kSep = static_cast<Char>('/');
constexpr Char kBackSep = static_cast<Char>('\\');
constexpr Char kColon = static_cast<Char>(':');
constexpr Char kUnderscore = static_cast<Char>('_');

// A non-negative number as a path string. The digits are ASCII either way, so this is
// the same widening on Windows as it is a copy on POSIX - and it avoids constructing a
// path from a narrow string, which on Windows would go through the ANSI code page.
Str digitsAsPathString(int n) {
    const std::string digits = std::to_string(n);
    return Str(digits.begin(), digits.end());
}

// A root name as one ordinary path component. Empty on POSIX, where there is no
// such thing; `C:` -> `C` and `\\server\share` -> `server_share` on Windows, so a
// mirrored path keeps the volume it came from instead of merging two of them.
//
// Done on the native string rather than on string(), which on Windows is the ANSI
// code page and would mangle a share name that is not representable there.
Str rootNameComponent(const fs::path& absolute) {
    Str name = absolute.root_name().native();

    size_t start = 0;
    while (start < name.size() && (name[start] == kSep || name[start] == kBackSep)) {
        ++start;
    }
    name.erase(0, start);

    for (Char& c : name) {
        if (c == kSep || c == kBackSep || c == kColon) {
            c = kUnderscore;
        }
    }
    while (!name.empty() && name.back() == kUnderscore) {
        name.pop_back();
    }
    return name;
}

// The source as an absolute path with no `.` or `..` left in it.
//
// weakly_canonical also resolves symlinks, which is what an analyst wants recorded:
// the place the bytes actually were, not the link that reached them. It needs the
// filesystem, so it can fail on a path that has just been moved or on a mount that
// refuses; the lexical form is then the answer, and it is the one that matters for
// safety, because it is what removes the `..` that could otherwise place the
// destination outside the quarantine directory entirely.
fs::path normalisedSource(const fs::path& source) {
    std::error_code ec;
    const fs::path canonical = fs::weakly_canonical(source, ec);
    if (!ec && !canonical.empty()) {
        return canonical;
    }
    return fs::absolute(source, ec).lexically_normal();
}

}  // namespace

fs::path destinationFor(const fs::path& quarantineDir,
                        const fs::path& source,
                        bool preserveStructure) {
    if (!preserveStructure) {
        return quarantineDir / source.filename();
    }

    const fs::path absolute = normalisedSource(source);

    fs::path dest = quarantineDir;
    if (const Str root = rootNameComponent(absolute); !root.empty()) {
        dest /= root;
    }
    dest /= absolute.relative_path();
    return dest;
}

fs::path withDisambiguator(const fs::path& dest, int n) {
    return dest.parent_path() /
           (dest.stem().native() + static_cast<Char>('.') + digitsAsPathString(n) +
            dest.extension().native());
}

#ifdef _WIN32

MoveResult moveWithoutReplacing(const fs::path& source, const fs::path& dest) {
    // No MOVEFILE_REPLACE_EXISTING: without it MoveFileExW is already the refusing
    // move, and MOVEFILE_COPY_ALLOWED lets it cross a volume boundary by copying and
    // deleting rather than failing the way a rename would.
    if (MoveFileExW(source.c_str(), dest.c_str(),
                    MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH)) {
        return MoveResult::Moved;
    }

    const DWORD error = GetLastError();
    if (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS) {
        return MoveResult::DestinationExists;
    }
    return MoveResult::Failed;
}

#else

namespace {

// The rename that refuses, where the platform has one. Returns 0 on success and an
// errno otherwise; ENOSYS means this build or this kernel has no such call, which is
// not a failure, only an instruction to use the copy path.
int renameRefusingToReplace(const fs::path& source, const fs::path& dest) {
#if defined(__linux__) && defined(SYS_renameat2)
    // Called through syscall() rather than the glibc wrapper: musl has no renameat2
    // wrapper at all, and the flag constant is spelled here rather than pulling in
    // <linux/fs.h>, which collides with <sys/stat.h> on some toolchains.
    constexpr unsigned int kNoReplace = 1u << 0;  // RENAME_NOREPLACE
    if (::syscall(SYS_renameat2, AT_FDCWD, source.c_str(), AT_FDCWD, dest.c_str(),
                  kNoReplace) == 0) {
        return 0;
    }
    return errno;
#elif defined(__APPLE__) && defined(RENAME_EXCL)
    if (::renamex_np(source.c_str(), dest.c_str(), RENAME_EXCL) == 0) {
        return 0;
    }
    return errno;
#else
    (void)source;
    (void)dest;
    return ENOSYS;
#endif
}

// Create the destination exclusively, copy the bytes into it, flush, then drop the
// source. O_EXCL is the refusal: the kernel either makes the name or fails with
// EEXIST, and O_NOFOLLOW means a symlink sitting at the destination is refused
// rather than followed somewhere else.
MoveResult copyThenUnlink(const fs::path& source, const fs::path& dest) {
    const int in = ::open(source.c_str(), O_RDONLY);
    if (in < 0) {
        return MoveResult::Failed;
    }

    const int out = ::open(dest.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (out < 0) {
        const int error = errno;
        ::close(in);
        return error == EEXIST ? MoveResult::DestinationExists : MoveResult::Failed;
    }

    bool ok = true;
    char buffer[64 * 1024];
    for (;;) {
        const ssize_t got = ::read(in, buffer, sizeof(buffer));
        if (got == 0) {
            break;
        }
        if (got < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        ssize_t written = 0;
        while (written < got) {
            const ssize_t put = ::write(out, buffer + written, static_cast<size_t>(got - written));
            if (put < 0) {
                if (errno == EINTR) continue;
                ok = false;
                break;
            }
            written += put;
        }
        if (!ok) {
            break;
        }
    }

    if (ok && ::fsync(out) != 0) {
        ok = false;
    }
    ::close(out);
    ::close(in);

    // Only now is the original allowed to go. If it will not, the copy goes instead:
    // two copies of the evidence is a mess, but reporting a file as contained while
    // it is still where the attacker left it is the failure that matters.
    if (ok && ::unlink(source.c_str()) != 0) {
        ok = false;
    }
    if (!ok) {
        ::unlink(dest.c_str());
        return MoveResult::Failed;
    }
    return MoveResult::Moved;
}

}  // namespace

MoveResult moveWithoutReplacing(const fs::path& source, const fs::path& dest) {
    const int error = renameRefusingToReplace(source, dest);
    if (error == 0) {
        return MoveResult::Moved;
    }
    if (error == EEXIST || error == ENOTEMPTY) {
        return MoveResult::DestinationExists;
    }

    // Anything else and the rename is simply not available here - a different
    // filesystem (EXDEV), a kernel or mount that does not implement the flag
    // (ENOSYS, EINVAL, EOPNOTSUPP), or a permission the copy path may still have.
    // Trying the copy costs one failed open when it was a real refusal, and the copy
    // path never replaces anything either, so there is no case in which falling
    // through to it can overwrite what the rename declined to.
    return copyThenUnlink(source, dest);
}

#endif  // _WIN32

}  // namespace lyxbosa::quarantine
