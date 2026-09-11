#include "FileWalker.h"
#include "Interrupt.h"
#include <algorithm>

#ifdef _WIN32
// Portable fnmatch replacement for Windows
// Supports *, ?, and ** (recursive) glob patterns
static bool portable_fnmatch(const char* pattern, const char* str) {
    while (*pattern && *str) {
        if (*pattern == '*') {
            if (*(pattern + 1) == '*') {
                // ** matches everything including path separators
                pattern += 2;
                if (*pattern == '/' || *pattern == '\\') pattern++;
                if (!*pattern) return true;
                for (const char* s = str; *s; ++s) {
                    if (portable_fnmatch(pattern, s)) return true;
                }
                return false;
            }
            // * matches everything except path separators
            pattern++;
            if (!*pattern) {
                // trailing * — match if no more separators
                while (*str) {
                    if (*str == '/' || *str == '\\') return false;
                    str++;
                }
                return true;
            }
            for (const char* s = str; *s; ++s) {
                if (*s == '/' || *s == '\\') return false;
                if (portable_fnmatch(pattern, s)) return true;
            }
            return portable_fnmatch(pattern, str);
        }
        if (*pattern == '?') {
            if (*str == '/' || *str == '\\') return false;
            pattern++;
            str++;
            continue;
        }
        char pc = *pattern, sc = *str;
        if (pc == '\\') pc = '/';
        if (sc == '\\') sc = '/';
        if (pc != sc) return false;
        pattern++;
        str++;
    }
    while (*pattern == '*') pattern++;
    return !*pattern && !*str;
}
#else
#include <fnmatch.h>
#endif

namespace lyxbosa {

FileWalker::FileWalker(const ScanConfig& config)
    : config_(config) {
}

std::optional<std::string> rootUnusableReason(const std::filesystem::path& dir) {
    namespace fs = std::filesystem;

    // The error_code overloads, because a root on a filesystem that is not answering
    // is a root this cannot walk either, and that has to be a reason rather than an
    // exception thrown out of a scan.
    std::error_code ec;
    if (!fs::exists(dir, ec) || ec) {
        return "no such directory";
    }
    if (!fs::is_directory(dir, ec) || ec) {
        return "not a directory";
    }
    return std::nullopt;
}

size_t FileWalker::walk(FileCallback callback, size_t* unreadableDirs,
                        std::vector<std::filesystem::path>* missingRoots) const {
    size_t dirCount = 0;
    bool stopped = false;

    for (const auto& dir : config_.directories) {
        // A root the operator named and that is not there is recorded rather than
        // walked past. walkDirectory() returns 0 for the same shape and must keep
        // doing so - it is the recursion step as well, and a subdirectory that
        // disappears mid-walk is a race - so the distinction is drawn here, which is
        // the only place that knows a path came from the operator.
        if (rootUnusableReason(dir)) {
            if (missingRoots) {
                missingRoots->push_back(dir);
            }
            continue;
        }
        dirCount += walkDirectory(dir, callback, stopped, unreadableDirs);
        if (stopped) break;
    }

    return dirCount;
}

size_t FileWalker::walkDirectory(const std::filesystem::path& dir, FileCallback callback, bool& stopped,
                                 size_t* unreadableDirs) const {
    namespace fs = std::filesystem;

    // An explicit stack of directories still to read, rather than one C++ call frame
    // per directory level.
    //
    // Directory depth is attacker-controlled - a mkdir loop is three lines of shell -
    // so a recursive walk turns a tree into a stack overflow, and the tool that
    // crashes is the one somebody is running to investigate an incident. It was
    // reachable in practice rather than in theory: Scanner::scan() runs a second walk
    // on a spawned thread to pre-count files, glibc gives that thread 8 MB of stack
    // and musl gives it 128 KB, so the static musl build died with SIGSEGV on a tree
    // the glibc build walked without noticing. Raising the thread's stack would have
    // moved the ceiling; an explicit stack removes it, on both C libraries, on any
    // thread, and on Windows.
    //
    // Only directories are held here, never the files in them. A walk that buffered
    // each directory's entries would trade a depth limit for a width one, and width
    // is attacker-controlled in exactly the same way: this way a directory of ten
    // million files costs the walk nothing at all.
    //
    // ORDER. Files are reported for the whole of one directory before the walk
    // descends into any of its subdirectories, where the recursive version descended
    // at the point a subdirectory appeared in the listing. Within each of those two
    // groups the host's own listing order is preserved - children are pushed in
    // reverse so they come back off the stack in the order they were read - and the
    // traversal is still depth-first. Nothing downstream reads the walk's order: the
    // scanner accumulates counts and appends findings, the reporters iterate whatever
    // they are given, and no case asserts a sequence.
    std::vector<fs::path> pending;
    pending.push_back(dir);

    // Subdirectories of the directory currently being read, in listing order. Held
    // outside the loop so one buffer serves the whole walk.
    std::vector<fs::path> children;

    size_t dirCount = 0;

    std::error_code ec;

    // Deliberately *not* skip_permission_denied. That option's whole job is to
    // report a directory the scanner cannot read as no error at all, which left
    // an unreadable tree indistinguishable from an empty one - the scan quietly
    // covered less than the operator asked for and said nothing.
    //
    // The error_code overload of directory_iterator does not throw either way, so
    // dropping the option costs nothing in robustness: the walk still continues
    // past a directory it cannot open. It just knows that it did.
    auto options = fs::directory_options::none;
    if (config_.followSymlinks) {
        options |= fs::directory_options::follow_directory_symlink;
    }

    auto processEntry = [&](const fs::directory_entry& entry) -> bool {
        if (stopped) return false;

        if (entry.is_directory(ec)) {
            if (config_.recursive && !entry.is_symlink(ec)) {
                children.push_back(entry.path());
            } else if (config_.recursive && config_.followSymlinks && entry.is_symlink(ec)) {
                children.push_back(entry.path());
            }
            return true;
        }

        if (!entry.is_regular_file(ec)) {
            return true;
        }

        // Check symlink handling
        if (entry.is_symlink(ec) && !config_.followSymlinks) {
            return true;
        }

        FileInfo info;
        info.path = entry.path();
        info.isSymlink = entry.is_symlink(ec);

        // Filters first. An excluded file is excluded whatever its size - deciding
        // that a 6 GB file the operator told us to ignore was "skipped for size"
        // is backwards, and it is the size skip that gets read as a coverage gap.
        if (!matchesFilters(entry.path())) {
            info.size = 0;
            info.skip = SkipReason::Excluded;
            if (!callback(info)) {
                stopped = true;
                return false;
            }
            return true;
        }

        // `ec` and oversize are two different facts and must not share a branch.
        // Conflated, a failed file_size() left `fileSize` unspecified (0 on
        // libstdc++), so the file was reported as a size skip and then, because
        // 0 > maxFileSize is false, read anyway - and reported scanned and clean.
        std::error_code sizeEc;
        auto fileSize = entry.file_size(sizeEc);
        if (sizeEc) {
            info.size = 0;
            info.skip = SkipReason::Unreadable;
        } else {
            info.size = fileSize;
            if (config_.maxFileSize > 0 && fileSize > config_.maxFileSize) {
                info.skip = SkipReason::Size;
            }
        }

        if (!callback(info)) {
            stopped = true;
            return false;
        }
        return true;
    };

    while (!pending.empty() && !stopped) {
        const fs::path current = std::move(pending.back());
        pending.pop_back();

        // Quiet about a path that is not a directory by the time the walk reaches
        // it. A subdirectory can vanish under a running scan, and that is a race and
        // nobody's error; a root the operator named and got wrong is walk()'s
        // question, because walk() is the only place that knows a path came from the
        // operator. One is_directory() answers both halves of the exists()-then-
        // is_directory() pair the recursive version asked - absent and not-a-
        // directory are both false - and asks the host once instead of twice.
        std::error_code currentEc;
        if (!fs::is_directory(current, currentEc)) {
            continue;
        }

        if (dirCallback_) {
            dirCallback_(current);
        }

        ++dirCount;
        children.clear();

        try {
            for (const auto& entry : fs::directory_iterator(current, options, ec)) {
                if (!processEntry(entry)) break;
            }
            // directory_options::skip_permission_denied means the iterator swallows an
            // unreadable subdirectory silently; `ec` is where it says so.
            if (ec && unreadableDirs) {
                ++*unreadableDirs;
            }
        } catch (const fs::filesystem_error&) {
            // A directory the scanner was pointed at and could not read is a fact about
            // the scan's coverage, not nothing.
            if (unreadableDirs) {
                ++*unreadableDirs;
            }
        }

        // Reversed, so the deepest-first stack hands them back in listing order.
        pending.insert(pending.end(), children.rbegin(), children.rend());
    }

    return dirCount;
}

bool FileWalker::matchesFilters(const std::filesystem::path& path) const {
    // If no include filters, include everything
    // If include filters exist, file must match at least one
    bool included = config_.include.empty();

    if (!included) {
        for (const auto& pattern : config_.include) {
            if (matchesGlob(pattern, path)) {
                included = true;
                break;
            }
        }
    }

    if (!included) {
        return false;
    }

    // Check exclude patterns
    for (const auto& pattern : config_.exclude) {
        if (matchesGlob(pattern, path)) {
            return false;
        }
    }

    return true;
}

CountResult FileWalker::countFiles(const CountProgressCallback& onProgress,
                                   const CountAugmentCallback& augment) const {
    CountResult result;

    // Counting is a full traversal in its own right and can run for minutes on a
    // large tree, so it has to honour an interrupt too - otherwise Ctrl+C during
    // the count appears to do nothing until the count finishes.
    walk([&result, &onProgress, &augment](const FileInfo& info) {
        if (interrupted()) {
            return false;
        }
        // The walk now reports excluded files so they can be tallied; they are not
        // work, so they must not enter the total the progress bar divides by.
        if (info.skip == SkipReason::Excluded) {
            return true;
        }
        ++result.files;
        result.bytes += info.size;
        if (augment) {
            augment(info, result);
        }
        if (onProgress && (result.files % 512) == 0) {
            onProgress(result.files);
        }
        return true;  // Continue counting
    });

    return result;
}

bool FileWalker::matchesGlob(const std::string& pattern, const std::filesystem::path& path) {
    // Handle special "!ext" pattern (files without extension)
    if (pattern == "!ext") {
        return !path.has_extension();
    }

    // Try matching against filename only first
    std::string filename = path.filename().string();
#ifdef _WIN32
    if (portable_fnmatch(pattern.c_str(), filename.c_str())) {
        return true;
    }

    // For patterns with **, try matching against full path
    if (pattern.find("**") != std::string::npos) {
        std::string fullPath = path.string();
        if (portable_fnmatch(pattern.c_str(), fullPath.c_str())) {
            return true;
        }
    }
#else
    if (fnmatch(pattern.c_str(), filename.c_str(), FNM_PATHNAME) == 0) {
        return true;
    }

    // For patterns with **, try matching against full path
    if (pattern.find("**") != std::string::npos) {
        std::string fullPath = path.string();
        if (fnmatch(pattern.c_str(), fullPath.c_str(), FNM_PATHNAME) == 0) {
            return true;
        }
    }
#endif

    return false;
}

}  // namespace lyxbosa
