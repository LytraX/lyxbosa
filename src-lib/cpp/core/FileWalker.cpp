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

size_t FileWalker::walk(FileCallback callback) const {
    size_t dirCount = 0;
    bool stopped = false;

    for (const auto& dir : config_.directories) {
        dirCount += walkDirectory(dir, callback, stopped);
        if (stopped) break;
    }

    return dirCount;
}

size_t FileWalker::walkDirectory(const std::filesystem::path& dir, FileCallback callback, bool& stopped) const {
    namespace fs = std::filesystem;

    if (stopped || !fs::exists(dir) || !fs::is_directory(dir)) {
        return 0;
    }

    if (dirCallback_) {
        dirCallback_(dir);
    }

    size_t dirCount = 1;

    std::error_code ec;
    auto options = fs::directory_options::skip_permission_denied;
    if (config_.followSymlinks) {
        options |= fs::directory_options::follow_directory_symlink;
    }

    auto processEntry = [&](const fs::directory_entry& entry) -> bool {
        if (stopped) return false;

        if (entry.is_directory(ec)) {
            if (config_.recursive && !entry.is_symlink(ec)) {
                dirCount += walkDirectory(entry.path(), callback, stopped);
            } else if (config_.recursive && config_.followSymlinks && entry.is_symlink(ec)) {
                dirCount += walkDirectory(entry.path(), callback, stopped);
            }
            return !stopped;
        }

        if (!entry.is_regular_file(ec)) {
            return true;
        }

        // Check symlink handling
        if (entry.is_symlink(ec) && !config_.followSymlinks) {
            return true;
        }

        // Check file size
        auto fileSize = entry.file_size(ec);
        if (ec || (config_.maxFileSize > 0 && fileSize > config_.maxFileSize)) {
            // Still report it but mark as skipped due to size
            FileInfo info;
            info.path = entry.path();
            info.size = fileSize;
            info.isSymlink = entry.is_symlink(ec);
            if (!callback(info)) {
                stopped = true;
                return false;
            }
            return true;
        }

        // Check filters
        if (!matchesFilters(entry.path())) {
            return true;
        }

        FileInfo info;
        info.path = entry.path();
        info.size = fileSize;
        info.isSymlink = entry.is_symlink(ec);
        if (!callback(info)) {
            stopped = true;
            return false;
        }
        return true;
    };

    try {
        for (const auto& entry : fs::directory_iterator(dir, options, ec)) {
            if (!processEntry(entry)) break;
        }
    } catch (const fs::filesystem_error&) {
        // Skip directories we can't access
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

size_t FileWalker::countFiles(const CountProgressCallback& onProgress) const {
    size_t count = 0;

    // Counting is a full traversal in its own right and can run for minutes on a
    // large tree, so it has to honour an interrupt too - otherwise Ctrl+C during
    // the count appears to do nothing until the count finishes.
    walk([&count, &onProgress](const FileInfo&) {
        if (interrupted()) {
            return false;
        }
        ++count;
        if (onProgress && (count % 512) == 0) {
            onProgress(count);
        }
        return true;  // Continue counting
    });

    return count;
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
