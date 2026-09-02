#pragma once

#include "config/Rules.h"
#include <filesystem>
#include <vector>
#include <string>
#include <functional>

namespace lyxbosa {

// File information passed to callbacks
struct FileInfo {
    std::filesystem::path path;
    uint64_t size = 0;
    bool isSymlink = false;
};

// Callback function type for file iteration
// Returns true to continue, false to stop walking
using FileCallback = std::function<bool(const FileInfo&)>;

// Called once as each directory is entered, so callers can report directory
// progress live rather than only learning the total when the walk ends.
using DirectoryCallback = std::function<void(const std::filesystem::path&)>;

// Called periodically during countFiles with the running total.
using CountProgressCallback = std::function<void(size_t discovered)>;

// Directory traversal with filtering
class FileWalker {
public:
    explicit FileWalker(const ScanConfig& config);

    // Walk all configured directories and call callback for each matching file
    // Returns the number of directories traversed
    size_t walk(FileCallback callback) const;

    // Walk a single directory (stopped is set to true if callback returns false)
    size_t walkDirectory(const std::filesystem::path& dir, FileCallback callback, bool& stopped) const;

    // Count total files without processing (fast pre-scan). The optional
    // callback receives the running total so a long count is not silent.
    size_t countFiles(const CountProgressCallback& onProgress = {}) const;

    // Report each directory as it is entered. Not thread-safe with respect to
    // walk(); set it before walking, and use a separate FileWalker per thread.
    void setDirectoryCallback(DirectoryCallback callback) {
        dirCallback_ = std::move(callback);
    }

    // Check if a file matches the include/exclude filters
    bool matchesFilters(const std::filesystem::path& path) const;

private:
    // Check if path matches a glob pattern
    static bool matchesGlob(const std::string& pattern, const std::filesystem::path& path);

    ScanConfig config_;
    DirectoryCallback dirCallback_;
};

}  // namespace lyxbosa
