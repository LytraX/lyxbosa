#pragma once

#include "config/Rules.h"
#include "SkipReason.h"
#include <filesystem>
#include <vector>
#include <string>
#include <functional>
#include <optional>

namespace lyxbosa {

// File information passed to callbacks
struct FileInfo {
    std::filesystem::path path;
    uint64_t size = 0;
    bool isSymlink = false;

    // Empty means "scan it". The walker decides *why* a file is not scanned, so
    // the scanner never has to re-derive it - which is how a failed stat used to
    // be reported as an oversize file and then scanned anyway.
    std::optional<SkipReason> skip;
};

// Callback function type for file iteration
// Returns true to continue, false to stop walking
using FileCallback = std::function<bool(const FileInfo&)>;

// Called once as each directory is entered, so callers can report directory
// progress live rather than only learning the total when the walk ends.
using DirectoryCallback = std::function<void(const std::filesystem::path&)>;

// Called periodically during countFiles with the running total.
using CountProgressCallback = std::function<void(size_t discovered)>;

// What the pre-count learned. Bytes matter as much as the count: scan time is
// dominated by the content actually matched against, so an ETA built on file
// counts alone lurches every time a large file turns up.
struct CountResult {
    size_t files = 0;
    uint64_t bytes = 0;
};

// Called for each file the count walks past, so a caller can add work the walk
// cannot see. An archive is a directory in every sense that matters to progress -
// its members are files - and a zip says how many it holds without decompressing
// one, so the count can be exact rather than a guess.
using CountAugmentCallback = std::function<void(const FileInfo&, CountResult&)>;

// Why a directory named as a scan root cannot be walked, or nullopt when it can be.
//
// A root is the operator's own words - an argument on the command line or a line in a
// configuration file - so a root that is not there is their mistake and not a fact
// about the tree. That is deliberately NOT the question walkDirectory() asks of a
// subdirectory it descends into: that one can vanish under a running scan, which is a
// race and nobody's error. The only thing that tells the two apart is which of them
// the operator named, and only walk() knows that.
std::optional<std::string> rootUnusableReason(const std::filesystem::path& dir);

// Directory traversal with filtering
class FileWalker {
public:
    explicit FileWalker(const ScanConfig& config);

    // Walk all configured directories and call callback for each matching file
    // Returns the number of directories traversed.
    //
    // `missingRoots` collects every configured root that rootUnusableReason() refused,
    // because a walk whose success is defined by what it managed to open reports a
    // root that was never there as a clean scan of nothing.
    size_t walk(FileCallback callback, size_t* unreadableDirs = nullptr,
                std::vector<std::filesystem::path>* missingRoots = nullptr) const;

    // Walk a single directory and everything under it (stopped is set to true if
    // callback returns false). Returns the number of directories entered.
    //
    // The traversal is iterative - an explicit stack of directories, not recursion -
    // so directory depth costs no call stack and cannot overflow one. That matters
    // because depth is attacker-controlled and because the pre-count walk runs on a
    // spawned thread, whose stack is 8 MB under glibc and 128 KB under musl. The
    // implementation says what else that choice buys.
    //
    // Order: depth-first, and within a directory every file is reported before the
    // walk descends into any subdirectory. Sibling order is the host's listing order.
    // Callers must not depend on more than that.
    size_t walkDirectory(const std::filesystem::path& dir, FileCallback callback, bool& stopped,
                         size_t* unreadableDirs = nullptr) const;

    // Count total files and bytes without processing (fast pre-scan). The
    // optional callback receives the running file count so a long count is not
    // silent.
    CountResult countFiles(const CountProgressCallback& onProgress = {},
                           const CountAugmentCallback& augment = {}) const;

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
