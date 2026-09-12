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

    // Which of the two filters rejected this file, when `skip` is Excluded.
    //
    // To a report they are one skip reason, and to the scanner they are two different
    // intentions. The include list decides what gets OPENED - the shipped
    // configuration says exactly that in its own comment, because an extension is
    // never trusted to say what a file is - while an `exclude` pattern is the operator
    // writing down a tree they do not want looked at. So a question that needs no open
    // may be asked of the first and must not be asked of the second, and the only such
    // question the scanner has is whether the file's NAME is hostile.
    //
    // It is carried here rather than re-derived from the path, because re-running the
    // glob list over every file a `node_modules/**` pattern cut is a second full pass
    // over the largest part of the tree.
    bool excludedByPattern = false;
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
    //
    // `cycleSkippedDirs` counts the directories the walk declined to enter because
    // entering one would have re-entered a directory it was already inside. Their
    // contents are covered at the path they lead back to, so this is not a coverage
    // gap - but it is not nothing either, and no other count moves when it happens.
    size_t walk(FileCallback callback, size_t* unreadableDirs = nullptr,
                std::vector<std::filesystem::path>* missingRoots = nullptr,
                size_t* cycleSkippedDirs = nullptr) const;

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
    //
    // STOPPING. `stopped` has two causes and the walk does not distinguish them: the
    // callback returned false, or interrupted() became true. It is polled per entry and
    // per directory rather than left to the callback, because the callback is reached
    // only by a regular file and a tree of nothing but directories contains none - such
    // a walk could not be stopped at all. A caller that needs to tell the two apart
    // asks interrupted(), which is the flag both of them read.
    //
    // LOOPS. A directory is not entered when its identity is already on the path from
    // `dir` down to it - the shape a directory symlink pointing at an ancestor makes.
    // Identity is asked of every directory whatever followSymlinks says, because what
    // stops the default configuration looping is the absence of such a link on the
    // hosts tried and not anything this walk checks: a FUSE filesystem or a hostile
    // network server can present a directory inside itself with no symlink anywhere.
    size_t walkDirectory(const std::filesystem::path& dir, FileCallback callback, bool& stopped,
                         size_t* unreadableDirs = nullptr,
                         size_t* cycleSkippedDirs = nullptr) const;

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

    // Which side of the filters has an opinion about this path.
    enum class FilterVerdict {
        Accepted,     // scan it
        NotIncluded,  // no `include` pattern covers it, so it is not opened
        Excluded,     // an `exclude` pattern names it: the operator said do not look
    };

    // Check if a file matches the include/exclude filters
    bool matchesFilters(const std::filesystem::path& path) const {
        return filterVerdict(path) == FilterVerdict::Accepted;
    }

    // The same question, answered with its reason. One definition, so the two can
    // never drift into disagreeing about whether a file is in the scan.
    FilterVerdict filterVerdict(const std::filesystem::path& path) const;

private:
    // Check if path matches a glob pattern
    static bool matchesGlob(const std::string& pattern, const std::filesystem::path& path);

    ScanConfig config_;
    DirectoryCallback dirCallback_;
};

}  // namespace lyxbosa
