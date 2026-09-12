#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <chrono>
#include <cstdint>
#include "config/Types.h"
#include "archive/ArchiveTypes.h"
#include "SkipReason.h"
#include <optional>

namespace lyxbosa {

// A single match within a file
struct FileMatch {
    std::string ruleName;
    Severity severity = Severity::Medium;
    Severity originalSeverity = Severity::Medium;  // Before suppression downgrade
    std::string category;
    std::string patternType;    // "string", "regex", etc.
    size_t offset = 0;          // byte offset in file
    size_t line = 1;            // 1-based line number
    size_t column = 1;          // 1-based column number
    std::string matchedText;
    std::string context;        // surrounding text
    bool suppressed = false;    // True if suppression comment detected nearby
};

// `patternType` of a finding the archive scanner raises about a *container* -
// that it is a site backup sitting in a web root - rather than about any bytes
// inside it.
inline constexpr std::string_view kExposurePatternType = "archive";

// An exposure finding says a file is in the wrong place, not that it is hostile.
// It is the operator's own backup, it can be tens of gigabytes, and moving it is
// a data-custody decision rather than remediation - so nothing that acts on
// findings may treat one as malware.
inline bool isExposureFinding(const FileMatch& match) {
    return match.patternType == kExposurePatternType;
}

// Result for a single file
struct FileResult {
    std::filesystem::path path;
    std::vector<FileMatch> matches;
    bool quarantined = false;
    std::string quarantinePath;  // where it was moved to, if quarantined

    // The file was selected for quarantine and could not be moved, so it is still
    // where it was found. Never the same fact as `!quarantined`, which is also what
    // an exposure finding and a run with quarantine switched off both look like -
    // and the difference is whether a webshell is still under the web root.
    bool quarantineFailed = false;

    // Empty when the file was scanned. A skip is never silent: every one of the
    // three file-level reasons is recorded, so a report can say which.
    std::optional<SkipReason> skipReason;
    uint64_t fileSize = 0;

    // What opening this file as a container covered, when it was one; empty when it
    // is not an archive or archives are off.
    //
    // A skip inside a container used to have nowhere to travel: the counters lived on
    // ScanResult, so the walk kept them and `scanFile()` - which returns one of these -
    // dropped them on the floor. `check` then printed "No matches found" for a
    // truncated gzip, which is what a genuinely clean file prints. The coverage rides
    // with the result it belongs to, so every caller of scanFile() inherits it rather
    // than having to know it exists.
    std::optional<archive::Stats> archive;

    bool skipped() const { return skipReason.has_value(); }

    // True when something about this file was not looked at: the file itself was
    // skipped, or its container could not be spoken for. What "No matches found" may
    // not be said about.
    bool examinedFully() const {
        return !skipped() && !(archive && archive::coverageIncomplete(*archive));
    }
};

// True when a report has something to say about this file. Matches and skips are the
// obvious two; the third is a quarantine outcome on a file with no matches of its own,
// which is what a container moved - or not moved - for what was inside it looks like.
// Without it a report says a file was quarantined nowhere at all, or worse, says
// nothing about one that could not be.
inline bool worthReporting(const FileResult& result) {
    return !result.matches.empty() || result.skipped() ||
           result.quarantined || result.quarantineFailed;
}

// True when a file carries at least one finding about its own content, as
// opposed to only an exposure finding about where it sits.
inline bool hasHostileContent(const FileResult& result) {
    for (const auto& match : result.matches) {
        if (!isExposureFinding(match)) {
            return true;
        }
    }
    return false;
}

// Aggregate scan results
struct ScanResult {
    std::vector<FileResult> files;

    // Statistics
    size_t totalFilesScanned = 0;
    size_t totalDirectoriesScanned = 0;
    size_t filesWithMatches = 0;
    size_t filesQuarantined = 0;

    // Files selected for quarantine that could not be moved, and so are still where
    // they were found. `if (quarantineFile(...))` with no else was the whole defect:
    // a file the tool was asked to contain and could not read exactly like one
    // quarantine was never enabled for.
    size_t filesQuarantineFailed = 0;

    size_t totalMatches = 0;
    uint64_t bytesScanned = 0;

    // Archive handling, including every member that was not scanned and why.
    // Silent skips are how a whole family of obfuscation stayed invisible; an
    // archive is exactly where a scanner is tempted to give up quietly.
    archive::Stats archives;

    // Files that were not scanned, by reason - the file-level counterpart of
    // archives.skips. `filesSkippedSize()` is kept so existing callers and the
    // `filesSkippedSize` JSON key mean exactly what they always did.
    SkipTally skips;

    size_t filesSkippedSize() const { return skips.count(SkipReason::Size); }

    // Directories the walk could not read at all. Not files, so not in the file
    // tally - but the operator asked for this tree and did not get all of it.
    size_t directoriesUnreadable = 0;

    // Directories the walk declined to enter because entering one would have re-entered
    // a directory it was already inside - what a directory symlink pointing at an
    // ancestor makes, and what made a scan of two links to `.` run without end.
    //
    // A third fact rather than a shade of either neighbour, and deliberately not an
    // error. directoriesUnreadable is a tree the scan asked for and did not get;
    // rootsMissing is a path the operator got wrong. This one is neither: the refused
    // directory's contents are read at the path it leads back to, so the answer is
    // complete and the exit code must not move - see the ranking in ScanUseCase. What
    // it does say is that the tree contains a loop, which explains a directory count
    // larger than the operator expected and is worth knowing about a web root.
    //
    // A count and not a list, exactly like directoriesUnreadable beside it. Listing the
    // paths was the alternative and rootsMissing does list them, because a root that is
    // not there cannot be acted on without its name; a loop needs no action, and one
    // fan-out tree can produce thousands of them.
    size_t directoriesCycleSkipped = 0;

    // Roots the operator named that the walk could not enter: absent, or there but
    // not a directory. A different fact from directoriesUnreadable, which is a tree
    // the scanner reached and could not read - this one was never there to reach, so
    // it is the operator's path that is wrong rather than the host's permissions.
    // Kept apart because they want different answers: an unreadable subdirectory is a
    // coverage warning, and a root that is not there means the scan that was asked
    // for did not happen at all.
    std::vector<std::filesystem::path> rootsMissing;

    // Timing
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;

    std::chrono::milliseconds duration() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    }

    // Summary by severity
    size_t criticalCount = 0;
    size_t highCount = 0;
    size_t mediumCount = 0;
    size_t lowCount = 0;

    void updateSeverityCounts() {
        criticalCount = highCount = mediumCount = lowCount = 0;
        for (const auto& file : files) {
            for (const auto& match : file.matches) {
                switch (match.severity) {
                    case Severity::Critical: ++criticalCount; break;
                    case Severity::High:     ++highCount; break;
                    case Severity::Medium:   ++mediumCount; break;
                    case Severity::Low:      ++lowCount; break;
                }
            }
        }
    }
};

}  // namespace lyxbosa
