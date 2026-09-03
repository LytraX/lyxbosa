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
    // Empty when the file was scanned. A skip is never silent: every one of the
    // three file-level reasons is recorded, so a report can say which.
    std::optional<SkipReason> skipReason;
    uint64_t fileSize = 0;

    bool skipped() const { return skipReason.has_value(); }
};

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
