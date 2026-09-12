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

// `patternType` of a finding raised by the FN rules: one about what the file is
// CALLED rather than about any byte inside it.
inline constexpr std::string_view kFilenamePatternType = "filename";

// A name finding says somebody uploaded a hostile name, not that these bytes are
// hostile. `x$(sleep 20)y.mdb` is very likely a perfectly ordinary Access database
// with a command substitution written on the outside of it.
inline bool isFilenameFinding(const FileMatch& match) {
    return match.patternType == kFilenamePatternType;
}

// Whether acting on this finding means moving the file.
//
// Two kinds of finding say no, for the same underlying reason twice: the finding is
// not about the bytes, so moving the bytes does not answer it.
//
//   - An exposure finding is the operator's own backup in the wrong place.
//   - A name finding is a hostile string attached to what may be the customer's
//     database. Worse than useless to move: quarantine under `preserve_structure`
//     mirrors the source path into the destination, so the command substitution
//     travels into the quarantine directory - the one directory an operator is most
//     likely to sweep later with a shell loop. The exposure would be relocated and
//     reported as handled. The answer to a hostile name is to delete it or rename it,
//     and which of those it is depends on whether the customer needs the file, which
//     is not a question a scanner can answer.
//
// A file carrying BOTH a name finding and a webshell signature still quarantines,
// because the signature is a content finding and this returns true for it. That falls
// out of asking the question per match rather than per file, which is why it is asked
// that way.
inline bool findingMeansMoveTheFile(const FileMatch& match) {
    return !isExposureFinding(match) && !isFilenameFinding(match);
}

// What happened to the container a file was found inside.
//
// A member of an archive is not a file on disk and is never moved on its own: the
// container goes as a unit, carrying every member with it. So this is a different fact
// from `quarantined` beside it, not a shade of it, and it is deliberately not written
// into that flag. Two reasons, and either alone would be enough. `filesQuarantined`
// counts files that were moved, so a member row claiming `quarantined` would make the
// rows disagree with the count - two answers to one question. And the operator's next
// action differs: nothing further is owed for a member that left with its container,
// while a member of a container that could NOT be moved is a webshell still under the
// web root, reachable at the same URL as before.
//
// Absent when no quarantine decision was made about the containing file at all -
// quarantine off, an exposure-only finding, or a loose file that has no container.
// That is the one thing absence may carry here, because it is the same "nothing was
// attempted" that an ordinary file's empty quarantine fields already mean.
enum class ContainerQuarantine : uint8_t {
    Moved,       // the container was quarantined; these bytes left the tree inside it
    MoveFailed,  // the container was selected and the move failed; still in place
};

// The machine-readable name: the JSON value and the CSV cell. Load-bearing, exactly
// like the skip-reason spellings - changing one breaks every consumer of a report.
constexpr std::string_view containerQuarantineToString(ContainerQuarantine outcome) {
    switch (outcome) {
        case ContainerQuarantine::Moved:      return "moved";
        case ContainerQuarantine::MoveFailed: return "moveFailed";
    }
    return "unknown";
}

// The human-readable phrase, for the readable report and the full-screen view.
//
// One definition because those are two commands answering about one file: the report
// file, the terminal and the scrolling pane of the full-screen UI all render the same
// member row, and an operator who sees them disagree stops trusting all three. Phrased
// to sit where `moved:` and `NOT quarantined` already sit on a loose file's line, so
// the two levels read as one vocabulary.
constexpr std::string_view containerQuarantineLabel(ContainerQuarantine outcome) {
    switch (outcome) {
        case ContainerQuarantine::Moved:      return "moved with its container";
        case ContainerQuarantine::MoveFailed: return "container NOT quarantined";
    }
    return "unknown";
}

// Result for a single file
struct FileResult {
    // Where the file was found. Never rewritten by a move: it is what the operator's
    // own notes and every earlier report say, and it is the half of the answer a
    // quarantine destination cannot reconstruct. `quarantinePath` below is where the
    // bytes are now, and the pair is what lets a row be followed in either direction.
    std::filesystem::path path;

    std::vector<FileMatch> matches;
    bool quarantined = false;

    // Where the bytes are NOW, empty when they did not move. A `std::filesystem::path`
    // rather than a string so that every writer renders it through pathForDisplay()
    // exactly as it renders `path`: a destination under `preserve_structure` mirrors
    // the source's whole path, so an attacker-controlled directory name reaches this
    // field, and it was previously printed raw and encoded in the host's ANSI code
    // page on Windows.
    //
    // For a container, the file's own destination. For a member of one, the address of
    // the member under that destination, `<container destination>!<member>` - the same
    // `container!member` form `path` already uses, so a reader who can follow one can
    // follow the other.
    std::filesystem::path quarantinePath;

    // The file was selected for quarantine and could not be moved, so it is still
    // where it was found. Never the same fact as `!quarantined`, which is also what
    // an exposure finding and a run with quarantine switched off both look like -
    // and the difference is whether a webshell is still under the web root.
    bool quarantineFailed = false;

    // What happened to the container this file was found inside; see the enum above.
    // Empty for a loose file and for a member no decision was made about.
    std::optional<ContainerQuarantine> containerQuarantine;

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
// nothing about one that could not be. The fourth is the same argument one level in: a
// member whose container did not move is a finding still under the web root, and that
// is worth a row whatever else the row carries.
inline bool worthReporting(const FileResult& result) {
    return !result.matches.empty() || result.skipped() ||
           result.quarantined || result.quarantineFailed ||
           result.containerQuarantine.has_value();
}

// True when a file carries at least one finding about its own content, as opposed to
// only findings about where it sits or what it is called.
inline bool hasHostileContent(const FileResult& result) {
    for (const auto& match : result.matches) {
        if (findingMeansMoveTheFile(match)) {
            return true;
        }
    }
    return false;
}

// True when a file carries at least one finding about its name.
inline bool hasHostileName(const FileResult& result) {
    for (const auto& match : result.matches) {
        if (isFilenameFinding(match)) {
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

    // Files carrying at least one FN finding - a hostile name. A count and not a list,
    // and a rollup rather than a shape of its own, because the per-file answer is
    // already carried where every other finding's is: a match row with an FN code, a
    // severity, a JSON entry and a CSV line. What this adds is the volume, which is the
    // one thing those cannot say. 83 in one upload directory is an afternoon; a worse
    // host gives thousands, and an operator who reads "Files with a hostile name: 4,102"
    // beside "Files with matches: 4,118" knows in one line that sixteen files are the
    // actual compromise and the rest is a vulnerability scanner's litter.
    //
    // Files rather than matches, so it is comparable with filesWithMatches directly
    // above it - one name can raise three findings, and a ratio between a match count
    // and a file count is a number nobody can use.
    size_t filesWithHostileNames = 0;

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
