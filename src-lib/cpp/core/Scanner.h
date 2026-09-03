#pragma once

#include "archive/ArchiveScanner.h"
#include "config/Rules.h"
#include "FileWalker.h"
#include "MatchEngine.h"
#include "ScanResult.h"
#include "SkipReason.h"
#include "Interrupt.h"
#include <filesystem>
#include <functional>

namespace lyxbosa {

// Where the scan is in its lifecycle. Counting runs concurrently with scanning,
// so Discovering means "scanning, but the total is not known yet".
enum class ScanPhase {
    Discovering,
    Scanning,
    Finished
};

// Callback for progress reporting
struct ScanProgress {
    ScanPhase phase = ScanPhase::Discovering;

    size_t filesScanned = 0;
    size_t totalFiles = 0;          // 0 while still unknown
    size_t discoveredFiles = 0;     // running count from the concurrent pre-count
    size_t directoriesScanned = 0;
    uint64_t bytesScanned = 0;
    uint64_t totalBytes = 0;        // 0 while still unknown; pairs with totalFiles

    size_t filesWithMatches = 0;
    size_t totalMatchCount = 0;     // Total matches found so far
    size_t filesQuarantined = 0;

    // Files not scanned, by reason - the file-level counterpart of `archives`
    // below, so the display can name a skip instead of only counting one kind.
    SkipTally skips;

    // Live severity breakdown, so the display can show what kind of trouble it
    // is finding rather than just how much.
    size_t criticalCount = 0;
    size_t highCount = 0;
    size_t mediumCount = 0;
    size_t lowCount = 0;

    size_t currentFileSize = 0;
    std::filesystem::path currentFile;

    // Where the scan is inside an archive, empty when it is not in one. An
    // archive must not be one tick on the progress bar: a 20 GB backup would
    // freeze the display on a single "file" for minutes and strand the ETA.
    // Scanning an archive should look like scanning a directory, because that is
    // what it is.
    std::filesystem::path currentArchive;
    size_t archiveMember = 0;       // 1-based position within the archive
    size_t archiveMemberTotal = 0;  // 0 when unknown, which a tar always is

    // Members not scanned, by reason, so nothing is skipped silently.
    archive::Stats archives;
};

using ProgressCallback = std::function<void(const ScanProgress&)>;

// Called for every file worth reporting - one with matches, or one skipped
// because of the size limit - as soon as it is known, so reports can stream.
using FileResultCallback = std::function<void(const FileResult&)>;

// Main scanner orchestrator
class Scanner {
public:
    explicit Scanner(const AppConfig& config);

    // Scan all configured directories
    ScanResult scan();

    // Scan a single file
    FileResult scanFile(const std::filesystem::path& path);

    // Set progress callback (optional)
    void setProgressCallback(ProgressCallback callback);

    // Set the reportable-file callback (matches found, or skipped for size)
    void setFileResultCallback(FileResultCallback callback);

    // Check if quarantine is enabled
    bool isQuarantineEnabled() const { return config_.actions.quarantine.enabled && !dryRun_; }

    // Set dry-run mode (no quarantine)
    void setDryRun(bool dryRun) { dryRun_ = dryRun; }

    // Pre-count files (concurrently) so progress can show a percentage.
    // Disabling it starts scanning immediately with an indeterminate total.
    void setPreCount(bool preCount) { preCount_ = preCount; }

    // Check if scan was interrupted
    bool wasInterrupted() const { return interrupted_; }

private:
    // Read file content
    // Thrown by readFile when the file is past maxSize. Distinct from a read
    // failure, because the two are different skip reasons and used to be the same
    // empty string.
    struct OversizeFile {};

    // Reads the whole file. Throws rather than returning empty: an empty string is
    // indistinguishable from an empty file, and treating it as content is how an
    // unreadable file came to be reported as scanned and clean.
    std::string readFile(const std::filesystem::path& path, uint64_t maxSize);

    // Scan a file, keeping the bytes that were read. The content is needed twice:
    // once for the rules, and once to find out whether the file is a container -
    // which is a question about its bytes, never about its name.
    FileResult scanContent(const std::filesystem::path& path, std::string& content);

    // Quarantine a file
    bool quarantineFile(const std::filesystem::path& source, std::string& destPath);

    AppConfig config_;
    MatchEngine engine_;
    archive::ArchiveScanner archives_;
    ProgressCallback progressCallback_;
    FileResultCallback fileResultCallback_;
    bool dryRun_ = false;
    bool preCount_ = true;
    bool interrupted_ = false;
};

}  // namespace lyxbosa
