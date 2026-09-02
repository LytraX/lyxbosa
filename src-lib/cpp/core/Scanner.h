#pragma once

#include "config/Rules.h"
#include "FileWalker.h"
#include "MatchEngine.h"
#include "ScanResult.h"
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

    size_t filesWithMatches = 0;
    size_t totalMatchCount = 0;     // Total matches found so far
    size_t filesSkippedSize = 0;
    size_t filesQuarantined = 0;

    // Live severity breakdown, so the display can show what kind of trouble it
    // is finding rather than just how much.
    size_t criticalCount = 0;
    size_t highCount = 0;
    size_t mediumCount = 0;
    size_t lowCount = 0;

    size_t currentFileSize = 0;
    std::filesystem::path currentFile;
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
    std::string readFile(const std::filesystem::path& path, uint64_t maxSize);

    // Quarantine a file
    bool quarantineFile(const std::filesystem::path& source, std::string& destPath);

    AppConfig config_;
    MatchEngine engine_;
    ProgressCallback progressCallback_;
    FileResultCallback fileResultCallback_;
    bool dryRun_ = false;
    bool preCount_ = true;
    bool interrupted_ = false;
};

}  // namespace lyxbosa
