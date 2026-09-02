#pragma once

#include "config/Rules.h"
#include "FileWalker.h"
#include "MatchEngine.h"
#include "ScanResult.h"
#include "Interrupt.h"
#include <filesystem>
#include <functional>

namespace lyxbosa {

// Callback for progress reporting
struct ScanProgress {
    size_t filesScanned = 0;
    size_t totalFiles = 0;          // Total files to scan (pre-counted)
    size_t filesWithMatches = 0;
    size_t totalMatchCount = 0;     // Total matches found so far
    size_t currentFileSize = 0;
    std::filesystem::path currentFile;
};

using ProgressCallback = std::function<void(const ScanProgress&)>;
using CountingCallback = std::function<void(size_t totalFiles)>;

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

    // Set counting done callback (called after file count is complete)
    void setCountingDoneCallback(CountingCallback callback);

    // Set the reportable-file callback (matches found, or skipped for size)
    void setFileResultCallback(FileResultCallback callback);

    // Check if quarantine is enabled
    bool isQuarantineEnabled() const { return config_.actions.quarantine.enabled && !dryRun_; }

    // Set dry-run mode (no quarantine)
    void setDryRun(bool dryRun) { dryRun_ = dryRun; }

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
    CountingCallback countingDoneCallback_;
    FileResultCallback fileResultCallback_;
    bool dryRun_ = false;
    bool interrupted_ = false;
};

}  // namespace lyxbosa
