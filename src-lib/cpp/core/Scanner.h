#pragma once

#include "config/Rules.h"
#include "FileWalker.h"
#include "MatchEngine.h"
#include "ScanResult.h"
#include <filesystem>
#include <functional>
#include <atomic>

namespace lyxbosa {

// Global flag for interrupt handling (signal-safe)
inline std::atomic<bool> g_interrupted{false};

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
using MatchCallback = std::function<void(const FileResult&)>;

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

    // Set match callback (called when a file with matches is found)
    void setMatchCallback(MatchCallback callback);

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
    MatchCallback matchCallback_;
    bool dryRun_ = false;
    bool interrupted_ = false;
};

}  // namespace lyxbosa
