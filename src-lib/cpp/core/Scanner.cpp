#include "Scanner.h"
#include "infrastructure/PathUtils.h"
#include "rules/Registry.hpp"
#include <fstream>
#include <sstream>
#include <fmt/base.h>

namespace lyxbosa {

Scanner::Scanner(const AppConfig& config)
    : config_(config) {
    // Load built-in CTRE rules first
    if (config_.builtinRules.enabled) {
        // First, disable any specified rules
        for (const auto& code : config_.builtinRules.disable) {
            engine_.disableBuiltinRule(code);
        }

        // Then load rules
        if (config_.builtinRules.use.empty()) {
            // Load all built-in rules by default
            engine_.loadAllBuiltinRules();
        } else {
            // Load only specified rules/categories
            for (const auto& spec : config_.builtinRules.use) {
                if (spec.starts_with("category:")) {
                    // Load entire category (e.g., "category:webshell")
                    auto catName = spec.substr(9);
                    auto cat = rules::parseCategory(catName);
                    if (cat) {
                        engine_.loadBuiltinCategory(*cat);
                    }
                } else {
                    // Load specific rule by code (e.g., "WS001")
                    engine_.loadBuiltinRule(spec);
                }
            }
        }
    }

    // Load custom YAML rules (in addition to built-in)
    engine_.loadRules(config_.rules);
}

ScanResult Scanner::scan() {
    ScanResult result;
    result.startTime = std::chrono::steady_clock::now();

    FileWalker walker(config_.scan);
    ScanProgress progress;

    // Pre-count files for progress reporting
    progress.totalFiles = walker.countFiles();

    // Notify that counting is done
    if (countingDoneCallback_) {
        countingDoneCallback_(progress.totalFiles);
    }

    auto reportProgress = [&](const std::filesystem::path& path, uint64_t size) {
        if (!progressCallback_) {
            return;
        }
        progress.filesScanned = result.totalFilesScanned;
        progress.filesWithMatches = result.filesWithMatches;
        progress.totalMatchCount = result.totalMatches;
        progress.currentFile = path;
        progress.currentFileSize = size;
        progressCallback_(progress);
    };

    auto fileCallback = [&](const FileInfo& info) -> bool {
        // Check for interrupt
        if (interrupted()) {
            interrupted_ = true;
            return false;  // Stop walking
        }

        // Files past the size limit are reported, not scanned
        if (config_.scan.maxFileSize > 0 && info.size > config_.scan.maxFileSize) {
            FileResult skipped;
            skipped.path = info.path;
            skipped.fileSize = info.size;
            skipped.skippedSize = true;

            ++result.filesSkippedSize;
            ++result.totalFilesScanned;
            result.files.push_back(skipped);

            reportProgress(info.path, info.size);
            if (fileResultCallback_) {
                fileResultCallback_(skipped);
            }
            return true;  // Continue walking
        }

        // Scan the file
        auto fileResult = scanFile(info.path);
        fileResult.fileSize = info.size;

        // Update statistics
        ++result.totalFilesScanned;
        result.totalMatches += fileResult.matches.size();

        if (!fileResult.matches.empty()) {
            ++result.filesWithMatches;

            // Quarantine if enabled
            if (isQuarantineEnabled()) {
                std::string destPath;
                if (quarantineFile(info.path, destPath)) {
                    fileResult.quarantined = true;
                    fileResult.quarantinePath = destPath;
                    ++result.filesQuarantined;
                }
            }
        }

        // Only reportable files are retained. Keeping a FileResult for every
        // clean file cost hundreds of megabytes of paths on a large tree and
        // bought nothing - every consumer filtered them straight back out.
        const bool reportable = !fileResult.matches.empty();
        if (reportable) {
            result.files.push_back(fileResult);
        }

        // Report progress FIRST (so display is initialized before match output)
        reportProgress(info.path, info.size);

        // Notify about the finding AFTER progress (for real-time output)
        if (reportable && fileResultCallback_) {
            fileResultCallback_(fileResult);
        }

        return true;  // Continue walking
    };

    result.totalDirectoriesScanned = walker.walk(fileCallback);

    result.endTime = std::chrono::steady_clock::now();
    result.updateSeverityCounts();

    return result;
}

FileResult Scanner::scanFile(const std::filesystem::path& path) {
    FileResult result;
    result.path = path;

    try {
        std::string content = readFile(path, config_.scan.maxFileSize);
        result.fileSize = content.size();

        auto matches = engine_.match(content, pathToUtf8(path));
        result.matches = std::move(matches);

    } catch (const std::exception&) {
        // Can't read file, return empty result
    }

    return result;
}

void Scanner::setProgressCallback(ProgressCallback callback) {
    progressCallback_ = std::move(callback);
}

void Scanner::setCountingDoneCallback(CountingCallback callback) {
    countingDoneCallback_ = std::move(callback);
}

void Scanner::setFileResultCallback(FileResultCallback callback) {
    fileResultCallback_ = std::move(callback);
}

std::string Scanner::readFile(const std::filesystem::path& path, uint64_t maxSize) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return "";
    }

    // Get file size
    file.seekg(0, std::ios::end);
    auto size = static_cast<uint64_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    // Check size limit
    if (maxSize > 0 && size > maxSize) {
        return "";
    }

    // Read entire file
    std::string content(size, '\0');
    file.read(content.data(), static_cast<std::streamsize>(size));

    return content;
}

bool Scanner::quarantineFile(const std::filesystem::path& source, std::string& destPath) {
    namespace fs = std::filesystem;

    if (!config_.actions.quarantine.enabled || config_.actions.quarantine.directory.empty()) {
        return false;
    }

    try {
        fs::path quarantineDir(config_.actions.quarantine.directory);

        // Create quarantine directory if it doesn't exist
        if (!fs::exists(quarantineDir)) {
            fs::create_directories(quarantineDir);
        }

        fs::path dest;

        if (config_.actions.quarantine.preserveStructure) {
            // Preserve directory structure relative to scan directories
            // Find which scan directory this file is under
            fs::path relativePath;
            for (const auto& scanDir : config_.scan.directories) {
                fs::path scanPath(scanDir);
                auto canonical = fs::weakly_canonical(source);
                auto canonicalScan = fs::weakly_canonical(scanPath);

                auto [rootEnd, nothing] = std::mismatch(
                    canonicalScan.begin(), canonicalScan.end(),
                    canonical.begin(), canonical.end()
                );

                if (rootEnd == canonicalScan.end()) {
                    // Source is under this scan directory
                    relativePath = fs::relative(source, scanPath);
                    break;
                }
            }

            if (relativePath.empty()) {
                relativePath = source.filename();
            }

            dest = quarantineDir / relativePath;

            // Create parent directories
            fs::create_directories(dest.parent_path());
        } else {
            // Flat structure - just use filename
            dest = quarantineDir / source.filename();

            // Handle duplicates by adding numeric suffix
            int suffix = 0;
            while (fs::exists(dest)) {
                dest = quarantineDir / (source.stem().string() + "." +
                                        std::to_string(++suffix) +
                                        source.extension().string());
            }
        }

        // Move the file
        fs::rename(source, dest);
        destPath = dest.string();
        return true;

    } catch (const fs::filesystem_error&) {
        return false;
    }
}

}  // namespace lyxbosa
