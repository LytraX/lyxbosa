#include "Scanner.h"
#include "archive/ArchiveFormat.h"
#include "infrastructure/PathUtils.h"
#include "rules/Registry.hpp"
#include <atomic>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <fmt/base.h>

namespace lyxbosa {

Scanner::Scanner(const AppConfig& config)
    : config_(config), archives_(config_.archives, config_.scan, engine_) {
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

    // Count on a second thread rather than before the scan. The pre-count is a
    // full traversal of its own; running it first meant minutes of dead air on a
    // large or network-mounted tree before the first file was even looked at.
    // Scanning starts immediately and the display switches from indeterminate to
    // a percentage when the total lands.
    std::atomic<size_t> discovered{0};
    std::atomic<size_t> countedTotal{0};
    std::atomic<uint64_t> countedBytes{0};
    std::atomic<bool> countReady{false};
    std::thread counter;

    if (preCount_) {
        counter = std::thread([this, &discovered, &countedTotal, &countedBytes, &countReady] {
            FileWalker countWalker(config_.scan);

            // A zip's central directory sits at the end of the file and lists
            // every member's name and uncompressed size: the index of a 337 MB,
            // 28,092-member backup reads in 0.096 s, which is 0.8% of the cost of
            // reading the file. So the count can be exact for a zip without
            // decompressing a single member. A .tar.gz has no index and
            // contributes only its compressed size, which the walk already
            // counted; its members raise the total as they are reached.
            //
            // This opens attacker-controlled containers on the counting thread.
            // Every guard applies here too, and a hostile index costs the count
            // its accuracy, never its termination.
            CountAugmentCallback augment;
            if (config_.archives.enabled) {
                augment = [this](const FileInfo& info, CountResult& counted) {
                    if (!archive::hasArchiveExtension(info.path)) {
                        return;
                    }
                    const archive::Kind kind = archive::sniffFile(info.path);
                    if (kind != archive::Kind::Zip) {
                        return;
                    }
                    const auto members = archive::ArchiveScanner::countMembers(
                        info.path, kind, config_.archives, config_.scan);
                    counted.files += members.files;
                    counted.bytes += members.bytes;
                };
            }

            const CountResult counted = countWalker.countFiles(
                [&discovered](size_t partial) {
                    discovered.store(partial, std::memory_order_relaxed);
                },
                augment);
            countedTotal.store(counted.files, std::memory_order_relaxed);
            countedBytes.store(counted.bytes, std::memory_order_relaxed);
            countReady.store(true, std::memory_order_release);
        });
    }

    // Directory count, updated live as the walk descends.
    std::atomic<size_t> directoriesSeen{0};
    walker.setDirectoryCallback([&directoriesSeen](const std::filesystem::path&) {
        directoriesSeen.fetch_add(1, std::memory_order_relaxed);
    });

    // Where the scan is inside an archive. Cleared the moment it leaves one, so
    // the display never attributes a loose file to the archive before it.
    std::filesystem::path currentArchive;
    size_t currentMember = 0;
    size_t currentMemberTotal = 0;

    // Members of containers the pre-count could not index - a .tar.gz has no
    // index to read - so they raise the total as they are reached rather than
    // pushing filesScanned past it.
    size_t uncountedMembers = 0;

    // Compressed bytes of the current stream archive already charged to
    // bytesScanned, so the archive contributes its own size exactly once.
    uint64_t streamCharged = 0;

    auto publishProgress = [&](const std::filesystem::path& path, uint64_t size) {
        if (!progressCallback_) {
            return;
        }

        // The counting thread only ever publishes through these atomics; the
        // callback itself always runs on this thread, so the display never has
        // to be thread-safe.
        if (countReady.load(std::memory_order_acquire)) {
            // Members of a solid stream were never counted - a .tar.gz has no
            // index to count them from - so the total is revised upward as they
            // are reached. fraction() clamps to 1.0, so the worst this can do is
            // stall the bar near the end rather than lie about where it is.
            progress.totalFiles =
                countedTotal.load(std::memory_order_relaxed) + uncountedMembers;
            progress.totalBytes = countedBytes.load(std::memory_order_relaxed);
            progress.phase = ScanPhase::Scanning;
        } else {
            progress.phase = ScanPhase::Discovering;
        }
        progress.discoveredFiles = discovered.load(std::memory_order_relaxed);
        progress.directoriesScanned = directoriesSeen.load(std::memory_order_relaxed);

        progress.filesScanned = result.totalFilesScanned;
        progress.filesWithMatches = result.filesWithMatches;
        progress.totalMatchCount = result.totalMatches;
        progress.skips = result.skips;
        progress.filesQuarantined = result.filesQuarantined;
        progress.criticalCount = result.criticalCount;
        progress.highCount = result.highCount;
        progress.mediumCount = result.mediumCount;
        progress.lowCount = result.lowCount;
        progress.currentFile = path;
        progress.currentFileSize = size;
        progress.currentArchive = currentArchive;
        progress.archiveMember = currentMember;
        progress.archiveMemberTotal = currentMemberTotal;
        progress.bytesScanned = result.bytesScanned;
        progress.archives = result.archives;

        progressCallback_(progress);
    };

    auto countSeverities = [&result](const std::vector<FileMatch>& matches) {
        for (const auto& match : matches) {
            switch (match.severity) {
                case Severity::Critical: ++result.criticalCount; break;
                case Severity::High:     ++result.highCount; break;
                case Severity::Medium:   ++result.mediumCount; break;
                case Severity::Low:      ++result.lowCount; break;
            }
        }
    };

    // A member with findings is reported exactly like a loose file, addressed
    // `archive.zip!member/path.php`. It went through the same MatchEngine, so it
    // carries the same rules, the same prefilter and the same escaping.
    archives_.setFindingCallback([&](const std::filesystem::path& display,
                                     uint64_t size,
                                     std::vector<FileMatch>&& matches) {
        FileResult member;
        member.path = display;
        member.fileSize = size;
        member.matches = std::move(matches);

        ++result.filesWithMatches;
        result.totalMatches += member.matches.size();
        countSeverities(member.matches);

        result.files.push_back(member);
        if (fileResultCallback_) {
            fileResultCallback_(result.files.back());
        }
    });

    // Every member is a progress unit, whether it matched or not.
    archives_.setProgressCallback([&](const archive::MemberProgress& member) {
        result.bytesScanned += member.bytes;

        // A nameless report is the tail of a stream: bytes that were read but
        // belong to no member. They move the bar; they are not a file.
        if (!member.member.empty()) {
            ++result.totalFilesScanned;
            if (!member.preCounted) {
                ++uncountedMembers;
            }
        }
        if (!member.preCounted) {
            streamCharged += member.bytes;
        }

        currentMember = member.index;
        currentMemberTotal = member.total;
        publishProgress(std::filesystem::path(member.member), member.bytes);
    });

    auto fileCallback = [&](const FileInfo& info) -> bool {
        // Check for interrupt
        if (interrupted()) {
            interrupted_ = true;
            return false;  // Stop walking
        }

        // An excluded file is not work and is not a finding: it is tallied so the
        // operator can see their globs took effect, and only listed if they asked.
        if (info.skip == SkipReason::Excluded) {
            result.skips.skip(SkipReason::Excluded);
            if (config_.scan.reportExcluded) {
                FileResult excluded;
                excluded.path = info.path;
                excluded.skipReason = SkipReason::Excluded;
                result.files.push_back(excluded);
                if (fileResultCallback_) {
                    fileResultCallback_(result.files.back());
                }
            }
            return true;
        }

        // A file whose size could not even be read is not going to open either.
        // Reporting it as scanned-and-clean is the silent skip this whole
        // mechanism exists to stop.
        if (info.skip == SkipReason::Unreadable) {
            FileResult unreadable;
            unreadable.path = info.path;
            unreadable.skipReason = SkipReason::Unreadable;
            result.skips.skip(SkipReason::Unreadable);
            ++result.totalFilesScanned;
            result.files.push_back(unreadable);

            publishProgress(info.path, 0);
            if (fileResultCallback_) {
                fileResultCallback_(result.files.back());
            }
            return true;
        }

        // The walker is the single source of truth for whether a file is oversize,
        // so this can no longer disagree with it - which is how a failed stat used
        // to slip through as a scanned file.
        const bool oversize = info.skip == SkipReason::Size;

        FileResult fileResult;
        fileResult.path = info.path;
        fileResult.fileSize = info.size;

        // Content is read once and used twice: for the rules, and to find out
        // whether this file is a container. An oversize file is not read at all,
        // so only its head is sniffed - which is the entire point for a 13 GB
        // backup, where the affordable answer is the archive itself and it costs
        // one short read.
        std::string content;
        if (!oversize) {
            fileResult = scanContent(info.path, content);
            fileResult.fileSize = info.size;

            // scanContent could not open it. Report the skip rather than the
            // empty match list, which would read as "scanned, clean".
            if (fileResult.skipReason == SkipReason::Unreadable) {
                result.skips.skip(SkipReason::Unreadable);
                ++result.totalFilesScanned;
                result.files.push_back(fileResult);

                publishProgress(info.path, info.size);
                if (fileResultCallback_) {
                    fileResultCallback_(result.files.back());
                }
                return true;
            }
        }

        archive::Kind kind = archive::Kind::None;
        if (config_.archives.enabled) {
            kind = oversize ? archive::sniffFile(info.path) : archive::sniff(content);
        }

        // Unchanged for everything that is not a container: past the size limit
        // it is reported, not scanned.
        if (kind == archive::Kind::None && oversize) {
            fileResult.skipReason = SkipReason::Size;
            result.skips.skip(SkipReason::Size);
            ++result.totalFilesScanned;
            result.files.push_back(fileResult);

            publishProgress(info.path, info.size);
            if (fileResultCallback_) {
                fileResultCallback_(fileResult);
            }
            return true;  // Continue walking
        }

        uint64_t chargeBytes = oversize ? 0 : info.size;

        if (kind != archive::Kind::None) {
            currentArchive = info.path;
            streamCharged = 0;
            publishProgress(info.path, info.size);

            auto outcome = archives_.scan(
                info.path, kind,
                oversize ? std::string_view{} : std::string_view(content));
            result.archives.merge(outcome.stats);

            for (auto& match : outcome.archiveMatches) {
                fileResult.matches.push_back(std::move(match));
            }

            currentArchive.clear();
            currentMember = 0;
            currentMemberTotal = 0;

            // A zip's members were counted separately, so the container is worth
            // its own size. A stream's members were charged in compressed bytes
            // that came out of the container, so only the remainder is left.
            chargeBytes = (kind == archive::Kind::Zip)
                ? info.size
                : (info.size > streamCharged ? info.size - streamCharged : 0);
        }

        // Update statistics
        ++result.totalFilesScanned;
        result.bytesScanned += chargeBytes;
        result.totalMatches += fileResult.matches.size();
        countSeverities(fileResult.matches);

        if (!fileResult.matches.empty()) {
            ++result.filesWithMatches;

            // Quarantine if enabled - but never for an exposure finding alone.
            // An exposed backup is the operator's own data, possibly their only
            // copy of the site and possibly 13 GB of it; fs::rename across a
            // filesystem boundary degrades to copy-and-delete, and moving it
            // somewhere still under the web root changes the URL without
            // removing the exposure while reporting it as handled. The finding
            // says what to do; the operator decides.
            if (isQuarantineEnabled() && hasHostileContent(fileResult)) {
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
        publishProgress(info.path, info.size);

        // Notify about the finding AFTER progress (for real-time output)
        if (reportable && fileResultCallback_) {
            fileResultCallback_(fileResult);
        }

        return true;  // Continue walking
    };

    result.totalDirectoriesScanned = walker.walk(fileCallback, &result.directoriesUnreadable);

    if (counter.joinable()) {
        // countFiles polls the interrupt flag, so this returns promptly on Ctrl+C.
        counter.join();
    }

    // The archive callbacks close over locals of this function. Drop them before
    // returning so nothing can reach a dead frame through the member.
    archives_.setFindingCallback({});
    archives_.setProgressCallback({});

    result.endTime = std::chrono::steady_clock::now();

    // Severity counters are maintained live now; this keeps them correct if the
    // file list is ever rebuilt from elsewhere.
    if (result.criticalCount + result.highCount + result.mediumCount + result.lowCount == 0) {
        result.updateSeverityCounts();
    }

    if (progressCallback_) {
        progress.phase = ScanPhase::Finished;
        progress.filesScanned = result.totalFilesScanned;
        if (countReady.load(std::memory_order_acquire)) {
            progress.totalFiles = countedTotal.load(std::memory_order_relaxed);
            progress.totalBytes = countedBytes.load(std::memory_order_relaxed);
        }
        progress.directoriesScanned = result.totalDirectoriesScanned;
        progressCallback_(progress);
    }

    return result;
}

FileResult Scanner::scanContent(const std::filesystem::path& path, std::string& content) {
    FileResult result;
    result.path = path;

    try {
        content = readFile(path, config_.scan.maxFileSize);
        result.fileSize = content.size();

        auto matches = engine_.match(content, pathToUtf8(path));
        result.matches = std::move(matches);

    } catch (const OversizeFile&) {
        // Only reachable through `check` on a single file; the walk decides this
        // before scanContent is called.
        content.clear();
        result.matches.clear();
        result.skipReason = SkipReason::Size;
    } catch (const std::exception&) {
        // A file that could not be read has not been cleared. This catch used to
        // return an empty result, which the caller then counted as a scanned file
        // with no matches - the scanner asserting a file was clean on the strength
        // of never having seen a byte of it. The caller tallies the reason.
        content.clear();
        result.matches.clear();
        result.skipReason = SkipReason::Unreadable;
    }

    return result;
}

FileResult Scanner::scanFile(const std::filesystem::path& path) {
    std::string content;
    FileResult result = scanContent(path, content);

    // `check` on a single file gets the same treatment a walked one does: a
    // container is opened, its exposure finding lands on the file itself, and
    // its members are reported through the file-result callback if one is set.
    if (!config_.archives.enabled) {
        return result;
    }

    // A file past the size limit was never read, so its bytes have to be sniffed
    // from disk - the same path the walk takes. Without this, `check` on an
    // 8.4 MB backup reported nothing at all while `scan` on its directory
    // reported the exposure, which is the kind of disagreement that makes an
    // operator stop trusting the tool.
    const archive::Kind kind =
        content.empty() ? archive::sniffFile(path) : archive::sniff(content);
    if (kind == archive::Kind::None) {
        return result;
    }

    archives_.setFindingCallback([this](const std::filesystem::path& display,
                                        uint64_t size,
                                        std::vector<FileMatch>&& matches) {
        if (!fileResultCallback_) {
            return;
        }
        FileResult member;
        member.path = display;
        member.fileSize = size;
        member.matches = std::move(matches);
        fileResultCallback_(member);
    });
    archives_.setProgressCallback({});

    auto outcome = archives_.scan(path, kind, content);   // empty: read from disk
    for (auto& match : outcome.archiveMatches) {
        result.matches.push_back(std::move(match));
    }
    return result;
}

void Scanner::setProgressCallback(ProgressCallback callback) {
    progressCallback_ = std::move(callback);
}

void Scanner::setFileResultCallback(FileResultCallback callback) {
    fileResultCallback_ = std::move(callback);
}

std::string Scanner::readFile(const std::filesystem::path& path, uint64_t maxSize) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        // This used to `return ""`, which is the silent skip in its purest form: the
        // empty string was then matched against every rule, found nothing, and the
        // file was reported scanned and clean without a byte of it ever being read.
        // scanContent turns this into SkipReason::Unreadable.
        throw std::runtime_error("cannot open file");
    }

    // Get file size
    file.seekg(0, std::ios::end);
    auto size = static_cast<uint64_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    // Check size limit
    if (maxSize > 0 && size > maxSize) {
        throw OversizeFile{};
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
