#include "Scanner.h"
#include "Quarantine.h"
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

    // Whether a marker inside a scanned file may lower that file's own findings. The
    // engine's default is no, and only a configuration the operator wrote can say yes;
    // the reasons are at MatchEngine::applyAnnotation(). The archive scanner shares this
    // engine, so a member of a zip is held to the same answer as a loose file.
    engine_.setTrustAnnotations(config_.annotations.trust);
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

    // Whether anything hostile was found *inside* the container currently being
    // scanned. A member is reported as its own FileResult and never joins the
    // container's match list - its bytes are compressed in the container and match
    // nothing there - so the container's own matches cannot answer the quarantine
    // question for it. Without this, a webshell in a zip that actually compresses is
    // detected, named in the report, and left on disk. The archive callbacks below
    // set it; fileCallback clears it for every file it starts.
    bool archiveMemberHostile = false;

    // The half-open range of `result.files` holding the member rows of the container
    // currently being scanned. They are pushed by the finding callback above and held
    // unpublished until publishMembers() below, which is the only place that fires
    // fileResultCallback_ for one.
    size_t memberRowsBegin = 0;
    size_t memberRowsEnd = 0;

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

    // One file's findings folded into the aggregate: the match total, the severity
    // breakdown and the two file counters.
    //
    // Every path that keeps a FileResult goes through this, including the two that end
    // in a skip. That is not tidiness: a name finding is knowable without reading a
    // byte, so a file whose size could not be stat'd and whose name carries a command
    // substitution has a real finding and no content. Counting it only where content
    // was read would leave the summary asserting a total that the rows below it
    // contradict - the aggregate saying nothing was found and a row naming the file.
    auto accountFindings = [&result, &countSeverities](const FileResult& file) {
        if (file.matches.empty()) {
            return;
        }
        ++result.filesWithMatches;
        result.totalMatches += file.matches.size();
        countSeverities(file.matches);
        if (hasHostileName(file)) {
            ++result.filesWithHostileNames;
        }
    };

    // A member's address under the container's new location.
    //
    // Built by replacing the prefix the display path was COMPOSED from -
    // ArchiveScanner writes `pathToUtf8(container) + "!" + name` - and never by
    // splitting on "!", which docs/KNOWN_ISSUES.md #1 records as ambiguous: a nested
    // container yields `outer.zip!inner.zip!x` and a filename may contain "!" of its
    // own. Replacing a prefix known by construction has neither problem.
    //
    // If the prefix somehow does not match, the container's own destination is the
    // answer. It is less precise and it is still true - the bytes are inside that file
    // - which is the direction to be wrong in when the alternative is naming a path
    // that holds nothing.
    auto memberDestination = [](const std::filesystem::path& containerSource,
                                const std::filesystem::path& containerDest,
                                const std::filesystem::path& memberDisplay) {
        const std::string prefix = pathToUtf8(containerSource);
        const std::string display = pathToUtf8(memberDisplay);
        if (display.size() > prefix.size() && display.starts_with(prefix)) {
            return std::filesystem::path(pathToUtf8(containerDest) +
                                         display.substr(prefix.size()));
        }
        return containerDest;
    };

    // Publish this container's member rows, now that what happened to the container is
    // known. Two facts are written onto each row first, and they are two because one
    // cannot stand for the other: where the bytes are now, and whether they are still
    // where an attacker can reach them.
    //
    // Nothing is written when no decision was taken - quarantine off, or a container
    // that was never selected - so a member row carries "no quarantine decision" as an
    // absent value rather than as a false one.
    auto publishMembers = [&](const std::filesystem::path& container,
                              const FileResult& containerResult) {
        for (size_t i = memberRowsBegin; i < memberRowsEnd; ++i) {
            FileResult& member = result.files[i];
            if (containerResult.quarantined) {
                member.containerQuarantine = ContainerQuarantine::Moved;
                member.quarantinePath =
                    memberDestination(container, containerResult.quarantinePath, member.path);
            } else if (containerResult.quarantineFailed) {
                member.containerQuarantine = ContainerQuarantine::MoveFailed;
            }
        }
        if (!fileResultCallback_) {
            return;
        }
        for (size_t i = memberRowsBegin; i < memberRowsEnd; ++i) {
            fileResultCallback_(result.files[i]);
        }
    };

    // A member with findings is reported exactly like a loose file, addressed
    // `archive.zip!member/path.php`. It went through the same MatchEngine, so it
    // carries the same rules, the same prefilter and the same escaping.
    //
    // The row is retained here and PUBLISHED LATER, by publishMembers() below, once the
    // container's quarantine decision has been taken. The delay is the repair for a
    // defect that is an ordering property rather than a mistake in any one writer: a
    // member row says where its bytes are and whether they are still under the web
    // root, and neither answer exists until the container's fate does. Publishing first
    // and correcting the retained row afterwards would have been strictly worse than
    // the defect - fileResultCallback_ is what drives every streaming writer and the
    // full-screen view, so the file on disk and the screen would both keep the value
    // from before the move, while only an in-process caller holding the whole
    // ScanResult ever saw the corrected one.
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

        // The same rule the container is held to: an exposure finding says a file is
        // in the wrong place, not that it is hostile, so a nested backup inside a zip
        // is no more a reason to move the zip than a loose one is to move itself.
        if (hasHostileContent(member)) {
            archiveMemberHostile = true;
        }

        result.files.push_back(member);
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

        // Cleared here rather than after the archive scan, so that it can only ever
        // describe the file this callback is looking at. The member range beside it is
        // emptied for the same reason: a file that is not a container publishes no
        // member rows, and a stale range would republish the previous container's.
        archiveMemberHostile = false;
        memberRowsBegin = memberRowsEnd = result.files.size();

        // An excluded file is not work and is not a finding: it is tallied so the
        // operator can see their globs took effect, and only listed if they asked.
        if (info.skip == SkipReason::Excluded) {
            result.skips.skip(SkipReason::Excluded);

            FileResult excluded;
            excluded.path = info.path;
            excluded.skipReason = SkipReason::Excluded;

            // A file the include list did not cover was not OPENED, which is all that
            // list decides - the shipped configuration says so in its own words,
            // because an extension is never trusted to say what a file is. Its name
            // was still read, by the walk, for free. Skipping the name question here
            // would make this whole rule set blind to most of its own evidence: of the
            // 83 hostile names measured on a production upload directory, 73 are
            // `.mdb`, and no include pattern covers a `.mdb`. A scanner that cannot
            // see 88% of what it was built for is not a scanner.
            //
            // An `exclude` pattern is the other intention and gets the other answer.
            // There the operator has written down a tree they do not want looked at,
            // and answering anyway - even about something as cheap as a name - is the
            // tool overruling them.
            if (!info.excludedByPattern) {
                addNameFindings(excluded);
            }
            accountFindings(excluded);

            // Reported when the operator asked for every excluded file, and reported
            // regardless when there is something to say about this one. `report_excluded`
            // is off by default because a glob that cuts node_modules produces hundreds
            // of thousands of these - which is an argument about volume and not about
            // whether a finding may be withheld.
            if (config_.scan.reportExcluded || !excluded.matches.empty()) {
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
            // The bytes could not be reached; the name was. A file the walk could not
            // even stat still has the name whoever uploaded it chose, and declining to
            // say so would be the scanner withholding something it knows for certain.
            addNameFindings(unreadable);
            result.skips.skip(SkipReason::Unreadable);
            ++result.totalFilesScanned;
            accountFindings(unreadable);
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
        if (oversize) {
            // scanContent() is where a name is normally examined, and it is not called
            // for a file past the size limit. A 13 GB backup has a name like any other
            // file and it is the one thing about it that costs nothing to read.
            addNameFindings(fileResult);
        } else {
            fileResult = scanContent(info.path, content);
            fileResult.fileSize = info.size;

            // scanContent could not open it. Report the skip rather than the
            // empty match list, which would read as "scanned, clean".
            if (fileResult.skipReason == SkipReason::Unreadable) {
                result.skips.skip(SkipReason::Unreadable);
                ++result.totalFilesScanned;
                // scanContent() has already read the name; the same argument as the
                // branch above applies to a file that opened and would not read.
                accountFindings(fileResult);
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
            accountFindings(fileResult);
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

            memberRowsBegin = result.files.size();
            auto outcome = archives_.scan(
                info.path, kind,
                oversize ? std::string_view{} : std::string_view(content));
            memberRowsEnd = result.files.size();
            result.archives.merge(outcome.stats);

            // The same coverage, kept on the file it belongs to as well as in the
            // aggregate. The summary answers "what did this scan not open"; this
            // answers it about one file, which is the question `check` asks and the
            // question a per-file report row can carry.
            fileResult.archive = outcome.stats;

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
        accountFindings(fileResult);

        // Quarantine if enabled - but never for an exposure finding alone.
        // An exposed backup is the operator's own data, possibly their only
        // copy of the site and possibly 13 GB of it; moving it somewhere still
        // under the web root changes the URL without removing the exposure while
        // reporting it as handled. The finding says what to do; the operator
        // decides.
        //
        // `archiveMemberHostile` is the second half of the question and not a
        // special case: malware inside an archive quarantines the container, so a
        // container whose own bytes match nothing is still moved when something
        // inside it does. That is why this sits outside the `matches.empty()`
        // guard above - a zip that compresses well has no matches of its own.
        if (isQuarantineEnabled() &&
            (hasHostileContent(fileResult) || archiveMemberHostile)) {
            std::filesystem::path destPath;
            if (quarantineFile(info.path, destPath)) {
                fileResult.quarantined = true;
                fileResult.quarantinePath = destPath;
                ++result.filesQuarantined;
            } else {
                // This branch is the whole third of the defect: it did not exist, so a
                // file the tool was asked to contain and could not looked exactly like
                // one quarantine was never enabled for. The operator needs to know
                // which webshell is still sitting in the web root.
                fileResult.quarantineFailed = true;
                ++result.filesQuarantineFailed;
            }
        }

        // Only reportable files are retained. Keeping a FileResult for every
        // clean file cost hundreds of megabytes of paths on a large tree and
        // bought nothing - every consumer filtered them straight back out.
        // A container quarantined for what was inside it carries no matches of its
        // own. Dropping it here would move a file and then not say so anywhere in
        // the report, with only the member rows beside it to hint at why. The same
        // container when the move *failed* carries neither matches nor a destination,
        // and dropping that one would lose the only row naming a file still in place.
        const bool reportable = !fileResult.matches.empty() || fileResult.quarantined ||
                                fileResult.quarantineFailed;
        if (reportable) {
            result.files.push_back(fileResult);
        }

        // Report progress FIRST (so display is initialized before match output)
        publishProgress(info.path, info.size);

        // The container's members, before the container's own row and in the order
        // they were found - which is the order every report has always shown them in,
        // and the only thing about them this change leaves alone.
        publishMembers(info.path, fileResult);

        // Notify about the finding AFTER progress (for real-time output)
        if (reportable && fileResultCallback_) {
            fileResultCallback_(fileResult);
        }

        return true;  // Continue walking
    };

    result.totalDirectoriesScanned =
        walker.walk(fileCallback, &result.directoriesUnreadable, &result.rootsMissing,
                    &result.directoriesCycleSkipped);

    // The walk stops on the interrupt flag itself now, not only when the file callback
    // above refuses - and that callback is reached by a regular file, so a tree holding
    // nothing but directories reached it never. Read the flag here or such a scan
    // reports a completed clean run and exits 0 after the operator pressed Ctrl+C,
    // which is the same lie as a report that was never written saying it was.
    if (interrupted()) {
        interrupted_ = true;
    }

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

    // After the catch, and deliberately: a name is knowable whether or not a single
    // byte was read, and the two clear() calls above throw away content findings only.
    // A file that would not open and is called `x$(id).php` has one true finding, and
    // this is where it survives.
    addNameFindings(result);

    return result;
}

void Scanner::addNameFindings(FileResult& result) const {
    auto named = engine_.matchName(pathToUtf8(result.path));
    if (named.empty()) {
        return;
    }

    // In front of the content findings. A name finding is about the whole file rather
    // than a position in it, so it reads first for the same reason a heading does -
    // and nothing about a file with no hostile name changes, which is every file in an
    // ordinary tree.
    result.matches.insert(result.matches.begin(),
                          std::make_move_iterator(named.begin()),
                          std::make_move_iterator(named.end()));
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

    // What the container did or did not cover, travelling out with the result. Without
    // this the caller has a FileResult and no way to learn that a member went unread,
    // which is how `check` came to print "No matches found" for a truncated gzip.
    result.archive = outcome.stats;

    // The walk does not call an oversize container a skipped file: its index was read
    // and its members were scanned, which is the affordable answer for a 13 GB backup.
    // So neither does this. Leaving the size skip on would make `check` and `scan`
    // disagree about the same file, and what the container did not reach is in
    // `archive` where it belongs. Only Size: a file whose bytes could not be read at
    // all is still unreadable, whatever its header sniffed as.
    if (result.skipReason == SkipReason::Size) {
        result.skipReason.reset();
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

bool Scanner::quarantineFile(const std::filesystem::path& source,
                             std::filesystem::path& destPath) {
    namespace fs = std::filesystem;

    if (!config_.actions.quarantine.enabled || config_.actions.quarantine.directory.empty()) {
        return false;
    }

    try {
        const fs::path quarantineDir(config_.actions.quarantine.directory);
        fs::create_directories(quarantineDir);

        const fs::path dest = quarantine::destinationFor(
            quarantineDir, source, config_.actions.quarantine.preserveStructure);

        // A destination that is already taken is stepped past rather than written
        // over, and the step is bounded: a directory that somehow answers "taken" a
        // thousand times running is a filesystem saying no, not a name to keep
        // guessing at. Failing here leaves the file exactly where it was, which the
        // report shows as a finding that was not quarantined.
        constexpr int kMaxDisambiguators = 1000;
        for (int attempt = 0; attempt <= kMaxDisambiguators; ++attempt) {
            const fs::path candidate =
                attempt == 0 ? dest : quarantine::withDisambiguator(dest, attempt);

            // Inside the loop: a disambiguated candidate has the same parent, but
            // the directory can have been removed between attempts by something
            // else on the machine, and re-making it costs nothing when it is there.
            fs::create_directories(candidate.parent_path());

            switch (quarantine::moveWithoutReplacing(source, candidate)) {
                case quarantine::MoveResult::Moved:
                    destPath = candidate;
                    return true;
                case quarantine::MoveResult::DestinationExists:
                    continue;
                case quarantine::MoveResult::Failed:
                    return false;
            }
        }
        return false;

    } catch (const fs::filesystem_error&) {
        return false;
    }
}

}  // namespace lyxbosa
