#pragma once

// ArchiveScanner.h - Scanning what is inside a container, and reporting the
// container itself.
//
// Two outputs, and the second one matters more often than the first:
//
//   - Members go through the ordinary MatchEngine, so they get the same rules,
//     the same literal prefilter and the same escaping in reports. A member is
//     just a file whose bytes came from somewhere else, and it is addressed
//     `archive.zip!member/path.php`.
//
//   - The archive itself becomes a finding when its entry list says it is a copy
//     of the site. That needs no extraction at all, which is the only affordable
//     answer for the 13 GB backups that turn up on real servers.
//
// Nothing is ever written to disk. Members are streamed into a bounded in-memory
// buffer: writing malware to the analyst's filesystem can trip their own AV
// mid-scan, land in a watched directory, or survive a crash as litter.

#include "ArchiveFormat.h"
#include "ArchiveIndex.h"
#include "ArchiveTypes.h"
#include "config/Rules.h"
#include "core/FileWalker.h"
#include "core/ScanResult.h"

#include <filesystem>
#include <functional>
#include <string>
#include <string_view>

namespace lyxbosa {
class MatchEngine;
}

namespace lyxbosa::archive {

// One member reached, whether or not it matched anything. An archive has to look
// like a directory on the progress display: a 20 GB backup must not be one tick
// on the bar, freezing the display on a single "file" for minutes.
struct MemberProgress {
    std::string_view archive;    // display path of the archive being read
    std::string_view member;     // member path within it
    uint64_t bytes = 0;          // work to charge: member size (zip) or
                                 // compressed bytes consumed since the last
                                 // member (tar, which has no index)
    size_t index = 0;            // 1-based position within the archive
    size_t total = 0;            // 0 when unknown, which a tar always is
    bool preCounted = false;     // already in ScanProgress::totalFiles
};

class ArchiveScanner {
public:
    ArchiveScanner(const ArchiveConfig& config, const ScanConfig& scan,
                   const MatchEngine& engine);

    using FindingCallback =
        std::function<void(const std::filesystem::path& displayPath,
                           uint64_t size,
                           std::vector<FileMatch>&& matches)>;
    using ProgressCallback = std::function<void(const MemberProgress&)>;

    void setFindingCallback(FindingCallback callback) { onFinding_ = std::move(callback); }
    void setProgressCallback(ProgressCallback callback) { onProgress_ = std::move(callback); }

    struct Outcome {
        bool handled = false;                  // false: not an archive, or disabled
        Stats stats;
        std::vector<FileMatch> archiveMatches;  // the ARC exposure findings
    };

    // `inMemory` is the archive's bytes when the caller already has them - a file
    // under the size limit has just been read for the ordinary scan, and reading
    // it twice would be a second pass over every zip in the tree. Empty means
    // "open the path".
    Outcome scan(const std::filesystem::path& path, Kind kind,
                 std::string_view inMemory);

    // What this archive will add to the scan total, from its index alone and
    // without decompressing a member. Zip only: a .tar.gz has no index, and is
    // counted by its compressed size like any other file.
    //
    // Runs on the counting thread, which means parsing attacker-controlled data
    // there; every guard applies, and a hostile index is counted as zero rather
    // than being allowed to hang the count.
    struct IndexCount {
        size_t files = 0;
        uint64_t bytes = 0;
    };
    static IndexCount countMembers(const std::filesystem::path& path, Kind kind,
                                   const ArchiveConfig& config, const ScanConfig& scan);

private:
    // Whether a member is worth opening, and why not when it is not. Shared with
    // countMembers() so the pre-count and the scan cannot disagree about what
    // the total means.
    static std::optional<SkipReason> selectionSkip(const std::string& name,
                                                   uint64_t size,
                                                   bool directory,
                                                   const ArchiveConfig& config,
                                                   uint64_t memberLimit,
                                                   const FileWalker& filters);

    struct Context {
        std::string display;   // "backup.zip" or "outer.zip!inner.zip"
        size_t depth = 1;
        Budget* budget = nullptr;
        Stats* stats = nullptr;
        IndexSummary* summary = nullptr;
    };

    void scanZip(class ZipReader& reader, Context& ctx);
    void scanTar(class ByteSource& source, Context& ctx, ByteSource& raw);
    void scanSingleGzip(class ByteSource& source, Context& ctx,
                        const std::string& memberName);

    // Run the rules over one member's bytes, recursing when the member is itself
    // an archive and the depth allows it.
    void scanMemberBytes(const std::string& memberDisplay, std::string& bytes,
                         Context& ctx);

    void reportMember(const Context& ctx, std::string_view member, uint64_t bytes,
                      size_t index, size_t total, bool preCounted);

    std::vector<FileMatch> exposureFindings(const IndexSummary& summary,
                                            bool truncated) const;

    const ArchiveConfig& config_;
    const MatchEngine& engine_;
    FileWalker filters_;
    uint64_t memberLimit_;
    FindingCallback onFinding_;
    ProgressCallback onProgress_;
};

}  // namespace lyxbosa::archive
