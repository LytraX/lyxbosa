#include "ArchiveScanner.h"

#include "ByteSource.h"
#include "GzipSource.h"
#include "TarReader.h"
#include "ZipReader.h"
#include "core/Interrupt.h"
#include "core/MatchEngine.h"
#include "infrastructure/PathUtils.h"
#include "rules/Registry.hpp"
#include "utils/SafeText.h"

#include <algorithm>
#include <map>
#include <fmt/format.h>

namespace lyxbosa::archive {

namespace {

// The separator between an archive and a member, as it appears in every report.
constexpr std::string_view kMemberSeparator = "!";

// Directory of a normalised member name, "" for a member at the root.
std::string_view directoryOf(std::string_view name) {
    const size_t slash = name.find_last_of('/');
    return slash == std::string_view::npos ? std::string_view{} : name.substr(0, slash);
}

// Which directories in an index are "otherwise media or assets".
//
// wp-content/uploads is WordPress-only and must not be hardcoded; the
// platform-independent version of the same idea is an executable script sitting
// in a directory that is otherwise media. That is equally true of OpenCart's
// image/catalog, Magento's pub/media and PrestaShop's img.
std::vector<std::string> assetDirectories(const std::vector<Entry>& entries) {
    struct Tally { size_t scripts = 0; size_t media = 0; };
    std::map<std::string, Tally> byDirectory;

    for (const auto& entry : entries) {
        if (entry.directory) continue;
        const std::string name = normalizeMemberName(entry.name);
        auto& tally = byDirectory[std::string(directoryOf(name))];
        if (isScriptName(name)) {
            ++tally.scripts;
        } else if (isMediaName(name)) {
            ++tally.media;
        }
    }

    std::vector<std::string> result;
    for (const auto& [dir, tally] : byDirectory) {
        if (tally.media > 0 && tally.scripts <= tally.media) {
            result.push_back(dir);
        }
    }
    std::sort(result.begin(), result.end());
    return result;
}

bool isAssetDirectory(const std::vector<std::string>& dirs, std::string_view name) {
    return std::binary_search(dirs.begin(), dirs.end(), std::string(directoryOf(name)));
}

FileMatch makeArchiveMatch(std::string_view code, std::string detail, std::string context) {
    const auto* rule = rules::getRuleByCode(code);

    FileMatch match;
    match.ruleName = rule ? std::string(rule->name) : std::string(code);
    match.severity = rule ? rule->severity : Severity::High;
    match.originalSeverity = match.severity;
    match.category = std::string(code);
    match.patternType = std::string(kExposurePatternType);
    match.offset = 0;
    match.line = 1;
    match.column = 1;
    match.matchedText = safe_text::sanitize(detail);
    match.context = safe_text::sanitize(context);
    return match;
}

std::string joinNames(const std::vector<std::string>& names, size_t limit) {
    std::string out;
    for (size_t i = 0; i < names.size() && i < limit; ++i) {
        if (!out.empty()) out += ", ";
        out += names[i];
    }
    if (names.size() > limit) {
        out += fmt::format(" (+{} more)", names.size() - limit);
    }
    return out;
}

}  // namespace

ArchiveScanner::ArchiveScanner(const ArchiveConfig& config, const ScanConfig& scan,
                               const MatchEngine& engine)
    : config_(config),
      engine_(engine),
      filters_(scan),
      memberLimit_(config.memberSizeLimit(scan.maxFileSize)) {}

std::optional<SkipReason> ArchiveScanner::selectionSkip(const std::string& name,
                                                        uint64_t size,
                                                        bool directory,
                                                        const ArchiveConfig& config,
                                                        uint64_t memberLimit,
                                                        const FileWalker& filters) {
    if (directory || name.empty()) {
        return SkipReason::Policy;
    }

    // Sidecar metadata is about the archive, not about the site inside it.
    if (isContainerMetadata(name)) {
        return SkipReason::Policy;
    }

    // Sequential extraction spends the budget on whatever happens to be at the
    // front of the archive. Non-code members are the 45.8% of a real site's
    // bytes that has never yet held a webshell in this corpus; exhaustive mode
    // is for operators who want them anyway.
    if (!config.exhaustive && classifyMember(name) == Bucket::Other) {
        return SkipReason::Policy;
    }

    // The same include/exclude the operator wrote for loose files. A tree
    // excluded on disk must not come back through a backup of itself.
    if (!filters.matchesFilters(std::filesystem::path(name))) {
        return SkipReason::Policy;
    }

    if (memberLimit > 0 && size > memberLimit) {
        return SkipReason::Size;
    }

    return std::nullopt;
}

ArchiveScanner::IndexCount ArchiveScanner::countMembers(const std::filesystem::path& path,
                                                        Kind kind,
                                                        const ArchiveConfig& config,
                                                        const ScanConfig& scan) {
    IndexCount count;
    if (!config.enabled || kind != Kind::Zip) {
        // A tar.gz is a solid stream: reaching member 10,000 means inflating
        // everything before it, and the gzip footer only stores the uncompressed
        // size mod 2^32. It contributes its compressed size, which the walk
        // already counted, and nothing else.
        return count;
    }

    auto reader = ZipReader::openFile(path);
    if (!reader) {
        return count;
    }

    const FileWalker filters(scan);
    const uint64_t memberLimit = config.memberSizeLimit(scan.maxFileSize);

    for (const auto& entry : reader->entries()) {
        if (interrupted()) break;
        const std::string name = normalizeMemberName(entry.name);
        if (selectionSkip(name, entry.size, entry.directory, config, memberLimit, filters)) {
            continue;
        }
        ++count.files;
        count.bytes += entry.size;
    }

    return count;
}

void ArchiveScanner::reportMember(const Context& ctx, std::string_view member,
                                  uint64_t bytes, size_t index, size_t total,
                                  bool preCounted) {
    if (!onProgress_) return;

    MemberProgress progress;
    progress.archive = ctx.display;
    progress.member = member;
    progress.bytes = bytes;
    progress.index = index;
    progress.total = total;
    progress.preCounted = preCounted;
    onProgress_(progress);
}

void ArchiveScanner::scanMemberBytes(const std::string& memberDisplay, std::string& bytes,
                                     Context& ctx) {
    ++ctx.stats->membersScanned;
    ctx.stats->bytesExpanded += bytes.size();

    const std::filesystem::path display(memberDisplay);
    auto matches = engine_.match(bytes, memberDisplay);
    if (!matches.empty() && onFinding_) {
        onFinding_(display, bytes.size(), std::move(matches));
    }

    // A member that is itself an archive. Its entries are folded into the same
    // summary: a credential file two containers down is still exposed by the one
    // sitting in the web root, and that outer file is what the operator deletes.
    //
    // The corpus contains zero nested archives, so
    // the default depth of 2 is already one more level than anything real has
    // needed - but a payload hidden one zip deeper is the obvious next move once
    // scanners start opening the first one.
    const Kind nested = sniff(bytes);
    if (nested == Kind::None) {
        return;
    }
    if (ctx.depth >= config_.maxDepth) {
        ctx.stats->skip(SkipReason::Depth);
        return;
    }

    Context inner;
    inner.display = memberDisplay;
    inner.depth = ctx.depth + 1;
    inner.budget = ctx.budget;
    inner.stats = ctx.stats;
    inner.summary = ctx.summary;

    ++ctx.stats->archivesOpened;

    if (nested == Kind::Zip) {
        auto reader = ZipReader::openBuffer(bytes);
        if (!reader) {
            ++ctx.stats->archivesUnreadable;
            return;
        }
        scanZip(*reader, inner);
        return;
    }

    MemorySource source(bytes);
    if (nested == Kind::Tar) {
        scanTar(source, inner, source);
        return;
    }

    GzipSource gzip(source);
    if (!gzip.ok()) {
        ++ctx.stats->archivesUnreadable;
        return;
    }
    if (nested == Kind::TarGz) {
        scanTar(gzip, inner, source);
    } else {
        scanSingleGzip(gzip, inner, gzipMemberName(std::filesystem::path(memberDisplay)));
    }
}

void ArchiveScanner::scanZip(ZipReader& reader, Context& ctx) {
    const auto& entries = reader.entries();

    // Classification first, from names alone. It costs nothing and it is what
    // produces the finding that matters on a large backup.
    for (const auto& entry : entries) {
        ctx.summary->observe(entry.name);
    }
    if (reader.indexTruncated()) {
        ctx.stats->skip(SkipReason::Corrupt);
    }

    const std::vector<std::string> assets = assetDirectories(entries);

    struct Item {
        size_t index;
        Bucket bucket;
        uint64_t size;
    };
    std::vector<Item> work;
    work.reserve(entries.size());

    for (size_t i = 0; i < entries.size(); ++i) {
        // A directory entry holds no content. It is not a member that went
        // unscanned, so it is not counted as one.
        if (entries[i].directory) {
            continue;
        }

        const std::string name = normalizeMemberName(entries[i].name);
        if (const auto skip = selectionSkip(name, entries[i].size, entries[i].directory,
                                            config_, memberLimit_, filters_)) {
            ctx.stats->skip(*skip);
            continue;
        }

        Bucket bucket = classifyMember(name);
        if (bucket == Bucket::Script && isAssetDirectory(assets, name)) {
            bucket = Bucket::HotScript;
        }
        work.push_back({i, bucket, entries[i].size});
    }

    // Priority order, not archive order. On a real production site the PHP under
    // upload/cache/tmp-like paths was 39 MB of 694 MB; whatever the budget can
    // afford, it should be spent there first.
    std::stable_sort(work.begin(), work.end(), [](const Item& a, const Item& b) {
        return static_cast<int>(a.bucket) < static_cast<int>(b.bucket);
    });

    std::string bytes;
    size_t position = 0;

    for (const auto& item : work) {
        ++position;
        // An interrupted scan already says its results are partial, so the
        // remaining members are not attributed to a guard that did not fire.
        if (interrupted()) {
            return;
        }
        if (const auto spent = ctx.budget->spent()) {
            // Everything left is skipped for one reason, and it is counted. The
            // pre-count already promised these members to the progress total, so
            // they are still reported as reached - otherwise the bar stops short
            // of 100% on every archive a guard ever stops.
            for (size_t rest = position - 1; rest < work.size(); ++rest) {
                ctx.stats->skip(*spent);
                reportMember(ctx, normalizeMemberName(entries[work[rest].index].name),
                             0, rest + 1, work.size(), ctx.depth == 1);
            }
            return;
        }

        const std::string name = normalizeMemberName(entries[item.index].name);

        // Progress before the work, exactly as the loose-file path does it: the
        // display should name what is being read, not what has just been read.
        // Members of a nested archive were never in the pre-count.
        reportMember(ctx, name, item.size, position, work.size(), ctx.depth == 1);

        if (!reader.read(item.index, bytes, memberLimit_)) {
            ctx.stats->skip(SkipReason::Corrupt);
            continue;
        }

        ctx.budget->addExpanded(bytes.size());
        ctx.budget->addConsumed(entries[item.index].compressedSize);

        const std::string display = ctx.display + std::string(kMemberSeparator) + name;
        scanMemberBytes(display, bytes, ctx);
    }
}

void ArchiveScanner::scanTar(ByteSource& stream, Context& ctx, ByteSource& raw) {
    TarReader tar(stream, *ctx.budget);

    Entry entry;
    std::string bytes;
    size_t index = 0;
    uint64_t lastConsumed = raw.consumed();

    while (tar.next(entry)) {
        if (interrupted()) {
            break;
        }

        // Progress moves in compressed bytes, which is exact and needs no second
        // pass. The delta covers the previous member's data plus this header.
        const uint64_t consumed = raw.consumed();
        const uint64_t delta = consumed > lastConsumed ? consumed - lastConsumed : 0;
        lastConsumed = consumed;

        if (entry.directory) {
            continue;
        }
        ++index;

        ctx.summary->observe(entry.name);
        const std::string name = normalizeMemberName(entry.name);

        reportMember(ctx, name, delta, index, 0, false);

        if (const auto skip = selectionSkip(name, entry.size, entry.directory,
                                            config_, memberLimit_, filters_)) {
            ctx.stats->skip(*skip);
            continue;
        }

        if (!tar.readCurrent(bytes, memberLimit_)) {
            ctx.stats->skip(tar.stopReason().value_or(SkipReason::Corrupt));
            if (tar.stopped() || tar.corrupt()) {
                break;
            }
            continue;
        }

        const std::string display = ctx.display + std::string(kMemberSeparator) + name;
        scanMemberBytes(display, bytes, ctx);
    }

    if (tar.corrupt()) {
        ctx.stats->skip(SkipReason::Corrupt);
    }

    // A guard stopped the stream part-way. How many members are left cannot be
    // known without reading the bytes the guard just refused to read, so this is
    // counted as one truncated archive rather than as a made-up member count.
    if (tar.stopped()) {
        ++ctx.stats->archivesTruncated;
    }

    // Whatever compressed bytes the tail of the archive cost still happened.
    const uint64_t consumed = raw.consumed();
    if (consumed > lastConsumed) {
        reportMember(ctx, "", consumed - lastConsumed, index, 0, false);
    }
}

void ArchiveScanner::scanSingleGzip(ByteSource& source, Context& ctx,
                                    const std::string& memberName) {
    ctx.summary->observe(memberName);

    const std::string name = normalizeMemberName(memberName);
    if (const auto skip = selectionSkip(name, 0, false, config_, 0, filters_)) {
        ctx.stats->skip(*skip);
        return;
    }

    // The size is unknown until it is out, so the cap is enforced while reading
    // rather than before it: one byte past the limit and the member is dropped.
    std::string bytes;
    const uint64_t limit = memberLimit_ > 0 ? memberLimit_ : 0;
    char buffer[64 * 1024];

    while (true) {
        if (const auto spent = ctx.budget->spent()) {
            ctx.stats->skip(*spent);
            return;
        }
        const size_t got = source.read(buffer, sizeof(buffer));
        if (got == 0) break;

        ctx.budget->addExpanded(got);
        if (limit > 0 && bytes.size() + got > limit) {
            ctx.stats->skip(SkipReason::Size);
            return;
        }
        bytes.append(buffer, got);
    }

    if (source.failed()) {
        ctx.stats->skip(SkipReason::Corrupt);
        return;
    }

    // Progress through a stream is measured in the compressed bytes it came
    // from, which are the bytes the container actually occupies on disk.
    reportMember(ctx, name, source.consumed(), 1, 1, false);

    const std::string display = ctx.display + std::string(kMemberSeparator) + name;
    scanMemberBytes(display, bytes, ctx);
}

std::vector<FileMatch> ArchiveScanner::exposureFindings(const IndexSummary& summary,
                                                        bool truncated) const {
    std::vector<FileMatch> matches;

    if (truncated) {
        matches.push_back(makeArchiveMatch(
            "ARC003", "unreadable archive",
            "container could not be parsed - truncated, encrypted or malformed - "
            "so its contents were not scanned"));
        return matches;
    }

    if (!summary.siteBackup()) {
        return matches;
    }

    const std::string platform = summary.platform();
    const bool credentials = summary.exposesSecrets();

    // The report shows `context`, so what the operator needs to act on goes
    // there: what this archive is, and what it hands to anyone who guesses the
    // URL. "delete this, it is exposing your database password" - not "here are
    // three shells inside it".
    std::string context = platform.empty() ? "archive of site source"
                                           : platform + " backup";
    context += fmt::format(" - {} entries, {} PHP", summary.entries, summary.phpEntries);
    if (summary.sqlDumps > 0) {
        context += fmt::format(", {} database dump{}",
                               summary.sqlDumps, summary.sqlDumps == 1 ? "" : "s");
    }
    if (!summary.credentials.empty()) {
        context += " - exposes " + joinNames(summary.credentials, 3);
    } else if (summary.sqlDumps > 0) {
        context += " - exposes the database contents";
    }

    // The finding is that the file is in the wrong place, so the finding says
    // what to do about it. This is the operator's own data, and the scanner will
    // not move it for them.
    context += "; delete it or move it outside the web root";

    std::string detail = platform.empty() ? std::string("site archive")
                                          : platform + " archive";

    matches.push_back(makeArchiveMatch(credentials ? "ARC001" : "ARC002",
                                       std::move(detail), std::move(context)));
    return matches;
}

ArchiveScanner::Outcome ArchiveScanner::scan(const std::filesystem::path& path, Kind kind,
                                             std::string_view inMemory) {
    Outcome outcome;
    if (!config_.enabled || kind == Kind::None || config_.maxDepth == 0) {
        return outcome;
    }

    outcome.handled = true;

    Budget budget(config_.maxExpansion, config_.maxRatio, memberLimit_,
                  config_.timeBudgetSeconds);
    IndexSummary summary;

    Context ctx;
    ctx.display = pathToUtf8(path);
    ctx.depth = 1;
    ctx.budget = &budget;
    ctx.stats = &outcome.stats;
    ctx.summary = &summary;

    ++outcome.stats.archivesOpened;
    bool unreadable = false;

    if (kind == Kind::Zip) {
        auto reader = inMemory.empty() ? ZipReader::openFile(path)
                                       : ZipReader::openBuffer(inMemory);
        if (reader) {
            scanZip(*reader, ctx);
        } else {
            unreadable = true;
        }
    } else {
        // One handle, read forward once, never seeked back. Nothing is extracted.
        FileSource fileSource(path);
        MemorySource memorySource(inMemory);
        ByteSource* raw = inMemory.empty() ? static_cast<ByteSource*>(&fileSource)
                                           : static_cast<ByteSource*>(&memorySource);
        if (inMemory.empty() && !fileSource.ok()) {
            unreadable = true;
        } else if (kind == Kind::Tar) {
            scanTar(*raw, ctx, *raw);
        } else {
            GzipSource gzip(*raw);
            if (!gzip.ok()) {
                unreadable = true;
            } else if (kind == Kind::TarGz) {
                scanTar(gzip, ctx, *raw);
            } else {
                scanSingleGzip(gzip, ctx, gzipMemberName(path));
            }
        }
    }

    if (unreadable) {
        ++outcome.stats.archivesUnreadable;
    }

    outcome.archiveMatches = exposureFindings(summary, unreadable);
    return outcome;
}

}  // namespace lyxbosa::archive
