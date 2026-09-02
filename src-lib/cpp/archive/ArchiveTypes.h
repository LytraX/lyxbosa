#pragma once

// ArchiveTypes.h - Vocabulary shared by the archive readers and the scanner.
//
// An archive is two different problems wearing one file extension. A payload
// archive holds one to three members, tens of kilobytes, dropped by the attacker;
// the malware inside it is the finding. A site backup holds thousands of members
// and can reach tens of gigabytes; the *archive itself* is the finding, because
// anyone who guesses the URL gets the source and, with wp-config.php or .env, the
// live database password. Conflating the two is the main design risk here, so the
// classification below is index-only and runs before anything is decompressed.

#include <chrono>
#include <optional>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace lyxbosa::archive {

// Container formats. Deliberately short: libzip and zlib cover every format seen
// in the corpora, and every format added is another C parser fed attacker-
// controlled bytes.
enum class Kind {
    None,
    Zip,
    Tar,
    TarGz,   // gzip stream whose contents are a tar
    Gzip     // gzip stream that is not a tar - a single compressed file
};

constexpr std::string_view kindToString(Kind k) {
    switch (k) {
        case Kind::None:  return "none";
        case Kind::Zip:   return "zip";
        case Kind::Tar:   return "tar";
        case Kind::TarGz: return "tar.gz";
        case Kind::Gzip:  return "gz";
    }
    return "none";
}

// One entry as the container names it, before anything is decompressed.
struct Entry {
    std::string name;
    uint64_t size = 0;             // uncompressed, as claimed by the index
    uint64_t compressedSize = 0;   // 0 when the format does not say (tar)
    bool directory = false;
};

// Why a member was not scanned. Every skip carries one: silent skips are how the
// goto-obfuscation family stayed invisible for so long, and an archive is exactly
// the place where a scanner is tempted to give up quietly.
enum class SkipReason {
    Size,     // member larger than the per-member cap
    Depth,    // nested deeper than max_depth
    Ratio,    // archive expands faster than max_ratio
    Budget,   // time or total-expansion budget spent
    Corrupt,  // truncated, encrypted or otherwise unreadable
    Policy    // not selected by the priority policy (see exhaustive)
};

constexpr std::string_view skipReasonToString(SkipReason r) {
    switch (r) {
        case SkipReason::Size:    return "size";
        case SkipReason::Depth:   return "depth";
        case SkipReason::Ratio:   return "ratio";
        case SkipReason::Budget:  return "budget";
        case SkipReason::Corrupt: return "corrupt";
        case SkipReason::Policy:  return "policy";
    }
    return "unknown";
}

// Everything the summary and the reports say about archive handling.
struct Stats {
    size_t archivesOpened = 0;      // archives read at all, nested ones included
    size_t archivesUnreadable = 0;  // could not be opened: truncated, hostile, encrypted
    size_t archivesTruncated = 0;   // a guard fired part-way through a solid stream,
                                    // where the members left are unknowable without
                                    // reading the very bytes the guard refused
    size_t membersScanned = 0;
    uint64_t bytesExpanded = 0;

    size_t skippedSize = 0;
    size_t skippedDepth = 0;
    size_t skippedRatio = 0;
    size_t skippedBudget = 0;
    size_t skippedCorrupt = 0;
    size_t skippedPolicy = 0;

    void skip(SkipReason reason, size_t count = 1) {
        switch (reason) {
            case SkipReason::Size:    skippedSize += count; break;
            case SkipReason::Depth:   skippedDepth += count; break;
            case SkipReason::Ratio:   skippedRatio += count; break;
            case SkipReason::Budget:  skippedBudget += count; break;
            case SkipReason::Corrupt: skippedCorrupt += count; break;
            case SkipReason::Policy:  skippedPolicy += count; break;
        }
    }

    size_t totalSkipped() const {
        return skippedSize + skippedDepth + skippedRatio +
               skippedBudget + skippedCorrupt + skippedPolicy;
    }

    void merge(const Stats& other) {
        archivesOpened     += other.archivesOpened;
        archivesUnreadable += other.archivesUnreadable;
        archivesTruncated  += other.archivesTruncated;
        membersScanned     += other.membersScanned;
        bytesExpanded      += other.bytesExpanded;
        skippedSize        += other.skippedSize;
        skippedDepth       += other.skippedDepth;
        skippedRatio       += other.skippedRatio;
        skippedBudget      += other.skippedBudget;
        skippedCorrupt     += other.skippedCorrupt;
        skippedPolicy      += other.skippedPolicy;
    }
};

// The guards, carried down through nested archives so a bomb cannot buy itself
// more budget by nesting. Everything here is measured in decompressed bytes or
// wall-clock time; the size of the archive on disk is not a bound on anything.
class Budget {
public:
    using Clock = std::chrono::steady_clock;

    Budget(uint64_t maxExpansion, uint64_t maxRatio, uint64_t maxMemberSize,
           uint64_t timeBudgetSeconds, Clock::time_point start = Clock::now())
        : maxExpansion_(maxExpansion),
          maxRatio_(maxRatio),
          maxMemberSize_(maxMemberSize),
          deadline_(start + std::chrono::seconds(timeBudgetSeconds)),
          timed_(timeBudgetSeconds > 0) {}

    uint64_t memberSizeLimit() const { return maxMemberSize_; }

    void addExpanded(uint64_t bytes) { expanded_ += bytes; }
    void addConsumed(uint64_t bytes) { consumed_ += bytes; }

    uint64_t expanded() const { return expanded_; }
    uint64_t consumed() const { return consumed_; }

    bool timeExpired(Clock::time_point now = Clock::now()) const {
        return timed_ && now >= deadline_;
    }

    bool expansionExhausted() const {
        return maxExpansion_ > 0 && expanded_ >= maxExpansion_;
    }

    // Only meaningful once enough has come out to be sure: a 4 KB member from a
    // 40 byte header would otherwise read as a 100:1 bomb. One megabyte of output
    // is far below anything the guard is meant to stop and far above the noise.
    bool ratioTripped() const {
        if (maxRatio_ == 0 || consumed_ == 0 || expanded_ < kRatioFloor) {
            return false;
        }
        return expanded_ / consumed_ > maxRatio_;
    }

    // The first guard that has fired, if any.
    std::optional<SkipReason> spent(Clock::time_point now = Clock::now()) const {
        if (expansionExhausted()) return SkipReason::Budget;
        if (ratioTripped())       return SkipReason::Ratio;
        if (timeExpired(now))     return SkipReason::Budget;
        return std::nullopt;
    }

private:
    static constexpr uint64_t kRatioFloor = 1024 * 1024;

    uint64_t maxExpansion_;
    uint64_t maxRatio_;
    uint64_t maxMemberSize_;
    Clock::time_point deadline_;
    bool timed_;
    uint64_t expanded_ = 0;
    uint64_t consumed_ = 0;
};

}  // namespace lyxbosa::archive
