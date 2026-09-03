#pragma once

#include "core/SkipReason.h"

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
//
// This enum now lives in core/SkipReason.h, shared with the file level, which grew
// the same need. The names below are unqualified aliases so the reasons still read
// as `SkipReason::Policy` throughout this layer, and the six spellings that reach
// the `archives.membersSkipped` JSON object are unchanged.
using SkipReason = lyxbosa::SkipReason;
using lyxbosa::skipReasonToString;
using lyxbosa::skipReasonLabel;

// Everything the summary and the reports say about archive handling.
struct Stats {
    size_t archivesOpened = 0;      // archives read at all, nested ones included
    size_t archivesUnreadable = 0;  // could not be opened: truncated, hostile, encrypted
    size_t archivesTruncated = 0;   // a guard fired part-way through a solid stream,
                                    // where the members left are unknowable without
                                    // reading the very bytes the guard refused
    size_t membersScanned = 0;
    uint64_t bytesExpanded = 0;

    // One tally instead of six counters. The named accessors are kept because the
    // JSON writer and the archive tests read them by name.
    lyxbosa::SkipTally skips;

    void skip(SkipReason reason, size_t count = 1) { skips.skip(reason, count); }

    size_t skippedSize() const    { return skips.count(SkipReason::Size); }
    size_t skippedDepth() const   { return skips.count(SkipReason::Depth); }
    size_t skippedRatio() const   { return skips.count(SkipReason::Ratio); }
    size_t skippedBudget() const  { return skips.count(SkipReason::Budget); }
    size_t skippedCorrupt() const { return skips.count(SkipReason::Corrupt); }
    size_t skippedPolicy() const  { return skips.count(SkipReason::Policy); }

    size_t totalSkipped() const { return skips.total(); }

    void merge(const Stats& other) {
        archivesOpened     += other.archivesOpened;
        archivesUnreadable += other.archivesUnreadable;
        archivesTruncated  += other.archivesTruncated;
        membersScanned     += other.membersScanned;
        bytesExpanded      += other.bytesExpanded;
        skips.merge(other.skips);
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
