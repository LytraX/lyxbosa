#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace lyxbosa {

// Why something was not scanned.
//
// One enum for both levels of the scan. The archive layer had this right first -
// a per-reason counter, a JSON object naming each reason, and a summary line that
// says what was not looked at - because an archive is exactly where a scanner is
// tempted to give up quietly. The file level had a single `bool skippedSize`, and
// so reported a glob-excluded file as nothing at all, an unreadable file as
// "skipped, size limit", and a file whose read *failed* as scanned and clean.
//
// A skip is a fact about the scan, and the operator has to be able to see it.
enum class SkipReason : uint8_t {
    // Both levels
    Size,        // over the per-file / per-member cap

    // File level only
    Excluded,    // did not survive scan.include / scan.exclude
    Unreadable,  // stat or open failed: permissions, a race, a dead mount

    // Archive member level only
    Depth,       // nested deeper than max_depth
    Ratio,       // archive expands faster than max_ratio
    Budget,      // time or total-expansion budget spent
    Corrupt,     // truncated, encrypted or otherwise unreadable
    Policy,      // not selected by the priority policy (see exhaustive)
};

inline constexpr size_t kSkipReasonCount = 8;

inline constexpr size_t skipReasonIndex(SkipReason reason) {
    return static_cast<size_t>(reason);
}

// The machine-readable name. The six archive spellings are load-bearing: they are
// the keys of the `archives.membersSkipped` JSON object, and changing one would
// silently break every consumer of an existing report.
constexpr std::string_view skipReasonToString(SkipReason reason) {
    switch (reason) {
        case SkipReason::Size:       return "size";
        case SkipReason::Excluded:   return "excluded";
        case SkipReason::Unreadable: return "unreadable";
        case SkipReason::Depth:      return "depth";
        case SkipReason::Ratio:      return "ratio";
        case SkipReason::Budget:     return "budget";
        case SkipReason::Corrupt:    return "corrupt";
        case SkipReason::Policy:     return "policy";
    }
    return "unknown";
}

// The human-readable label, for the summary and the per-file lines. Phrased to
// read after a count: "487 over size limit, 18 excluded by filters".
// The six archive spellings are the ones printArchiveSummary already used, verbatim,
// so the summary line an operator has been reading does not silently change wording.
constexpr std::string_view skipReasonLabel(SkipReason reason) {
    switch (reason) {
        case SkipReason::Size:       return "over size limit";
        case SkipReason::Excluded:   return "excluded by filters";
        case SkipReason::Unreadable: return "unreadable";
        case SkipReason::Depth:      return "too deeply nested";
        case SkipReason::Ratio:      return "compression ratio";
        case SkipReason::Budget:     return "budget spent";
        case SkipReason::Corrupt:    return "corrupt";
        case SkipReason::Policy:     return "not code";
    }
    return "unknown";
}

// A skip is a finding about the scan rather than about a file, and two of these
// reasons are the operator's own decision while one is not. An oversize file and
// an excluded file are policy working as configured; a file the scanner could not
// open on a host it was pointed at is something the operator did not ask for and
// should see.
constexpr bool skipReasonIsUnexpected(SkipReason reason) {
    switch (reason) {
        case SkipReason::Unreadable:
        case SkipReason::Corrupt:
            return true;
        default:
            return false;
    }
}

// Per-reason skip counts. This is archive::Stats's counting half, generalised so
// the file level and the member level tally the same way.
class SkipTally {
public:
    void skip(SkipReason reason, size_t count = 1) {
        counts_[skipReasonIndex(reason)] += count;
    }

    size_t count(SkipReason reason) const {
        return counts_[skipReasonIndex(reason)];
    }

    size_t total() const {
        size_t sum = 0;
        for (size_t value : counts_) sum += value;
        return sum;
    }

    void merge(const SkipTally& other) {
        for (size_t i = 0; i < kSkipReasonCount; ++i) {
            counts_[i] += other.counts_[i];
        }
    }

private:
    std::array<size_t, kSkipReasonCount> counts_{};
};

// The order each level presents its reasons in.
//
// Two arrays rather than enum order, because the archive line is pre-existing output:
// it has always led with "not code", which is both the largest and the least alarming
// reason, and reordering it would change what an operator reads for no gain. The file
// level is new and leads with the size cap for the same reason - it is the common case.
inline constexpr SkipReason kFileSkipOrder[] = {
    SkipReason::Size, SkipReason::Excluded, SkipReason::Unreadable,
};
inline constexpr SkipReason kArchiveSkipOrder[] = {
    SkipReason::Policy, SkipReason::Size, SkipReason::Budget,
    SkipReason::Ratio, SkipReason::Depth, SkipReason::Corrupt,
};

// "487 over size limit, 18 excluded by filters, 7 unreadable" - the reasons that
// actually occurred, in the given order, each with its count. Empty when nothing was
// skipped, so a caller can decide whether to print the line at all.
inline std::string formatSkipTally(const SkipTally& tally,
                                   std::span<const SkipReason> order) {
    std::string out;
    for (SkipReason reason : order) {
        const size_t n = tally.count(reason);
        if (n == 0) continue;
        if (!out.empty()) out += ", ";
        out += std::to_string(n);
        out += ' ';
        out += skipReasonLabel(reason);
    }
    return out;
}

}  // namespace lyxbosa
