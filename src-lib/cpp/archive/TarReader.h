#pragma once

// TarReader.h - Streaming tar member iteration.
//
// tar is what real backups are made of. On a production ISPConfig server holding
// 50 sites and 164 GB, 201 of the archives were .tar.gz and *none* were zip, so
// this path - not the zip one - is what an operator actually meets.
//
// A tar is a solid stream with no index: reaching member 10,000 means reading
// everything before it. So there is one pass, members are handed out in the order
// they occur, and nothing is ever seeked back to.

#include "ArchiveTypes.h"
#include "ByteSource.h"

#include <string>

namespace lyxbosa::archive {

// True if a 512-byte block looks like a tar header (the "ustar" magic sits at
// offset 257). Used both to sniff a file and to decide whether a gzip stream
// wraps a tar or a single compressed file.
bool looksLikeTarBlock(std::string_view block);

class TarReader {
public:
    // `budget` bounds the bytes this reader will pull out of the source. It is
    // not optional in spirit: without it a single member claiming a petabyte
    // would be skipped over forever.
    TarReader(ByteSource& source, Budget& budget)
        : source_(source), budget_(budget) {}

    // Advance to the next member, skipping over whatever is left of the current
    // one. Returns false at the end of the archive, on a corrupt header, or when
    // the budget is spent - which of those is told by corrupt() and stopped().
    bool next(Entry& out);

    // Read the current member into `out`. Returns false if the member is larger
    // than `maxBytes` (in which case it is skipped over and nothing is buffered)
    // or if the stream ends early.
    bool readCurrent(std::string& out, uint64_t maxBytes);

    bool corrupt() const { return corrupt_; }
    bool stopped() const { return stopped_.has_value(); }
    std::optional<SkipReason> stopReason() const { return stopped_; }

private:
    // Read one 512-byte block. False at end of stream.
    bool readBlock(char* block);

    // Skip the current member's data and its padding to the next block boundary.
    bool finishMember();

    // Pull `n` bytes into `out` (or discard them when `out` is null), charging
    // them to the budget and stopping the moment a guard fires.
    bool pull(std::string* out, uint64_t n);

    // Charge decompressed output, and the compressed input behind it, to the
    // budget.
    void chargeBudget(uint64_t produced);

    ByteSource& source_;
    Budget& budget_;
    uint64_t lastConsumed_ = 0;
    uint64_t remaining_ = 0;   // unread bytes of the current member
    uint64_t padding_ = 0;     // bytes of padding after the current member
    bool corrupt_ = false;
    bool ended_ = false;
    std::optional<SkipReason> stopped_;
};

}  // namespace lyxbosa::archive
