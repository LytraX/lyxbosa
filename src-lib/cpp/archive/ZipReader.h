#pragma once

// ZipReader.h - Central-directory access to a zip, via libzip.
//
// Zip is the one format that can be triaged for free. Its central directory sits
// at the end of the file and names every member and its uncompressed size, so the
// index of a 337 MB, 28,092-member backup reads in 0.096 s - 0.8% of the cost of
// reading the file - and the scanner learns exactly how many members it will open
// and how many bytes they hold before it decompresses a single one.
//
// libzip is a C parser being handed attacker-controlled bytes, which is a new
// kind of surface for a scanner that until now treated every file as a flat byte
// buffer for regex. It is here rather than libarchive because it covers what the
// corpora actually contain (zip, gz, tar.gz) with a fraction of the parser, and
// every entry point is wrapped so a hostile archive becomes a `corrupt` count
// rather than a crash.

#include "ArchiveTypes.h"

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

struct zip;

namespace lyxbosa::archive {

class ZipReader {
public:
    ~ZipReader();

    ZipReader(const ZipReader&) = delete;
    ZipReader& operator=(const ZipReader&) = delete;

    // Both return nullptr when the archive cannot be opened at all. The buffer
    // overload does not copy, so `bytes` must outlive the reader - it is the
    // member buffer of an enclosing archive.
    static std::unique_ptr<ZipReader> openFile(const std::filesystem::path& path);
    static std::unique_ptr<ZipReader> openBuffer(std::string_view bytes);

    const std::vector<Entry>& entries() const { return entries_; }

    // Inflate one member into `out`, never more than `maxBytes`. False means the
    // member was unreadable - truncated, encrypted, or lying about its size.
    bool read(size_t index, std::string& out, uint64_t maxBytes);

    // True when the index itself was suspicious: more entries than any real
    // archive has, or entries libzip could not stat.
    bool indexTruncated() const { return indexTruncated_; }

private:
    ZipReader() = default;

    // Reading the index of an archive with hundreds of millions of claimed
    // entries is itself the attack. No real backup comes close: the largest
    // measured held 28,092.
    static constexpr size_t kMaxEntries = 2'000'000;

    void loadIndex();

    zip* archive_ = nullptr;
    std::vector<Entry> entries_;
    std::vector<uint64_t> indices_;   // entry -> libzip index
    bool indexTruncated_ = false;
};

}  // namespace lyxbosa::archive
