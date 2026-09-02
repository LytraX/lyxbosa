#pragma once

// ByteSource.h - A byte stream a tar can be read out of.
//
// Three of them: a file, a block of memory (a member of an outer archive), and a
// gzip inflater wrapping either. `consumed()` is the number of bytes of the
// *underlying* stream used so far - for the gzip source that is compressed input,
// which is the only quantity that can be turned into honest progress on a
// .tar.gz. See ARCHIVE_SCANNING_PLAN.md section 5: the gzip footer stores the
// uncompressed size mod 2^32 and is unusable for anything large, and inflating
// once to count and again to scan doubles the cost of the single most expensive
// item in the scan.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <filesystem>
#include <string_view>
#include <vector>

namespace lyxbosa::archive {

class ByteSource {
public:
    virtual ~ByteSource() = default;

    // Fill up to n bytes. Returns the number read; 0 means end of stream.
    virtual size_t read(char* buf, size_t n) = 0;

    // Bytes of the underlying stream consumed so far.
    virtual uint64_t consumed() const = 0;

    // True once the stream has failed rather than simply ended.
    virtual bool failed() const { return false; }

    // Read exactly n bytes, or fewer at end of stream.
    size_t readFully(char* buf, size_t n) {
        size_t total = 0;
        while (total < n) {
            const size_t got = read(buf + total, n - total);
            if (got == 0) break;
            total += got;
        }
        return total;
    }

    // Discard n bytes. Returns the number actually skipped.
    uint64_t skip(uint64_t n) {
        char scratch[16 * 1024];
        uint64_t total = 0;
        while (total < n) {
            const size_t want = static_cast<size_t>(
                std::min<uint64_t>(sizeof(scratch), n - total));
            const size_t got = read(scratch, want);
            if (got == 0) break;
            total += got;
        }
        return total;
    }
};

// A file on disk, read with a modest buffer. Nothing is ever extracted to disk -
// see ARCHIVE_SCANNING_PLAN.md section 6 - so this is the only file handle in the
// archive path, and it is read-only.
class FileSource : public ByteSource {
public:
    explicit FileSource(const std::filesystem::path& path) {
#ifdef _WIN32
        file_ = _wfopen(path.c_str(), L"rb");
#else
        file_ = std::fopen(path.c_str(), "rb");
#endif
    }

    ~FileSource() override {
        if (file_) std::fclose(file_);
    }

    FileSource(const FileSource&) = delete;
    FileSource& operator=(const FileSource&) = delete;

    bool ok() const { return file_ != nullptr; }

    size_t read(char* buf, size_t n) override {
        if (!file_ || n == 0) return 0;
        const size_t got = std::fread(buf, 1, n, file_);
        consumed_ += got;
        if (got < n && std::ferror(file_)) {
            failed_ = true;
        }
        return got;
    }

    uint64_t consumed() const override { return consumed_; }
    bool failed() const override { return failed_; }

private:
    std::FILE* file_ = nullptr;
    uint64_t consumed_ = 0;
    bool failed_ = false;
};

// A block of memory - a member of an enclosing archive, already in the bounded
// buffer it was inflated into.
class MemorySource : public ByteSource {
public:
    explicit MemorySource(std::string_view bytes) : bytes_(bytes) {}

    size_t read(char* buf, size_t n) override {
        const size_t left = bytes_.size() - pos_;
        const size_t take = n < left ? n : left;
        if (take > 0) {
            std::memcpy(buf, bytes_.data() + pos_, take);
            pos_ += take;
        }
        return take;
    }

    uint64_t consumed() const override { return pos_; }

private:
    std::string_view bytes_;
    size_t pos_ = 0;
};

}  // namespace lyxbosa::archive
