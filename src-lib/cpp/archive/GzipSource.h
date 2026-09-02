#pragma once

// GzipSource.h - zlib inflate over another ByteSource.
//
// Reports `consumed()` in *compressed* bytes, which is what makes progress
// through a .tar.gz honest: the compressed size is known exactly from the
// filesystem, so "how far into this archive am I" needs no estimate, no second
// pass, and no guess at an expansion ratio (the corpus averages 3.2x, a real
// WordPress backup 5.6x, and a directory of JPEGs ~1.0x - an estimate that wrong
// makes the ETA worse than no ETA).
//
// Output is never buffered beyond the caller's request, so a bomb cannot make
// this allocate: the caller stops pulling and the inflater stops running.

#include "ByteSource.h"

#include <memory>
#include <zlib.h>

namespace lyxbosa::archive {

class GzipSource : public ByteSource {
public:
    explicit GzipSource(ByteSource& inner) : inner_(inner), in_(kChunk) {
        stream_.zalloc = Z_NULL;
        stream_.zfree = Z_NULL;
        stream_.opaque = Z_NULL;
        stream_.next_in = Z_NULL;
        stream_.avail_in = 0;
        // 15 window bits + 32: accept both a gzip and a zlib header, decided by
        // the header itself rather than by the file extension.
        ok_ = inflateInit2(&stream_, 15 + 32) == Z_OK;
    }

    ~GzipSource() override {
        if (ok_) inflateEnd(&stream_);
    }

    GzipSource(const GzipSource&) = delete;
    GzipSource& operator=(const GzipSource&) = delete;

    bool ok() const { return ok_; }
    bool failed() const override { return failed_; }

    // Compressed bytes pulled from the underlying stream.
    uint64_t consumed() const override { return inner_.consumed(); }

    // Uncompressed bytes handed out so far.
    uint64_t produced() const { return produced_; }

    size_t read(char* buf, size_t n) override {
        if (!ok_ || done_ || n == 0) return 0;

        stream_.next_out = reinterpret_cast<Bytef*>(buf);
        stream_.avail_out = static_cast<uInt>(n);

        while (stream_.avail_out > 0) {
            if (stream_.avail_in == 0) {
                const size_t got = inner_.read(in_.data(), in_.size());
                if (got == 0) {
                    // Input ended mid-stream. A truncated archive is a real
                    // thing on a compromised host; report it rather than
                    // pretending the archive simply ended.
                    if (stream_.avail_out == n) {
                        failed_ = !streamEnded_;
                        done_ = true;
                        return 0;
                    }
                    break;
                }
                stream_.next_in = reinterpret_cast<Bytef*>(in_.data());
                stream_.avail_in = static_cast<uInt>(got);
            }

            const int rc = inflate(&stream_, Z_NO_FLUSH);
            if (rc == Z_STREAM_END) {
                streamEnded_ = true;
                // gzip streams are legally concatenated - `cat a.gz b.gz` is a
                // valid .gz - so keep going if there is more input behind it.
                if (stream_.avail_in > 0 || peekMore()) {
                    if (inflateReset(&stream_) != Z_OK) {
                        failed_ = true;
                        done_ = true;
                        break;
                    }
                    streamEnded_ = false;
                    continue;
                }
                done_ = true;
                break;
            }
            if (rc != Z_OK) {
                failed_ = true;
                done_ = true;
                break;
            }
        }

        const size_t produced = n - stream_.avail_out;
        produced_ += produced;
        return produced;
    }

private:
    static constexpr size_t kChunk = 64 * 1024;

    // Refill from the inner source to find out whether another gzip member
    // follows the one that just ended.
    bool peekMore() {
        const size_t got = inner_.read(in_.data(), in_.size());
        if (got == 0) return false;
        stream_.next_in = reinterpret_cast<Bytef*>(in_.data());
        stream_.avail_in = static_cast<uInt>(got);
        return true;
    }

    ByteSource& inner_;
    std::vector<char> in_;
    z_stream stream_{};
    uint64_t produced_ = 0;
    bool ok_ = false;
    bool done_ = false;
    bool failed_ = false;
    bool streamEnded_ = false;
};

}  // namespace lyxbosa::archive
