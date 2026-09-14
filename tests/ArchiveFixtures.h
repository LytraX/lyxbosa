#pragma once

// ArchiveFixtures.h - Building the archives a test scans, from bytes the test chooses.
//
// Written by hand rather than with a tool on the host, so that a member can carry any name a
// format can hold - a newline, a backslash, a byte no filesystem here would accept - and so
// that the same bytes are built on every platform the suite runs on.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include <zip.h>
#include <zlib.h>

namespace lyxbosa::test::fixtures {

namespace fs = std::filesystem;

// --- tar construction -------------------------------------------------------

inline void writeOctal(char* field, size_t width, uint64_t value) {
    // tar writes numbers as zero-padded octal with a trailing NUL.
    for (size_t i = width - 1; i-- > 0;) {
        field[i] = static_cast<char>('0' + (value & 7));
        value >>= 3;
    }
    field[width - 1] = '\0';
}

inline std::string tarHeader(const std::string& name, uint64_t size, char type = '0') {
    std::string block(512, '\0');
    char* raw = block.data();

    std::memcpy(raw, name.data(), std::min<size_t>(name.size(), 99));
    writeOctal(raw + 100, 8, 0644);
    writeOctal(raw + 108, 8, 0);
    writeOctal(raw + 116, 8, 0);
    writeOctal(raw + 124, 12, size);
    writeOctal(raw + 136, 12, 0);
    raw[156] = type;
    std::memcpy(raw + 257, "ustar", 5);
    std::memcpy(raw + 263, "00", 2);

    // The checksum is computed with its own field read as eight spaces.
    std::memset(raw + 148, ' ', 8);
    unsigned sum = 0;
    for (size_t i = 0; i < 512; ++i) {
        sum += static_cast<unsigned char>(block[i]);
    }
    writeOctal(raw + 148, 7, sum);
    raw[155] = ' ';

    return block;
}

inline void appendTarMember(std::string& tar, const std::string& name, const std::string& body,
                            char type = '0') {
    tar += tarHeader(name, body.size(), type);
    tar += body;
    if (const size_t rem = body.size() % 512; rem != 0) {
        tar.append(512 - rem, '\0');
    }
}

inline std::string endOfTar() { return std::string(1024, '\0'); }

// --- gzip -------------------------------------------------------------------

inline std::string gzipCompress(const std::string& input) {
    z_stream stream{};
    // 15 window bits + 16: write a gzip header rather than a zlib one.
    EXPECT_EQ(deflateInit2(&stream, Z_BEST_SPEED, Z_DEFLATED, 15 + 16, 8,
                           Z_DEFAULT_STRATEGY),
              Z_OK);

    std::string out;
    out.resize(deflateBound(&stream, input.size()) + 64);

    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
    stream.avail_in = static_cast<uInt>(input.size());
    stream.next_out = reinterpret_cast<Bytef*>(out.data());
    stream.avail_out = static_cast<uInt>(out.size());

    EXPECT_EQ(deflate(&stream, Z_FINISH), Z_STREAM_END);
    out.resize(stream.total_out);
    deflateEnd(&stream);
    return out;
}

// --- zip construction -------------------------------------------------------

// Members are added from buffers this vector keeps alive: libzip does not copy
// them until the archive is written out.
inline void writeZip(const fs::path& path,
                     const std::vector<std::pair<std::string, std::string>>& members) {
    int err = 0;
    zip_t* za = zip_open(path.string().c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    ASSERT_NE(za, nullptr);

    for (const auto& [name, body] : members) {
        zip_source_t* source = zip_source_buffer(za, body.data(), body.size(), 0);
        ASSERT_NE(source, nullptr);
        ASSERT_GE(zip_file_add(za, name.c_str(), source, ZIP_FL_OVERWRITE), 0);
    }

    ASSERT_EQ(zip_close(za), 0);
}

// The bytes of a file, for an archive built on disk and then carried inside another one.
inline std::string readBytes(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

}  // namespace lyxbosa::test::fixtures
