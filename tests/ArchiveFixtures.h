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
#include <optional>
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
//
// `host` is the host byte of each entry's "version made by" - ZIP_OPSYS_DOS for what a Windows
// archiver writes. Left empty, libzip writes its default, which is ZIP_OPSYS_UNIX on every
// platform. hostBytesOf() below reads it back from the file, without libzip.
inline void writeZip(const fs::path& path,
                     const std::vector<std::pair<std::string, std::string>>& members,
                     std::optional<uint8_t> host = std::nullopt) {
    int err = 0;
    zip_t* za = zip_open(path.string().c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    ASSERT_NE(za, nullptr);

    for (const auto& [name, body] : members) {
        zip_source_t* source = zip_source_buffer(za, body.data(), body.size(), 0);
        ASSERT_NE(source, nullptr);
        const zip_int64_t index = zip_file_add(za, name.c_str(), source, ZIP_FL_OVERWRITE);
        ASSERT_GE(index, 0);
        if (host) {
            ASSERT_EQ(zip_file_set_external_attributes(za, static_cast<zip_uint64_t>(index), 0,
                                                       *host, 0),
                      0);
        }
    }

    ASSERT_EQ(zip_close(za), 0);
}

// Each central-directory entry's name and host byte, read from the file's own bytes rather than
// through libzip, so that a case can see its archive holds what it says before trusting what a
// scan of it says. Empty when the file is not a zip this simple reader understands.
inline std::vector<std::pair<std::string, uint8_t>> hostBytesOf(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    const std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const auto u16 = [&](size_t at) {
        return static_cast<uint32_t>(static_cast<unsigned char>(data[at]) |
                                     (static_cast<unsigned char>(data[at + 1]) << 8));
    };
    const auto u32 = [&](size_t at) { return u16(at) | (u16(at + 2) << 16); };

    std::vector<std::pair<std::string, uint8_t>> out;
    const size_t end = data.rfind(std::string("PK\x05\x06", 4));
    if (end == std::string::npos || end + 22 > data.size()) {
        return out;
    }
    size_t at = u32(end + 16);
    for (uint32_t i = 0, count = u16(end + 10); i < count; ++i) {
        if (at + 46 > data.size() || data.compare(at, 4, std::string("PK\x01\x02", 4)) != 0) {
            return {};
        }
        const uint32_t nameLength = u16(at + 28);
        const uint32_t extraLength = u16(at + 30);
        const uint32_t commentLength = u16(at + 32);
        out.emplace_back(data.substr(at + 46, nameLength), static_cast<uint8_t>(u16(at + 4) >> 8));
        at += 46 + nameLength + extraLength + commentLength;
    }
    return out;
}

// The bytes of a file, for an archive built on disk and then carried inside another one.
inline std::string readBytes(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

}  // namespace lyxbosa::test::fixtures
