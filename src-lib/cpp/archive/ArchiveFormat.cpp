#include "ArchiveFormat.h"
#include "ByteSource.h"
#include "GzipSource.h"
#include "TarReader.h"

#include <cctype>
#include <cstdio>
#include <string>

namespace lyxbosa::archive {

namespace {

bool startsWith(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

// Inflate the head of a gzip stream far enough to see a tar header block. A
// budget is required by the reader interface; this one is generous enough for
// 512 bytes and stops anything else dead.
Kind classifyGzip(ByteSource& source) {
    GzipSource gz(source);
    if (!gz.ok()) {
        return Kind::None;
    }

    char block[512] = {};
    const size_t got = gz.readFully(block, sizeof(block));
    if (got < sizeof(block)) {
        return Kind::Gzip;   // too short to be a tar, but still a gzip stream
    }
    return looksLikeTarBlock(std::string_view(block, sizeof(block))) ? Kind::TarGz
                                                                    : Kind::Gzip;
}

}  // namespace

Kind sniffMagic(std::string_view head) {
    // Local file header, empty archive, or a spanned/split marker. libzip
    // tolerates leading junk; this deliberately does not, because "the bytes
    // start with PK" is the claim being tested.
    if (startsWith(head, "PK\x03\x04") ||
        startsWith(head, "PK\x05\x06") ||
        startsWith(head, "PK\x07\x08")) {
        return Kind::Zip;
    }

    if (head.size() >= 2 &&
        static_cast<unsigned char>(head[0]) == 0x1f &&
        static_cast<unsigned char>(head[1]) == 0x8b) {
        return Kind::Gzip;
    }

    if (looksLikeTarBlock(head)) {
        return Kind::Tar;
    }

    return Kind::None;
}

Kind sniff(std::string_view content) {
    const Kind magic = sniffMagic(content);
    if (magic != Kind::Gzip) {
        return magic;
    }

    MemorySource source(content);
    return classifyGzip(source);
}

Kind sniffFile(const std::filesystem::path& path) {
    FileSource source(path);
    if (!source.ok()) {
        return Kind::None;
    }

    char head[kSniffBytes] = {};
    const size_t got = source.readFully(head, sizeof(head));
    if (got == 0) {
        return Kind::None;
    }

    const Kind magic = sniffMagic(std::string_view(head, got));
    if (magic != Kind::Gzip) {
        return magic;
    }

    // Re-open rather than seek: the gzip stream has to be read from byte zero,
    // and a fresh handle is cheaper to reason about than a rewind.
    FileSource again(path);
    if (!again.ok()) {
        return Kind::Gzip;
    }
    return classifyGzip(again);
}

bool hasArchiveExtension(const std::filesystem::path& path) {
    std::string name = path.filename().string();
    for (char& c : name) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    static constexpr std::string_view kSuffixes[] = {
        ".zip", ".zipx", ".tar", ".gz", ".tgz", ".taz", ".jar", ".war", ".apk",
    };
    for (std::string_view suffix : kSuffixes) {
        if (name.size() > suffix.size() &&
            name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0) {
            return true;
        }
    }
    return false;
}

std::string gzipMemberName(const std::filesystem::path& path) {
    std::string name = path.filename().string();
    if (name.size() > 3 && name.compare(name.size() - 3, 3, ".gz") == 0) {
        name.resize(name.size() - 3);
    } else if (name.size() > 4 && name.compare(name.size() - 4, 4, ".tgz") == 0) {
        name.resize(name.size() - 4);
        name += ".tar";
    }
    return name.empty() ? "content" : name;
}

}  // namespace lyxbosa::archive
