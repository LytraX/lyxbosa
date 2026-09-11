#include "update/BuildIdentity.h"

#include "update/ReleaseAssets.h"

#include <fmt/format.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

namespace lyxbosa {

namespace {

#if defined(__linux__)

// The glibc the standard build is linked against. It is built on almalinux:8, so this
// is that image's glibc and not a number anybody chose: raising the build image raises
// the floor, and this constant is where that has to be noticed.
constexpr unsigned kStandardBuildGlibcMinor = 28;   // GLIBC_2.28

// Where the dynamic loader lives, which the ABI fixes per architecture rather than
// leaving to the distribution. A dynamically linked binary carries this path inside it
// as its PT_INTERP, so its absence is not a hint - no such binary can start at all.
#if defined(__x86_64__)
#define LYXBOSA_HAVE_LOADER_PATH 1
constexpr const char* kLoaderPath = "/lib64/ld-linux-x86-64.so.2";
constexpr std::array<const char*, 4> kLibcPaths{
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/lib64/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib64/libc.so.6",
};
#elif defined(__aarch64__)
#define LYXBOSA_HAVE_LOADER_PATH 1
constexpr const char* kLoaderPath = "/lib/ld-linux-aarch64.so.1";
constexpr std::array<const char*, 4> kLibcPaths{
    "/lib/aarch64-linux-gnu/libc.so.6",
    "/lib64/libc.so.6",
    "/usr/lib/aarch64-linux-gnu/libc.so.6",
    "/usr/lib64/libc.so.6",
};
#endif

// A .dynstr of a C library is tens of kilobytes. A megabyte is far past anything real
// and stops a file that is not what it claims from turning into a large allocation on a
// host somebody is in the middle of an incident on.
constexpr uint64_t kMaxDynstrBytes = 1024ull * 1024;

bool readAt(std::ifstream& in, uint64_t offset, void* into, size_t bytes) {
    in.clear();
    in.seekg(static_cast<std::streamoff>(offset));
    if (!in) return false;
    in.read(static_cast<char*>(into), static_cast<std::streamsize>(bytes));
    return static_cast<size_t>(in.gcount()) == bytes;
}

// The highest N in any `<prefix>N` string in a shared object's dynamic string table, or
// nullopt when the file could not be read as one.
//
// Every step refuses rather than assuming: a bad magic, a class or byte order this does
// not handle, a section table that does not fit, a .dynstr that is absent or absurd. An
// ELF parser that guesses on a file it half-recognises is a crash on somebody's host.
std::optional<unsigned> highestSymbolVersion(const std::filesystem::path& path,
                                            std::string_view prefix) {
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in) return std::nullopt;

    unsigned char ident[16]{};
    if (!readAt(in, 0, ident, sizeof(ident))) return std::nullopt;
    if (std::memcmp(ident, "\x7f" "ELF", 4) != 0) return std::nullopt;
    // 64-bit, little-endian only. Both architectures a release publishes for are that,
    // and a file that is not is a question this was not written to answer.
    if (ident[4] != 2 || ident[5] != 1) return std::nullopt;

    uint64_t sectionOffset = 0;
    uint16_t sectionEntrySize = 0;
    uint16_t sectionCount = 0;
    uint16_t sectionNameIndex = 0;
    if (!readAt(in, 0x28, &sectionOffset, sizeof(sectionOffset))) return std::nullopt;
    if (!readAt(in, 0x3A, &sectionEntrySize, sizeof(sectionEntrySize))) return std::nullopt;
    if (!readAt(in, 0x3C, &sectionCount, sizeof(sectionCount))) return std::nullopt;
    if (!readAt(in, 0x3E, &sectionNameIndex, sizeof(sectionNameIndex))) return std::nullopt;

    // A stripped-of-section-headers object, or one claiming more sections than could be
    // read, is unreadable rather than an error worth reporting.
    if (sectionOffset == 0 || sectionEntrySize < 64 || sectionCount == 0) return std::nullopt;
    if (sectionNameIndex >= sectionCount) return std::nullopt;
    if (sectionCount > 4096) return std::nullopt;

    // Only the three fields of a section header this needs: name offset, file offset
    // and size. Read one header at a time rather than the whole table, so a bogus
    // sectionCount cannot become a large allocation before it is rejected.
    struct Section {
        uint32_t nameOffset = 0;
        uint64_t offset = 0;
        uint64_t size = 0;
    };
    const auto sectionAt = [&](uint16_t index) -> std::optional<Section> {
        const uint64_t base = sectionOffset + uint64_t{index} * sectionEntrySize;
        Section s;
        if (!readAt(in, base + 0x00, &s.nameOffset, sizeof(s.nameOffset))) return std::nullopt;
        if (!readAt(in, base + 0x18, &s.offset, sizeof(s.offset))) return std::nullopt;
        if (!readAt(in, base + 0x20, &s.size, sizeof(s.size))) return std::nullopt;
        return s;
    };

    const auto names = sectionAt(sectionNameIndex);
    if (!names || names->size == 0 || names->size > kMaxDynstrBytes) return std::nullopt;
    std::vector<char> nameTable(static_cast<size_t>(names->size));
    if (!readAt(in, names->offset, nameTable.data(), nameTable.size())) return std::nullopt;
    nameTable.back() = '\0';

    std::vector<char> dynstr;
    for (uint16_t index = 0; index < sectionCount; ++index) {
        const auto section = sectionAt(index);
        if (!section) return std::nullopt;
        if (section->nameOffset >= nameTable.size()) continue;
        if (std::strcmp(nameTable.data() + section->nameOffset, ".dynstr") != 0) continue;
        if (section->size == 0 || section->size > kMaxDynstrBytes) return std::nullopt;
        dynstr.resize(static_cast<size_t>(section->size));
        if (!readAt(in, section->offset, dynstr.data(), dynstr.size())) return std::nullopt;
        dynstr.back() = '\0';
        break;
    }
    if (dynstr.empty()) return std::nullopt;

    // Walk the NUL-separated strings. A version name is `<prefix><digits>` exactly:
    // anything trailing means it is a different name that happens to start the same
    // way, and is skipped rather than half-parsed.
    std::optional<unsigned> highest;
    size_t at = 0;
    while (at < dynstr.size()) {
        const std::string_view entry(dynstr.data() + at);
        at += entry.size() + 1;
        if (entry.size() <= prefix.size() || entry.compare(0, prefix.size(), prefix) != 0) {
            continue;
        }
        const std::string_view digits = entry.substr(prefix.size());
        if (digits.empty() || digits.size() > 6) continue;
        unsigned value = 0;
        bool numeric = true;
        for (const char c : digits) {
            if (c < '0' || c > '9') {
                numeric = false;
                break;
            }
            value = value * 10 + static_cast<unsigned>(c - '0');
        }
        if (!numeric) continue;
        if (!highest || value > *highest) highest = value;
    }
    return highest;
}

#endif  // __linux__

}  // namespace

bool isPortableBuild() {
#if defined(__linux__) && defined(LYXBOSA_LIBC_MUSL)
    return true;
#else
    return false;
#endif
}

std::string buildIdentity() {
    const std::string_view asset = platformAssetName();
    if (asset.empty()) return {};

#if defined(__linux__)
    return fmt::format("{} build, {}", isPortableBuild() ? "portable" : "standard", asset);
#else
    return std::string(asset);
#endif
}

StandardBuildHere standardBuildHereAt(const std::filesystem::path& loader,
                                      const std::vector<std::filesystem::path>& libcs) {
#if defined(__linux__)
    // No loader, no dynamically linked binary - whatever else is true of this host.
    // This is the Alpine case and every other musl-only one, and it is the only answer
    // here that needs nothing parsed.
    std::error_code ec;
    if (loader.empty() || !std::filesystem::exists(loader, ec) || ec) {
        return StandardBuildHere::No;
    }

    for (const auto& path : libcs) {
        const auto highest = highestSymbolVersion(path, "GLIBC_2.");
        if (!highest) continue;   // absent, unreadable, or not an ELF this can read
        return *highest >= kStandardBuildGlibcMinor ? StandardBuildHere::Yes
                                                    : StandardBuildHere::No;
    }

    // A loader is there and no glibc could be read. Not proof of either answer.
    return StandardBuildHere::Unknown;
#else
    (void)loader;
    (void)libcs;
    return StandardBuildHere::Unknown;
#endif
}

StandardBuildHere standardBuildHere() {
#if defined(__linux__) && defined(LYXBOSA_HAVE_LOADER_PATH)
    return standardBuildHereAt(kLoaderPath,
                               {kLibcPaths.begin(), kLibcPaths.end()});
#else
    // An architecture a release publishes no Linux asset for, or not Linux at all.
    // There is no standard build whose availability could be reported.
    return StandardBuildHere::Unknown;
#endif
}

std::string portableBuildNoticeFor(std::string_view standardAsset) {
    // Six spaces on the continuation lines, because the scan prints this behind a
    // "Note: " prefix - the same shape as updateNotice(), and the lines are kept inside
    // 78 columns so a narrow terminal does not re-wrap them into a paragraph.
    //
    // NO NUMBER IN HERE, and that is the rule rather than an omission. The difference
    // between the two builds is a property of the work and not of the binaries: about a
    // tenth on a tree of small files, a fortieth on a server scan whose time goes into
    // archive expansion. One percentage compiled in cannot be corrected without a
    // release, so the claim made here has to be one that stays true on a tree nobody has
    // measured - and the measurements, with what each was over, belong in README.md
    // under *System support*, where they can be added to. A test asserts that no
    // digit-and-percent comes back into this string.
    return fmt::format(
        "this is the portable build, and this host can run the standard one.\n"
        "      {} is faster on the same scan - how much depends on\n"
        "      the tree and the host - and finds exactly the same things.\n"
        "      Install it once by hand; updates stay on it. This is said\n"
        "      again at most once a month.\n",
        standardAsset);
}

std::string portableBuildNotice() {
    if (!isPortableBuild()) return {};
    if (standardBuildHere() != StandardBuildHere::Yes) return {};

    constexpr std::string_view kSuffix = "-portable";
    const std::string_view asset = platformAssetName();
    if (!asset.ends_with(kSuffix)) return {};

    return portableBuildNoticeFor(asset.substr(0, asset.size() - kSuffix.size()));
}

}  // namespace lyxbosa
