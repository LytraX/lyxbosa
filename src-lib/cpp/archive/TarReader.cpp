#include "TarReader.h"

#include <cstring>

namespace lyxbosa::archive {

namespace {

constexpr size_t kBlock = 512;
constexpr size_t kMagicOffset = 257;
constexpr size_t kSizeOffset = 124;
constexpr size_t kChecksumOffset = 148;
constexpr size_t kTypeOffset = 156;
constexpr size_t kPrefixOffset = 345;

// A path longer than this is not a path, it is an attempt to make the scanner
// allocate. Real ones stop at 4096 on every filesystem that matters.
constexpr uint64_t kMaxNameBytes = 64 * 1024;

std::string_view field(std::string_view block, size_t offset, size_t size) {
    std::string_view raw = block.substr(offset, size);
    const size_t end = raw.find('\0');
    return end == std::string_view::npos ? raw : raw.substr(0, end);
}

// tar numbers are octal ASCII, except that GNU writes large values as base-256
// with the top bit of the first byte set.
uint64_t parseNumeric(std::string_view block, size_t offset, size_t size) {
    const auto* bytes = reinterpret_cast<const unsigned char*>(block.data() + offset);

    if (bytes[0] & 0x80) {
        uint64_t value = static_cast<uint64_t>(bytes[0] & 0x7f);
        for (size_t i = 1; i < size; ++i) {
            value = (value << 8) | bytes[i];
        }
        return value;
    }

    uint64_t value = 0;
    for (size_t i = 0; i < size; ++i) {
        const char c = block[offset + i];
        if (c == ' ' || c == '\0') {
            if (value > 0) break;
            continue;
        }
        if (c < '0' || c > '7') return value;
        value = value * 8 + static_cast<uint64_t>(c - '0');
    }
    return value;
}

// The header checksum is computed with the checksum field itself read as eight
// spaces. Historic tars disagreed on whether the bytes are signed, so both sums
// are accepted - which is what every tar implementation does.
bool checksumOk(std::string_view block) {
    const uint64_t stored = parseNumeric(block, kChecksumOffset, 8);

    uint64_t unsignedSum = 0;
    int64_t signedSum = 0;
    for (size_t i = 0; i < kBlock; ++i) {
        const bool inChecksum = i >= kChecksumOffset && i < kChecksumOffset + 8;
        const unsigned char c = inChecksum
            ? static_cast<unsigned char>(' ')
            : static_cast<unsigned char>(block[i]);
        unsignedSum += c;
        signedSum += static_cast<signed char>(c);
    }

    return stored == unsignedSum || static_cast<int64_t>(stored) == signedSum;
}

bool isZeroBlock(std::string_view block) {
    for (char c : block) {
        if (c != '\0') return false;
    }
    return true;
}

// A pax extended header is a sequence of "<len> <key>=<value>\n" records. Only
// `path` matters here - it is how GNU tar and bsdtar carry names too long for the
// 100-byte field, which is most of a deeply nested site backup.
std::string paxPath(std::string_view data) {
    size_t pos = 0;
    while (pos < data.size()) {
        size_t space = data.find(' ', pos);
        if (space == std::string_view::npos) break;

        uint64_t len = 0;
        for (size_t i = pos; i < space; ++i) {
            if (data[i] < '0' || data[i] > '9') return {};
            len = len * 10 + static_cast<uint64_t>(data[i] - '0');
        }
        if (len == 0 || pos + len > data.size()) break;

        std::string_view record = data.substr(space + 1, pos + len - space - 2);
        if (record.starts_with("path=")) {
            return std::string(record.substr(5));
        }
        pos += static_cast<size_t>(len);
    }
    return {};
}

}  // namespace

bool looksLikeTarBlock(std::string_view block) {
    if (block.size() < kMagicOffset + 5) return false;
    const std::string_view magic = block.substr(kMagicOffset, 5);
    return magic == "ustar";
}

bool TarReader::pull(std::string* out, uint64_t n) {
    char scratch[64 * 1024];

    uint64_t left = n;
    while (left > 0) {
        if (const auto reason = budget_.spent()) {
            stopped_ = reason;
            return false;
        }

        const size_t want = static_cast<size_t>(
            left < sizeof(scratch) ? left : sizeof(scratch));
        const size_t got = source_.read(scratch, want);
        if (got == 0) {
            corrupt_ = corrupt_ || source_.failed();
            return false;
        }

        chargeBudget(got);
        if (out) out->append(scratch, got);
        left -= got;
    }
    return true;
}

bool TarReader::readBlock(char* block) {
    if (const auto reason = budget_.spent()) {
        stopped_ = reason;
        return false;
    }
    const size_t got = source_.readFully(block, kBlock);
    if (got == 0) {
        return false;
    }
    if (got < kBlock) {
        corrupt_ = true;
        return false;
    }
    chargeBudget(kBlock);
    return true;
}

// Both halves of the compression-ratio guard, taken from the same place every
// time: bytes handed out by the source, and bytes the source pulled from the
// stream underneath it. For a .tar.gz the second is compressed input, which is
// what makes the ratio real rather than notional.
void TarReader::chargeBudget(uint64_t produced) {
    budget_.addExpanded(produced);
    const uint64_t consumed = source_.consumed();
    if (consumed > lastConsumed_) {
        budget_.addConsumed(consumed - lastConsumed_);
        lastConsumed_ = consumed;
    }
}

bool TarReader::finishMember() {
    const uint64_t left = remaining_ + padding_;
    remaining_ = 0;
    padding_ = 0;
    if (left == 0) return true;
    return pull(nullptr, left);
}

bool TarReader::next(Entry& out) {
    if (ended_ || corrupt_ || stopped_) return false;
    if (!finishMember()) {
        // A stream that ends inside a member is truncated, not finished.
        if (!stopped_) corrupt_ = true;
        return false;
    }

    std::string pendingName;   // set by a GNU 'L' or pax 'x' header
    char block[kBlock];

    // Extended headers precede the member they describe, so this loop runs until
    // it reaches a real entry. The bound is not a style choice: without it a
    // crafted archive of nothing but extended headers is an endless loop.
    for (int header = 0; header < 16; ++header) {
        if (!readBlock(block)) {
            ended_ = true;
            return false;
        }

        std::string_view view(block, kBlock);
        if (isZeroBlock(view)) {
            ended_ = true;
            return false;
        }
        if (!checksumOk(view)) {
            corrupt_ = true;
            return false;
        }

        const uint64_t size = parseNumeric(view, kSizeOffset, 12);
        const char type = block[kTypeOffset];
        const uint64_t padded = (size % kBlock == 0) ? 0 : kBlock - (size % kBlock);

        // GNU long name / long link, and pax extended headers: the data block
        // holds the real name of the entry that follows.
        if (type == 'L' || type == 'K' || type == 'x' || type == 'X') {
            std::string data;
            if (size > kMaxNameBytes) {
                corrupt_ = true;
                return false;
            }
            if (!pull(&data, size) || !pull(nullptr, padded)) {
                if (!stopped_) corrupt_ = true;
                return false;
            }
            if (type == 'L') {
                const size_t nul = data.find('\0');
                pendingName = nul == std::string::npos ? data : data.substr(0, nul);
            } else if (type == 'x' || type == 'X') {
                auto path = paxPath(data);
                if (!path.empty()) pendingName = std::move(path);
            }
            continue;
        }

        // 'g' is a global pax header: it applies to the rest of the archive and
        // carries nothing this scanner uses.
        if (type == 'g') {
            if (!pull(nullptr, size) || !pull(nullptr, padded)) {
                if (!stopped_) corrupt_ = true;
                return false;
            }
            continue;
        }

        std::string name;
        if (!pendingName.empty()) {
            name = std::move(pendingName);
        } else {
            const std::string_view prefix = field(view, kPrefixOffset, 155);
            const std::string_view base = field(view, 0, 100);
            name = prefix.empty() ? std::string(base)
                                  : std::string(prefix) + "/" + std::string(base);
        }

        out.name = std::move(name);
        out.size = size;
        out.compressedSize = 0;   // a tar member is stored, not compressed
        out.directory = (type == '5') || (!out.name.empty() && out.name.back() == '/');

        remaining_ = size;
        padding_ = padded;

        // Links, devices, fifos and directories carry no content worth scanning,
        // but their (zero) data still has to be stepped over.
        return true;
    }

    corrupt_ = true;
    return false;
}

bool TarReader::readCurrent(std::string& out, uint64_t maxBytes) {
    if (remaining_ == 0) {
        out.clear();
        return true;
    }
    if (maxBytes > 0 && remaining_ > maxBytes) {
        return false;   // left for finishMember() to step over
    }

    out.clear();
    out.reserve(static_cast<size_t>(remaining_));

    const uint64_t want = remaining_;
    remaining_ = 0;
    if (!pull(&out, want)) {
        padding_ = 0;
        if (!stopped_) corrupt_ = true;
        return false;
    }
    return true;
}

}  // namespace lyxbosa::archive
