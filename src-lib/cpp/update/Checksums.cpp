#include "update/Checksums.h"

#include <fmt/format.h>

#include <array>
#include <cstdio>

#ifdef LYXBOSA_UPDATE_VERIFY
#include <openssl/evp.h>
#endif

namespace lyxbosa {

namespace {

bool isLowerHex(std::string_view s) {
    for (const char c : s) {
        const bool digit = c >= '0' && c <= '9';
        const bool letter = c >= 'a' && c <= 'f';
        if (!digit && !letter) return false;
    }
    return true;
}

char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

}  // namespace

const ChecksumEntry* ChecksumList::find(std::string_view name) const {
    for (const auto& entry : entries) {
        if (entry.name == name) return &entry;
    }
    return nullptr;
}

ChecksumList parseChecksumList(std::string_view text) {
    ChecksumList out;
    size_t lineNumber = 0;
    size_t start = 0;

    while (start <= text.size()) {
        const size_t nl = text.find('\n', start);
        std::string_view line =
            nl == std::string_view::npos ? text.substr(start) : text.substr(start, nl - start);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        ++lineNumber;

        const bool last = nl == std::string_view::npos;
        start = last ? text.size() + 1 : nl + 1;

        if (line.empty()) {
            if (last) break;
            continue;  // a trailing newline, or a blank line between records
        }

        // `<64 hex><two spaces><name>`. sha256sum's binary form writes `hash *name`;
        // release-checksums.sh writes the text form and its controls assert the exact
        // bytes, so the two-space form is the only one a release produces.
        if (line.size() < 67 || line.substr(64, 2) != "  ") {
            out.entries.clear();
            out.error = fmt::format("line {}: not '<64 hex><two spaces><name>'", lineNumber);
            return out;
        }
        const std::string_view hash = line.substr(0, 64);
        const std::string_view name = line.substr(66);

        if (!isLowerHex(hash)) {
            out.entries.clear();
            out.error = fmt::format("line {}: the digest is not 64 lowercase hex digits",
                                    lineNumber);
            return out;
        }
        // Bare names, which is the property that lets a consumer run `sha256sum -c` in
        // their download directory - release-checksums.sh asserts it on every release,
        // separately from the bytes, for exactly that reason. Refusing a path here also
        // means a list can never name a file outside the directory being verified.
        if (name.find('/') != std::string_view::npos ||
            name.find('\\') != std::string_view::npos || name == "." || name == "..") {
            out.entries.clear();
            out.error = fmt::format("line {}: the name is a path rather than a bare name",
                                    lineNumber);
            return out;
        }

        out.entries.push_back(ChecksumEntry{std::string(hash), std::string(name)});
        if (last) break;
    }

    if (out.entries.empty() && out.error.empty()) {
        // An empty list passes `sha256sum -c` - zero lines, zero failures - which is
        // the "no findings reads as green" shape release-checksums.sh already refuses
        // to write. It is refused here too, one level out.
        out.error = "the list is empty";
    }
    return out;
}

std::optional<std::string> sha256File(const std::filesystem::path& path) {
#ifndef LYXBOSA_UPDATE_VERIFY
    (void)path;
    return std::nullopt;
#else
    std::FILE* file = std::fopen(path.string().c_str(), "rb");
    if (file == nullptr) return std::nullopt;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        std::fclose(file);
        return std::nullopt;
    }

    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1;
    std::array<unsigned char, 64 * 1024> buffer{};
    while (ok) {
        const size_t read = std::fread(buffer.data(), 1, buffer.size(), file);
        if (read > 0 && EVP_DigestUpdate(ctx, buffer.data(), read) != 1) {
            ok = false;
            break;
        }
        if (read < buffer.size()) {
            // A short read is either the end of the file or an error, and they are not
            // the same thing: hashing the prefix of a file that failed to read would
            // produce a digest of something nobody asked about.
            if (std::ferror(file) != 0) ok = false;
            break;
        }
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digestLen = 0;
    if (ok) ok = EVP_DigestFinal_ex(ctx, digest.data(), &digestLen) == 1;

    EVP_MD_CTX_free(ctx);
    std::fclose(file);

    if (!ok || digestLen != 32) return std::nullopt;

    std::string hex;
    hex.reserve(64);
    for (unsigned int i = 0; i < digestLen; ++i) {
        fmt::format_to(std::back_inserter(hex), "{:02x}", digest[i]);
    }
    return hex;
#endif
}

bool hashesEqual(std::string_view a, std::string_view b) {
    if (a.size() != b.size() || a.empty()) return false;
    unsigned char difference = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        difference |= static_cast<unsigned char>(lower(a[i]) ^ lower(b[i]));
    }
    return difference == 0;
}

}  // namespace lyxbosa
