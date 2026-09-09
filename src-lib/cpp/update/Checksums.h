#pragma once

// Checksums.h - the SHA256SUMS list, and hashing a file against it.
//
// THE ORDER IS THE GUARD, AND THIS FILE IS THE SECOND HALF OF IT
// ---------------------------------------------------------------
// A hash checked against an UNVERIFIED list defends against a corrupted transfer and
// nothing else, because whoever can rewrite the asset can rewrite the list published
// beside it. keys/minisign-trusted.txt and docs/RELEASING.md both say so, and it is why
// nothing here has an entry point that takes a URL: this parses text a caller has
// already had verified, and UpdateApply is the one place that decides the order.
//
// The format is exactly what `sha256sum` writes and `.github/scripts/release-checksums.sh`
// pins: `<64 hex>  <name>`, two spaces, bare names, one per line, in byte order. That
// script's own controls assert those properties on every release, so this parser can
// afford to refuse anything else rather than guess.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace lyxbosa {

struct ChecksumEntry {
    std::string hash;  // lowercase hex, 64 characters
    std::string name;  // a bare name; never a path
};

struct ChecksumList {
    std::vector<ChecksumEntry> entries;
    std::string error;  // empty when the whole text parsed
    bool ok() const { return error.empty(); }

    // The entry for `name`, or nullptr. An exact match on the whole name: a list that
    // mentions `lyxbosa-linux-amd64.sig` does not answer for `lyxbosa-linux-amd64`.
    const ChecksumEntry* find(std::string_view name) const;
};

// Parse a SHA256SUMS file. A malformed line is an error rather than a skipped line:
// skipping is how a list that describes something else reads as a list that simply does
// not mention this asset, and those two must not become the same answer.
ChecksumList parseChecksumList(std::string_view text);

// SHA-256 of a file, as lowercase hex. Nullopt when the file cannot be read or this
// build has no digest - the caller must treat both as "cannot verify", never as "no
// mismatch found".
std::optional<std::string> sha256File(const std::filesystem::path& path);

// Constant-time-ish equality over two hex digests, case-insensitive on the input.
// Nothing here is secret, so this is about being total rather than about timing: two
// digests of different lengths must compare unequal instead of throwing.
bool hashesEqual(std::string_view a, std::string_view b);

}  // namespace lyxbosa
