#pragma once

// ArchiveFormat.h - What a file actually is, decided by its bytes.
//
// Never by its extension. Incident response has recovered working webshells from
// files named .jpeg, .tif and .ico, and the same indifference to naming applies
// in reverse: a site backup renamed backup.dat is still a site backup, and a
// .zip that is really a JPEG must not be handed to a zip parser.

#include "ArchiveTypes.h"

#include <filesystem>
#include <string_view>

namespace lyxbosa::archive {

// Enough bytes for the tar magic at offset 257 plus room for a gzip header.
constexpr size_t kSniffBytes = 1024;

// Container magic only. Returns Kind::Gzip for any gzip stream: telling a .tar.gz
// from a plain .gz costs 512 inflated bytes, which sniff() spends and this does
// not.
Kind sniffMagic(std::string_view head);

// The full answer, including inflating a gzip header far enough to see whether a
// tar block sits behind it.
Kind sniff(std::string_view content);

// Same, reading only the head of a file - the path taken for archives too large
// to hold in memory, where the whole point is not to read the file.
Kind sniffFile(const std::filesystem::path& path);

// A name that suggests a container, used only to decide whether the concurrent
// pre-count should spend an open() reading a file's index. Getting it wrong costs
// an approximate total, never a missed member: the scan sniffs the bytes of every
// file it reaches regardless of what the file is called.
bool hasArchiveExtension(const std::filesystem::path& path);

// The name a single gzipped file should be reported under: "dump.sql.gz" holds
// "dump.sql".
std::string gzipMemberName(const std::filesystem::path& path);

}  // namespace lyxbosa::archive
