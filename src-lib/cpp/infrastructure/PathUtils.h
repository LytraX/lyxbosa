#pragma once

#include "utils/SafeText.h"

#include <cstdio>
#include <string>
#include <string_view>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#endif

namespace lyxbosa {

// A path and UTF-8 text, in both directions, and why neither goes through the code page.
//
// Every std::string in this program that holds a path holds UTF-8: a root from the command
// line or the configuration file, an archive member's name, a report's address for a
// member. On Windows a path is UTF-16, and std::filesystem converts between the two in the
// host's ANSI code page - 1252 on a Western host, 1253 on a Greek one - which is wrong in
// both directions and wrong differently:
//
//   path::string() THROWS std::system_error on a character the code page cannot hold. A
//   name somebody else chose - a Japanese file name on a Greek host, U+009B anywhere -
//   escaped the walk as an exception and the scan aborted after writing the first ten
//   bytes of its report.
//
//   path(std::string) never throws and decodes the wrong encoding. A member named with
//   a Greek alpha was reported as two characters of mojibake, and a root written in UTF-8
//   in a YAML file named a directory that does not exist.
//
// So nothing here calls either one. pathToUtf8() and pathFromUtf8() convert through
// WideCharToMultiByte and MultiByteToWideChar with CP_UTF8, and each is the other's
// inverse: pathFromUtf8(pathToUtf8(p)) == p for a name that is valid UTF-16, and
// pathToUtf8(pathFromUtf8(s)) == s for a string that is valid UTF-8.
// tests/path_encoding_test.cpp asserts both, against native wide spellings rather than
// against each other - two functions that both used the code page would round-trip
// every name the code page holds.
//
// Elsewhere a path is bytes, both are the identity, and a name that is not UTF-8 goes
// through unchanged for pathForDisplay() to escape.

#ifdef _WIN32
// UTF-16 as UTF-8. An unpaired surrogate becomes U+FFFD. The conversion cannot otherwise fail
// for a string a path or a command line can hold, and if it somehow did the answer is empty
// rather than anything that goes through the code page.
inline std::string utf8FromWide(std::wstring_view wide) {
    if (wide.empty()) return "";

    const int size = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) return "";

    std::string utf8(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), utf8.data(),
                        size, nullptr, nullptr);
    return utf8;
}
#endif

// The path as UTF-8, for every reader that is not a terminal: a rule matching on a name, a
// glob from the configuration, a key a report is built from.
//
// On Windows an unpaired surrogate - which NTFS accepts in a name - becomes U+FFFD, so that
// name is the one shape this cannot round-trip; see pathBytesHex().
inline std::string pathToUtf8(const std::filesystem::path& p) {
#ifdef _WIN32
    return utf8FromWide(p.native());
#else
    return p.native();
#endif
}

// The path a UTF-8 string names: the inverse of pathToUtf8().
//
// Use it wherever a std::string becomes a path, including the implicit conversions - a
// std::string passed to a parameter of type `const std::filesystem::path&` is decoded in the
// code page exactly as an explicit constructor is.
//
// On Windows an ill-formed sequence becomes U+FFFD, because UTF-16 has no way to carry the
// bytes. The only strings that can be ill-formed here are a tar member's name, which is
// whatever bytes its header holds, and a configuration value somebody wrote that way; the
// name rules read a member's bytes before this is reached, so what is lost is the report's
// spelling of the address and not a finding. Elsewhere the bytes are the path.
inline std::filesystem::path pathFromUtf8(std::string_view utf8) {
#ifdef _WIN32
    if (utf8.empty()) return {};

    const int size = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()),
                                         nullptr, 0);
    if (size <= 0) return {};

    std::wstring wide(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), wide.data(),
                        size);
    return std::filesystem::path(std::move(wide));
#else
    return std::filesystem::path(std::string(utf8));
#endif
}

// A C stream on a path, opened by the path's native name. std::fopen() takes a narrow name,
// which Windows reads in the ANSI code page, so a caller holding a path had to spell it with
// path::string() - and that throws for a directory the code page cannot hold. `mode` is the
// fopen() mode string, and is ASCII.
inline std::FILE* openPathForStdio(const std::filesystem::path& p, const char* mode) {
#ifdef _WIN32
    const std::wstring wideMode(mode, mode + std::char_traits<char>::length(mode));
    return _wfopen(p.c_str(), wideMode.c_str());
#else
    return std::fopen(p.c_str(), mode);
#endif
}

// Path rendered for a human. A directory or file name is attacker-controlled on a
// compromised host and can carry ESC just as file *content* can, so anything headed
// for a terminal, a report or a progress line goes through here. Scanner keeps the
// raw pathToUtf8 - the context filters match on real path text.
inline std::string pathForDisplay(const std::filesystem::path& p) {
    std::string utf8 = pathToUtf8(p);
    return safe_text::needsSanitizing(utf8) ? safe_text::sanitize(utf8) : utf8;
}

// True when pathForDisplay() could not render this path without losing something - a
// control byte, DEL, or a byte outside well-formed UTF-8. Exactly the condition under
// which the escape above is one-way, and therefore exactly when a machine-readable
// report owes its reader the bytes as well as the rendering.
inline bool pathDisplayIsLossy(const std::filesystem::path& p) {
    return safe_text::needsSanitizing(pathToUtf8(p));
}

// The path's bytes, lowercase hex, no separators.
//
// WHY A SECOND REPRESENTATION EXISTS AT ALL. The escape pathForDisplay() writes is for a
// terminal, and a terminal is the one consumer that cannot be given the bytes: a name
// carrying ESC is not text there, it is commands - OSC 52 writes the analyst's clipboard
// on the way past. So the rendering is escaped and one-way, and a person reading it goes
// and looks at the directory.
//
// A log file, a CSV loaded into a spreadsheet and a JSON document loaded into a database
// have no such problem and the opposite need: nobody is there to go and look, and the
// row IS the record. They must be able to reconstruct the name exactly - to open the
// file, to match it against an earlier inventory, to hand it to a delete that has to hit
// the right file and no other. The rendering cannot give them that, because a backslash
// already in the name is written through unchanged and `a\x0ab` on disk renders the same
// as `a`, a newline, `b`.
//
// Hex rather than a reversible escape. The alternative was to double every backslash,
// which would make the rendering reversible and would also rewrite every path in every
// report produced on Windows, where the separator IS a backslash - a break for every
// existing consumer, to pay for a case that is rare. Hex is additive, has no escaping
// rules of its own to get wrong, and is what a loader wants anyway.
//
// Emitted only when pathDisplayIsLossy() says the rendering lost something, so an
// ordinary report carries nothing new. On Windows this is the UTF-8 conversion of the
// native wide path, which is what every other reader of that path already sees; an
// unpaired surrogate in a name is converted before it reaches here and is the one shape
// this cannot round-trip.
inline std::string pathBytesHex(const std::filesystem::path& p) {
    static constexpr char kHex[] = "0123456789abcdef";
    const std::string utf8 = pathToUtf8(p);
    std::string out;
    out.reserve(utf8.size() * 2);
    for (unsigned char c : utf8) {
        out += kHex[(c >> 4) & 0xf];
        out += kHex[c & 0xf];
    }
    return out;
}

}  // namespace lyxbosa
