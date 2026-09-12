#pragma once

#include "utils/SafeText.h"

#include <string>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#endif

namespace lyxbosa {

// Convert a filesystem path to a UTF-8 encoded string safe for console output.
// On Windows, path::string() uses the ANSI code page which can cause crashes
// when fmt::print sends non-UTF-8 bytes to WriteConsoleW on the Windows Console.
// Path rendered for a human. A directory or file name is attacker-controlled on a
// compromised host and can carry ESC just as file *content* can, so anything headed
// for a terminal, a report or a progress line goes through here. Scanner keeps the
// raw pathToUtf8 - the context filters match on real path text.
inline std::string pathForDisplay(const std::filesystem::path& p);

inline std::string pathToUtf8(const std::filesystem::path& p) {
#ifdef _WIN32
    const auto& ws = p.native();  // Returns const wstring& on Windows
    if (ws.empty()) return "";

    int size = WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()),
                                   nullptr, 0, nullptr, nullptr);
    if (size <= 0) return p.string();  // Fallback

    std::string utf8(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()),
                        utf8.data(), size, nullptr, nullptr);
    return utf8;
#else
    return p.string();  // Already UTF-8 on Linux/macOS
#endif
}

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
