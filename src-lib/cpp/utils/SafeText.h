#pragma once

// SafeText.h - Rendering untrusted bytes without handing the terminal to them.
//
// Findings quote the file that was scanned, and that file is malware. In one
// real-world corpus 122 samples carried raw ESC bytes. Echoed straight to a
// terminal those
// are not text, they are commands: a file containing "\033[c" makes the terminal
// answer with its device attributes, and the answer lands on *stdin* - which is
// how a finished scan prints
//
//     ^[[?61;4;6;7;14;21;22;23;24;28;32;42;52c
//
// and leaves "61;4;...c" typed at the next shell prompt. The same channel carries
// worse: OSC 52 writes the analyst's clipboard, OSC 0 rewrites the window title,
// and some terminals can be driven into echoing text back as input.
//
// Truncation makes it easier, not harder: cutting a quote at a fixed byte length
// can leave a dangling "\033[" whose sequence is completed by whatever gets
// printed next.
//
// So every quoted byte is escaped before it reaches an output stream. Bytes >= 0x80
// are deliberately left alone: that is what UTF-8 is made of, and mangling it would
// wreck every finding quoted from a file with Greek, Japanese or Cyrillic in it.
// A terminal in a UTF-8 locale does not act on lone C1 bytes.

#include <string>
#include <string_view>

namespace lyxbosa::safe_text {

// Escape C0 controls and DEL as \xNN, leaving printable ASCII and UTF-8 intact.
inline std::string sanitize(std::string_view in) {
    static constexpr char kHex[] = "0123456789abcdef";

    std::string out;
    out.reserve(in.size());

    for (unsigned char c : in) {
        if (c < 0x20 || c == 0x7f) {
            out += "\\x";
            out += kHex[(c >> 4) & 0xf];
            out += kHex[c & 0xf];
        } else {
            out += static_cast<char>(c);
        }
    }

    return out;
}

// True if the value carries anything that must not reach a terminal raw. Lets
// callers skip the copy on the overwhelmingly common clean path.
inline bool needsSanitizing(std::string_view in) {
    for (unsigned char c : in) {
        if (c < 0x20 || c == 0x7f) {
            return true;
        }
    }
    return false;
}

// Sanitize, then cut to `limit` bytes without splitting a UTF-8 sequence or an
// escape we just wrote. Appends an ellipsis when it cuts.
inline std::string sanitizeAndTruncate(std::string_view in, size_t limit) {
    std::string out = sanitize(in);
    if (out.size() <= limit) {
        return out;
    }

    size_t cut = limit;
    // Do not leave half a UTF-8 character behind.
    while (cut > 0 && (static_cast<unsigned char>(out[cut]) & 0xc0) == 0x80) {
        --cut;
    }
    // Do not leave half a "\xNN" behind either.
    size_t backslash = out.find_last_of('\\', cut);
    if (backslash != std::string::npos && cut - backslash < 4) {
        cut = backslash;
    }

    out.resize(cut);
    out += "...";
    return out;
}

}  // namespace lyxbosa::safe_text
