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
// So every quoted byte is escaped before it reaches an output stream.
//
// WELL-FORMED UTF-8 IS LEFT ALONE AND NOTHING ELSE IS. That distinction is the whole
// of this file. A file name or a match excerpt full of Greek, Japanese or Cyrillic
// must come through untouched, so a valid multi-byte sequence is copied verbatim; a
// terminal in a UTF-8 locale does not act on the bytes inside one. But a byte that is
// not part of a well-formed sequence is not text in any encoding the report claims to
// be in, and writing it through raw is what made a JSON document that a standard
// parser refuses outright - the escaper answering the two halves of one question
// differently. Linux accepts any byte but NUL and `/` in a name, so `0xC0 0xAF` - the
// overlong UTF-8 slash, which is exactly what somebody aiming at a normaliser
// downstream would choose - is one `touch` away on any host this tool runs on.
//
// Overlong forms, surrogates and anything past U+10FFFF are rejected along with
// structural breakage, and rejecting the overlongs is not pedantry here: `C0 AF`
// decodes to `/` in a decoder that accepts it, and a scanner that silently passed it
// on as text would be laundering the one byte that a path is defined by.
//
// THE ESCAPE IS ONE-WAY, AND THAT IS A DECISION RATHER THAN AN OVERSIGHT. A backslash
// already in the input is written through unchanged, so a file whose name really is
// the six characters `a\x0ab` renders identically to one whose name is `a`, a newline
// and `b`. Doubling the backslash would fix that and would also rewrite every path in
// every report produced on Windows, where the separator IS a backslash, in exchange
// for an ambiguity that has a one-command answer at the other end: the report names
// the directory, and a listing of it distinguishes the two candidates immediately. So
// a consumer may NOT reconstruct the original bytes from this string, and no consumer
// should be written that tries - the value is for a person to read and for a person to
// go and look with. docs/SCANNING.md says so where an integrator will see it.

#include <string>
#include <string_view>

namespace lyxbosa::safe_text {

namespace detail {

// Length of the well-formed UTF-8 sequence starting at `in[i]`, or 0 if there is not
// one. The ranges are the ones the standard actually permits, not merely the lead-byte
// shape: C0 and C1 can only ever begin an overlong two-byte form, E0 must be followed
// by A0..BF, ED must not reach into the surrogate block, F0 must be followed by 90..BF
// and F4 must stop at U+10FFFF.
inline size_t sequenceLength(std::string_view in, size_t i) {
    const auto byteAt = [&](size_t k) { return static_cast<unsigned char>(in[k]); };
    const size_t left = in.size() - i;
    const unsigned char c = byteAt(i);

    const auto cont = [&](size_t k, unsigned char lo, unsigned char hi) {
        return k < in.size() && byteAt(k) >= lo && byteAt(k) <= hi;
    };

    if (c < 0x80) return 1;
    if (c < 0xc2) return 0;                       // continuation byte, or an overlong lead
    if (c <= 0xdf) {
        return (left >= 2 && cont(i + 1, 0x80, 0xbf)) ? 2 : 0;
    }
    if (c <= 0xef) {
        if (left < 3) return 0;
        const unsigned char lo = (c == 0xe0) ? 0xa0 : 0x80;
        const unsigned char hi = (c == 0xed) ? 0x9f : 0xbf;
        return (cont(i + 1, lo, hi) && cont(i + 2, 0x80, 0xbf)) ? 3 : 0;
    }
    if (c <= 0xf4) {
        if (left < 4) return 0;
        const unsigned char lo = (c == 0xf0) ? 0x90 : 0x80;
        const unsigned char hi = (c == 0xf4) ? 0x8f : 0xbf;
        return (cont(i + 1, lo, hi) && cont(i + 2, 0x80, 0xbf) && cont(i + 3, 0x80, 0xbf))
                   ? 4 : 0;
    }
    return 0;
}

}  // namespace detail

// Escape C0 controls, DEL and every byte that is not part of well-formed UTF-8 as
// \xNN. Printable ASCII and valid UTF-8 pass through untouched.
inline std::string sanitize(std::string_view in) {
    static constexpr char kHex[] = "0123456789abcdef";

    std::string out;
    out.reserve(in.size());

    const auto escape = [&out](unsigned char c) {
        out += "\\x";
        out += kHex[(c >> 4) & 0xf];
        out += kHex[c & 0xf];
    };

    size_t i = 0;
    while (i < in.size()) {
        const auto c = static_cast<unsigned char>(in[i]);
        if (c < 0x20 || c == 0x7f) {
            escape(c);
            ++i;
            continue;
        }
        if (c < 0x80) {
            out += in[i];
            ++i;
            continue;
        }
        const size_t len = detail::sequenceLength(in, i);
        if (len == 0) {
            // One byte at a time, then re-examine from the next: a valid sequence may
            // begin immediately after a stray byte, and consuming more than the byte
            // that is actually wrong would swallow it.
            escape(c);
            ++i;
            continue;
        }
        out.append(in, i, len);
        i += len;
    }

    return out;
}

// True when every byte of `in` belongs to a well-formed UTF-8 sequence.
//
// A different question from needsSanitizing() below, and the two are easy to confuse
// to a test's cost: a JSON report is full of newlines, so needsSanitizing() says yes
// about every document ever written and says nothing at all about whether a parser
// will accept it. This is the one to ask of an output stream.
inline bool isValidUtf8(std::string_view in) {
    size_t i = 0;
    while (i < in.size()) {
        const size_t len = detail::sequenceLength(in, i);
        if (len == 0) {
            return false;
        }
        i += len;
    }
    return true;
}

// True if the value carries anything that must not reach a terminal raw - a control
// byte, DEL, or a byte outside well-formed UTF-8. Lets callers skip the copy on the
// overwhelmingly common clean path, and it has to agree with sanitize() exactly: a
// cheaper test that only looked for control bytes is what let invalid UTF-8 past, and
// the two answering the same question differently was the defect rather than a
// symptom of it.
inline bool needsSanitizing(std::string_view in) {
    size_t i = 0;
    while (i < in.size()) {
        const auto c = static_cast<unsigned char>(in[i]);
        if (c < 0x20 || c == 0x7f) {
            return true;
        }
        if (c < 0x80) {
            ++i;
            continue;
        }
        const size_t len = detail::sequenceLength(in, i);
        if (len == 0) {
            return true;
        }
        i += len;
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
