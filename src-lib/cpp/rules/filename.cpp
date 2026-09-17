#include "filename.h"

#include "utils/SafeText.h"

#include <algorithm>
#include <array>
#include <optional>

namespace lyxbosa::rules::filename {

// The FN rules are about a name, not about bytes, so they carry no patterns and the
// match engine never runs them against file content - exactly like the ARC rules
// beside them. They are in the registry so that they are named, described, listed and
// disabled like every other rule: `builtin_rules.disable: [FN004]` has to mean
// something, and an operator reading a report needs FN001 to resolve to a sentence.

// FN001: a command substitution in a file name.
//
// `$(...)`, a backtick pair and `${...}` are not characters that happen to be awkward
// to quote - they are the three ways a shell is told to run something and paste the
// output in. There is no accident that produces one in an upload. 37 of the 83
// observed names carry one, and their contents are `id`, `sleep 8`, `sleep 20` and
// `echo CANARY9182 > lficanary9182.txt`: a scanner timing a command and writing a
// canary, which is what a person would do next.
//
// High and not Critical. The payload is live but it is not running: it fires only if
// something downstream hands the name to a shell, and the file's own bytes may be a
// perfectly ordinary database. Critical in this tool means the host is compromised
// now.
const BuiltinRule FN001 {
    .code = {Category::Filename, 1},
    .name = "Command substitution in a file name",
    .description = "File name contains $(...), `...` or ${...}, which a shell would execute",
    .severity = Severity::High,
    .patterns = {},
};

// FN002: a shell metacharacter in a file name.
//
// A double quote, a semicolon, a pipe or a backslash end an argument, end a command or
// escape the next character. Alone, each is a step short of FN001: the intent to break
// out of a quoted argument is legible, but nothing says what would have been run. 37
// of the 83 carry one without a substitution - `a;b.mdb`, `a|id.mdb`, `x" ; id ; ".mdb`.
//
// Medium. An operator looks at it; it does not reorder their day.
const BuiltinRule FN002 {
    .code = {Category::Filename, 2},
    .name = "Shell metacharacter in a file name",
    .description = "File name contains a quote, semicolon, pipe or backslash that would "
                   "end an argument or a command in a shell",
    .severity = Severity::Medium,
    .patterns = {},
};

// FN003: a control character in a file name.
//
// A newline in a name splits one line of a log, of `find` output and of a report into
// two, and the second half is whatever the attacker wrote after it. The harm is
// downstream parsing rather than execution, which is why this is Medium rather than
// High - and it is the one rule here with a plausible innocent origin, a broken
// uploader that wrote a raw byte into a name it built from a form field.
//
// Below 0x20 and nothing else, because that is what was measured. DEL at 0x7f is the
// same class of byte and fired on nothing in either direction, so it is left out
// rather than added on the strength of an argument.
const BuiltinRule FN003 {
    .code = {Category::Filename, 3},
    .name = "Control character in a file name",
    .description = "File name contains a byte below 0x20, which splits a log line, a "
                   "report row or a pipeline reading names one per line",
    .severity = Severity::Medium,
    .patterns = {},
};

// FN004: a file name that a tool will read as an option.
//
// `--help-<id>.mdb` and `-<id>.htaccess` are four of the 83. The target is not a shell
// but every command that takes options before it takes paths: `rm *`, `tar *`,
// `grep pattern *` all expand the glob and hand the leading-dash name over as a flag.
//
// Medium, and the most likely of these rules to fire on something an operator wrote
// themselves - `-draft.txt` is a name a person types. The finding is still correct:
// the file is a hazard to the next glob run over that directory.
const BuiltinRule FN004 {
    .code = {Category::Filename, 4},
    .name = "File name starts with a dash",
    .description = "File name begins with '-', so a glob expansion hands it to the next "
                   "command as an option rather than a path",
    .severity = Severity::Medium,
    .patterns = {},
};

// FN005: a dot-dot beside a separator that is not a separator.
//
// Two of the 83, and they are the two worth reading closely. One spells its separators
// with U+FF0F FULLWIDTH SOLIDUS; the other with U+00C0 U+00AF, which is what the
// overlong UTF-8 slash `C0 AF` turns into when something on the way in decoded it as
// Latin-1 and re-encoded it. Neither is a separator, so neither traverses anything
// here. Both are aimed at something downstream that normalises before it validates -
// and the normalisation already happened once to produce the second one, which is the
// evidence that such a thing is in the path.
//
// The adjacency requirement is the whole precision of this rule. A bare dot-dot cannot
// traverse out of a name, because a name has no separators in it; what it can be is
// `photo_2_final..jpg`, which is one file in 268,853 real ones and not an attack.
// Requiring the dot-dot to sit against a would-be separator is the "in combination
// with something else" that a character this ordinary has to earn.
//
// High. Nobody writes `..／..／public／uploads／` into a file name by accident.
const BuiltinRule FN005 {
    .code = {Category::Filename, 5},
    .name = "Path traversal in a lookalike encoding",
    .description = "File name contains a dot-dot segment against a character that "
                   "resembles a path separator without being one",
    .severity = Severity::High,
    .patterns = {},
};

// FN006: a percent-encoded NUL in a file name.
//
// `x.php%00-<id>.mdb` is one of the two. The only purpose of `%00` in a name is to end
// a C string early in whatever decodes it, so that an extension check reads `.mdb` and
// the thing that opens the file reads `.php`. There is no second reading.
//
// High for that reason: unlike a semicolon, this construct has no innocent use at all.
const BuiltinRule FN006 {
    .code = {Category::Filename, 6},
    .name = "Percent-encoded NUL in a file name",
    .description = "File name contains %00, which truncates the name in anything that "
                   "percent-decodes it and lets a real extension hide behind a safe one",
    .severity = Severity::High,
    .patterns = {},
};

// FN007: a name that climbs out of the directory it is extracted into.
//
// A member is written to `<destination>/<name>`. A `..` component, or a name that begins at
// a root - a slash, a backslash, a drive letter and a colon - points that write outside the
// destination: over a web root's index.php, into whatever directory the server executes.
// Either separator counts, because the extractor decides what separates and the archive
// cannot: a Windows extractor splits `..\..\index.php` whatever the entry's host byte says,
// and a file on Linux NAMED `..\..\index.php` becomes exactly that member the moment a backup
// copies it. A loose file and a member with the same name answer the same.
//
// Measured against the extractors that write members to disk. Probe archives holding each
// shape, under host bytes 0 and 3 and in a tar, were extracted into a sandbox with PHP's
// ZipArchive::extractTo, PclZip, WordPress's unzip_file on both of its paths, Info-ZIP unzip,
// 7-Zip, Python, GNU tar and PharData on Linux, and with the PHP ones, Expand-Archive 5.1 and
// 7.6, bsdtar and Python on Windows. PclZip called directly, as plugins call it, wrote outside
// the destination: through `../` on Linux, and through `../` and `..\` on Windows, under
// either host byte. Every other extractor kept the file inside or refused it and said why -
// `Path contains '..'`, `Removing leading drive letter`, `Can not process invalid archive
// entry` - and WordPress's unzip_file turns backslashes into slashes and then skips both `..`
// spellings and a drive letter. So every shape here is one a hardened extractor treats as an
// escape, and the commonest one is followed by a library that is still called directly. A
// component of three or four dots is not one: it stayed inside, or failed, everywhere. Over
// the stock WordPress 7.1 tree, twelve widely installed plugins, seven backups of them and the
// 83 observed hostile names, the rule fired on nothing.
//
// High, like FN005, and for a stronger reason: nothing stores `..\` or a drive letter at the
// start of a name by accident, and this shape does its harm without a shell - the extractor
// writes the file where the name points.
const BuiltinRule FN007 {
    .code = {Category::Filename, 7},
    .name = "File name climbs out of its directory",
    .description = "File name holds a '..' component or starts at a root - '/', '\\' or a "
                   "drive letter - under either separator, so extracting it writes outside the "
                   "destination",
    .severity = Severity::High,
    .patterns = {},
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &FN001, &FN002, &FN003, &FN004, &FN005, &FN006, &FN007
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

namespace {

// Characters that a human, a log reader or a normaliser downstream may take for a path
// separator, and that the filesystem here does not. Two kinds, and both were observed:
//
//   - Unicode solidus lookalikes, spelled in UTF-8.
//   - The overlong UTF-8 slash `C0 AF` - invalid UTF-8, which is the point of it - and
//     `C3 80 C2 AF`, what `C0 AF` becomes after one round of decode-as-Latin-1 and
//     re-encode-as-UTF-8. The second is what arrived on the real server.
//   - Percent-encoded separators, for the same decoder FN006 is about.
//
// Not a real `/`: a POSIX name cannot hold one, and on Windows the split in
// finalComponent() has already removed it.
constexpr std::string_view kSeparatorLookalikes[] = {
    "\xEF\xBC\x8F",      // U+FF0F FULLWIDTH SOLIDUS
    "\xEF\xBC\xBC",      // U+FF3C FULLWIDTH REVERSE SOLIDUS
    "\xE2\x88\x95",      // U+2215 DIVISION SLASH
    "\xE2\x81\x84",      // U+2044 FRACTION SLASH
    "\xE2\xA7\xB8",      // U+29F8 BIG SOLIDUS
    "\xC0\xAF",          // overlong UTF-8 '/', raw
    "\xC3\x80\xC2\xAF",  // the same after one decode/re-encode round trip
    "%2f",
    "%5c",
};

// The name a lookalike goes by in a finding. An operator reading `%2f` knows what they
// are looking at; `\xef\xbc\x8f` would make them go and decode it.
std::string_view lookalikeName(std::string_view token) {
    if (token == "\xEF\xBC\x8F")     return "U+FF0F fullwidth solidus";
    if (token == "\xEF\xBC\xBC")     return "U+FF3C fullwidth reverse solidus";
    if (token == "\xE2\x88\x95")     return "U+2215 division slash";
    if (token == "\xE2\x81\x84")     return "U+2044 fraction slash";
    if (token == "\xE2\xA7\xB8")     return "U+29F8 big solidus";
    if (token == "\xC0\xAF")         return "overlong UTF-8 slash (c0 af)";
    if (token == "\xC3\x80\xC2\xAF") return "re-encoded overlong UTF-8 slash";
    if (token == "%2f")              return "percent-encoded slash";
    if (token == "%5c")              return "percent-encoded backslash";
    return "separator lookalike";
}

std::string toLowerAscii(std::string_view in) {
    std::string out(in);
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

bool endsWithDotDot(std::string_view s) {
    return s.size() >= 2 && s.substr(s.size() - 2) == ".." ;
}

bool endsWithEncodedDotDot(std::string_view s) {
    return s.size() >= 6 && s.substr(s.size() - 6) == "%2e%2e";
}

bool startsWithDotDot(std::string_view s) {
    return s.starts_with("..") || s.starts_with("%2e%2e");
}

// Whether `name`, split on `separator`, has a component that is exactly `..`.
bool hasDotDotComponent(std::string_view name, char separator) {
    size_t start = 0;
    while (true) {
        const size_t end = name.find(separator, start);
        const std::string_view component =
            name.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
        if (component == "..") return true;
        if (end == std::string_view::npos) return false;
        start = end + 1;
    }
}

// FN007's shapes, in the order a finding names the first one found.
std::optional<std::string_view> climbingShape(std::string_view name) {
    if (name.empty()) return std::nullopt;
    if (hasDotDotComponent(name, '/'))  return "a '..' component between slashes";
    if (hasDotDotComponent(name, '\\')) return "a '..' component between backslashes";
    if (name.front() == '/')            return "a leading slash";
    if (name.front() == '\\')           return "a leading backslash";
    const unsigned char first = static_cast<unsigned char>(name.front());
    if (name.size() >= 2 && name[1] == ':' &&
        ((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z'))) {
        return "a leading drive letter";
    }
    return std::nullopt;
}

// FN001 to FN006 over one final component.
std::vector<NameFinding> examineFinal(std::string_view name);

}  // namespace

std::string_view finalComponent(std::string_view pathUtf8) {
    size_t cut = pathUtf8.find_last_of('/');
#ifdef _WIN32
    const size_t back = pathUtf8.find_last_of('\\');
    if (back != std::string_view::npos && (cut == std::string_view::npos || back > cut)) {
        cut = back;
    }
#endif
    return cut == std::string_view::npos ? pathUtf8 : pathUtf8.substr(cut + 1);
}

std::string_view memberFinalComponent(std::string_view storedName, MemberSeparators separators) {
    const size_t cut = separators == MemberSeparators::SlashAndBackslash
                           ? storedName.find_last_of("/\\")
                           : storedName.find_last_of('/');
    return cut == std::string_view::npos ? storedName : storedName.substr(cut + 1);
}

std::vector<NameFinding> examine(std::string_view name) {
    std::vector<NameFinding> found = examineFinal(name);
    if (const auto shape = climbingShape(name)) {
        found.push_back({"FN007", std::string(*shape)});
    }
    return found;
}

std::vector<NameFinding> examineMember(std::string_view storedName, MemberSeparators separators) {
    std::vector<NameFinding> found = examineFinal(memberFinalComponent(storedName, separators));
    if (const auto shape = climbingShape(storedName)) {
        found.push_back({"FN007", std::string(*shape)});
    }
    return found;
}

namespace {

std::vector<NameFinding> examineFinal(std::string_view name) {
    std::vector<NameFinding> found;
    if (name.empty()) {
        return found;
    }

    // FN001 - command substitution.
    {
        std::string_view token;
        if (name.find("$(") != std::string_view::npos)      token = "$(";
        else if (name.find('`') != std::string_view::npos)  token = "`";
        else if (name.find("${") != std::string_view::npos) token = "${";
        if (!token.empty()) {
            found.push_back({"FN001", std::string(token)});
        }
    }

    // FN002 - a shell metacharacter. A bare `$` is deliberately not one of these; see
    // the header for the office lock file that made that decision.
    {
        static constexpr std::string_view kMeta = "\";|\\";
        const size_t at = name.find_first_of(kMeta);
        if (at != std::string_view::npos) {
            found.push_back({"FN002", std::string(1, name[at])});
        }
    }

    // FN003 - a control byte. Named as an escape rather than emitted raw: this detail
    // is printed, and the byte is the thing that would split the line it is printed on.
    for (unsigned char c : name) {
        if (c < 0x20) {
            found.push_back({"FN003", safe_text::sanitize(std::string_view(
                                          reinterpret_cast<const char*>(&c), 1))});
            break;
        }
    }

    // FN004 - a leading dash.
    if (name.front() == '-') {
        found.push_back({"FN004", "-"});
    }

    // The lowercase copy the last two rules need, built at most once and only when one
    // of them could possibly fire. examine() runs on every file the walk reaches - a
    // name costs no open, which is the whole reason these rules see files the content
    // rules never will - so the common path here is a name that raises nothing, and it
    // must not allocate. Every separator lookalike starts with `%` or a byte at 0x80 or
    // above, and `%00` needs the `%`; a name with neither cannot reach either rule.
    std::string lower;
    bool mayBeEncoded = false;
    for (unsigned char c : name) {
        if (c == '%' || c >= 0x80) {
            mayBeEncoded = true;
            break;
        }
    }
    if (mayBeEncoded) {
        lower = toLowerAscii(name);
    }

    // FN005 - a dot-dot against a separator that is not one. Case folded for the
    // percent forms only, which is all the folding `%2F` and `%2f` need; the Unicode
    // tokens have no case.
    if (mayBeEncoded) {
        bool raised = false;
        for (std::string_view token : kSeparatorLookalikes) {
            for (size_t at = lower.find(token); at != std::string::npos && !raised;
                 at = lower.find(token, at + 1)) {
                const std::string_view before(lower.data(), at);
                const std::string_view after =
                    std::string_view(lower).substr(at + token.size());
                if (endsWithDotDot(before) || endsWithEncodedDotDot(before) ||
                    startsWithDotDot(after)) {
                    // One finding per name. A traversal attempt spells its separator
                    // the same way every time it repeats it, and three rows saying the
                    // same thing about one file is volume without information.
                    found.push_back({"FN005", std::string("dot-dot beside a ") +
                                                  std::string(lookalikeName(token))});
                    raised = true;
                }
            }
            if (raised) break;
        }
    }

    // FN006 - a percent-encoded NUL.
    if (mayBeEncoded && lower.find("%00") != std::string::npos) {
        found.push_back({"FN006", "%00"});
    }

    return found;
}

}  // namespace

}  // namespace lyxbosa::rules::filename
