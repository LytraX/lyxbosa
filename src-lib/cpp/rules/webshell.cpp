#include "webshell.h"
#include <array>
#include <string>
#include <vector>

namespace lyxbosa::rules::webshell {

// WS001: China Chopper
namespace detail_WS001 {
    static constexpr Pattern patterns[] = {
        { R"(@(?i:eval)\s*\(\s*\$_POST\s*\[)",
          "eval($_POST[", false,
          {"_post", "eval"} },
        { R"(@?(?i:assert)\s*\(\s*\$_POST\s*\[)",
          "assert($_POST[", false,
          {"assert", "_post"} },
    };
}
const BuiltinRule WS001 {
    .code = {Category::Webshell, 1},
    .name = "China Chopper webshell",
    .description = "Detects China Chopper one-line PHP webshell pattern",
    .severity = Severity::Critical,
    .patterns = detail_WS001::patterns,
};

// WS002: Generic one-liner backdoor with z0 parameter
namespace detail_WS002 {
    static constexpr Pattern patterns[] = {
        { R"(\$_REQUEST\s*\[\s*['"]z0['"]\s*\])",
          "z0 parameter access", false,
          {"_request"} },
        { R"(\$_POST\s*\[\s*['"]z0['"]\s*\])",
          "z0 POST parameter", false,
          {"_post"} },
    };
}
const BuiltinRule WS002 {
    .code = {Category::Webshell, 2},
    .name = "Z0 parameter backdoor",
    .description = "Detects webshells using the common z0 parameter name",
    .severity = Severity::Critical,
    .patterns = detail_WS002::patterns,
};

// WS003: Weevely webshell
namespace detail_WS003 {
    static constexpr Pattern patterns[] = {
        { R"(\$\w+\s*=\s*(?i:str_replace)\s*\([^;]+;\s*\$\w+\s*\(\s*\$\w+\s*\(\s*\$_)",
          "Weevely pattern", false,
          {"str_replace"} },
    };
}
const BuiltinRule WS003 {
    .code = {Category::Webshell, 3},
    .name = "Weevely webshell",
    .description = "Detects Weevely PHP webshell obfuscation pattern",
    .severity = Severity::Critical,
    .patterns = detail_WS003::patterns,
};

// WS004: WSO webshell
namespace detail_WS004 {
    static constexpr Pattern patterns[] = {
        { R"(WSO\s+\d+\.\d+)",
          "WSO version string", false,
          {"wso"} },
        { R"(Web\s*Shell\s*by\s*oRb)",
          "WSO author signature", false,
          {"shell"} },
    };
}
const BuiltinRule WS004 {
    .code = {Category::Webshell, 4},
    .name = "WSO webshell",
    .description = "Detects WSO (Web Shell by oRb) signatures",
    .severity = Severity::Critical,
    .patterns = detail_WS004::patterns,
};

// WS005: r57/c99 shell signatures
namespace detail_WS005 {
    static constexpr Pattern patterns[] = {
        { R"(r57shell|c99shell|c99mad)",
          "r57/c99 shell name", false,
          {"r57shell|c99shell|c99mad"} },
        { R"(r57\s+shell|c99\s+shell)",
          "r57/c99 shell variant", false,
          {"r57|c99"} },
    };
}
const BuiltinRule WS005 {
    .code = {Category::Webshell, 5},
    .name = "r57/c99 shell",
    .description = "Detects r57 and c99 PHP shell signatures",
    .severity = Severity::Critical,
    .patterns = detail_WS005::patterns,
};

// WS006: FilesMan webshell
namespace detail_WS006 {
    static constexpr Pattern patterns[] = {
        { R"(FilesMan|Fil3sM4n)",
          "FilesMan signature", false,
          {"filesman|fil3sm4n"} },
    };
}
const BuiltinRule WS006 {
    .code = {Category::Webshell, 6},
    .name = "FilesMan webshell",
    .description = "Detects FilesMan PHP webshell",
    .severity = Severity::Critical,
    .patterns = detail_WS006::patterns,
};

// WS007: b374k shell
namespace detail_WS007 {
    static constexpr Pattern patterns[] = {
        { R"(b374k\s*shell|b374k\s+\d+\.\d+)",
          "b374k signature", false,
          {"b374k"} },
    };
}
const BuiltinRule WS007 {
    .code = {Category::Webshell, 7},
    .name = "b374k webshell",
    .description = "Detects b374k PHP webshell signatures",
    .severity = Severity::Critical,
    .patterns = detail_WS007::patterns,
};

// WS008: Upload shell pattern
namespace detail_WS008 {
    static constexpr Pattern patterns[] = {
        { R"((?i:move_uploaded_file)\s*\([^,]+,\s*\$_(GET|POST|REQUEST))",
          "Upload to user-controlled path", false,
          {"move_uploaded_file", "$_get|$_post|$_request"} },
    };
}
const BuiltinRule WS008 {
    .code = {Category::Webshell, 8},
    .name = "Malicious upload handler",
    .description = "Detects file upload to user-controlled destination",
    .severity = Severity::High,
    .patterns = detail_WS008::patterns,
};

// WS009: Encoded webshell loader
namespace detail_WS009 {
    static constexpr Pattern patterns[] = {
        { R"((?i:eval)\s*\(\s*(?i:gzinflate)\s*\(\s*(?i:base64_decode))",
          "gzinflate+base64 eval", false,
          {"gzinflate", "eval"} },
        { R"((?i:eval)\s*\(\s*(?i:gzuncompress)\s*\(\s*(?i:base64_decode))",
          "gzuncompress+base64 eval", false,
          {"gzuncompress", "eval"} },
        { R"((?i:eval)\s*\(\s*(?i:str_rot13)\s*\(\s*(?i:base64_decode))",
          "str_rot13+base64 eval", false,
          {"str_rot13", "eval"} },
    };
}
const BuiltinRule WS009 {
    .code = {Category::Webshell, 9},
    .name = "Encoded webshell loader",
    .description = "Detects multi-layer encoded webshell loaders",
    .severity = Severity::Critical,
    .patterns = detail_WS009::patterns,
};

// WS010: a 404 the file writes about itself
//
// The shells above are recognised by what they execute. This one is recognised by how
// it hides, which is the part the operator sees first:
//
//     if (!$pass) {
//         if (!isset($_REQUEST['520'])) {
//             header("HTTP/1.1 404 Not Found");
//             die();
//         }
//         echo '<form ...><input type="password" name="p8"> ...';
//     }
//
// Request the file and it is not there. Request it with `?520` and it is a login form.
// That is why the family survived on nine accounts at once: every check that consists
// of fetching the URL agrees with the file being gone, and a crawler, an uptime probe
// and an operator all get the same answer.
//
// The condition is what the 404 is gated on. A file returning 404 is unremarkable by
// itself - WordPress core's `wp-includes/ms-files.php` does it twice - so the rule
// tests what decides. Every one of the 22 benign files measured decides on STATE:
// `is_multisite()`, `$current_blog->archived`, `! is_file( $file )`, or Jetpack's
// `dirname( WP_UNINSTALL_PLUGIN ) !== dirname( plugin_basename( __FILE__ ) )`. Those
// are a server answering honestly about a resource that is genuinely unavailable.
//
// Gating on `!isset($_REQUEST['520'])` inverts that: the resource is always there, and
// the 404 is a lie told to everyone who does not know the token. None of the 22
// reaches that shape, and the five malicious files that do are all the same family.
//
// A caveat worth writing down rather than leaving for someone to rediscover: this
// zero is the least informative of the three shipped in this round. Only 111 of
// 107,500 files emit a 404 status at all, so the first gate is narrow before the second
// one does any work - unlike RCE015, whose first gate takes in 1,073 files. The rule
// is carried by the argument above more than by the size of the population it survived.
namespace detail_WS010 {
    constexpr size_t kBackWindow = 200;    // the gate, before the header call
    constexpr size_t kForwardGap = 64;     // the header call, to die/exit
    constexpr size_t kMaxFindings = 2;

    inline bool isIdentByte(unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '_' || c >= 0x80;
    }

    inline bool isSpace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    bool wholeWordAt(std::string_view c, size_t at, std::string_view w) {
        if (at + w.size() > c.size()) return false;
        if (c.compare(at, w.size(), w) != 0) return false;
        if (at > 0 && isIdentByte(static_cast<unsigned char>(c[at - 1]))) return false;
        const size_t after = at + w.size();
        return after >= c.size() || !isIdentByte(static_cast<unsigned char>(c[after]));
    }

    // A request superglobal named inside [from, to), in either of the two shapes a
    // presence test takes it: `$_REQUEST['520']` for isset, and a bare `$_REQUEST`
    // for `array_key_exists('520', $_REQUEST)`.
    bool namesRequestSuperglobal(std::string_view c, size_t from, size_t to) {
        static constexpr std::string_view kNames[] = {
            "$_REQUEST", "$_GET", "$_POST", "$_COOKIE"
        };
        for (size_t i = from; i < to && i < c.size(); ++i) {
            if (c[i] != '$') continue;
            for (const auto& n : kNames) {
                if (i + n.size() > c.size()) continue;
                if (c.compare(i, n.size(), n) != 0) continue;
                size_t j = i + n.size();
                if (j < c.size() && isIdentByte(static_cast<unsigned char>(c[j]))) continue;
                while (j < c.size() && isSpace(c[j])) ++j;
                // Subscripted, or handed to array_key_exists as the array itself.
                if (j >= c.size() || c[j] == '[' || c[j] == ')' || c[j] == ',') return true;
            }
        }
        return false;
    }

    // `!isset($_REQUEST[...])` or `!array_key_exists('520', $_REQUEST)` in [from, to).
    //
    // The negation is required, and so is the polarity. `if (isset($_GET['x']))`
    // guarding real work is not a cloak. Nor is `!empty(...)`, which was in this list
    // for one draft and is exactly backwards: it makes the 404 the answer when the
    // parameter IS present, which is the opposite of hiding behind a token. Only a
    // negated *presence* test puts the 404 in front of everybody who lacks it.
    bool negatedRequestGate(std::string_view c, size_t from, size_t to) {
        static constexpr std::string_view kTests[] = {"isset", "array_key_exists"};
        for (size_t i = from; i < to && i < c.size(); ++i) {
            std::string_view test;
            for (const auto& t : kTests) {
                if (wholeWordAt(c, i, t)) { test = t; break; }
            }
            if (test.empty()) continue;

            size_t b = i;
            while (b > from && isSpace(c[b - 1])) --b;
            if (b == 0 || c[b - 1] != '!') continue;

            size_t p = i + test.size();
            while (p < c.size() && isSpace(c[p])) ++p;
            if (p >= c.size() || c[p] != '(') continue;
            size_t depth = 0, close = std::string_view::npos;
            for (size_t j = p; j < c.size() && j < p + 160; ++j) {
                if (c[j] == '(') ++depth;
                else if (c[j] == ')') { if (--depth == 0) { close = j; break; } }
            }
            if (close == std::string_view::npos) continue;
            if (namesRequestSuperglobal(c, p, close)) return true;
        }
        return false;
    }

    // `die` / `exit` within kForwardGap bytes after `from`, with nothing but whitespace,
    // `;` and `@` in between - i.e. stopping is literally the next thing that runs.
    //
    // Braces are deliberately not allowed through. Letting `}` past would accept
    // `if ( $x ) { status_header( 404 ); } exit;`, where the exit is not inside the
    // guarded branch at all and the file does not vanish for anyone.
    bool stopsImmediately(std::string_view c, size_t from) {
        const size_t to = std::min(c.size(), from + kForwardGap);
        for (size_t i = from; i < to; ++i) {
            if (wholeWordAt(c, i, "die") || wholeWordAt(c, i, "exit")) return true;
            const char ch = c[i];
            if (!isSpace(ch) && ch != ';' && ch != '@') return false;
        }
        return false;
    }

    std::vector<MatchResult> detectCloaked404(std::string_view content) {
        std::vector<MatchResult> out;
        if (content.find("404") == std::string_view::npos) return out;
        if (content.find("eader") == std::string_view::npos) return out;   // header|status_header

        for (size_t at = content.find("404"); at != std::string_view::npos;
             at = content.find("404", at + 1)) {
            // Walk back to the call this 404 is an argument of.
            size_t open = std::string_view::npos;
            size_t depth = 0;
            const size_t floorPos = (at > 120) ? at - 120 : 0;
            for (size_t i = at; i-- > floorPos;) {
                if (content[i] == ')') ++depth;
                else if (content[i] == '(') {
                    if (depth == 0) { open = i; break; }
                    --depth;
                }
            }
            if (open == std::string_view::npos) continue;

            size_t n = open;
            while (n > 0 && isSpace(content[n - 1])) --n;
            size_t s = n;
            while (s > 0 && isIdentByte(static_cast<unsigned char>(content[s - 1]))) --s;
            const std::string_view fn = content.substr(s, n - s);
            if (fn != "header" && fn != "status_header") continue;

            // Find the call's closing paren, then require an immediate stop.
            size_t close = std::string_view::npos;
            depth = 0;
            for (size_t j = open; j < content.size() && j < open + 200; ++j) {
                if (content[j] == '(') ++depth;
                else if (content[j] == ')') { if (--depth == 0) { close = j; break; } }
            }
            if (close == std::string_view::npos) continue;
            if (!stopsImmediately(content, close + 1)) continue;

            const size_t from = (s > kBackWindow) ? s - kBackWindow : 0;
            if (!negatedRequestGate(content, from, s)) continue;

            auto [line, col] = positionToLineCol(content, s);
            MatchResult r;
            r.line = line;
            r.column = col;
            r.matched = content.substr(s, std::min<size_t>(close + 1 - s, 64));
            r.note = std::string(fn) +
                     "() answers 404 and the script stops, and what decides is whether a "
                     "request parameter is set rather than any state of the resource - the "
                     "file is present for whoever knows the parameter and absent for "
                     "everyone else";
            out.push_back(r);
            if (out.size() >= kMaxFindings) return out;
        }
        return out;
    }
}
const BuiltinRule WS010 {
    .code = {Category::Webshell, 10},
    .name = "404 cloak on a request parameter",
    .description = "Detects a script that answers 404 and exits unless a magic request parameter is present, so it reads as absent to anyone without the token",
    .severity = Severity::High,
    .patterns = {},
    .analyzer = &detail_WS010::detectCloaked404,
};

// Static array of all rules
static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &WS001, &WS002, &WS003, &WS004, &WS005,
    &WS006, &WS007, &WS008, &WS009, &WS010
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::webshell
