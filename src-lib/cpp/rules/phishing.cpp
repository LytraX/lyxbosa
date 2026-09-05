#include "phishing.h"
#include <array>
#include <cctype>
#include <string>
#include <vector>

namespace lyxbosa::rules::phishing {

// PHI001: Phishing form targeting known services
//
// The gap between the form tag and the brand has to be bounded. With `.*?` and dot_nl it
// spanned whole files, so any page carrying a `<form>` anywhere and the words "google" and
// "password" anywhere later matched - a Mailchimp subscribe form, NextGEN's admin screen,
// WPBakery's settings page, a page cache of a slider. 6 findings, none phishing.
//
// 1000 bytes is roughly one form's worth of markup: a brand-labelled password field belongs
// to the form it is in, not to one several screens away.
namespace detail_PHI001 {
    static constexpr Pattern patterns[] = {
        { R"(<form[^>]*action\s*=\s*['"][^'"]*['"][^>]*>.{0,1000}?(?i:paypal|apple|microsoft|google|facebook|instagram|netflix)[^<]{0,200}(?i:password))",
          "Phishing form with brand name", false,
          {"password", "action", "<form"} },
    };
}
const BuiltinRule PHI001 {
    .code = {Category::Phishing, 1},
    .name = "Brand phishing form",
    .description = "Detects phishing forms targeting known brands",
    .severity = Severity::Critical,
    .patterns = detail_PHI001::patterns,
};

// PHI002: Credential capture to external URL
namespace detail_PHI002 {
    static constexpr Pattern patterns[] = {
        { R"((?i:mail)\s*\([^)]+\$_(POST|GET|REQUEST)\s*\[\s*['"]pass(word)?['"])",
          "Password emailed", false,
          {"pass", "mail"} },
    };
}
const BuiltinRule PHI002 {
    .code = {Category::Phishing, 2},
    .name = "Password email exfiltration",
    .description = "Detects passwords being sent via email",
    .severity = Severity::Critical,
    .patterns = detail_PHI002::patterns,
};

// PHI003: Cookie stealing
namespace detail_PHI003 {
    static constexpr Pattern patterns[] = {
        { R"(document\.cookie.*?(location|window\.open|fetch|XMLHttpRequest))",
          "Cookie exfiltration attempt", false,
          {"document", "cookie"} },
    };
}
const BuiltinRule PHI003 {
    .code = {Category::Phishing, 3},
    .name = "Cookie stealing",
    .description = "Detects JavaScript cookie exfiltration patterns",
    .severity = Severity::Critical,
    .patterns = detail_PHI003::patterns,
};

// PHI004: Fake login page
// Note: Pattern uses possessive [^<]*+ to avoid CTRE stack overflow on large files
namespace detail_PHI004 {
    static constexpr Pattern patterns[] = {
        { R"(<title>[^<]*(login|signin|sign in|verify|update|confirm)[^<]*</title>.*?<form.*?password)",
          "Suspicious login page", false,
          {"password", "</title>", "<title>"} },
    };
}
const BuiltinRule PHI004 {
    .code = {Category::Phishing, 4},
    .name = "Fake login page",
    .description = "Detects suspicious login page patterns",
    .severity = Severity::High,
    .patterns = detail_PHI004::patterns,
};

// PHI005: Data exfiltration via curl/wget
// Note: Pattern uses possessive [^;]*+ to avoid CTRE stack overflow on large files
namespace detail_PHI005 {
    static constexpr Pattern patterns[] = {
        { R"(curl\s+[^;]*-d\s+[^;]*\$_(POST|GET|REQUEST)\s*\[)",
          "curl POST with user data", false,
          {"curl"} },
    };
}
const BuiltinRule PHI005 {
    .code = {Category::Phishing, 5},
    .name = "curl data exfiltration",
    .description = "Detects curl used to exfiltrate user input",
    .severity = Severity::High,
    .patterns = detail_PHI005::patterns,
};

// PHI006: Session hijacking
namespace detail_PHI006 {
    static constexpr Pattern patterns[] = {
        { R"(session_id\s*\(\s*\$_(GET|POST|REQUEST))",
          "Session ID from user input", false,
          {"session_id", "$_get|$_post|$_request"} },
    };
}
const BuiltinRule PHI006 {
    .code = {Category::Phishing, 6},
    .name = "Session hijacking",
    .description = "Detects session fixation via user input",
    .severity = Severity::High,
    .patterns = detail_PHI006::patterns,
};

// PHI007: Credit card harvesting
namespace detail_PHI007 {
    static constexpr Pattern patterns[] = {
        { R"((?i:preg_match)\s*\([^)]*\d{13,16}[^)]*,\s*\$_(POST|GET|REQUEST))",
          "Credit card regex capture", false,
          {"preg_match"} },
    };
}
const BuiltinRule PHI007 {
    .code = {Category::Phishing, 7},
    .name = "Credit card harvesting",
    .description = "Detects credit card number capture patterns",
    .severity = Severity::Critical,
    .patterns = detail_PHI007::patterns,
};

// PHI008: Fake error/security page
namespace detail_PHI008 {
    static constexpr Pattern patterns[] = {
        { R"((your\s+account\s+(has\s+been|is)\s+(compromised|hacked|suspended))|(verify\s+your\s+identity))",
          "Fake security warning", false },
    };
}
const BuiltinRule PHI008 {
    .code = {Category::Phishing, 8},
    .name = "Fake security warning",
    .description = "Detects social engineering text patterns",
    .severity = Severity::Medium,
    .patterns = detail_PHI008::patterns,
};

// PHI009: submitted form data mailed to an address written into the file
//
// A 2012 card-and-identity phish kit is present as 14 rows, 7 distinct files after
// normalising a doubled carriage return, and exactly ONE of the seven does anything.
// The kit splits the harvest from the send: the page carrying the card and SSN field
// names is HTML with no PHP in it, and the file that mails carries no form.
//
//     $send = "...@...";                                 // the drop, a literal
//     $message .= "SOCIAL SECURITY NUMBER  : ".$_POST['ssn1']."/"...;
//     $message .= "CARD NUMBER             : ".$_POST['cardnum']."\n";
//     $message .= "CARD VERIFICATION NUM   : ".$_POST['cvn']."\n";
//     mail($send, $subject, $message, $headers);
//
// NO SINGLE-FILE RULE CAN SEE BOTH HALVES, and 1 of 7 is therefore the correct target
// rather than a shortfall - the other six are presentation and carry no behaviour to
// detect. A rules agent should not spend effort trying to make one file out of two.
//
// The form-shaped alternative was measured rather than argued about: a `<form>` whose
// field names include card, CVV or SSN takes 18 files in the benign trees to reach that
// one, a 90% false-positive rate, on Magento checkout templates, a payment form partial
// and a consent form definition. The failure is structural and no field list fixes it -
// card field names inside a form are what e-commerce IS. Rejected, and kept reproducible
// as `REJECTED:form-with-card-field` in corpus/fp-population.py.
//
// Three conjuncts, and each is load-bearing. Dropping the address literal - `mail()`
// plus `$_POST` alone - costs 30 false positives; dropping the superglobal instead
// costs 24. The test pins one real file from each of those two sets:
//
//   * WordPress `wp-includes/pluggable.php`, one of the 30, reaches `mail()` and
//     `$_REQUEST[...]` in one file, but every address `wp_mail()` sends to arrives as
//     an argument or through a filter. Nothing is written down.
//   * PHPMailer's own `PHPMailer.php`, one of the 24, has a real `mail()` call and a
//     quoted address - but the address is a docblock example beside `validateAddress()`
//     and the class never reads a superglobal.
//
// A hardcoded recipient is what separates exfiltration to a fixed drop from a contact
// form mailing the site's own owner, because a CMS contact form takes its recipient
// from configuration.
//
// Measured over trail-data/CMS, CMS-ext and Sites - 207,311 files, 175 of them at risk
// (files calling mail()): 0 false positives, 95% upper bound 1.7%.
namespace detail_PHI009 {
    inline bool isIdentByte(unsigned char c) {
        return std::isalnum(c) != 0 || c == '_';
    }

    inline bool isSpace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    inline char lower(char c) {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }

    inline bool isLocalByte(unsigned char c) {
        return std::isalnum(c) != 0 || c == '.' || c == '_' || c == '%' || c == '+' || c == '-';
    }

    inline bool isDomainByte(unsigned char c) {
        return std::isalnum(c) != 0 || c == '.' || c == '-';
    }

    // Case-insensitive whole-word `mail` followed by `(`. The word boundary is what
    // keeps `wp_mail(`, `$mailer->sendmail(` and `->Mail(` off this: PHP's own mail()
    // is what the rule is about, and a wrapper's name is not evidence of one.
    size_t findMailCall(std::string_view c) {
        for (size_t i = 0; i + 5 <= c.size(); ++i) {
            if (lower(c[i]) != 'm') continue;
            if (lower(c[i + 1]) != 'a' || lower(c[i + 2]) != 'i' || lower(c[i + 3]) != 'l') continue;
            if (i > 0 && isIdentByte(static_cast<unsigned char>(c[i - 1]))) continue;
            size_t j = i + 4;
            while (j < c.size() && isSpace(c[j])) ++j;
            if (j < c.size() && c[j] == '(') return i;
        }
        return std::string_view::npos;
    }

    // `$_POST[` or `$_REQUEST[`, the two a harvester reads its fields out of.
    size_t findSubmittedFieldRead(std::string_view c) {
        for (size_t at = c.find("$_"); at != std::string_view::npos; at = c.find("$_", at + 1)) {
            size_t j = at + 2;
            size_t n = 0;
            while (j < c.size() && isIdentByte(static_cast<unsigned char>(c[j]))) { ++j; ++n; }
            std::string name;
            for (size_t k = at + 2; k < at + 2 + n; ++k) name.push_back(lower(c[k]));
            if (name != "post" && name != "request") continue;
            while (j < c.size() && isSpace(c[j])) ++j;
            if (j < c.size() && c[j] == '[') return at;
        }
        return std::string_view::npos;
    }

    // A quoted e-mail address: '"' local '@' domain '.' tld '"'. The quotes are the
    // point - an address assembled from variables or read from an option is not a
    // literal, and that is the whole discriminator.
    size_t findAddressLiteral(std::string_view c, std::string& address) {
        for (size_t at = c.find('@'); at != std::string_view::npos; at = c.find('@', at + 1)) {
            size_t b = at;
            while (b > 0 && isLocalByte(static_cast<unsigned char>(c[b - 1]))) --b;
            if (b == at) continue;                                   // empty local part
            if (b == 0 || (c[b - 1] != '"' && c[b - 1] != '\'')) continue;

            size_t e = at + 1;
            while (e < c.size() && isDomainByte(static_cast<unsigned char>(c[e]))) ++e;
            if (e >= c.size() || (c[e] != '"' && c[e] != '\'')) continue;

            // The last dot has to leave a two-letter-or-longer all-alphabetic tld, and
            // at least one byte of domain in front of it.
            const std::string_view domain = c.substr(at + 1, e - at - 1);
            const size_t dot = domain.find_last_of('.');
            if (dot == std::string_view::npos || dot == 0) continue;
            if (domain.size() - dot - 1 < 2) continue;
            bool alpha = true;
            for (size_t k = dot + 1; k < domain.size(); ++k) {
                if (std::isalpha(static_cast<unsigned char>(domain[k])) == 0) { alpha = false; break; }
            }
            if (!alpha) continue;

            address.assign(c.substr(b - 1, e + 1 - (b - 1)));
            return b - 1;
        }
        return std::string_view::npos;
    }

    std::vector<MatchResult> detectFixedDropMailer(std::string_view content) {
        std::vector<MatchResult> out;
        // Cheap guards first: this analyzer has no literal gate, so it runs on every
        // file in the tree. Every match needs an '@' and a superglobal, and both are
        // one memchr/memmem away.
        if (content.find('@') == std::string_view::npos) return out;
        if (content.find("$_") == std::string_view::npos) return out;

        const size_t readAt = findSubmittedFieldRead(content);
        if (readAt == std::string_view::npos) return out;
        const size_t mailAt = findMailCall(content);
        if (mailAt == std::string_view::npos) return out;
        std::string address;
        const size_t addrAt = findAddressLiteral(content, address);
        if (addrAt == std::string_view::npos) return out;

        auto [line, col] = positionToLineCol(content, mailAt);
        auto [addrLine, addrCol] = positionToLineCol(content, addrAt);
        (void)addrCol;
        MatchResult r;
        r.line = line;
        r.column = col;
        r.matched = content.substr(mailAt, std::min<size_t>(64, content.size() - mailAt));
        r.note = "mail() is called in a file that reads submitted fields out of a "
                 "superglobal and carries the recipient " + address + " as a literal at "
                 "line " + std::to_string(addrLine) +
                 " - a fixed drop written into the source, not a recipient the site "
                 "configured";
        out.push_back(r);
        return out;
    }
}
const BuiltinRule PHI009 {
    .code = {Category::Phishing, 9},
    .name = "Form data mailed to a hardcoded address",
    .description = "Detects mail() in a file that reads submitted fields from a superglobal and carries the recipient address as a literal",
    .severity = Severity::Critical,
    .patterns = {},
    .analyzer = &detail_PHI009::detectFixedDropMailer,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &PHI001, &PHI002, &PHI003, &PHI004,
    &PHI005, &PHI006, &PHI007, &PHI008, &PHI009
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::phishing
