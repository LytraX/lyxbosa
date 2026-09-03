#include "phishing.h"
#include <array>

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

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &PHI001, &PHI002, &PHI003, &PHI004,
    &PHI005, &PHI006, &PHI007, &PHI008
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::phishing
