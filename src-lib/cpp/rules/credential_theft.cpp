#include "credential_theft.h"
#include <array>

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

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &CRED001, &CRED002, &CRED003, &CRED004, &CRED005, &CRED006
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::credential_theft
