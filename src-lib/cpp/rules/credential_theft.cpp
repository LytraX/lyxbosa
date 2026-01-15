#include "credential_theft.h"
#include <array>

namespace lyxbosa::rules::credential_theft {

// CRED001: Database dump
namespace detail_CRED001 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(SELECT\s+\*\s+FROM\s+\S*users\S*\s+INTO\s+OUTFILE)">(),
          "User table export", false },
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
        { makePattern<R"(file_get_contents\s*\(\s*['"]/etc/passwd['"])">(),
          "passwd file read", false },
        { makePattern<R"(file_get_contents\s*\(\s*['"]/etc/shadow['"])">(),
          "shadow file read", false },
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
        { makePattern<R"(ftp_login\s*\([^)]*+\$_(GET|POST|REQUEST))">(),
          "FTP login with user input", false },
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
namespace detail_CRED004 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(addEventListener\s*\(\s*['"]key(down|press|up)['"])">(),
          "Keyboard event listener", false },
    };
}
const BuiltinRule CRED004 {
    .code = {Category::CredTheft, 4},
    .name = "Keylogger injection",
    .description = "Detects keyboard event logging scripts",
    .severity = Severity::High,
    .patterns = detail_CRED004::patterns,
};

// CRED005: Credential logging to file
namespace detail_CRED005 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(file_put_contents\s*\([^,]*+,\s*[^)]*+\$_(POST|GET|REQUEST)\s*\[\s*['"]pass)">(),
          "Password logged to file", false },
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
namespace detail_CRED006 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(https?://[a-zA-Z0-9.\-]+\.(ru|cn|tk|ml|ga|cf|gq)/)">(),
          "Suspicious TLD URL", false },
    };
}
const BuiltinRule CRED006 {
    .code = {Category::CredTheft, 6},
    .name = "Suspicious TLD in URL",
    .description = "Detects URLs with suspicious top-level domains",
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
