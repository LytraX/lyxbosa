#include "backdoor.h"
#include <array>

namespace lyxbosa::rules::backdoor {

// BD001: Hidden admin creation
// Note: Patterns use possessive [^...]*+ to avoid CTRE stack overflow on large files
namespace detail_BD001 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(wp_insert_user\s*\([^)]*+user_login[^)]*+administrator)">(),
          "Hidden WordPress admin creation", false },
        { makePattern<R"(INSERT\s+INTO\s+\S*users\S*[^;]*+admin)">(),
          "Direct admin user insertion", false },
    };
}
const BuiltinRule BD001 {
    .code = {Category::Backdoor, 1},
    .name = "Hidden admin creation",
    .description = "Detects hidden admin user creation in CMS",
    .severity = Severity::Critical,
    .patterns = detail_BD001::patterns,
};

// BD002: Cron-based persistence
namespace detail_BD002 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(wp_schedule_event\s*\([^)]*+\$_(GET|POST|REQUEST))">(),
          "Cron with user input", false },
    };
}
const BuiltinRule BD002 {
    .code = {Category::Backdoor, 2},
    .name = "Cron-based persistence",
    .description = "Detects WordPress cron abuse for persistence",
    .severity = Severity::High,
    .patterns = detail_BD002::patterns,
};

// BD003: Plugin/theme backdoor installer
namespace detail_BD003 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(file_put_contents\s*\([^,]*+wp-content/(plugins|themes)[^,]*+,\s*base64_decode)">(),
          "Plugin/theme file write with base64", false },
    };
}
const BuiltinRule BD003 {
    .code = {Category::Backdoor, 3},
    .name = "Plugin/theme backdoor installer",
    .description = "Detects base64 payload written to plugin/theme directory",
    .severity = Severity::Critical,
    .patterns = detail_BD003::patterns,
};

// BD004: Database credential harvester
namespace detail_BD004 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(file_get_contents\s*\([^)]*+wp-config\.php)">(),
          "Reading wp-config", false },
        { makePattern<R"(file_get_contents\s*\([^)]*+configuration\.php)">(),
          "Reading Joomla config", false },
    };
}
const BuiltinRule BD004 {
    .code = {Category::Backdoor, 4},
    .name = "Config file reader",
    .description = "Detects reading of CMS configuration files",
    .severity = Severity::High,
    .patterns = detail_BD004::patterns,
};

// BD005: Socket-based backdoor
namespace detail_BD005 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(fsockopen\s*\([^)]+\)\s*.*?fwrite\s*\([^)]*+\$_(GET|POST|REQUEST))">(),
          "Socket with user data", false },
        { makePattern<R"(socket_create\s*\([^)]+\).*?socket_connect)">(),
          "Raw socket connection", false },
    };
}
const BuiltinRule BD005 {
    .code = {Category::Backdoor, 5},
    .name = "Socket-based backdoor",
    .description = "Detects socket connections that may be reverse shells",
    .severity = Severity::Critical,
    .patterns = detail_BD005::patterns,
};

// BD006: Reverse shell patterns
namespace detail_BD006 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(bash\s+-i\s+>&\s*/dev/tcp/)">(),
          "Bash reverse shell", false },
        { makePattern<R"(/bin/sh\s*\|\s*nc\s+)">(),
          "Netcat shell pipe", false },
    };
}
const BuiltinRule BD006 {
    .code = {Category::Backdoor, 6},
    .name = "Reverse shell pattern",
    .description = "Detects common reverse shell command patterns",
    .severity = Severity::Critical,
    .patterns = detail_BD006::patterns,
};

// BD007: Base64-encoded reverse shell
namespace detail_BD007 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(base64_decode\s*\([^)]*+\).*?(fsockopen|socket_create|pfsockopen))">(),
          "Decoded socket operation", false },
    };
}
const BuiltinRule BD007 {
    .code = {Category::Backdoor, 7},
    .name = "Encoded reverse shell",
    .description = "Detects base64-encoded socket operations",
    .severity = Severity::Critical,
    .patterns = detail_BD007::patterns,
};

// BD008: Hidden file creation
namespace detail_BD008 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(file_put_contents\s*\(\s*['"][^'"]*+\.htaccess)">(),
          ".htaccess modification", false },
    };
}
const BuiltinRule BD008 {
    .code = {Category::Backdoor, 8},
    .name = "htaccess backdoor",
    .description = "Detects .htaccess file manipulation",
    .severity = Severity::High,
    .patterns = detail_BD008::patterns,
};

// BD009: Password reset backdoor
namespace detail_BD009 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(wp_set_password\s*\([^)]*+\$_(GET|POST|REQUEST))">(),
          "Password reset with user input", false },
    };
}
const BuiltinRule BD009 {
    .code = {Category::Backdoor, 9},
    .name = "Password reset backdoor",
    .description = "Detects password manipulation via user input",
    .severity = Severity::Critical,
    .patterns = detail_BD009::patterns,
};

// BD010: Auto-update disable + backdoor
namespace detail_BD010 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(add_filter\s*\(\s*['"]auto_update_)">(),
          "Auto-update filter manipulation", false },
    };
}
const BuiltinRule BD010 {
    .code = {Category::Backdoor, 10},
    .name = "Auto-update manipulation",
    .description = "Detects disabling of auto-updates (persistence technique)",
    .severity = Severity::Medium,
    .patterns = detail_BD010::patterns,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &BD001, &BD002, &BD003, &BD004, &BD005,
    &BD006, &BD007, &BD008, &BD009, &BD010
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::backdoor
