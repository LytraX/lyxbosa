#include "dropper.h"
#include <array>

namespace lyxbosa::rules::dropper {

// DRP001: Remote file download and execute
namespace detail_DRP001 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(file_get_contents\s*\(\s*['"]https?://[^'"]+['"]\s*\).*?eval)">(),
          "Remote file eval", false },
    };
}
const BuiltinRule DRP001 {
    .code = {Category::Dropper, 1},
    .name = "Remote code loader",
    .description = "Detects downloading and executing remote code",
    .severity = Severity::Critical,
    .patterns = detail_DRP001::patterns,
};

// DRP002: curl/wget download and execute
namespace detail_DRP002 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"((curl|wget)\s+[^;|&]+\s*\|\s*(php|sh|bash))">(),
          "curl/wget pipe to interpreter", false },
    };
}
const BuiltinRule DRP002 {
    .code = {Category::Dropper, 2},
    .name = "Download and execute",
    .description = "Detects curl/wget piped to interpreter",
    .severity = Severity::Critical,
    .patterns = detail_DRP002::patterns,
};

// DRP003: Self-replicating code
namespace detail_DRP003 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(file_put_contents\s*\(\s*\$_SERVER\s*\[\s*['"]SCRIPT_FILENAME['"])">(),
          "Self-modification", false },
    };
}
const BuiltinRule DRP003 {
    .code = {Category::Dropper, 3},
    .name = "Self-replicating code",
    .description = "Detects code that modifies itself",
    .severity = Severity::High,
    .patterns = detail_DRP003::patterns,
};

// DRP004: Dropper writing to web root
namespace detail_DRP004 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(file_put_contents\s*\(\s*\$_SERVER\s*\[\s*['"]DOCUMENT_ROOT['"]\s*\]\s*\.\s*['"][^'"]+\.php['"])">(),
          "Writing PHP to document root", false },
    };
}
const BuiltinRule DRP004 {
    .code = {Category::Dropper, 4},
    .name = "Web root dropper",
    .description = "Detects PHP files written to document root",
    .severity = Severity::Critical,
    .patterns = detail_DRP004::patterns,
};

// DRP005: include_once remote file
namespace detail_DRP005 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"((include|require)(_once)?\s*\(\s*['"]https?://)">(),
          "Remote file include", false },
    };
}
const BuiltinRule DRP005 {
    .code = {Category::Dropper, 5},
    .name = "Remote file include",
    .description = "Detects including files from remote URLs",
    .severity = Severity::Critical,
    .patterns = detail_DRP005::patterns,
};

// DRP006: base64 file dropper
namespace detail_DRP006 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(file_put_contents\s*\([^,]+,\s*base64_decode\s*\(\s*['"][A-Za-z0-9+/]{100,})">(),
          "Base64 payload dropper", false },
    };
}
const BuiltinRule DRP006 {
    .code = {Category::Dropper, 6},
    .name = "Base64 payload dropper",
    .description = "Detects base64-encoded payloads being written to files",
    .severity = Severity::Critical,
    .patterns = detail_DRP006::patterns,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &DRP001, &DRP002, &DRP003, &DRP004, &DRP005, &DRP006
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::dropper
