#include "dropper.h"
#include <array>

namespace lyxbosa::rules::dropper {

// DRP001: Remote file download and execute
namespace detail_DRP001 {
    static constexpr Pattern patterns[] = {
        { R"((?i:file_get_contents)\s*\(\s*['"]https?://[^'"]+['"]\s*\).*?(?i:eval))",
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
        { R"((curl|wget)\s+[^;|&]+\s*\|\s*(php|sh|bash))",
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
        { R"((?i:file_put_contents)\s*\(\s*\$_SERVER\s*\[\s*['"]SCRIPT_FILENAME['"])",
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
        { R"((?i:file_put_contents)\s*\(\s*\$_SERVER\s*\[\s*['"]DOCUMENT_ROOT['"]\s*\]\s*\.\s*['"][^'"]+\.php['"])",
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
        { R"(((?i:include)|(?i:require))(_once)?\s*\(\s*['"]https?://)",
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
        { R"((?i:file_put_contents)\s*\([^,]+,\s*(?i:base64_decode)\s*\(\s*['"][A-Za-z0-9+/]{100,})",
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

// DRP007: Large base64 string assigned to variable (payload staging)
namespace detail_DRP007 {
    static constexpr Pattern patterns[] = {
        { R"(\$\w+\s*=\s*(?i:base64_decode)\s*\(\s*['"][A-Za-z0-9+/]{500,})",
          "Large base64 payload in variable", false },
    };
}
const BuiltinRule DRP007 {
    .code = {Category::Dropper, 7},
    .name = "Base64 payload staging",
    .description = "Detects large base64-encoded data stored in a variable (dropper staging)",
    .severity = Severity::Critical,
    .patterns = detail_DRP007::patterns,
};

// DRP008: file_put_contents writing archive files
namespace detail_DRP008 {
    static constexpr Pattern patterns[] = {
        { R"((?i:file_put_contents)\s*\(\s*['"][^'"]*\.(zip|tar|gz|rar|7z)['"])",
          "Writing archive file", false },
    };
}
const BuiltinRule DRP008 {
    .code = {Category::Dropper, 8},
    .name = "Archive dropper",
    .description = "Detects writing archive files (zip/tar/etc) - common dropper behavior",
    .severity = Severity::High,
    .patterns = detail_DRP008::patterns,
};

// DRP009: Dropper function patterns
// Malware defines functions to fetch remote content and write locally
// Pattern: function named copy/write/save etc (specific suspicious names)
namespace detail_DRP009 {
    static constexpr Pattern patterns[] = {
        // function copyfile, writefile, savefile, dropfile, createfile (specific names)
        { R"(function\s+((?i:copy)|write|save|drop|create)file\s*\()",
          "Named dropper function", false },
    };
}
const BuiltinRule DRP009 {
    .code = {Category::Dropper, 9},
    .name = "Dropper function",
    .description = "Detects dropper functions that write content to files",
    .severity = Severity::High,
    .patterns = detail_DRP009::patterns,
};

// DRP010: DOCUMENT_ROOT file path manipulation
// Malware writes files using DOCUMENT_ROOT to target web directories
// More specific than DRP004 - catches variable concatenation
namespace detail_DRP010 {
    static constexpr Pattern patterns[] = {
        // $_SERVER['DOCUMENT_ROOT'] concatenated with variable (dynamic path)
        { R"(\$_SERVER\s*\[\s*['"]DOCUMENT_ROOT['"]\s*\]\s*\.\s*['"]/['"]\s*\.\s*\$)",
          "DOCUMENT_ROOT path building", false },
        // file_put_contents with DOCUMENT_ROOT and /index
        { R"((?i:file_put_contents)\s*\([^,]*DOCUMENT_ROOT[^,]*index)",
          "Writing to index in document root", false },
    };
}
const BuiltinRule DRP010 {
    .code = {Category::Dropper, 10},
    .name = "Document root file drop",
    .description = "Detects file writing using DOCUMENT_ROOT path building",
    .severity = Severity::Critical,
    .patterns = detail_DRP010::patterns,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &DRP001, &DRP002, &DRP003, &DRP004, &DRP005, &DRP006, &DRP007, &DRP008,
    &DRP009, &DRP010
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::dropper
