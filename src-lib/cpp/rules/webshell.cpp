#include "webshell.h"
#include <array>

namespace lyxbosa::rules::webshell {

// WS001: China Chopper
namespace detail_WS001 {
    static constexpr Pattern patterns[] = {
        { R"(@eval\s*\(\s*\$_POST\s*\[)",
          "eval($_POST[", false },
        { R"(@?assert\s*\(\s*\$_POST\s*\[)",
          "assert($_POST[", false },
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
          "z0 parameter access", false },
        { R"(\$_POST\s*\[\s*['"]z0['"]\s*\])",
          "z0 POST parameter", false },
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
        { R"(\$\w+\s*=\s*str_replace\s*\([^;]+;\s*\$\w+\s*\(\s*\$\w+\s*\(\s*\$_)",
          "Weevely pattern", false },
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
          "WSO version string", false },
        { R"(Web\s*Shell\s*by\s*oRb)",
          "WSO author signature", false },
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
          "r57/c99 shell name", false },
        { R"(r57\s+shell|c99\s+shell)",
          "r57/c99 shell variant", false },
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
          "FilesMan signature", false },
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
          "b374k signature", false },
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
        { R"(move_uploaded_file\s*\([^,]+,\s*\$_(GET|POST|REQUEST))",
          "Upload to user-controlled path", false },
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
        { R"(eval\s*\(\s*gzinflate\s*\(\s*base64_decode)",
          "gzinflate+base64 eval", false },
        { R"(eval\s*\(\s*gzuncompress\s*\(\s*base64_decode)",
          "gzuncompress+base64 eval", false },
        { R"(eval\s*\(\s*str_rot13\s*\(\s*base64_decode)",
          "str_rot13+base64 eval", false },
    };
}
const BuiltinRule WS009 {
    .code = {Category::Webshell, 9},
    .name = "Encoded webshell loader",
    .description = "Detects multi-layer encoded webshell loaders",
    .severity = Severity::Critical,
    .patterns = detail_WS009::patterns,
};

// Static array of all rules
static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &WS001, &WS002, &WS003, &WS004, &WS005,
    &WS006, &WS007, &WS008, &WS009
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::webshell
