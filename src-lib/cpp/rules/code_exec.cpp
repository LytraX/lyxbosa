#include "code_exec.h"
#include <array>

namespace lyxbosa::rules::code_exec {

// RCE001: eval with base64 decode
namespace detail_RCE001 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(eval\s*\(\s*base64_decode\s*\()">(),
          "eval(base64_decode(", false },
    };
}
const BuiltinRule RCE001 {
    .code = {Category::CodeExec, 1},
    .name = "eval base64 decode",
    .description = "Detects eval() with base64_decode() - common obfuscation",
    .severity = Severity::Critical,
    .patterns = detail_RCE001::patterns,
};

// RCE002: eval with gzinflate
namespace detail_RCE002 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(eval\s*\(\s*gzinflate\s*\()">(),
          "eval(gzinflate(", false },
    };
}
const BuiltinRule RCE002 {
    .code = {Category::CodeExec, 2},
    .name = "eval gzinflate",
    .description = "Detects eval() with gzinflate() compression",
    .severity = Severity::Critical,
    .patterns = detail_RCE002::patterns,
};

// RCE003: Dynamic function call with user input
namespace detail_RCE003 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[)">(),
          "Dynamic call with user input", false },
    };
}
const BuiltinRule RCE003 {
    .code = {Category::CodeExec, 3},
    .name = "Dynamic function with user input",
    .description = "Detects variable function calls with user-controlled input",
    .severity = Severity::Critical,
    .patterns = detail_RCE003::patterns,
};

// RCE004: eval with user input
namespace detail_RCE004 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[)">(),
          "eval with user input", false },
    };
}
const BuiltinRule RCE004 {
    .code = {Category::CodeExec, 4},
    .name = "eval with user input",
    .description = "Detects eval() directly using superglobal input",
    .severity = Severity::Critical,
    .patterns = detail_RCE004::patterns,
};

// RCE005: assert with user input
namespace detail_RCE005 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[)">(),
          "assert with user input", false },
    };
}
const BuiltinRule RCE005 {
    .code = {Category::CodeExec, 5},
    .name = "assert with user input",
    .description = "Detects assert() with user-controlled input (PHP code execution)",
    .severity = Severity::Critical,
    .patterns = detail_RCE005::patterns,
};

// RCE006: preg_replace with /e modifier and user input
namespace detail_RCE006 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(preg_replace\s*\(\s*['"]/[^/]+/[a-zA-Z]*e[a-zA-Z]*['"])">(),
          "preg_replace /e modifier", false },
    };
}
const BuiltinRule RCE006 {
    .code = {Category::CodeExec, 6},
    .name = "preg_replace code execution",
    .description = "Detects preg_replace() with dangerous /e modifier",
    .severity = Severity::High,
    .patterns = detail_RCE006::patterns,
};

// RCE007: create_function (deprecated, dangerous)
namespace detail_RCE007 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(create_function\s*\(\s*['"][^'"]*['"]\s*,\s*\$_(GET|POST|REQUEST))">(),
          "create_function with user input", false },
    };
}
const BuiltinRule RCE007 {
    .code = {Category::CodeExec, 7},
    .name = "create_function with user input",
    .description = "Detects create_function() with user-controlled code",
    .severity = Severity::Critical,
    .patterns = detail_RCE007::patterns,
};

// RCE008: shell_exec/system/passthru/exec with user input
namespace detail_RCE008 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"((shell_exec|system|passthru|exec|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE))">(),
          "Shell command with user input", false },
    };
}
const BuiltinRule RCE008 {
    .code = {Category::CodeExec, 8},
    .name = "Shell execution with user input",
    .description = "Detects shell command execution with user-controlled input",
    .severity = Severity::Critical,
    .patterns = detail_RCE008::patterns,
};

// RCE009: backtick operator with variable
// Note: Using bounded quantifier because backticks are rare in PHP files,
// causing [^`]* to scan entire files and overflow CTRE's recursive stack.
// 500 chars is sufficient for any realistic backtick command.
namespace detail_RCE009 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(`[^`]{0,500}\$_(GET|POST|REQUEST|COOKIE))">(),
          "Backtick with user input", false },
    };
}
const BuiltinRule RCE009 {
    .code = {Category::CodeExec, 9},
    .name = "Backtick command execution",
    .description = "Detects backtick operator with user-controlled variables",
    .severity = Severity::Critical,
    .patterns = detail_RCE009::patterns,
};

// RCE010: call_user_func with user input
namespace detail_RCE010 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(call_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST))">(),
          "call_user_func with user input", false },
    };
}
const BuiltinRule RCE010 {
    .code = {Category::CodeExec, 10},
    .name = "call_user_func with user input",
    .description = "Detects call_user_func() with user-controlled callback",
    .severity = Severity::Critical,
    .patterns = detail_RCE010::patterns,
};

// RCE011: array_map/array_filter with user callback
namespace detail_RCE011 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"((array_map|array_filter|array_reduce)\s*\(\s*\$_(GET|POST|REQUEST))">(),
          "Array function with user callback", false },
    };
}
const BuiltinRule RCE011 {
    .code = {Category::CodeExec, 11},
    .name = "Array function with user callback",
    .description = "Detects array functions with user-controlled callbacks",
    .severity = Severity::High,
    .patterns = detail_RCE011::patterns,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &RCE001, &RCE002, &RCE003, &RCE004, &RCE005,
    &RCE006, &RCE007, &RCE008, &RCE009, &RCE010, &RCE011
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::code_exec
