#include "defacement.h"
#include <array>

namespace lyxbosa::rules::defacement {

// DEFC001: Hacker signature
namespace detail_DEFC001 {
    static constexpr Pattern patterns[] = {
        { R"(hacked\s+by\s+[A-Za-z0-9_\-\.]+)",
          "Hacker signature", true },  // case-insensitive
        { R"(defaced\s+by\s+[A-Za-z0-9_\-\.]+)",
          "Defacement signature", true },  // case-insensitive
    };
}
const BuiltinRule DEFC001 {
    .code = {Category::Defacement, 1},
    .name = "Hacker signature",
    .description = "Detects common defacement signatures",
    .severity = Severity::Critical,  // Defacement is critical
    .patterns = detail_DEFC001::patterns,
};

// DEFC002: index.html replacement
namespace detail_DEFC002 {
    static constexpr Pattern patterns[] = {
        { R"(file_put_contents\s*\(\s*['"][^'"]*index\.(html|php)['"]\s*,)",
          "Index file replacement", false },
    };
}
const BuiltinRule DEFC002 {
    .code = {Category::Defacement, 2},
    .name = "Index file replacement",
    .description = "Detects attempts to replace index files",
    .severity = Severity::High,
    .patterns = detail_DEFC002::patterns,
};

// DEFC003: Mass file replacement
namespace detail_DEFC003 {
    static constexpr Pattern patterns[] = {
        { R"(glob\s*\(\s*['"]\*\.php['"]\s*\).*?file_put_contents)",
          "Mass PHP file modification", false },
    };
}
const BuiltinRule DEFC003 {
    .code = {Category::Defacement, 3},
    .name = "Mass file replacement",
    .description = "Detects bulk file modification patterns",
    .severity = Severity::Critical,
    .patterns = detail_DEFC003::patterns,
};

// DEFC004: JavaScript context menu/selection blocking
// Malicious pages disable right-click and text selection to prevent analysis
// Patterns: oncontextmenu="return false", document.onselectstart=...
namespace detail_DEFC004 {
    static constexpr Pattern patterns[] = {
        // oncontextmenu handler blocking
        { R"(oncontextmenu\s*=\s*["']?\s*return\s+false)",
          "Context menu disabled", false },
        // document.oncontextmenu with Function
        { R"(document\.oncontextmenu\s*=\s*new\s+Function)",
          "Context menu blocked via Function", false },
        // onselectstart blocking
        { R"(onselectstart\s*=\s*new\s+Function\s*\(\s*["']return\s+false["']\s*\))",
          "Text selection disabled", false },
    };
}
const BuiltinRule DEFC004 {
    .code = {Category::Defacement, 4},
    .name = "User interaction blocking",
    .description = "Detects blocking of right-click and text selection",
    .severity = Severity::Medium,
    .patterns = detail_DEFC004::patterns,
};

// DEFC005: JavaScript window manipulation
// Malicious pages use window.resizeTo/moveTo spam to annoy users
// Often combined with alert() spam
namespace detail_DEFC005 {
    static constexpr Pattern patterns[] = {
        // window.resizeTo inside for loop - spam pattern
        { R"(for\s*\([^)]+\)\s*\{[^}]*window\.resizeTo)",
          "Window resize spam", false },
        // Multiple window.moveTo calls
        { R"(window\.moveTo\s*\(\s*0\s*,\s*0\s*\)\s*[;\n]?\s*window\.resizeTo)",
          "Window manipulation sequence", false },
    };
}
const BuiltinRule DEFC005 {
    .code = {Category::Defacement, 5},
    .name = "Window manipulation",
    .description = "Detects malicious window resizing/moving spam",
    .severity = Severity::High,
    .patterns = detail_DEFC005::patterns,
};

// DEFC006: JavaScript eval with DOM/property access
// Malicious JS uses eval() to dynamically access DOM properties
// Legitimate JSON parsing: eval('(' + data + ')') - has opening paren
// Malicious pattern: eval('document.'+x) or eval('var x=object.'+prop)
namespace detail_DEFC006 {
    static constexpr Pattern patterns[] = {
        // eval building dynamic variable/property access (not JSON parsing)
        // Malicious: eval('var temp=document...'+where) or eval('obj.'+prop)
        // Safe: eval('(' + data + ')') for JSON
        { R"(eval\s*\(\s*['"]var\s+\w+\s*=)",
          "JavaScript eval variable assignment", false },
    };
}
const BuiltinRule DEFC006 {
    .code = {Category::Defacement, 6},
    .name = "JavaScript eval dynamic code",
    .description = "Detects eval() building dynamic variable assignments",
    .severity = Severity::High,
    .patterns = detail_DEFC006::patterns,
};

// DEFC007: Keyboard event hijacking with alert
// Malicious pages intercept keydown/keypress to show alerts or block actions
// Legitimate uses (accessibility hotkeys) don't pop alerts on every keypress
namespace detail_DEFC007 {
    static constexpr Pattern patterns[] = {
        // Function that shows alert assigned to onkeydown
        // Pattern: function foo(){alert(...)}...document.onkeydown=foo
        { R"(function\s+(\w+)\s*\(\s*\)\s*\{[^}]*alert\s*\([^)]*\)[^}]*\}[^;]*document\.onkeydown\s*=\s*\1)",
          "Keyboard hijack with alert", false },
    };
}
const BuiltinRule DEFC007 {
    .code = {Category::Defacement, 7},
    .name = "Keyboard hijacking",
    .description = "Detects keyboard event hijacking for malicious purposes",
    .severity = Severity::Medium,
    .patterns = detail_DEFC007::patterns,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &DEFC001, &DEFC002, &DEFC003, &DEFC004, &DEFC005, &DEFC006, &DEFC007
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::defacement
