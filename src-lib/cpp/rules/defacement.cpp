#include "defacement.h"
#include <string>
#include <array>

namespace lyxbosa::rules::defacement {

// DEFC001: Hacker signature
namespace detail_DEFC001 {
    static constexpr Pattern patterns[] = {
        { R"(hacked\s+by\s+[A-Za-z0-9_\-\.]+)",
          "Hacker signature", true,
          {"hacked"} },  // case-insensitive
        { R"(defaced\s+by\s+[A-Za-z0-9_\-\.]+)",
          "Defacement signature", true,
          {"defaced"} },  // case-insensitive
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
        { R"((?i:file_put_contents)\s*\(\s*['"][^'"]*index\.(html|php)['"]\s*,)",
          "Index file replacement", false,
          {"file_put_contents", "index"} },
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
        { R"((?i:glob)\s*\(\s*['"]\*\.php['"]\s*\).*?(?i:file_put_contents))",
          "Mass PHP file modification", false,
          {"glob"} },
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
          "Context menu disabled", false,
          {"oncontextmenu", "return", "false"} },
        // document.oncontextmenu with Function
        { R"(document\.oncontextmenu\s*=\s*new\s+Function)",
          "Context menu blocked via Function", false,
          {"oncontextmenu", "document", "function"} },
        // onselectstart blocking
        { R"(onselectstart\s*=\s*new\s+Function\s*\(\s*["']return\s+false["']\s*\))",
          "Text selection disabled", false,
          {"onselectstart", "function", "return"} },
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
          "Window resize spam", false,
          {"resizeto", "window"} },
        // Multiple window.moveTo calls
        { R"(window\.moveTo\s*\(\s*0\s*,\s*0\s*\)\s*[;\n]?\s*window\.resizeTo)",
          "Window manipulation sequence", false,
          {"resizeto", "window", "moveto"} },
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
        { R"((?i:eval)\s*\(\s*['"]var\s+\w+\s*=)",
          "JavaScript eval variable assignment", false,
          {"eval"} },
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
// The original pattern used a backreference to tie the handler name to the
// function it names. RE2 has no backreferences, so it never compiled and the rule
// was silently dead. That identity check is the whole precision of the rule -
// "document.onkeydown = <something>" on its own is ordinary - so it moves here.
namespace detail_DEFC007 {
    std::vector<MatchResult> detectKeyboardHijack(std::string_view content) {
        std::vector<MatchResult> out;

        static const RE2 kAssign(R"(document\.onkeydown\s*=\s*(\w+))");
        if (!kAssign.ok()) return out;

        re2::StringPiece input(content.data(), content.size());
        re2::StringPiece handler;
        while (RE2::FindAndConsume(&input, kAssign, &handler)) {
            const std::string name(handler.data(), handler.size());

            // The named function must exist and must pop an alert.
            const RE2 body("function\\s+" + RE2::QuoteMeta(name) +
                           R"(\s*\([^)]*\)\s*\{[^}]{0,400}alert\s*\()");
            if (!body.ok() || !RE2::PartialMatch(
                    re2::StringPiece(content.data(), content.size()), body)) {
                continue;
            }

            const size_t pos = static_cast<size_t>(handler.data() - content.data());
            auto [line, col] = positionToLineCol(content, pos);
            MatchResult r;
            r.line = line;
            r.column = col;
            r.matched = std::string_view(handler.data(), handler.size());
            r.note = "document.onkeydown bound to " + name + "(), which pops an alert";
            out.push_back(r);
            if (out.size() >= 10) break;
        }

        return out;
    }
}
const BuiltinRule DEFC007 {
    .code = {Category::Defacement, 7},
    .name = "Keyboard hijacking",
    .description = "Detects keyboard event hijacking for malicious purposes",
    .severity = Severity::Medium,
    .patterns = {},
    .analyzer = &detail_DEFC007::detectKeyboardHijack,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &DEFC001, &DEFC002, &DEFC003, &DEFC004, &DEFC005, &DEFC006, &DEFC007
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::defacement
