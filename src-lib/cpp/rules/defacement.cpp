#include "defacement.h"
#include <array>

namespace lyxbosa::rules::defacement {

// DEFC001: Hacker signature
namespace detail_DEFC001 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(hacked\s+by\s+[A-Za-z0-9_\-]+)">(),
          "Hacker signature", false },
        { makePattern<R"(defaced\s+by\s+[A-Za-z0-9_\-]+)">(),
          "Defacement signature", false },
    };
}
const BuiltinRule DEFC001 {
    .code = {Category::Defacement, 1},
    .name = "Hacker signature",
    .description = "Detects common defacement signatures",
    .severity = Severity::High,
    .patterns = detail_DEFC001::patterns,
};

// DEFC002: index.html replacement
namespace detail_DEFC002 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(file_put_contents\s*\(\s*['"][^'"]*index\.(html|php)['"]\s*,)">(),
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
        { makePattern<R"(glob\s*\(\s*['"]\*\.php['"]\s*\).*?file_put_contents)">(),
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

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &DEFC001, &DEFC002, &DEFC003
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::defacement
