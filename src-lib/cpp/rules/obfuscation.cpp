#include "obfuscation.h"
#include <array>

namespace lyxbosa::rules::obfuscation {

// OBF001: Hex-encoded variable names
namespace detail_OBF001 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(\$GLOBALS\s*\[\s*['"]\\x[0-9a-fA-F]{2})">(),
          "Hex-encoded GLOBALS access", false },
    };
}
const BuiltinRule OBF001 {
    .code = {Category::Obfuscation, 1},
    .name = "Hex-encoded variable names",
    .description = "Detects variables accessed via hex-encoded strings",
    .severity = Severity::High,
    .patterns = detail_OBF001::patterns,
};

// OBF002: chr() string building
namespace detail_OBF002 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr)">(),
          "chr() string concatenation", false },
    };
}
const BuiltinRule OBF002 {
    .code = {Category::Obfuscation, 2},
    .name = "chr() string building",
    .description = "Detects strings built using chr() concatenation",
    .severity = Severity::Medium,
    .patterns = detail_OBF002::patterns,
};

// OBF003: pack() obfuscation
namespace detail_OBF003 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(pack\s*\(\s*['"]H\*['"]\s*,\s*['"][0-9a-fA-F]{20,}['"])">(),
          "pack() hex decoding", false },
    };
}
const BuiltinRule OBF003 {
    .code = {Category::Obfuscation, 3},
    .name = "pack() hex obfuscation",
    .description = "Detects pack() used to decode hex-encoded payloads",
    .severity = Severity::High,
    .patterns = detail_OBF003::patterns,
};

// OBF004: Very long base64 strings
namespace detail_OBF004 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(['"][A-Za-z0-9+/]{500,}={0,2}['"])">(),
          "Very long base64 string", false },
    };
}
const BuiltinRule OBF004 {
    .code = {Category::Obfuscation, 4},
    .name = "Long base64 encoded payload",
    .description = "Detects suspiciously long base64-encoded strings",
    .severity = Severity::Medium,
    .patterns = detail_OBF004::patterns,
};

// OBF005: strrev obfuscation
namespace detail_OBF005 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(strrev\s*\(\s*['"][a-zA-Z_]+['"]\s*\))">(),
          "strrev function name hiding", false },
    };
}
const BuiltinRule OBF005 {
    .code = {Category::Obfuscation, 5},
    .name = "strrev() function hiding",
    .description = "Detects strrev() used to hide function names",
    .severity = Severity::Medium,
    .patterns = detail_OBF005::patterns,
};

// OBF006: String concatenation to build function name
namespace detail_OBF006 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(\$\w+\s*=\s*['"][a-z]{1,4}['"]\s*\.\s*['"][a-z]{1,4}['"]\s*\.\s*['"][a-z]{1,4}['"])">(),
          "String concat for function name", false },
    };
}
const BuiltinRule OBF006 {
    .code = {Category::Obfuscation, 6},
    .name = "Concatenated function name",
    .description = "Detects function names built via string concatenation",
    .severity = Severity::Medium,
    .patterns = detail_OBF006::patterns,
};

// OBF007: Variable function from array
namespace detail_OBF007 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(\$\w+\[\d+\]\s*\(\s*\$\w+\[\d+\])">(),
          "Array-based obfuscated call", false },
    };
}
const BuiltinRule OBF007 {
    .code = {Category::Obfuscation, 7},
    .name = "Array-based function call",
    .description = "Detects function calls using array indices for obfuscation",
    .severity = Severity::High,
    .patterns = detail_OBF007::patterns,
};

// OBF008: str_replace used to build function names
namespace detail_OBF008 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(str_replace\s*\(\s*['"][^'"]+['"]\s*,\s*['"]['"]?\s*,\s*['"](e|ba|as|ev|sy|ex)[^'"]+['"])">(),
          "str_replace function name building", false },
    };
}
const BuiltinRule OBF008 {
    .code = {Category::Obfuscation, 8},
    .name = "str_replace() obfuscation",
    .description = "Detects str_replace() used to construct function names",
    .severity = Severity::High,
    .patterns = detail_OBF008::patterns,
};

// OBF009: Multiple nested base64_decode
namespace detail_OBF009 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(base64_decode\s*\(\s*base64_decode)">(),
          "Nested base64_decode", false },
    };
}
const BuiltinRule OBF009 {
    .code = {Category::Obfuscation, 9},
    .name = "Nested base64 decoding",
    .description = "Detects multiple layers of base64 encoding",
    .severity = Severity::High,
    .patterns = detail_OBF009::patterns,
};

// OBF010: gzuncompress with base64
namespace detail_OBF010 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(gzuncompress\s*\(\s*base64_decode)">(),
          "gzuncompress+base64", false },
    };
}
const BuiltinRule OBF010 {
    .code = {Category::Obfuscation, 10},
    .name = "Compressed base64 payload",
    .description = "Detects gzuncompress() with base64_decode()",
    .severity = Severity::High,
    .patterns = detail_OBF010::patterns,
};

// OBF011: rawurldecode with base64
namespace detail_OBF011 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(rawurldecode\s*\(\s*base64_decode)">(),
          "rawurldecode+base64", false },
    };
}
const BuiltinRule OBF011 {
    .code = {Category::Obfuscation, 11},
    .name = "URL-encoded base64 payload",
    .description = "Detects rawurldecode() with base64_decode()",
    .severity = Severity::Medium,
    .patterns = detail_OBF011::patterns,
};

// OBF012: Suspicious variable variable ($$)
namespace detail_OBF012 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(\$\{\s*\$\w+\s*\}\s*\()">(),
          "Variable variable call", false },
    };
}
const BuiltinRule OBF012 {
    .code = {Category::Obfuscation, 12},
    .name = "Variable variable function call",
    .description = "Detects function calls using variable variables",
    .severity = Severity::High,
    .patterns = detail_OBF012::patterns,
};

// OBF013: extract() with user input
namespace detail_OBF013 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE))">(),
          "extract with user input", false },
    };
}
const BuiltinRule OBF013 {
    .code = {Category::Obfuscation, 13},
    .name = "extract() with user input",
    .description = "Detects extract() that can overwrite variables from user input",
    .severity = Severity::High,
    .patterns = detail_OBF013::patterns,
};

// OBF014: Rot13 encoding
namespace detail_OBF014 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(str_rot13\s*\(\s*['"][^'"]{20,}['"])">(),
          "str_rot13 encoded string", false },
    };
}
const BuiltinRule OBF014 {
    .code = {Category::Obfuscation, 14},
    .name = "ROT13 encoded payload",
    .description = "Detects str_rot13() with suspicious payload",
    .severity = Severity::Medium,
    .patterns = detail_OBF014::patterns,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &OBF001, &OBF002, &OBF003, &OBF004, &OBF005,
    &OBF006, &OBF007, &OBF008, &OBF009, &OBF010,
    &OBF011, &OBF012, &OBF013, &OBF014
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::obfuscation
