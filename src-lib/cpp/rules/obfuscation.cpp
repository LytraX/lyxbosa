#include "obfuscation.h"
#include <array>

namespace lyxbosa::rules::obfuscation {

// OBF001: Hex-encoded variable names
namespace detail_OBF001 {
    static constexpr Pattern patterns[] = {
        { R"(\$GLOBALS\s*\[\s*['"]\\x[0-9a-fA-F]{2})",
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
        { R"(chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr)",
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
        { R"(pack\s*\(\s*['"]H\*['"]\s*,\s*['"][0-9a-fA-F]{20,}['"])",
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

// OBF004: Very long base64 strings being decoded
// Plain base64 strings are common in legitimate code (fonts, images, crypto keys)
// Only flag when combined with base64_decode() - actual obfuscation intent
namespace detail_OBF004 {
    static constexpr Pattern patterns[] = {
        // base64_decode with inline long string
        { R"(base64_decode\s*\(\s*['"][A-Za-z0-9+/]{500,}={0,2}['"])",
          "base64_decode with long payload", false },
        // Variable assigned from base64_decode of long string
        { R"(\$\w+\s*=\s*base64_decode\s*\(\s*['"][A-Za-z0-9+/]{300,})",
          "Variable from decoded base64", false },
    };
}
const BuiltinRule OBF004 {
    .code = {Category::Obfuscation, 4},
    .name = "Long base64 decode",
    .description = "Detects base64_decode() with long encoded payloads",
    .severity = Severity::Medium,
    .patterns = detail_OBF004::patterns,
};

// OBF005: strrev obfuscation with string literal concatenation
// Malware uses strrev() with concatenated STRING LITERALS to hide function names:
// - strrev("noi"."tcnuf"."_eta"."erc") = create_function
// Legitimate usage: strrev($var . $other) - uses variables, not literals
// Key difference: malicious has "literal"."literal", legitimate has $var . $var
namespace detail_OBF005 {
    static constexpr Pattern patterns[] = {
        // strrev with 2+ concatenated string literals (quoted strings joined by .)
        // Pattern: strrev( ... "..." . "..." ... )
        { R"(strrev\s*\([^)]*["'][^"']*["']\s*\.\s*["'][^"']*["'][^)]*\))",
          "strrev with literal concatenation", false },
    };
}
const BuiltinRule OBF005 {
    .code = {Category::Obfuscation, 5},
    .name = "strrev() function hiding",
    .description = "Detects strrev() with concatenated string literals to hide function names",
    .severity = Severity::Critical,
    .patterns = detail_OBF005::patterns,
};

// OBF006: String concatenation to build function name
namespace detail_OBF006 {
    static constexpr Pattern patterns[] = {
        { R"(\$\w+\s*=\s*['"][a-z]{1,4}['"]\s*\.\s*['"][a-z]{1,4}['"]\s*\.\s*['"][a-z]{1,4}['"])",
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
        { R"(\$\w+\[\d+\]\s*\(\s*\$\w+\[\d+\])",
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
        { R"(str_replace\s*\(\s*['"][^'"]+['"]\s*,\s*['"]['"]?\s*,\s*['"](e|ba|as|ev|sy|ex)[^'"]+['"])",
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
        { R"(base64_decode\s*\(\s*base64_decode)",
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
        { R"(gzuncompress\s*\(\s*base64_decode)",
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
        { R"(rawurldecode\s*\(\s*base64_decode)",
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
        { R"(\$\{\s*\$\w+\s*\}\s*\()",
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
        { R"(extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE))",
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
        { R"(str_rot13\s*\(\s*['"][^'"]{20,}['"])",
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

// OBF015: Excessive goto statements (goto obfuscation)
// This technique uses many goto labels to make code flow unreadable
// Malicious: mixed case like uSX2KSIiDgl, V2mVgtmQnwI (random-looking)
// Legitimate: ALL_UPPERCASE with underscores (like SCANNER_TOP)
namespace detail_OBF015 {
    static constexpr Pattern patterns[] = {
        // Labels must contain mixed case (lowercase followed by uppercase somewhere)
        // This excludes SCANNER_TOP style labels which are all uppercase
        { R"(goto\s+[a-zA-Z0-9]*[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*;\s+[a-zA-Z0-9]*[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*:)",
          "Multiple goto jumps with mixed-case labels", false },
    };
}
const BuiltinRule OBF015 {
    .code = {Category::Obfuscation, 15},
    .name = "Goto obfuscation",
    .description = "Detects excessive goto statements used to obfuscate code flow",
    .severity = Severity::Critical,
    .patterns = detail_OBF015::patterns,
};

// OBF016: Octal string encoding
// Malware uses \62\65\65 style encoding to hide strings
namespace detail_OBF016 {
    static constexpr Pattern patterns[] = {
        // 8+ consecutive octal escapes = obfuscated string
        { R"((\\[0-7]{2,3}){8,})",
          "Heavy octal string encoding", false },
    };
}
const BuiltinRule OBF016 {
    .code = {Category::Obfuscation, 16},
    .name = "Octal-encoded strings",
    .description = "Detects strings heavily encoded with octal escapes",
    .severity = Severity::High,
    .patterns = detail_OBF016::patterns,
};

// OBF017: Variable function call pattern (decode to variable, then call)
// Extremely common in advanced webshells - decode function name then call it:
//   $var = decryptFunc("encoded"); return $var($param);
// This pattern is almost never legitimate - normal code calls functions directly
namespace detail_OBF017 {
    static constexpr Pattern patterns[] = {
        // Pattern: $var = func("..."); return $var(
        // Captures: decode something into variable, then immediately call that variable
        { R"(\$\w+\s*=\s*\w+\s*\(\s*["'][^"']+["']\s*\)\s*;\s*return\s+\$\w+\s*\()",
          "Decoded variable function call", false },
    };
}
const BuiltinRule OBF017 {
    .code = {Category::Obfuscation, 17},
    .name = "Variable function call",
    .description = "Detects pattern where decoded string is called as function",
    .severity = Severity::Critical,
    .patterns = detail_OBF017::patterns,
};

// OBF020: Double decode obfuscation (rot13 + urldecode or similar)
// Malware uses nested decode functions to hide C2 domains and payloads
// Pattern: str_rot13(urldecode($var)) or urldecode(str_rot13($var))
// Also covers: base64_decode(str_rot13(...)) and similar combos
namespace detail_OBF020 {
    static constexpr Pattern patterns[] = {
        // str_rot13(urldecode(...))
        { R"(str_rot13\s*\(\s*urldecode\s*\()",
          "ROT13+urldecode obfuscation", false },
        // urldecode(str_rot13(...))
        { R"(urldecode\s*\(\s*str_rot13\s*\()",
          "urldecode+ROT13 obfuscation", false },
        // base64_decode(str_rot13(...))
        { R"(base64_decode\s*\(\s*str_rot13\s*\()",
          "base64+ROT13 obfuscation", false },
        // str_rot13(base64_decode(...))
        { R"(str_rot13\s*\(\s*base64_decode\s*\()",
          "ROT13+base64 obfuscation", false },
    };
}
const BuiltinRule OBF020 {
    .code = {Category::Obfuscation, 20},
    .name = "Double decode obfuscation",
    .description = "Detects nested encoding functions to hide malicious content",
    .severity = Severity::High,
    .patterns = detail_OBF020::patterns,
};

// OBF021: Double variable function call
// Pattern: $var1($var2) where function and argument are both variables
// Common in webshells: $y1($y2) executes arbitrary function with arbitrary argument
// This is extremely dangerous when variables come from user input
namespace detail_OBF021 {
    static constexpr Pattern patterns[] = {
        // Short variable names calling each other: $a($b) or $y1($y2)
        // These short names are suspicious - legitimate code uses descriptive names
        { R"(\$[a-z][0-9]?\s*\(\s*\$[a-z][0-9]?\s*\))",
          "Double variable function call", false },
    };
}
const BuiltinRule OBF021 {
    .code = {Category::Obfuscation, 21},
    .name = "Double variable function call",
    .description = "Detects $var1($var2) pattern - arbitrary function execution",
    .severity = Severity::Critical,
    .patterns = detail_OBF021::patterns,
};

// OBF018: Custom decryption function with base64 + XOR loop
// Webshells often include a custom decrypt function like:
//   function name($param) { $param=base64_decode($param); ... while(true) { ... chr(...) ... } }
// The key indicators: base64_decode + while/for loop + chr() + XOR (^)
namespace detail_OBF018 {
    static constexpr Pattern patterns[] = {
        // Function containing base64_decode with XOR and chr in a loop
        { R"(function\s+\w+\s*\([^)]*\)\s*\{[^}]*base64_decode[^}]*while[^}]*chr[^}]*\^)",
          "Custom decryption function with base64+XOR", false },
        // Alternative: for loop variant
        { R"(function\s+\w+\s*\([^)]*\)\s*\{[^}]*base64_decode[^}]*for[^}]*chr[^}]*\^)",
          "Custom decryption function with base64+XOR loop", false },
    };
}
const BuiltinRule OBF018 {
    .code = {Category::Obfuscation, 18},
    .name = "Custom decryption function",
    .description = "Detects custom functions combining base64, XOR, and chr() decryption",
    .severity = Severity::Critical,
    .patterns = detail_OBF018::patterns,
};

// OBF019: Arithmetic obfuscation (complex arithmetic for simple values)
// Malware uses expressions like: (-53524+54229+52996) = 53701 or (930-(-25632)+188)
// Indicators: large numbers, negative numbers in parentheses, multiple operations
// This makes static analysis difficult
namespace detail_OBF019 {
    static constexpr Pattern patterns[] = {
        // Large number arithmetic: (1234-5678+9012) or (-1234+5678-9012)
        // Multiple ops with numbers > 1000
        { R"(\(-?\d{4,}\s*[+\-]\s*\(?\-?\d{3,}\)?\s*[+\-]\s*\(?\-?\d{3,}\)?)",
          "Arithmetic obfuscation", false },
    };
}
const BuiltinRule OBF019 {
    .code = {Category::Obfuscation, 19},
    .name = "Arithmetic obfuscation",
    .description = "Detects complex arithmetic expressions hiding simple values",
    .severity = Severity::Medium,
    .patterns = detail_OBF019::patterns,
};

// OBF022: Hex variable variable syntax
// Malware uses ${"\x47\x4c\x4f\x42\x41\x4c\x53"} = $GLOBALS
// This is ALWAYS malicious - legitimate code never uses hex escapes for variable names
namespace detail_OBF022 {
    static constexpr Pattern patterns[] = {
        // ${"\x...} variable variable with hex escapes
        { R"(\$\{["']\\x[0-9a-fA-F]{2})",
          "Hex variable variable syntax", false },
    };
}
const BuiltinRule OBF022 {
    .code = {Category::Obfuscation, 22},
    .name = "Hex variable variable",
    .description = "Detects ${\"\\x..\"} hex-encoded variable names",
    .severity = Severity::Critical,
    .patterns = detail_OBF022::patterns,
};

// OBF023: GLOBALS array string building
// Malware builds strings by concatenating GLOBALS array elements:
//   $GLOBALS['key'][0].$GLOBALS['key'][1].$GLOBALS['key'][2]
// This hides function names and strings from static analysis
namespace detail_OBF023 {
    static constexpr Pattern patterns[] = {
        // 3+ consecutive GLOBALS array index concatenations
        { R"(\$GLOBALS\s*\[[^]]+\]\s*\[\s*\d+\s*\]\s*\.\s*\$GLOBALS\s*\[[^]]+\]\s*\[\s*\d+\s*\]\s*\.\s*\$GLOBALS)",
          "GLOBALS array string building", false },
    };
}
const BuiltinRule OBF023 {
    .code = {Category::Obfuscation, 23},
    .name = "GLOBALS array concatenation",
    .description = "Detects string building via GLOBALS array index concatenation",
    .severity = Severity::Critical,
    .patterns = detail_OBF023::patterns,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &OBF001, &OBF002, &OBF003, &OBF004, &OBF005,
    &OBF006, &OBF007, &OBF008, &OBF009, &OBF010,
    &OBF011, &OBF012, &OBF013, &OBF014, &OBF015, &OBF016,
    &OBF017, &OBF018, &OBF019, &OBF020, &OBF021, &OBF022, &OBF023
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::obfuscation
