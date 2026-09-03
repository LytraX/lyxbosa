#include "obfuscation.h"
#include "analysis/StringAssembly.h"
#include <array>
#include <cctype>
#include <fmt/format.h>
#include <string>

namespace lyxbosa::rules::obfuscation {

// OBF001: Hex-encoded variable names
namespace detail_OBF001 {
    static constexpr Pattern patterns[] = {
        { R"(\$GLOBALS\s*\[\s*['"]\\x[0-9a-fA-F]{2})",
          "Hex-encoded GLOBALS access", false,
          {"globals"} },
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
        { R"((?i:chr)\s*\(\s*\d+\s*\)\s*\.\s*(?i:chr)\s*\(\s*\d+\s*\)\s*\.\s*(?i:chr)\s*\(\s*\d+\s*\)\s*\.\s*(?i:chr))",
          "chr() string concatenation", false,
          {"chr"} },
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
        { R"((?i:pack)\s*\(\s*['"]H\*['"]\s*,\s*['"][0-9a-fA-F]{20,}['"])",
          "pack() hex decoding", false,
          {"pack"} },
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
        { R"((?i:base64_decode)\s*\(\s*['"][A-Za-z0-9+/]{500,}={0,2}['"])",
          "base64_decode with long payload", false,
          {"base64_decode"} },
        // Variable assigned from base64_decode of long string
        { R"(\$\w+\s*=\s*(?i:base64_decode)\s*\(\s*['"][A-Za-z0-9+/]{300,})",
          "Variable from decoded base64", false,
          {"base64_decode"} },
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
        { R"((?i:strrev)\s*\([^)]*["'][^"']*["']\s*\.\s*["'][^"']*["'][^)]*\))",
          "strrev with literal concatenation", false,
          {"strrev"} },
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
        { R"((?i:str_replace)\s*\(\s*['"][^'"]+['"]\s*,\s*['"]['"]?\s*,\s*['"](e|ba|as|ev|sy|ex)[^'"]+['"])",
          "str_replace function name building", false,
          {"str_replace"} },
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
        { R"((?i:base64_decode)\s*\(\s*(?i:base64_decode))",
          "Nested base64_decode", false,
          {"base64_decode"} },
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
        { R"((?i:gzuncompress)\s*\(\s*(?i:base64_decode))",
          "gzuncompress+base64", false,
          {"gzuncompress"} },
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
        { R"((?i:rawurldecode)\s*\(\s*(?i:base64_decode))",
          "rawurldecode+base64", false,
          {"rawurldecode"} },
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
          "Variable variable call", false,
          {"${"} },
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
        { R"((?i:extract)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE))",
          "extract with user input", false,
          {"extract", "$_get|$_post|$_request|$_cookie"} },
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
        { R"((?i:str_rot13)\s*\(\s*['"][^'"]{20,}['"])",
          "str_rot13 encoded string", false,
          {"str_rot13"} },
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
        // This excludes SCANNER_TOP style labels which are all uppercase.
        //
        // The separator is \s* rather than \s+: emitters differ on whether they put
        // a space after the semicolon, and one that does not
        //     goto kPpzye;LQL4spRSOK: tQtVYGj1();
        // was invisible to this rule while carrying 52 jumps. Relaxing it adds 74
        // detections in the labelled corpus for no false positive on CMS or Sites -
        // the two mixed-case identifiers either side of the ';' carry the precision.
        { R"(goto\s+[a-zA-Z0-9]*[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*;\s*[a-zA-Z0-9]*[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*:)",
          "Multiple goto jumps with mixed-case labels", false,
          {"goto"} },
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
          "Decoded variable function call", false,
          {"return"} },
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
        { R"((?i:str_rot13)\s*\(\s*(?i:urldecode)\s*\()",
          "ROT13+urldecode obfuscation", false,
          {"urldecode", "str_rot13"} },
        // urldecode(str_rot13(...))
        { R"((?i:urldecode)\s*\(\s*(?i:str_rot13)\s*\()",
          "urldecode+ROT13 obfuscation", false,
          {"urldecode", "str_rot13"} },
        // base64_decode(str_rot13(...))
        { R"((?i:base64_decode)\s*\(\s*(?i:str_rot13)\s*\()",
          "base64+ROT13 obfuscation", false,
          {"base64_decode", "str_rot13"} },
        // str_rot13(base64_decode(...))
        { R"((?i:str_rot13)\s*\(\s*(?i:base64_decode)\s*\()",
          "ROT13+base64 obfuscation", false,
          {"base64_decode", "str_rot13"} },
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
        { R"(function\s+\w+\s*\([^)]*\)\s*\{[^}]*(?i:base64_decode)[^}]*while[^}]*(?i:chr)[^}]*\^)",
          "Custom decryption function with base64+XOR", false,
          {"base64_decode", "function", "while"} },
        // Alternative: for loop variant
        { R"(function\s+\w+\s*\([^)]*\)\s*\{[^}]*(?i:base64_decode)[^}]*for[^}]*(?i:chr)[^}]*\^)",
          "Custom decryption function with base64+XOR loop", false,
          {"base64_decode", "function"} },
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
//
// "Legitimate code never uses hex escapes for variable names" is true of PHP - but `${` also
// opens a JavaScript template-literal substitution, and there the braces hold an arbitrary
// expression. WordPress core's block-editor.js writes
// `${"\xB6".repeat(value.length - 2)}` to pad a CSS selector display, which made 24 copies
// of a 2.8 MB core asset critical findings.
//
// The brace content is the discriminator, not the file extension: a PHP variable-variable
// holds nothing but the escaped string, whereas the JavaScript case is always a call or an
// operator. Requiring the closing brace to follow the literal directly separates them
// without having to guess the language from the path.
namespace detail_OBF022 {
    static constexpr Pattern patterns[] = {
        // ${"\x47\x4c..."} - the whole brace content is one hex-escaped string literal.
        // Spelled as an alternation rather than a backreferenced quote, because RE2 has no
        // backreferences and would leave the pattern silently uncompiled.
        { R"(\$\{\s*(?:"(?:\\x[0-9a-fA-F]{2})+"|'(?:\\x[0-9a-fA-F]{2})+')\s*\})",
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
          "GLOBALS array string building", false,
          {"globals"} },
    };
}
const BuiltinRule OBF023 {
    .code = {Category::Obfuscation, 23},
    .name = "GLOBALS array concatenation",
    .description = "Detects string building via GLOBALS array index concatenation",
    .severity = Severity::Critical,
    .patterns = detail_OBF023::patterns,
};

// OBF024 / OBF025: identifiers the code assembles at runtime
//
// The generic form of OBF005/OBF006/OBF008: instead of matching one particular
// way of cutting up a function name, fold the expression and look at the result.
//   $f="ba"; $h="s"; $l="e"; $n="64";
//   $o=$f.$h.$l.$n."_d".$l."cod".$l;          -> "base64_decode"
//   $s="as"; $s.="sert"; @$s(...);            -> "assert"
//   strrev("edoced_46esab")                   -> "base64_decode"
//   implode("", array("ba","se","64_decode")) -> "base64_decode"
//   chr(101).chr(118).chr(97).chr(108)        -> "eval"
// Any cut, any mix of literals and variables, any of the pure string builtins
// the folder understands. What matters is the value that comes out and how many
// separate pieces it was written in.
namespace detail_assembly {
    // Never emit more than this per file - one obfuscated file can hold hundreds
    constexpr size_t MAX_FINDINGS = 20;

    // A sensitive name written as exactly two adjacent literals ('base64' . '_decode')
    // is the weak end of the technique: malware uses it, but so do plugins splitting
    // names to get past WordPress.org's review scanners. OBF025 reports those.
    bool isPlainLiteralSplit(const analysis::AssembledString& assembled) {
        return assembled.sensitive && assembled.fragments == 2 &&
               assembled.transforms == 0 && !assembled.viaVariables;
    }

    std::string describe(const analysis::AssembledString& assembled, std::string_view reason) {
        std::string note = "Assembles \"" + assembled.value + "\" at runtime";

        if (assembled.fragments >= 2) {
            note += " from " + std::to_string(assembled.fragments) + " fragments";
        }
        if (assembled.transforms > 0) {
            note += (assembled.fragments >= 2 ? " and " : " via ") +
                    std::to_string(assembled.transforms) + " decode/transform call" +
                    (assembled.transforms == 1 ? "" : "s");
        }

        note += " - ";
        note += reason;
        return note;
    }

    MatchResult toMatch(std::string_view content, const analysis::AssembledString& assembled,
                        std::string_view reason) {
        auto [line, column] = positionToLineCol(content, assembled.offset);

        MatchResult result;
        result.line = line;
        result.column = column;
        result.matched = content.substr(assembled.offset, assembled.length);
        result.note = describe(assembled, reason);
        return result;
    }

    std::vector<MatchResult> detectAssembled(std::string_view content) {
        std::vector<MatchResult> results;

        for (const auto& assembled : analysis::findAssembledStrings(content)) {
            std::string_view reason;

            if (assembled.sensitive && !isPlainLiteralSplit(assembled)) {
                // A name on the sensitive list, never written out in one piece
                reason = "a security-sensitive PHP identifier";
            } else if (assembled.fragments >= 3 && !assembled.variable.empty() &&
                       analysis::isDynamicallyCalled(content, assembled.variable)) {
                // Unknown name, but the result is what gets called
                reason = "an identifier that is then called dynamically";
            } else if (assembled.fragments >= 5 && assembled.value.size() >= 8 &&
                       assembled.value.size() / assembled.fragments <= 3) {
                // Nobody splits an identifier into this many tiny pieces by accident
                reason = "an identifier split into single-character fragments";
            } else {
                continue;
            }

            results.push_back(toMatch(content, assembled, reason));
            if (results.size() >= MAX_FINDINGS) break;
        }

        return results;
    }

    std::vector<MatchResult> detectLiteralSplit(std::string_view content) {
        std::vector<MatchResult> results;

        for (const auto& assembled : analysis::findAssembledStrings(content)) {
            if (!isPlainLiteralSplit(assembled)) continue;

            results.push_back(toMatch(content, assembled,
                "a security-sensitive PHP identifier written as two literals"));
            if (results.size() >= MAX_FINDINGS) break;
        }

        return results;
    }
}
const BuiltinRule OBF024 {
    .code = {Category::Obfuscation, 24},
    .name = "Runtime-assembled identifier",
    .description = "Detects function names built at runtime from fragments to evade signature matching",
    .severity = Severity::Critical,
    .patterns = {},
    .analyzer = &detail_assembly::detectAssembled,
};

// OBF025: the low-confidence half of OBF024 - a sensitive name split across two
// adjacent literals, with no variables and no decoding in between.
const BuiltinRule OBF025 {
    .code = {Category::Obfuscation, 25},
    .name = "Split sensitive function name",
    .description = "Detects sensitive function names written as two concatenated literals to avoid review scanners",
    .severity = Severity::Medium,
    .patterns = {},
    .analyzer = &detail_assembly::detectLiteralSplit,
};

// OBF036: binary payload embedded in a file that declares itself as text
//
// A .php/.js/.html file is source. Bytes that cannot occur in source - NUL and the
// other C0 controls - mean something non-source is stored in it: an encrypted stage,
// a raw deflate stream, or an appended blob the PHP half decodes at runtime.
//
// The metric counts ONLY C0 control bytes (minus \t \n \r \f) plus DEL. It deliberately
// ignores every byte >= 0x80, because that is what UTF-8 text is made of. Greek,
// Japanese, Chinese, Korean, Arabic, Hebrew, Thai, Devanagari, emoji (ZWJ sequences
// included), combining marks and box-drawing all measure exactly 0.000% - verified
// against the full set before this rule was written. A rule that counted "non-ASCII"
// would flag every translated string table in the tree.
//
// UTF-16/UTF-32 are the one real trap: their ASCII range is half NUL bytes, so a
// UTF-16 source file would score ~50%. Those are detected by BOM or by the
// alternating-NUL signature and exempted before any measurement happens.
//
// The ratio alone is not enough, because a *byte table* also scores above it. Symfony's
// polyfill-iconv charset maps (`from.us-ascii.php`) list every byte value 0x00-0x1F as an
// array key, and captured terminal output stores its ANSI bytes one at a time; both clear
// 2% while containing no payload at all. What separates them is adjacency, not density:
// see kMinAdjacent below.
namespace detail_OBF036 {
    constexpr double kRatioThreshold = 0.02;   // 2% of the file
    constexpr size_t kMinControlBytes = 8;     // ignore a stray control in a short file
    constexpr size_t kMinSize = 64;

    // A stored payload - deflate stream, ciphertext, serialised descriptor - has a roughly
    // uniform byte distribution, so its control bytes land next to each other: ~11% of byte
    // values are counted-control, so ~21% of them have a control neighbour. A byte table has
    // none, because every control byte is separated by the `=>` and `,` around it. Measured
    // over this corpus: every one of the 50 real payloads scores >=5 adjacent pairs and
    // >=9.8% adjacency, while the iconv tables and the nvm terminal-output fixtures score
    // exactly 0 on both.
    //
    // Do NOT replace this with "require a long contiguous run". The payloads here are dense
    // in *high* bytes, which this rule deliberately never counts, so their longest run of
    // counted-control bytes is only 3-7. A >=32 run test scores 42 of 43 known payloads as
    // clean while leaving the AppleDouble stubs (longest run 38) flagged - exactly backwards.
    constexpr size_t kMinAdjacent = 2;
    constexpr double kMinAdjacentRatio = 0.02;

    inline bool isControl(unsigned char c) {
        // C0 controls except tab (9), LF (10), FF (12), CR (13); plus DEL (127).
        return (c < 9) || (c == 11) || (c > 13 && c < 32) || (c == 127);
    }

    // UTF-16/32 text is not a binary payload - exempt it before measuring.
    bool looksLikeWideEncoding(std::string_view c) {
        const auto* p = reinterpret_cast<const unsigned char*>(c.data());
        if (c.size() >= 2) {
            if ((p[0] == 0xFF && p[1] == 0xFE) || (p[0] == 0xFE && p[1] == 0xFF)) return true;
        }
        if (c.size() >= 4 && p[0] == 0 && p[1] == 0 && p[2] == 0xFE && p[3] == 0xFF) return true;

        // No BOM: UTF-16 ASCII alternates value/NUL. Sample the head and look for that
        // regularity rather than for NUL bytes as such.
        size_t sample = std::min<size_t>(c.size(), 512);
        if (sample < 16) return false;
        size_t evenNul = 0, oddNul = 0;
        for (size_t i = 0; i + 1 < sample; i += 2) {
            if (p[i] == 0) ++evenNul;
            if (p[i + 1] == 0) ++oddNul;
        }
        size_t pairs = sample / 2;
        return (evenNul * 10 >= pairs * 9) || (oddNul * 10 >= pairs * 9);
    }

    std::vector<MatchResult> detectBinaryInText(std::string_view content) {
        std::vector<MatchResult> out;
        if (content.size() < kMinSize) return out;
        if (looksLikeWideEncoding(content)) return out;

        size_t controls = 0;
        size_t adjacent = 0;
        size_t firstOffset = content.size();
        bool prevWasControl = false;
        for (size_t i = 0; i < content.size(); ++i) {
            const bool isCtl = isControl(static_cast<unsigned char>(content[i]));
            if (isCtl) {
                if (controls == 0) firstOffset = i;
                ++controls;
                if (prevWasControl) ++adjacent;
            }
            prevWasControl = isCtl;
        }

        if (controls < kMinControlBytes) return out;
        double ratio = static_cast<double>(controls) / static_cast<double>(content.size());
        if (ratio <= kRatioThreshold) return out;

        // Isolated control bytes are a table or escaped text, not a stored blob.
        double adjacentRatio = static_cast<double>(adjacent) / static_cast<double>(controls);
        if (adjacent < kMinAdjacent || adjacentRatio < kMinAdjacentRatio) return out;

        auto [line, col] = positionToLineCol(content, firstOffset);
        MatchResult r;
        r.line = line;
        r.column = col;
        r.matched = std::string_view(content.data() + firstOffset, 1);
        r.note = "Source file carries " + std::to_string(controls) +
                 " control bytes (" + fmt::format("{:.1f}", ratio * 100.0) +
                 "% of file, " + fmt::format("{:.0f}", adjacentRatio * 100.0) +
                 "% adjacent) - a binary payload is stored inside declared text";
        out.push_back(r);
        return out;
    }
}
const BuiltinRule OBF036 {
    .code = {Category::Obfuscation, 36},
    .name = "Binary payload in text file",
    .description = "Detects binary/control-byte content embedded in a file whose type declares it as source text",
    .severity = Severity::High,
    .patterns = {},
    .analyzer = &detail_OBF036::detectBinaryInText,
};

// OBF037: a single escaped run that mixes octal and hex
//
// OBF016 wants 8+ *consecutive octal* escapes. An emitter that alternates the two
// notations slips between it and any hex-only rule:
//
//     echo "\74\144\x69\166\x3e\x3c\x69\156\160\165\x74";
//
// 98 octal and 73 hex escapes in that file, and never eight octal in a row.
//
// Mixing is the signal. Hand-written code picks a convention and keeps it; only a
// generator randomises the notation per character. Requiring both styles inside one
// run is what makes this safe - a plain "8+ escapes of either kind" rule costs 32
// false positives on stock CMS and 27 on a real site (binary constants in getID3,
// phpseclib and minified JS), and this costs none.
namespace detail_OBF037 {
    constexpr size_t kMinRun = 8;     // escapes in one uninterrupted run
    constexpr size_t kMinEach = 2;    // ...of which at least this many in each style

    std::vector<MatchResult> detectMixedEscapes(std::string_view content) {
        std::vector<MatchResult> out;

        size_t i = 0;
        while (i + 1 < content.size()) {
            if (content[i] != '\\') { ++i; continue; }

            const size_t runStart = i;
            size_t octal = 0, hex = 0;

            for (;;) {
                if (i + 1 >= content.size() || content[i] != '\\') break;

                const char c = content[i + 1];
                if (c == 'x' || c == 'X') {
                    size_t digits = 0;
                    while (digits < 2 && i + 2 + digits < content.size() &&
                           std::isxdigit(static_cast<unsigned char>(content[i + 2 + digits]))) {
                        ++digits;
                    }
                    if (digits < 2) break;
                    ++hex;
                    i += 2 + digits;
                } else if (c >= '0' && c <= '7') {
                    size_t digits = 0;
                    while (digits < 3 && i + 1 + digits < content.size() &&
                           content[i + 1 + digits] >= '0' && content[i + 1 + digits] <= '7') {
                        ++digits;
                    }
                    if (digits < 2) break;
                    ++octal;
                    i += 1 + digits;
                } else {
                    break;
                }
            }

            if (octal + hex >= kMinRun && octal >= kMinEach && hex >= kMinEach) {
                auto [line, col] = positionToLineCol(content, runStart);
                MatchResult r;
                r.line = line;
                r.column = col;
                r.matched = content.substr(runStart, std::min<size_t>(i - runStart, 64));
                r.note = "String built from " + std::to_string(octal) + " octal and " +
                         std::to_string(hex) + " hex escapes interleaved in one literal";
                out.push_back(r);
                if (out.size() >= 20) return out;  // one file can hold hundreds
            }

            if (i == runStart) ++i;
        }

        return out;
    }
}
const BuiltinRule OBF037 {
    .code = {Category::Obfuscation, 37},
    .name = "Mixed octal/hex escaped string",
    .description = "Detects a string literal that interleaves octal and hex escapes, a generator-only pattern",
    .severity = Severity::High,
    .patterns = {},
    .analyzer = &detail_OBF037::detectMixedEscapes,
};

// OBF029: payload staged as a long run of small `.=` appends
//
// The technique defeats every length-based and adjacency-based rule at once. A
// 268 KB webshell on a live host was staged as 14,066 statements of
// `$z .= "Skdze";`, then decoded and run:
//
//     $z = "";  $z .= "Skdze";  $z .= "mVYY2";  ... (14,066 lines)
//     $fn = 'base64_decode';  $s1 = $fn($z);  $s2 = $fn($s1);  eval($s2);
//
// Nothing in the rule set saw it. RCE001 wants `eval(base64_decode(` adjacent, and
// here the call is `eval($s2)`. DRP007 wants one literal of 500+ base64 characters,
// and here there are 14,066 literals of five. OBF024/OBF025 fold *split* identifiers,
// and 'base64_decode' is written out whole. OBF017 wants `return $var(`.
//
// So match the staging itself. Four conditions, each closing a different way an
// honest program builds a string by appending:
//
//   * >=20 consecutive appends to the *same* variable. Interleaving another
//     variable ends the run, because building two strings in a loop is ordinary.
//   * at most 3 distinct fragment widths. This is the one that matters. A generator
//     cuts a payload into fixed-size pieces; hand-written HTML building
//     (`$html .= '<div>'; $html .= $title;`) has a different width every time, and
//     without this test a naive threshold of 12 cost 5 CMS and 15 Sites false
//     positives.
//   * fragments averaging under 16 characters. Real text accumulation appends
//     sentences and tags, not syllables.
//   * the joined result is pure base64 alphabet. It is a payload, not prose.
namespace detail_OBF029 {
    constexpr size_t kMinRun = 20;
    constexpr size_t kMaxDistinctWidths = 3;
    constexpr size_t kMaxMeanWidth = 16;

    inline bool isBase64Byte(unsigned char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
    }

    // One `$name .= "literal";` statement starting at or after `pos`.
    struct Append {
        size_t start = 0;       // offset of the '$'
        size_t end = 0;         // one past the closing quote
        std::string_view name;  // variable name, without the '$'
        size_t width = 0;       // literal length
        bool base64 = true;     // literal is entirely base64 alphabet
    };

    // Parses an append at exactly `i`, or returns false. Deliberately strict: this
    // is a shape test, and anything it cannot read is not the shape.
    bool parseAppend(std::string_view c, size_t i, Append& out) {
        const size_t start = i;
        if (i >= c.size() || c[i] != '$') return false;
        ++i;
        const size_t nameStart = i;
        while (i < c.size() && (std::isalnum(static_cast<unsigned char>(c[i])) || c[i] == '_')) ++i;
        if (i == nameStart) return false;
        const std::string_view name = c.substr(nameStart, i - nameStart);

        while (i < c.size() && (c[i] == ' ' || c[i] == '\t')) ++i;
        if (i + 1 >= c.size() || c[i] != '.' || c[i + 1] != '=') return false;
        i += 2;
        while (i < c.size() && (c[i] == ' ' || c[i] == '\t')) ++i;

        if (i >= c.size() || (c[i] != '"' && c[i] != '\'')) return false;
        const char quote = c[i];
        ++i;
        const size_t litStart = i;
        bool base64 = true;
        while (i < c.size() && c[i] != quote) {
            if (c[i] == '\\') return false;   // an escape means it is not a raw chunk
            if (!isBase64Byte(static_cast<unsigned char>(c[i]))) base64 = false;
            ++i;
        }
        if (i >= c.size()) return false;
        const size_t width = i - litStart;
        ++i;   // past the closing quote

        while (i < c.size() && (c[i] == ' ' || c[i] == '\t')) ++i;
        if (i >= c.size() || c[i] != ';') return false;
        ++i;

        out = Append{start, i, name, width, base64};
        return true;
    }

    std::vector<MatchResult> detectChunkAccumulation(std::string_view content) {
        std::vector<MatchResult> out;
        // Cheap guard first: this analyzer has no literal gate to sit behind, so it
        // runs on every file in the tree.
        if (content.find(".=") == std::string_view::npos) return out;

        size_t i = 0;
        while (i < content.size()) {
            Append first;
            if (!parseAppend(content, i, first)) { ++i; continue; }

            // Walk the run of appends to this same variable.
            std::vector<size_t> widths;
            size_t count = 0, totalWidth = 0;
            bool allBase64 = true;
            size_t cursor = first.start;
            Append a = first;
            const size_t runStart = first.start;
            size_t runEnd = first.end;

            while (true) {
                ++count;
                totalWidth += a.width;
                allBase64 = allBase64 && a.base64;
                if (std::find(widths.begin(), widths.end(), a.width) == widths.end()) {
                    widths.push_back(a.width);
                }
                runEnd = a.end;

                cursor = a.end;
                while (cursor < content.size() &&
                       (content[cursor] == ' ' || content[cursor] == '\t' ||
                        content[cursor] == '\r' || content[cursor] == '\n')) {
                    ++cursor;
                }
                Append next;
                if (!parseAppend(content, cursor, next) || next.name != first.name) break;
                a = next;
            }

            if (count >= kMinRun && allBase64 &&
                widths.size() <= kMaxDistinctWidths &&
                totalWidth / count < kMaxMeanWidth) {
                auto [line, col] = positionToLineCol(content, runStart);
                MatchResult r;
                r.line = line;
                r.column = col;
                r.matched = content.substr(runStart, std::min<size_t>(runEnd - runStart, 64));
                r.note = "Payload staged as " + std::to_string(count) +
                         " consecutive appends to $" + std::string(first.name) +
                         " of " + std::to_string(widths.size()) +
                         (widths.size() == 1 ? " width" : " widths") +
                         ", mean " + std::to_string(totalWidth / count) +
                         " base64 characters";
                out.push_back(r);
                if (out.size() >= 8) return out;
            }

            i = (runEnd > i) ? runEnd : i + 1;
        }

        return out;
    }
}
const BuiltinRule OBF029 {
    .code = {Category::Obfuscation, 29},
    .name = "Chunked payload accumulation",
    .description = "Detects a payload staged as a long run of small uniform .= appends to one variable",
    .severity = Severity::Critical,
    .patterns = {},
    .analyzer = &detail_OBF029::detectChunkAccumulation,
};

// OBF038: generated noise comments
//
// An obfuscator that wants to break every "identifier immediately followed by (",
// "bracket immediately followed by (" and constant-folding rule at once can do it
// by wedging a comment into every gap:
//
//     $evUV /*-9-mk%J,N3-*/// =/*- ╀⒬ qj╀⒬ -*/// "ra"/*-L>#$|d@^jy-*/// ."nge";
//
// Deobfuscated that is `$evUV = "ra"."nge";`, but no pattern in the rule set could
// see it, and neither could the string-assembly folder. Rather than chase the
// technique through every rule, match the noise itself: the comments are the tell.
//
// Three conditions together. A file needs many of them, they have to be short, and
// their contents have to be the kind of thing no author writes - symbol soup with no
// words in it. Minified assets carry long licence banners and sourcemap comments,
// which have plenty of words and are few; this wants the opposite of both.
namespace detail_OBF038 {
    constexpr size_t kMinComments = 10;
    constexpr size_t kMaxMeanLength = 64;
    constexpr double kMinNoiseShare = 0.7;
    constexpr size_t kMinNoisyLength = 8;
    constexpr double kMinDistinctShare = 0.7;

    // "Wordless" is necessary but nowhere near sufficient, and getting that wrong is
    // what a first cut of this rule did: `/****/` banner rules, `/* @var int */`
    // docblock fragments and `/* 1 << 128 */` arithmetic notes are all wordless, and
    // WordPress core alone carries dozens. 88 false positives across CMS and Sites.
    //
    // What generated filler actually looks like is *high character diversity in a
    // short span* - `-9-mk%J,N3-`, `-L>#$|d@^jy-` - or a run of non-ASCII symbols
    // picked to be visually noisy. A banner is one character repeated; a docblock
    // fragment reuses a small alphabet. Either signal alone is enough, because an
    // obfuscator that avoids non-ASCII still cannot avoid the entropy.
    bool looksGenerated(std::string_view body) {
        // Symbol soup: ⓸④✞⇟ and friends. No author writes this in a comment.
        //
        // A *single* non-ASCII codepoint is not soup, though: icon-font CSS documents
        // each glyph as `/* '\uE002' */`, which is one three-byte character between
        // quotes, and RevSlider ships fifty of them in one stylesheet. Require several
        // distinct ones, which is what a run of decorative symbols actually is.
        {
            size_t highBytes = 0;
            bool seenHigh[128] = {};
            size_t distinctHigh = 0;
            for (unsigned char ch : body) {
                if (ch < 0x80) continue;
                ++highBytes;
                if (!seenHigh[ch - 0x80]) { seenHigh[ch - 0x80] = true; ++distinctHigh; }
            }
            if (highBytes >= 6 && distinctHigh >= 4) return true;
            if (highBytes > 0) return false;   // some non-ASCII, but not soup
        }

        if (body.size() < kMinNoisyLength) return false;

        size_t letters = 0;
        for (char ch : body) {
            if (std::isalpha(static_cast<unsigned char>(ch))) {
                if (++letters >= 4) return false;   // four letters in a row is a word
            } else {
                letters = 0;
            }
        }

        bool seen[256] = {};
        size_t distinct = 0;
        for (unsigned char ch : body) {
            if (!seen[ch]) { seen[ch] = true; ++distinct; }
        }
        return static_cast<double>(distinct) >=
               kMinDistinctShare * static_cast<double>(body.size());
    }

    std::vector<MatchResult> detectNoiseComments(std::string_view content) {
        std::vector<MatchResult> out;
        if (content.find("/*") == std::string_view::npos) return out;

        size_t comments = 0, noisy = 0, totalLength = 0;
        size_t firstNoisy = std::string_view::npos;

        size_t i = 0;
        while ((i = content.find("/*", i)) != std::string_view::npos) {
            const size_t close = content.find("*/", i + 2);
            if (close == std::string_view::npos) break;
            const std::string_view body = content.substr(i + 2, close - i - 2);
            ++comments;
            totalLength += body.size();
            if (looksGenerated(body)) {
                if (firstNoisy == std::string_view::npos) firstNoisy = i;
                ++noisy;
            }
            i = close + 2;
        }

        if (comments < kMinComments) return out;
        if (totalLength / comments > kMaxMeanLength) return out;
        if (static_cast<double>(noisy) < kMinNoiseShare * static_cast<double>(comments)) return out;
        if (noisy < kMinComments) return out;

        auto [line, col] = positionToLineCol(content, firstNoisy);
        MatchResult r;
        r.line = line;
        r.column = col;
        r.matched = content.substr(firstNoisy, std::min<size_t>(48, content.size() - firstNoisy));
        r.note = std::to_string(noisy) + " of " + std::to_string(comments) +
                 " block comments carry no words, mean length " +
                 std::to_string(totalLength / comments) +
                 " - generated noise wedged between tokens to break signature matching";
        out.push_back(r);
        return out;
    }
}
const BuiltinRule OBF038 {
    .code = {Category::Obfuscation, 38},
    .name = "Generated noise comments",
    .description = "Detects wordless block comments wedged between tokens to defeat pattern matching",
    .severity = Severity::High,
    .patterns = {},
    .analyzer = &detail_OBF038::detectNoiseComments,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &OBF001, &OBF002, &OBF003, &OBF004, &OBF005,
    &OBF006, &OBF007, &OBF008, &OBF009, &OBF010,
    &OBF011, &OBF012, &OBF013, &OBF014, &OBF015, &OBF016,
    &OBF017, &OBF018, &OBF019, &OBF020, &OBF021, &OBF022, &OBF023,
    &OBF024, &OBF025, &OBF029, &OBF036, &OBF037, &OBF038
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::obfuscation
