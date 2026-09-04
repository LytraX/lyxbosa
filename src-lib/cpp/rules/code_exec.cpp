#include "code_exec.h"
#include <array>
#include <string>
#include <vector>

namespace lyxbosa::rules::code_exec {

// The gap between a function name and its opening paren.
//
// Every eval-family rule used to spell this `\s*`, which allows only whitespace -
// so wedging a comment in defeated all of them at once. A live sample ran
//
//     /********/ /*******//****/@/***//*!50000*/eval/***//********/ /*******/(...)
//
// and matched nothing at all. `/*!50000*/` is MySQL's versioned-comment form,
// which PHP reads as an ordinary comment; the rest is filler. Allowing comments in
// the gap closes the technique for the whole family in one place, at the cost of
// permitting something no legitimate code writes anyway.
#define LYX_GAP R"__((?:\s|/\*(?:[^*]|\*+[^*/])*\*+/)*)__"

// RCE001: eval with base64 decode
namespace detail_RCE001 {
    static constexpr Pattern patterns[] = {
        { R"((?i:eval))" LYX_GAP R"(\(\s*(?i:base64_decode))" LYX_GAP R"(\()",
          "eval(base64_decode(", false,
          {"base64_decode", "eval"} },
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
        { R"((?i:eval))" LYX_GAP R"(\(\s*(?i:gzinflate))" LYX_GAP R"(\()",
          "eval(gzinflate(", false,
          {"gzinflate", "eval"} },
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
// Pattern $func($_GET[...]) is malicious - direct user input to dynamic call
// But $this->$method($_GET['ID']) is common in WordPress admin tables (safe context)
// Match patterns at statement boundaries to exclude method calls
namespace detail_RCE003 {
    static constexpr Pattern patterns[] = {
        // $var( at statement start (after newline, semicolon, brace, or space)
        // This excludes ->$method( patterns because -> is not in the char class
        { R"([\n;{(\s]\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[)",
          "Dynamic call with user input", false,
          {"$_get|$_post|$_request|$_cookie"} },
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
        { R"((?i:eval))" LYX_GAP R"(\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[)",
          "eval with user input", false,
          {"eval", "$_get|$_post|$_request|$_cookie"} },
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
        { R"((?i:assert))" LYX_GAP R"(\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[)",
          "assert with user input", false,
          {"assert", "$_get|$_post|$_request|$_cookie"} },
    };
}
const BuiltinRule RCE005 {
    .code = {Category::CodeExec, 5},
    .name = "assert with user input",
    .description = "Detects assert() with user-controlled input (PHP code execution)",
    .severity = Severity::Critical,
    .patterns = detail_RCE005::patterns,
};

// RCE006: preg_replace with /e modifier (code execution)
// The /e modifier can be literal 'e' or hex-encoded '\x65'
namespace detail_RCE006 {
    static constexpr Pattern patterns[] = {
        // Literal /e modifier
        { R"((?i:preg_replace)\s*\(\s*['"]/[^/]+/[a-zA-Z]*e[a-zA-Z]*['"])",
          "preg_replace /e modifier", false,
          {"preg_replace"} },
        // Hex-encoded /e modifier (\x65 = 'e')
        { R"((?i:preg_replace)\s*\(\s*['"]/[^/]+/[^'"]*\\x65[^'"]*['"])",
          "preg_replace hex-encoded /e", false,
          {"preg_replace"} },
    };
}
const BuiltinRule RCE006 {
    .code = {Category::CodeExec, 6},
    .name = "preg_replace code execution",
    .description = "Detects preg_replace() with dangerous /e modifier",
    .severity = Severity::Critical,
    .patterns = detail_RCE006::patterns,
};

// RCE007: create_function (deprecated, dangerous)
namespace detail_RCE007 {
    static constexpr Pattern patterns[] = {
        { R"((?i:create_function)\s*\(\s*['"][^'"]*['"]\s*,\s*\$_(GET|POST|REQUEST))",
          "create_function with user input", false,
          {"create_function", "$_get|$_post|$_request"} },
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
//
// The function-name alternation must be anchored on the left. Unanchored, `exec` matches
// any identifier ending in it and `system` matches any word ending in "system", so
// `$db->exec($_POST['sql'])` and `wpvivid_backup_module_add_exec()` both read as shell
// execution. `[^A-Za-z0-9_$>:]` rejects an identifier tail, a variable, a `->` method call
// and a `::` static call; `^` covers a match at the very start of the file.
namespace detail_RCE008 {
    static constexpr Pattern patterns[] = {
        { R"((?:^|[^A-Za-z0-9_$>:])((?i:shell_exec)|(?i:system)|(?i:passthru)|(?i:exec)|(?i:popen))\s*\(\s*\$_(GET|POST|REQUEST|COOKIE))",
          "Shell command with user input", false,
          {"shell_exec|system|passthru|exec|popen", "$_get|$_post|$_request|$_cookie"} },
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
        { R"(`[^`]{0,500}\$_(GET|POST|REQUEST|COOKIE))",
          "Backtick with user input", false,
          {"$_get|$_post|$_request|$_cookie"} },
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
        { R"((?i:call_user_func)(_array)?\s*\(\s*\$_(GET|POST|REQUEST))",
          "call_user_func with user input", false,
          {"call_user_func", "$_get|$_post|$_request"} },
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
//
// The rule is about a *callback* coming from user input, so it has to respect where each
// function keeps its callback. array_map takes it first; array_filter and array_reduce take
// it second, and their first argument is the data. Matching a superglobal in the first
// position for all three read `array_filter($_POST['id'])` - which filters empty values out
// of an array and takes no callback at all - as arbitrary code execution, for 12 findings
// and no true positive on one production host.
namespace detail_RCE011 {
    static constexpr Pattern patterns[] = {
        // array_map(callback, array): the callback is the first argument.
        { R"((?i:array_map)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[)",
          "array_map callback from user input", false,
          {"array_map", "$_get|$_post|$_request|$_cookie"} },
        // array_filter(array, callback) / array_reduce(array, callback): second argument.
        // `[^,()]` and not `[^,)]`: the open paren has to be excluded too, or the data
        // argument swallows a nested call and the superglobal inside *it* is read as
        // the callback - `array_filter( array_map( 'absint', $_POST['imgs'] ) )` is a
        // sanitiser, and it matched.
        { R"(((?i:array_filter)|(?i:array_reduce))\s*\(\s*[^,()]*,\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[)",
          "Array callback from user input", false,
          {"array_filter|array_reduce", "$_get|$_post|$_request|$_cookie"} },
    };
}
const BuiltinRule RCE011 {
    .code = {Category::CodeExec, 11},
    .name = "Array function with user callback",
    .description = "Detects array functions with user-controlled callbacks",
    .severity = Severity::High,
    .patterns = detail_RCE011::patterns,
};

// RCE012: eval with hex2bin (hex-encoded code execution)
// Pattern: eval(hex2bin("...")) - hex string decodes to PHP code
// This is ALWAYS malicious - no legitimate use for eval(hex2bin())
namespace detail_RCE012 {
    static constexpr Pattern patterns[] = {
        { R"((?i:eval))" LYX_GAP R"(\(\s*(?i:hex2bin))" LYX_GAP R"(\()",
          "eval(hex2bin(", false,
          {"hex2bin", "eval"} },
    };
}
const BuiltinRule RCE012 {
    .code = {Category::CodeExec, 12},
    .name = "eval hex2bin",
    .description = "Detects eval() with hex2bin() - hex-encoded code execution",
    .severity = Severity::Critical,
    .patterns = detail_RCE012::patterns,
};

// RCE013: eval with php://input (direct backdoor)
// Pattern: eval(...file_get_contents('php://input')...) - executes HTTP POST body
// This is a PURE backdoor - attacker sends PHP code in request body
// Zero legitimate use cases for this pattern
// Note: json_decode(file_get_contents('php://input')) is LEGITIMATE (API JSON parsing)
namespace detail_RCE013 {
    static constexpr Pattern patterns[] = {
        // eval with file_get_contents('php://input')
        { R"((?i:eval)\s*\([^;]*(?i:file_get_contents)\s*\(\s*['"]php://input['"])",
          "eval with php://input", false,
          {"file_get_contents", "php://input", "eval"} },
    };
}
const BuiltinRule RCE013 {
    .code = {Category::CodeExec, 13},
    .name = "eval with php://input",
    .description = "Detects eval() with php://input - direct backdoor",
    .severity = Severity::Critical,
    .patterns = detail_RCE013::patterns,
};

// RCE014: eval over a decrypted payload
//
// No rule paired eval with a *cipher*. The sample that prompted this holds its
// payload as AES-128-ECB ciphertext and runs
// `eval(openssl_decrypt($data, 'AES-128-ECB', $kunci, 0))`, which every base64- and
// gzinflate-shaped rule walked straight past. Decrypting a string and executing the
// result has no honest use: a program that needs a secret decrypts data, not code.
namespace detail_RCE014 {
    static constexpr Pattern patterns[] = {
        { R"((?i:eval))" LYX_GAP R"(\(\s*(?:(?i:openssl_decrypt)|(?i:mcrypt_decrypt)|(?i:sodium_crypto_secretbox_open)|(?i:openssl_open)))" LYX_GAP R"(\()",
          "eval(<decrypt>(", false,
          {"eval", "openssl_decrypt|mcrypt_decrypt|sodium_crypto_secretbox_open|openssl_open"} },
    };
}
const BuiltinRule RCE014 {
    .code = {Category::CodeExec, 14},
    .name = "eval decrypted payload",
    .description = "Detects eval() over the result of a decryption call - executing ciphertext",
    .severity = Severity::Critical,
    .patterns = detail_RCE014::patterns,
};

// RCE015: eval implemented with the filesystem
//
// Every rule above this one keys on `eval` or a sibling that takes code as a string.
// A remote-loader family sidesteps all of them by never calling one. It writes the
// code it fetched to a path, includes the path, and deletes it:
//
//     $file_path = '.c';
//     file_put_contents($file_path, $code);      // $code came off the network
//     @require($file_path);
//     @unlink($file_path);
//
// This is `eval` with extra steps, and the steps are the point: it survives
// `disable_functions=eval`, it needs no `allow_url_include`, and it leaves nothing on
// disk for the next scan to find. Seven distinct blobs in the malware trees do it,
// with the include spelled `include`, `require` and `@require` between them.
//
// The rule is the three-way linkage on ONE path variable: written, included, then
// unlinked - in that order, close together. Each part alone is ordinary. 1,073 files
// in the benign trees include a bare variable, because that is how a plugin loads a
// template.
//
// What separates the malware is ordering and distance, and both were measured rather
// than guessed. Nine benign files put the same variable through an include and an
// unlink. In eight of the nine the unlink comes *before* the include and never after,
// so the delete-after-execute shape does not occur at all. In the ninth - OceanWP's
// theme panel, reusing the common name `$file` in two unrelated functions - the
// nearest following unlink is 10,738 bytes away. The malware's is 26. The window is
// 400 bytes: twenty-six times inside the nearest benign pair and fifteen times outside
// the malware's, which is margin rather than tuning.
//
// The write test is what takes those nine to zero on its own: not one of them ever
// passes that variable to `file_put_contents`, because a template a plugin includes
// is a file the plugin shipped, not one it just wrote. `fwrite` is deliberately NOT
// accepted here - it takes a stream handle, not a path, so counting it would conflate
// the handle with the filename and weaken the linkage the rule rests on.
//
// Identifier bytes include everything >= 0x80. That is not decoration: this family
// ships two variants of the same shell, one naming the variable `$file_path` and one
// naming it `$ファイルパス`, and a `\w`-based pattern silently matches only the first.
namespace detail_RCE015 {
    constexpr size_t kWindow = 400;      // include -> unlink, in bytes
    constexpr size_t kMaxFindings = 4;

    inline bool isIdentByte(unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '_' || c >= 0x80;
    }

    inline bool isSpace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    inline void skipSpace(std::string_view c, size_t& i) {
        while (i < c.size() && isSpace(c[i])) ++i;
    }

    // A whole-word occurrence of `word` at `at`.
    bool wholeWordAt(std::string_view c, size_t at, std::string_view word) {
        if (at + word.size() > c.size()) return false;
        if (c.compare(at, word.size(), word) != 0) return false;
        if (at > 0 && isIdentByte(static_cast<unsigned char>(c[at - 1]))) return false;
        const size_t after = at + word.size();
        return after >= c.size() || !isIdentByte(static_cast<unsigned char>(c[after]));
    }

    // `$name` starting at `i` (which must be the '$'). Returns the name, or empty.
    std::string_view readVar(std::string_view c, size_t i, size_t& end) {
        if (i >= c.size() || c[i] != '$') return {};
        size_t j = i + 1;
        while (j < c.size() && isIdentByte(static_cast<unsigned char>(c[j]))) ++j;
        if (j == i + 1) return {};
        end = j;
        return c.substr(i + 1, j - i - 1);
    }

    // `<call> ( $name )` at `at`, where `at` is the start of the call name.
    // Returns the variable, or empty. `sep` is the byte that must follow the
    // variable: ')' for unlink, ',' for a two-argument write.
    std::string_view callOnVar(std::string_view c, size_t at, std::string_view name, char sep) {
        if (!wholeWordAt(c, at, name)) return {};
        size_t p = at + name.size();
        skipSpace(c, p);
        if (p >= c.size() || c[p] != '(') return {};
        ++p;
        skipSpace(c, p);
        size_t end = 0;
        const std::string_view v = readVar(c, p, end);
        if (v.empty()) return {};
        skipSpace(c, end);
        if (end >= c.size() || c[end] != sep) return {};
        return v;
    }

    // True if some `file_put_contents($var, ...)` names `var` anywhere in the file.
    bool writtenAsPath(std::string_view c, std::string_view var) {
        for (size_t at = c.find("file_put_contents"); at != std::string_view::npos;
             at = c.find("file_put_contents", at + 1)) {
            if (callOnVar(c, at, "file_put_contents", ',') == var) return true;
        }
        return false;
    }

    // `unlink($var)` in [from, to), naming `var`. Returns its offset or npos.
    size_t unlinkOfVar(std::string_view c, std::string_view var, size_t from, size_t to) {
        for (size_t at = c.find("unlink", from); at != std::string_view::npos && at < to;
             at = c.find("unlink", at + 1)) {
            if (callOnVar(c, at, "unlink", ')') == var) return at;
        }
        return std::string_view::npos;
    }

    std::vector<MatchResult> detectIncludeAndDelete(std::string_view content) {
        std::vector<MatchResult> out;
        // Cheap guards: no linkage exists without all three calls being present.
        if (content.find("unlink") == std::string_view::npos) return out;
        if (content.find("file_put_contents") == std::string_view::npos) return out;

        static constexpr std::string_view kIncludes[] = {
            "include_once", "require_once", "include", "require"
        };

        for (size_t i = 0; i < content.size(); ++i) {
            if (content[i] != 'i' && content[i] != 'r') continue;

            std::string_view kw;
            for (const auto& candidate : kIncludes) {
                if (wholeWordAt(content, i, candidate)) { kw = candidate; break; }
            }
            if (kw.empty()) continue;

            // `include $f;`, `include($f);`, `@require($f);` - the '@' sits before the
            // keyword and needs no special handling, it just is not an identifier byte.
            size_t p = i + kw.size();
            skipSpace(content, p);
            const bool paren = (p < content.size() && content[p] == '(');
            if (paren) { ++p; skipSpace(content, p); }
            size_t varEnd = 0;
            const std::string_view var = readVar(content, p, varEnd);
            if (var.empty()) { i += kw.size() - 1; continue; }

            size_t q = varEnd;
            skipSpace(content, q);
            if (paren) {
                if (q >= content.size() || content[q] != ')') { i += kw.size() - 1; continue; }
                ++q;
                skipSpace(content, q);
            }
            if (q >= content.size() || content[q] != ';') { i += kw.size() - 1; continue; }
            ++q;

            const size_t stop = std::min(content.size(), q + kWindow);
            const size_t at = unlinkOfVar(content, var, q, stop);
            if (at == std::string_view::npos) { i += kw.size() - 1; continue; }
            if (!writtenAsPath(content, var)) { i += kw.size() - 1; continue; }

            auto [line, col] = positionToLineCol(content, i);
            MatchResult r;
            r.line = line;
            r.column = col;
            r.matched = content.substr(i, std::min<size_t>(at + 6 - i, 96));
            r.note = "$" + std::string(var) +
                     " is written with file_put_contents, executed with " +
                     std::string(kw) + ", then unlinked " + std::to_string(at - q) +
                     " bytes later - the file exists only to be run once, which is eval "
                     "performed through the filesystem";
            out.push_back(r);
            if (out.size() >= kMaxFindings) return out;
            i = at;
        }
        return out;
    }
}
const BuiltinRule RCE015 {
    .code = {Category::CodeExec, 15},
    .name = "Include and delete a written file",
    .description = "Detects a path written with file_put_contents, executed with include/require, then immediately unlinked - eval performed through the filesystem",
    .severity = Severity::Critical,
    .patterns = {},
    .analyzer = &detail_RCE015::detectIncludeAndDelete,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &RCE001, &RCE002, &RCE003, &RCE004, &RCE005,
    &RCE006, &RCE007, &RCE008, &RCE009, &RCE010, &RCE011, &RCE012, &RCE013, &RCE014,
    &RCE015
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::code_exec

#undef LYX_GAP
