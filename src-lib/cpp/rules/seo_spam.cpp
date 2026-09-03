#include "seo_spam.h"
#include <algorithm>
#include <array>
#include <cctype>
#include <string>
#include <vector>

namespace lyxbosa::rules::seo_spam {

// SEO001: Hidden link injection
// Note: Patterns use possessive [^...]*+ to avoid CTRE stack overflow on large files
namespace detail_SEO001 {
    static constexpr Pattern patterns[] = {
        // The href must be a literal external URL. Themes and widgets legitimately
        // hide anchors whose href is generated - Avada's slideshow and Fusion's
        // Twitter widget both emit  <a style="display:none" href="<?php echo ...  -
        // and matching those cost 9 false positives on one real site. Injected spam
        // links carry the destination inline.
        { R"(<a\s+[^>]*style\s*=\s*['"][^'"]*display\s*:\s*none[^'"]*['"][^>]*href\s*=\s*['"]https?://)",
          "Hidden link", false,
          {"display", "style", "none"} },
        // Pattern 1's discipline applied to the wrapper-div form: the anchor must carry a
        // literal external href and sit within a few tags of the hidden div.
        //
        // Unbounded, `.*?<a\s+` paired a hidden div with the next anchor *anywhere* later in
        // the file - hundreds of lines away, in an unrelated block. That reported 22 files on
        // one production host and found nothing: PixelYourSite's settings popovers
        // (`<div id="pys-search_event" style="display: none; visibility: hidden">`) and the
        // standard dark-mode-image trick in HTML e-mail, both of which are hidden layout
        // wrappers with no link in them at all.
        { R"(<div\s+[^>]*style\s*=\s*['"][^'"]*visibility\s*:\s*hidden[^'"]*['"][^>]*>\s*(?:<[^>]{0,200}>\s*){0,3}<a\s+[^>]*href\s*=\s*['"]https?://)",
          "Hidden div with links", false,
          {"visibility", "hidden", "style"} },
    };
}
const BuiltinRule SEO001 {
    .code = {Category::SeoSpam, 1},
    .name = "Hidden link injection",
    .description = "Detects SEO spam via hidden links",
    .severity = Severity::Medium,
    .patterns = detail_SEO001::patterns,
};

// SEO002: Doorway page generator
// Note: Pattern uses possessive [^,]*+ to avoid CTRE stack overflow on large files
namespace detail_SEO002 {
    static constexpr Pattern patterns[] = {
        { R"((?i:file_put_contents)\s*\([^,]*\.html['"]\s*,.*?(viagra|cialis|casino|poker|pharmacy))",
          "Spam page generation", false,
          {"file_put_contents", "html"} },
    };
}
const BuiltinRule SEO002 {
    .code = {Category::SeoSpam, 2},
    .name = "Doorway page generator",
    .description = "Detects automated spam page creation",
    .severity = Severity::High,
    .patterns = detail_SEO002::patterns,
};

// SEO003: Cloaking via user-agent/referer
namespace detail_SEO003 {
    static constexpr Pattern patterns[] = {
        { R"(RewriteCond.*?HTTP_REFERER.*?(google|bing|yahoo).*?\[NC\])",
          "Referer-based redirect in htaccess", false,
          {"http_referer", "rewritecond"} },
        { R"(RewriteRule.*?\^.*?https?://[a-zA-Z0-9.\-]+\.(ru|cn|tk))",
          "Redirect to suspicious TLD", false,
          {"rewriterule", "http"} },
    };
}
const BuiltinRule SEO003 {
    .code = {Category::SeoSpam, 3},
    .name = "SEO cloaking",
    .description = "Detects search engine cloaking techniques",
    .severity = Severity::High,
    .patterns = detail_SEO003::patterns,
};

// SEO004: Suspicious TLD in htaccess
namespace detail_SEO004 {
    static constexpr Pattern patterns[] = {
        { R"(RewriteRule.*?\.(ru|cn|tk|ml|ga|cf|gq)/)",
          "htaccess redirect to suspicious TLD", false,
          {"rewriterule"} },
    };
}
const BuiltinRule SEO004 {
    .code = {Category::SeoSpam, 4},
    .name = "Suspicious htaccess redirect",
    .description = "Detects htaccess redirects to suspicious TLDs",
    .severity = Severity::High,
    .patterns = detail_SEO004::patterns,
};

// SEO005: Keyword stuffing
// Note: Pattern uses possessive [^>]*+ to avoid CTRE stack overflow on large files
namespace detail_SEO005 {
    static constexpr Pattern patterns[] = {
        { R"(<meta\s+name\s*=\s*['"]keywords['"][^>]*content\s*=\s*['"][^'"]{500,}['"])",
          "Excessive meta keywords", false,
          {"keywords", "content", "<meta"} },
    };
}
const BuiltinRule SEO005 {
    .code = {Category::SeoSpam, 5},
    .name = "Keyword stuffing",
    .description = "Detects excessive meta keyword stuffing",
    .severity = Severity::Low,
    .patterns = detail_SEO005::patterns,
};

// SEO006: Japanese keyword hack
// Note: Pattern uses possessive [^<]*+ to avoid CTRE stack overflow on large files
namespace detail_SEO006 {
    static constexpr Pattern patterns[] = {
        { R"(<title>[^<]*[\x{3040}-\x{309F}\x{30A0}-\x{30FF}]{10,}[^<]*</title>)",
          "Japanese characters in title", false,
          {"</title>", "<title>"} },
    };
}
const BuiltinRule SEO006 {
    .code = {Category::SeoSpam, 6},
    .name = "Japanese keyword hack",
    .description = "Detects Japanese SEO spam injection",
    .severity = Severity::High,
    .patterns = detail_SEO006::patterns,
};

// SEO008: PHP-level user-agent cloaking
//
// SEO003 knows only .htaccess RewriteCond cloaking. The far more common form is a
// few lines of PHP prepended to a document-root index.php:
//
//     'bots' => 'Googlebot,bingbot,Slurp,DuckDuckBot,YandexBot,Baiduspider,...',
//     $v_ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
//     if (_sys_validate($v_ua, $cdc_config['bots'])) {
//         $content = _sys_sync($cdc_config['remote_url'], ...);
//         if ($content) { echo $content; exit; }
//     }
//
// Crawlers get gambling spam fetched from the operator's server; humans get the real
// site, so the owner sees nothing wrong and the ranking damage is invisible from a
// browser.
//
// All three conditions are required, because each alone is ordinary. Caching and
// analytics plugins enumerate crawler user-agents; plenty of code fetches a remote
// URL; plenty of code echoes a variable. What no legitimate plugin does is fetch
// remote HTML and print it *only* to search engines.
namespace detail_SEO008 {
    constexpr size_t kMinCrawlerNames = 3;

    // Names distinctive enough that seeing several together means a crawler list.
    constexpr std::string_view kCrawlers[] = {
        "googlebot", "bingbot", "slurp", "duckduckbot", "yandexbot", "baiduspider",
        "ahrefsbot", "semrushbot", "mj12bot", "facebookexternalhit", "applebot",
        "bingpreview", "mediapartners-google", "twitterbot", "petalbot", "sogou",
    };

    constexpr std::string_view kFetches[] = {
        "curl_exec", "curl_init", "wp_remote_get", "wp_remote_post",
        "file_get_contents", "fopen",
    };

    constexpr std::string_view kEmitters[] = {
        "echo", "print", "printf", "eval", "readfile", "include", "require",
    };

    // A hardcoded remote address has to sit next to the call that fetches it. This is
    // the condition that separates a cloaker from a plugin that merely knows what a
    // crawler is: the cloaker's whole purpose is to serve *this URL* to bots, so the
    // two are written together. Measured over every known sample, the gap is 103-427
    // bytes; in a maintenance-mode plugin that lists crawlers and also happens to
    // contain URLs elsewhere, the nearest pair is 15 KB apart, and a security plugin's
    // firewall has crawler names and a curl call but no URL literal at all.
    constexpr size_t kMaxUrlToFetch = 800;

    bool containsLower(const std::string& haystack, std::string_view needle) {
        return haystack.find(needle) != std::string::npos;
    }

    // Offsets of every `http://` or `https://` inside a quoted literal.
    std::vector<size_t> literalUrlOffsets(const std::string& lowered) {
        std::vector<size_t> out;
        for (size_t i = 0; (i = lowered.find("http", i)) != std::string::npos; i += 4) {
            const size_t after = i + 4;
            if (lowered.compare(after, 3, "://") != 0 &&
                lowered.compare(after, 4, "s://") != 0) {
                continue;
            }
            // A URL the code fetches is written as a literal, so a quote precedes it.
            const size_t start = (i > 2) ? i - 2 : 0;
            bool quoted = false;
            for (size_t j = start; j < i; ++j) {
                if (lowered[j] == '\'' || lowered[j] == '"') { quoted = true; break; }
            }
            if (quoted) out.push_back(i);
            if (out.size() >= 512) break;
        }
        return out;
    }

    bool fetchesAHardcodedUrl(const std::string& lowered) {
        const auto urls = literalUrlOffsets(lowered);
        if (urls.empty()) return false;
        for (auto fn : kFetches) {
            for (size_t i = 0; (i = lowered.find(fn, i)) != std::string::npos; i += fn.size()) {
                for (size_t url : urls) {
                    const size_t gap = (url > i) ? url - i : i - url;
                    if (gap <= kMaxUrlToFetch) return true;
                }
            }
        }
        return false;
    }


    std::vector<MatchResult> detectUserAgentCloaking(std::string_view content) {
        std::vector<MatchResult> out;

        // Cheap guard: this analyzer has no literal gate, so it runs on every file.
        const size_t uaAt = content.find("HTTP_USER_AGENT");
        if (uaAt == std::string_view::npos) return out;

        std::string lowered(content);
        std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        size_t crawlers = 0;
        for (auto name : kCrawlers) {
            if (containsLower(lowered, name) && ++crawlers >= kMinCrawlerNames) break;
        }
        if (crawlers < kMinCrawlerNames) return out;

        if (!fetchesAHardcodedUrl(lowered)) return out;

        bool emits = false;
        for (auto fn : kEmitters) {
            if (containsLower(lowered, fn)) { emits = true; break; }
        }
        if (!emits) return out;

        auto [line, col] = positionToLineCol(content, uaAt);
        MatchResult r;
        r.line = line;
        r.column = col;
        r.matched = content.substr(uaAt, std::min<size_t>(48, content.size() - uaAt));
        r.note = "User-agent tested against " + std::to_string(crawlers) +
                 "+ crawler names in a file that also fetches a remote URL and prints it - "
                 "search engines are being served different content from visitors";
        out.push_back(r);
        return out;
    }
}
const BuiltinRule SEO008 {
    .code = {Category::SeoSpam, 8},
    .name = "PHP user-agent cloaking",
    .description = "Detects PHP that serves remotely fetched content only to search-engine crawlers",
    .severity = Severity::High,
    .patterns = {},
    .analyzer = &detail_SEO008::detectUserAgentCloaking,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &SEO001, &SEO002, &SEO003, &SEO004, &SEO005, &SEO006, &SEO008
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::seo_spam
