#include "seo_spam.h"
#include <array>

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
          "Hidden link", false },
        { R"(<div\s+[^>]*style\s*=\s*['"][^'"]*visibility\s*:\s*hidden[^'"]*['"][^>]*>.*?<a\s+)",
          "Hidden div with links", false },
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
          "Spam page generation", false },
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
          "Referer-based redirect in htaccess", false },
        { R"(RewriteRule.*?\^.*?https?://[a-zA-Z0-9.\-]+\.(ru|cn|tk))",
          "Redirect to suspicious TLD", false },
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
          "htaccess redirect to suspicious TLD", false },
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
          "Excessive meta keywords", false },
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
          "Japanese characters in title", false },
    };
}
const BuiltinRule SEO006 {
    .code = {Category::SeoSpam, 6},
    .name = "Japanese keyword hack",
    .description = "Detects Japanese SEO spam injection",
    .severity = Severity::High,
    .patterns = detail_SEO006::patterns,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &SEO001, &SEO002, &SEO003, &SEO004, &SEO005, &SEO006
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::seo_spam
