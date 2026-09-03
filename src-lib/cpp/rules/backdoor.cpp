#include "backdoor.h"
#include <array>

namespace lyxbosa::rules::backdoor {

// BD001: Hidden admin creation
// Note: Patterns use possessive [^...]*+ to avoid CTRE stack overflow on large files
namespace detail_BD001 {
    static constexpr Pattern patterns[] = {
        { R"((?i:wp_insert_user)\s*\([^)]*user_login[^)]*administrator)",
          "Hidden WordPress admin creation", false,
          {"wp_insert_user", "administrator", "user_login"} },
        { R"(INSERT\s+INTO\s+\S*users\S*[^;]*admin)",
          "Direct admin user insertion", false,
          {"insert", "admin", "users"} },
    };
}
const BuiltinRule BD001 {
    .code = {Category::Backdoor, 1},
    .name = "Hidden admin creation",
    .description = "Detects hidden admin user creation in CMS",
    .severity = Severity::Critical,
    .patterns = detail_BD001::patterns,
};

// BD002: Cron-based persistence
//
// The technique is an attacker registering a cron *hook* they can then fire. The signature
// is therefore positional: wp_schedule_event($timestamp, $recurrence, $hook), and only a
// superglobal in the third argument means the attacker chose what runs.
//
// Matching a superglobal anywhere in the argument list instead cost 43 false positives on
// one production host and found nothing: WP Fastest Cache's settings screen passes the
// recurrence the admin picked from its own dropdown as argument two,
// `wp_schedule_event($timestamp, $_POST["wpFastestCacheTimeOut"], $this->slug())`.
//
// Requiring two commas ahead of the superglobal is what excludes that, and `[^,)]` on the
// leading arguments is what keeps the two commas from being found inside a nested call.
namespace detail_BD002 {
    static constexpr Pattern patterns[] = {
        { R"((?i:wp_schedule_event)\s*\(\s*[^,)]*,\s*[^,)]*,\s*[^)]*\$_(GET|POST|REQUEST|COOKIE))",
          "Cron hook name from user input", false,
          {"wp_schedule_event", "$_get|$_post|$_request|$_cookie"} },
    };
}
const BuiltinRule BD002 {
    .code = {Category::Backdoor, 2},
    .name = "Cron-based persistence",
    .description = "Detects WordPress cron abuse for persistence",
    .severity = Severity::High,
    .patterns = detail_BD002::patterns,
};

// BD003: Plugin/theme backdoor installer
namespace detail_BD003 {
    static constexpr Pattern patterns[] = {
        { R"((?i:file_put_contents)\s*\([^,]*wp-content/(plugins|themes)[^,]*,\s*(?i:base64_decode))",
          "Plugin/theme file write with base64", false,
          {"file_put_contents", "wp-content/"} },
    };
}
const BuiltinRule BD003 {
    .code = {Category::Backdoor, 3},
    .name = "Plugin/theme backdoor installer",
    .description = "Detects base64 payload written to plugin/theme directory",
    .severity = Severity::Critical,
    .patterns = detail_BD003::patterns,
};

// BD004: Database credential harvester
namespace detail_BD004 {
    static constexpr Pattern patterns[] = {
        { R"((?i:file_get_contents)\s*\([^)]*wp-config\.php)",
          "Reading wp-config", false,
          {"file_get_contents", "wp-config"} },
        { R"((?i:file_get_contents)\s*\([^)]*configuration\.php)",
          "Reading Joomla config", false,
          {"file_get_contents", "configuration"} },
    };
}
const BuiltinRule BD004 {
    .code = {Category::Backdoor, 4},
    .name = "Config file reader",
    .description = "Detects reading of CMS configuration files",
    .severity = Severity::High,
    .patterns = detail_BD004::patterns,
};

// BD005: Socket-based backdoor
// Generic socket_create/socket_connect is used by legitimate libraries (Monolog, etc.)
// Only flag when combined with user input or shell execution
namespace detail_BD005 {
    static constexpr Pattern patterns[] = {
        // fsockopen with user data being written
        { R"((?i:fsockopen)\s*\([^)]+\)\s*.*?(?i:fwrite)\s*\([^)]*\$_(GET|POST|REQUEST))",
          "Socket with user data", false,
          {"fsockopen", "fwrite", "$_get|$_post|$_request"} },
        // socket operations combined with shell commands
        { R"((?i:socket_create)\s*\([^)]+\).*?((?i:shell_exec)|(?i:exec)|(?i:system)|(?i:passthru)|(?i:popen)))",
          "Socket with shell execution", false,
          {"socket_create"} },
        // socket write with user input
        { R"(socket_write\s*\([^,]+,\s*\$_(GET|POST|REQUEST))",
          "Socket write with user input", false,
          {"socket_write", "$_get|$_post|$_request"} },
    };
}
const BuiltinRule BD005 {
    .code = {Category::Backdoor, 5},
    .name = "Socket-based backdoor",
    .description = "Detects socket connections with user input or shell execution",
    .severity = Severity::Critical,
    .patterns = detail_BD005::patterns,
};

// BD006: Reverse shell patterns
namespace detail_BD006 {
    static constexpr Pattern patterns[] = {
        { R"(bash\s+-i\s+>&\s*/dev/tcp/)",
          "Bash reverse shell", false,
          {"/dev/tcp/", "bash"} },
        { R"(/bin/sh\s*\|\s*nc\s+)",
          "Netcat shell pipe", false,
          {"/bin/sh"} },
    };
}
const BuiltinRule BD006 {
    .code = {Category::Backdoor, 6},
    .name = "Reverse shell pattern",
    .description = "Detects common reverse shell command patterns",
    .severity = Severity::Critical,
    .patterns = detail_BD006::patterns,
};

// BD007: Base64-encoded reverse shell
namespace detail_BD007 {
    static constexpr Pattern patterns[] = {
        // Bounded proximity, not ".*?". With dot_nl the unbounded form matched a
        // base64_decode near the top of a file against an fsockopen hundreds of
        // lines later - phpseclib's X509, SimplePie's Sanitize and wp-admin's
        // file.php all tripped it. The technique is one expression feeding the
        // other, so the two have to be close.
        { R"((?i:base64_decode)\s*\([^)]*\).{0,200}?((?i:fsockopen)|(?i:socket_create)|(?i:pfsockopen)))",
          "Decoded socket operation", false,
          {"base64_decode"} },
    };
}
const BuiltinRule BD007 {
    .code = {Category::Backdoor, 7},
    .name = "Encoded reverse shell",
    .description = "Detects base64-encoded socket operations",
    .severity = Severity::Critical,
    .patterns = detail_BD007::patterns,
};

// BD008: Hidden file creation
namespace detail_BD008 {
    static constexpr Pattern patterns[] = {
        { R"((?i:file_put_contents)\s*\(\s*['"][^'"]*\.htaccess)",
          ".htaccess modification", false,
          {"file_put_contents", "htaccess"} },
    };
}
const BuiltinRule BD008 {
    .code = {Category::Backdoor, 8},
    .name = "htaccess backdoor",
    .description = "Detects .htaccess file manipulation",
    .severity = Severity::High,
    .patterns = detail_BD008::patterns,
};

// BD009: Password reset backdoor
namespace detail_BD009 {
    static constexpr Pattern patterns[] = {
        { R"((?i:wp_set_password)\s*\([^)]*\$_(GET|POST|REQUEST))",
          "Password reset with user input", false,
          {"wp_set_password", "$_get|$_post|$_request"} },
    };
}
const BuiltinRule BD009 {
    .code = {Category::Backdoor, 9},
    .name = "Password reset backdoor",
    .description = "Detects password manipulation via user input",
    .severity = Severity::Critical,
    .patterns = detail_BD009::patterns,
};

// BD010: Auto-update disable + backdoor
//
// Requiring `__return_false` as the callback is what makes this mean *disabling* updates
// rather than managing them. Every plugin that ships an update policy calls this filter -
// WooCommerce passes 'wc_prevent_dangerous_auto_updates', Cookiebot passes an object
// method - and matching the filter name alone produced 47 findings and no true positive on
// a 1.3 M-file host. See the context filter for the comment and file-type gates, and
// Severity::Low: this is a corroborator, not a finding on its own.
namespace detail_BD010 {
    static constexpr Pattern patterns[] = {
        { R"(add_filter\s*\(\s*['"]auto_update_[a-z_]*['"]\s*,\s*['"]__return_false['"])",
          "Auto-update disabled outright", false,
          {"auto_update_", "add_filter", "__return_false"} },
    };
}
const BuiltinRule BD010 {
    .code = {Category::Backdoor, 10},
    .name = "Auto-update manipulation",
    .description = "Detects disabling of auto-updates (persistence technique)",
    .severity = Severity::Low,
    .patterns = detail_BD010::patterns,
};

// BD011: Hardcoded password hash backdoor
// Malware often has a hardcoded SHA1/MD5 hash to verify a secret password
// Patterns: sha1($var) == 'hash' OR $var = sha1(...); if($var == 'hash')
namespace detail_BD011 {
    static constexpr Pattern patterns[] = {
        // Direct sha1 comparison with 40-char hex hash
        { R"((?i:sha1)\s*\([^)]+\)\s*==\s*['"][0-9a-fA-F]{40}['"])",
          "SHA1 password hash backdoor", false,
          {"sha1"} },
        // Direct md5 comparison with 32-char hex hash
        { R"((?i:md5)\s*\([^)]+\)\s*==\s*['"][0-9a-fA-F]{32}['"])",
          "MD5 password hash backdoor", false,
          {"md5"} },
        // Variable comparison with 40-char hex hash (SHA1)
        { R"(\$\w+\s*==\s*['"][0-9a-fA-F]{40}['"])",
          "Variable compared to SHA1 hash", false },
        // Variable comparison with 32-char hex hash (MD5)
        { R"(\$\w+\s*==\s*['"][0-9a-fA-F]{32}['"])",
          "Variable compared to MD5 hash", false },
    };
}
const BuiltinRule BD011 {
    .code = {Category::Backdoor, 11},
    .name = "Hardcoded password hash",
    .description = "Detects backdoor with hardcoded password hash check",
    .severity = Severity::Critical,
    .patterns = detail_BD011::patterns,
};

// BD012: file_put_contents with user input (file write backdoor)
// Pattern: file_put_contents with $_REQUEST in path or content
// This allows arbitrary file write - critical backdoor functionality
namespace detail_BD012 {
    static constexpr Pattern patterns[] = {
        // file_put_contents with REQUEST/GET/POST variable in content
        { R"((?i:file_put_contents)\s*\([^,]+,\s*\$_(GET|POST|REQUEST)\s*\[)",
          "file_put_contents with user-controlled content", false,
          {"file_put_contents", "$_get|$_post|$_request"} },
    };
}
const BuiltinRule BD012 {
    .code = {Category::Backdoor, 12},
    .name = "File write with user input",
    .description = "Detects file_put_contents() with user-controlled content",
    .severity = Severity::Critical,
    .patterns = detail_BD012::patterns,
};

// BD013: Embedded RSA private key (C2 encrypted communication)
// Legitimate code doesn't embed actual private keys in PHP files
// Documentation may mention the format marker, but won't have actual key data
// Real keys start with MII... (base64 encoded DER)
namespace detail_BD013 {
    static constexpr Pattern patterns[] = {
        // Private key marker followed by actual key data (MII... base64)
        { R"(-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----\s*MII[A-Za-z0-9+/]{50,})",
          "Embedded private key with data", false,
          {"-----begin", "key-----", "private"} },
    };
}
const BuiltinRule BD013 {
    .code = {Category::Backdoor, 13},
    .name = "Embedded private key",
    .description = "Detects embedded RSA private key (encrypted C2 communication)",
    .severity = Severity::Critical,
    .patterns = detail_BD013::patterns,
};

// BD014: Timestamp manipulation for evasion
// Malware uses touch() with past timestamps to make files look old
// Pattern: time() - mt_rand() to generate random past time, then touch()
namespace detail_BD014 {
    static constexpr Pattern patterns[] = {
        // time() minus mt_rand (calculating random past timestamp)
        { R"(time\s*\(\s*\)\s*-\s*\(?mt_rand)",
          "Random past timestamp calculation", false,
          {"mt_rand", "time"} },
        // A fourth pattern used to sit here: touch($f, $t, $t), written with a
        // backreference to demand the same variable for mtime and atime. RE2 has
        // no backreferences, so it never compiled and was silently dead.
        //
        // It is not restored, because the identity was doing all the work and
        // cannot be expressed here. Dropping it to "three-argument touch() with
        // variable arguments" matches WordPress's class-wp-filesystem-direct.php
        // and phpseclib's SFTP stream, both of which call
        // touch($file, $time, $atime) legitimately - measured, 2 CMS + 1 Sites
        // false positives. The two patterns that remain cover the technique from
        // the timestamp-forgery side instead.
        // filectime followed by touch in same function (timestamp preservation)
        { R"(filectime\s*\(\s*\$\w+\s*\)[^;]*;[^}]*(?i:touch)\s*\()",
          "Timestamp read and modification", false,
          {"filectime", "touch"} },
    };
}
const BuiltinRule BD014 {
    .code = {Category::Backdoor, 14},
    .name = "Timestamp manipulation",
    .description = "Detects file timestamp manipulation to evade detection",
    .severity = Severity::High,
    .patterns = detail_BD014::patterns,
};

// BD015: Custom HTTP header command channel
// Malware receives commands via custom HTTP headers (not GET/POST)
// Pattern: $_SERVER['HTTP_X'] where X is not a standard header
namespace detail_BD015 {
    static constexpr Pattern patterns[] = {
        // Custom single-letter HTTP header (HTTP_P, HTTP_X, etc.)
        { R"(\$_SERVER\s*\[\s*['"]HTTP_[A-Z]['"])",
          "Single-letter HTTP header extraction", false,
          {"_server", "http_"} },
        // openssl_private_decrypt with server variable
        { R"((?i:openssl_private_decrypt)\s*\([^,]+\$_SERVER)",
          "Encrypted HTTP header decryption", false,
          {"openssl_private_decrypt", "_server"} },
    };
}
const BuiltinRule BD015 {
    .code = {Category::Backdoor, 15},
    .name = "HTTP header command channel",
    .description = "Detects command extraction from custom HTTP headers",
    .severity = Severity::Critical,
    .patterns = detail_BD015::patterns,
};

// BD016: Include/require with base64-encoded path
// Malware injects @include base64_decode("...") into legitimate files (e.g. WordPress templates)
// to load a backdoor from an obfuscated path. There is no legitimate reason to base64-encode
// an include/require path. Covers all variants: include, include_once, require, require_once,
// with or without @ error suppression.
namespace detail_BD016 {
    static constexpr Pattern patterns[] = {
        // @include base64_decode("...") — error-suppressed include with encoded path
        { R"(@\s*((?i:include)|(?i:include_once)|(?i:require)|(?i:require_once))\s*\(?\s*(?i:base64_decode)\s*\()",
          "Error-suppressed include with base64-encoded path", true,
          {"base64_decode"} },
        // include/require base64_decode("...") without @ — still malicious
        { R"(((?i:include)|(?i:include_once)|(?i:require)|(?i:require_once))\s*\(?\s*(?i:base64_decode)\s*\()",
          "Include with base64-encoded path", true,
          {"include|include_once|require|require_once", "base64_decode"} },
    };
}
const BuiltinRule BD016 {
    .code = {Category::Backdoor, 16},
    .name = "Base64 include backdoor",
    .description = "Detects include/require with base64-encoded file path (template injection backdoor)",
    .severity = Severity::Critical,
    .patterns = detail_BD016::patterns,
};

// BD017: Malicious .htaccess backdoor protection
// Attackers drop .htaccess files that deny access to all PHP files EXCEPT their specific
// backdoor scripts. The pattern is: FilesMatch denying *.php combined with a second
// FilesMatch whitelisting specific filenames. The whitelisted names are often leet-speak
// variants of WordPress files (wp-l0gin, wp-the1me, wp-scr1pts) or generic shells.
namespace detail_BD017 {
    static constexpr Pattern patterns[] = {
        // FilesMatch block that denies PHP + another FilesMatch that allows specific files
        { R"(<FilesMatch[^>]*php[^>]*>\s*Order\s[^<]*Deny\s+from\s+all[^<]*</FilesMatch>\s*<FilesMatch[^>]*>\s*Order\s[^<]*Allow\s+from\s+all)",
          "htaccess backdoor whitelist pattern", true,
          {"</filesmatch>", "<filesmatch", "allow"} },
        // FilesMatch whitelisting known backdoor filenames (leet-speak or suspicious names)
        { R"(<FilesMatch[^>]*(wp-l0gin|wp-the1me|wp-scr1pts|lock360|sh3ll|c99|r57|b374k|alfa|fox|mini|wso|mari)[^>]*>)",
          "htaccess whitelisting known backdoor names", true,
          {"<filesmatch"} },
    };
}
const BuiltinRule BD017 {
    .code = {Category::Backdoor, 17},
    .name = "htaccess backdoor whitelist",
    .description = "Detects .htaccess files that deny PHP access except for specific backdoor scripts",
    .severity = Severity::Critical,
    .patterns = detail_BD017::patterns,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &BD001, &BD002, &BD003, &BD004, &BD005,
    &BD006, &BD007, &BD008, &BD009, &BD010,
    &BD011, &BD012, &BD013, &BD014, &BD015,
    &BD016, &BD017
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::backdoor
