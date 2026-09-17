#include "backdoor.h"
#include <array>

namespace lyxbosa::rules::backdoor {

// BD001: Hidden admin creation
// Note: RE2 guarantees time linear in the input and does not recurse on it, so the
// negated classes below cannot overflow a stack or go exponential on a large file.
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
// Requiring two commas ahead of the superglobal is what excludes that: WP Fastest Cache's
// call has exactly two, and the text after the second is `$this->slug()`, which holds no
// superglobal. The leading arguments allow parentheses, because a timestamp is normally
// written `time()` or `strtotime('+1 hour')`; only the third is paren-bounded, so a nested
// `foo($_POST['h'])` in the hook position still reports.
namespace detail_BD002 {
    static constexpr Pattern patterns[] = {
        { R"((?i:wp_schedule_event)\s*\(\s*[^,]{0,200},\s*[^,]{0,200},\s*[^)]{0,200}\$_(GET|POST|REQUEST|COOKIE))",
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
        // socket operations combined with shell commands. The shell function is a CALL
        // at a word boundary: bare `exec` reached `_exec(` and `execute(`, which is how
        // WordPress core's own FTP class fired this Critical rule under any name its
        // path prior did not cover (25 stock versions of it; Monolog's CubeHandler
        // matched too, 9 vendored copies, and the UDP line test in the context filter
        // caught those). With the boundary and the paren, none of the 34 matches.
        { R"((?i:socket_create)\s*\([^)]+\).*?\b((?i:shell_exec)|(?i:exec)|(?i:system)|(?i:passthru)|(?i:popen))\s*\()",
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

// BD018: a rename() that undoes a quarantine
//
// Three deployer scripts in a doorway-kit directory carry this line:
//
//     if (file_exists("../oyptke.php.suspected")) rename("../oyptke.php.suspected", "../oyptke.php");
//
// `.suspected` is the suffix cPanel and ImunifyAV append when they quarantine a file.
// The rename is the quarantine run backwards. There is no honest reading of it: a
// legitimate program has no reason to know that suffix exists, still less to undo it,
// and the same three files also delete and re-install `../.htaccess` and delete
// `../index.php` - the script's whole job is to re-establish the kit after a cleanup.
//
// WHY THIS IS IN BACKDOOR RATHER THAN WITH THE KIT THAT CARRIED IT. The samples come
// from an SEO doorway campaign, but nothing here keys on doorways, on that campaign or
// on its output. It keys on anti-remediation - reversing an incident responder's
// action - which is orthogonal to whatever is being re-established and is worth
// catching whoever wrote it.
//
// The condition that carries the rule is that BOTH ENDS matter, and each is worthless
// alone:
//
//   * renaming *to* an executable extension is ordinary. wp-super-cache does exactly
//     that - `rename( $tmp_config_filename, $tmp_config_filename . '.php' )` after a
//     tempnam - and it is the only file in the 207,311 measured that renames anything
//     to a `.php` at all. A rule on the target alone would be a rule against writing
//     config files.
//   * a quarantine suffix on the source is what makes it a reversal. Nothing in the
//     benign trees renames a `.suspected`, `.quarantine`, `.infected`, `.virus`,
//     `.malware` or `.bak_av` file at all, in either direction.
//
// Measured over trail-data/CMS, CMS-ext and Sites - 207,311 files, 343 of them at risk
// (files containing a rename() call): 0 false positives, 95% upper bound 0.87%.
// Recall 3 of 3, every deployer in the campaign directory.
namespace detail_BD018 {
    static constexpr Pattern patterns[] = {
        { R"(rename\s*\(\s*[^,)]*\.(suspected|quarantine|infected|virus|malware|bak_av)[^,)]*,\s*[^)]*\.(php|phtml|php5|inc|module|cgi|pl|py|sh)\b)",
          "rename() from a quarantine suffix back to an executable extension", true,
          {"rename", "suspected|quarantine|infected|virus|malware|bak_av"} },
    };
}
const BuiltinRule BD018 {
    .code = {Category::Backdoor, 18},
    .name = "Quarantine-reversing rename",
    .description = "Detects a rename() whose source carries an antivirus quarantine suffix and whose target is an executable extension, which is a cleanup run backwards",
    .severity = Severity::Critical,
    .patterns = detail_BD018::patterns,
};

// BD019 and BD020: an .htaccess that makes the server run, as a script, a file whose name is
// not a script's
//
// An upload endpoint that refuses `.php` usually accepts an image, an archive or a database,
// and an .htaccess in the same directory decides what the server does with those names:
//
//     AddType application/x-httpd-php .mdb
//
// An automated vulnerability scanner probing one host's upload endpoint uploaded exactly that
// directive, for `.mdb` and for `.zip`, and stored its webshells under `.mdb` names beside it.
// The directive is not the shell. It is the directory being prepared to run one, and it
// survives the shell's removal.
//
// THE FAMILY, FROM THE SERVERS' OWN DOCUMENTATION. Every form below is allowed in an .htaccess
// under AllowOverride FileInfo, or Options for ExecCGI.
//
//   * AddType and AddHandler (mod_mime). "The extension argument is case-insensitive and can
//     be specified with or without a leading dot", and a file with several extensions is
//     compared against each (httpd.apache.org/docs/2.4/mod/mod_mime.html).
//   * SetHandler and ForceType (core). SetHandler "forces all matching files to be processed by
//     the handler" - every file in the directory at the top of the file, and what a <Files>,
//     <Files ~> or <FilesMatch> block selects inside one (docs/2.4/mod/core.html). php.net
//     recommends exactly that block, <FilesMatch \.php$>, to keep exploit.php.jpg from running
//     (php.net/manual/en/install.unix.apache2.php).
//   * PHP-FPM, `SetHandler "proxy:unix:/path/php-fpm.sock|fcgi://localhost"`: a SetHandler, so
//     allowed where ProxyPass is not (docs/2.4/mod/mod_proxy_fcgi.html). FPM itself refuses a
//     script outside security.limit_extensions, `.php .phar` by default (php-src
//     sapi/fpm/fpm/fpm_conf.c); the directive is reported because it is the attempt, and a
//     pool can be widened.
//   * The handler names the hosting stacks write: mod_php's application/x-httpd-php and its
//     php-script, php5-script and php7-script tokens (php-src sapi/apache2handler/php_apache.h);
//     cPanel MultiPHP's application/x-httpd-ea-phpNN, in the block it generates -
//     `AddHandler application/x-httpd-ea-php81 .php .php81 .phtml` - and in the older AddType
//     form LiteSpeed's cPanel documentation reproduces (docs.litespeedtech.com/lsws/cp/cpanel/
//     php-selector/); CloudLinux's application/x-httpd-alt-phpNN___lsphp; LiteSpeed's
//     application/x-httpd-lsphp and application/x-httpd-phpNN, since "the script handlers use
//     MIME types, not suffixes" and AddType and ForceType in .htaccess choose them
//     (litespeedtech.com/docs/webserver/config/scripthandler); 1&1's x-mapp-php. Any handler
//     token naming PHP, less application/x-httpd-php-source, which highlights a file instead
//     of running it, and less a text/ media type, which is never a handler. OpenLiteSpeed
//     reads only rewrite rules from an .htaccess and ignores every directive here
//     (docs.openlitespeed.org/config/rewriterules/).
//   * cgi-script and fcgid-script, WITH ExecCGI. mod_cgi runs the file itself, and needs both
//     "the cgi-script handler ... activated using the AddHandler or SetHandler directive" and
//     "ExecCGI ... specified in the Options directive" (docs/2.4/howto/cgi.html); mod_fcgid
//     checks ExecCGI the same way. It belongs in the family on evidence rather than on the
//     documentation alone: every attacker .htaccess with a CGI handler in the incident trees
//     measured below - 11 files, 3 distinct - maps cgi-script onto an invented extension under
//     an Options list naming ExecCGI, and every legitimate CGI mapping found - 7 copies of one
//     guard, in stock and customer trees, in .htaccess files and in code that writes one -
//     turns ExecCGI off and lists .htm beside the script extensions.
//     So the CGI handlers count only in a file whose Options enable ExecCGI. A server whose own
//     configuration already enables it is not seen, and that is the gap this condition costs.
//
// Left out, each with a reason. `Action` binds a handler name to a CGI program, and a PHP
// interpreter published at a URL is what it needs; no .htaccess measured carries one. `<If>`
// is not read as a selector, so a handler inside one counts as reaching the whole directory.
// `php_value auto_prepend_file` and `.user.ini` run a file by a different mechanism: see
// docs/RULE_CANDIDATES.md.
//
// WHICH NAMES ARE SCRIPTS. PHP's own extensions (.php with any version digits, .phtml, .pht,
// .phtm, .phps, .phar) and the PHP source conventions OBF036 and SEO008 already read as PHP;
// CGI, Perl, Python, Ruby and shell; ASP, JSP and ColdFusion; server-side includes. A PHP
// handler on any of them adds nothing an upload filter did not already have to refuse.
// Everything else is data, including no extension and `.htaccess` itself, which is how an
// .htaccess that holds its own PHP runs.
//
// A SELECTOR IS ASKED, NOT PARSED. A <FilesMatch> regex or <Files> glob is tried against names
// of every class and against the names its own literal runs spell, and an extension it spells
// at the end of an alternative counts whether a name reached it or not. One RE2 cannot compile,
// or one that no name tried reaches, is read as reaching data.
//
// THE NAME. Apache opens the configured AccessFileName - `.htaccess` everywhere but OS/2
// (include/httpd.h) - by joining it to the directory and handing it to APR
// (server/config.c ap_open_htaccess), so whether `.HTACCESS` is read is the filesystem's
// answer: no on ext4, yes on NTFS and on a case-insensitive APFS volume, and Apache matches
// <FilesMatch> without case on Windows (server/core.c, USE_ICASE). The platform the scanner
// runs on is not the filesystem the site is served from - a Linux scan reads Windows shares,
// DrvFs mounts and backups made on either - so the name is folded on every platform, and the
// trailing dots and spaces Windows drops from a name are dropped. Scoped in the engine's
// context filter, loose and as an archive member alike.
//
// THE FALSE-POSITIVE MEASUREMENT. `tests/rule-fp-measure.py --rules BD019,BD020 --archives`,
// which loads the two rules alone, reads every file whatever its type, opens archives with no
// time budget, and carries a control that has to fire on a loose file and on a member:
//
//   population                          files read   of them members   .htaccess   at risk   BD019   BD020
//   trail-data/CMS, stock CMS trees         54,428               450          35         1       0       0
//   trail-data/CMS-ext: pinned benign
//     trees and their 136 archives         298,711           137,877         104         0       0       0
//   customer trees under trail-data        483,612           162,544      16,209        13      11       0
//
// "At risk" is an .htaccess carrying a live AddType, AddHandler, SetHandler or ForceType with a
// PHP, PHP-FPM or CGI handler. The 11 are the attacker CGI files above, all of them, and no
// other file fired. The 13 at risk in the customer trees are those 11, one ExecCGI guard, and
// one cPanel-generated handler block mapping PHP's own extensions inside an archive, which
// `check` reads as clean. Across all 16,348 .htaccess files no PHP or FPM handler is mapped
// onto any extension that is not a script's, and nothing fired that was not an attack: a
// per-file false-positive rate of at most 0.019% at 95%. That bound is over .htaccess files; over
// the 14 at risk it is only 21%, and the silence the rule owes the lines hosting stacks write
// is pinned by tests/htaccess_handler_test.cpp rather than by this population, which holds
// almost none of them.
//
// Recall is not measured here. The two corpus rows are the samples that taught the technique,
// and the CGI condition was drawn from the 11 attacker files and the guards beside them.
//
// .HTML AND .HTM, AND WHY THEY ARE BD020. Measured, a finding on them costs nothing: 2 of the
// 16,348 map a handler onto .htm, both the ExecCGI guard and silent for that reason, and none
// maps a PHP or FPM handler onto .html or .htm. But hosting providers document it as a
// supported configuration for legacy sites - `AddHandler application/x-httpd-php .html .htm`
// in AccuWebHosting's, ICDSoft's and Ultra Web Hosting's knowledge bases - which no provider
// does for an image, an archive or a database, and a finding that says there is no honest
// reading of it would be wrong about them. So they are neither silent, which the measurement
// does not support, nor Critical: BD020, Medium, which an operator whose sites do this can turn
// off by code without losing BD019. A directive reaching both is BD019 alone.
//
// BD019 IS CRITICAL for the reason BD017 and BD018 are. No documentation describes mapping a
// script handler onto a data extension as a configuration, php.net describes preventing it,
// and none of 16,348 real .htaccess files does it outside an attack.
namespace detail_htaccess_handler {
    static constexpr Pattern patterns[] = {
        { R"((?m)^[ \t]*(?:AddType|AddHandler)[ \t]+["']?[^\s"']*(?:php|proxy:[^\s"']*fcgi:|cgi-script|fcgid-script)(?:\\\r?\n|[^\r\n])*)",
          "Script handler mapped onto an extension", true,
          {"addtype|addhandler", "php|fcgi:|cgi-script|fcgid-script"} },
        { R"((?m)^[ \t]*(?:SetHandler|ForceType)[ \t]+["']?[^\s"']*(?:php|proxy:[^\s"']*fcgi:|cgi-script|fcgid-script)[^\r\n]*)",
          "Script handler set on the files a block selects", true,
          {"sethandler|forcetype", "php|fcgi:|cgi-script|fcgid-script"} },
    };
}
const BuiltinRule BD019 {
    .code = {Category::Backdoor, 19},
    .name = "htaccess runs a data file as a script",
    .description = "Detects an .htaccess directive that attaches a PHP, PHP-FPM or CGI handler to "
                   "file names that are not scripts, so an uploaded image, archive or database runs "
                   "as code",
    .severity = Severity::Critical,
    .patterns = detail_htaccess_handler::patterns,
};
const BuiltinRule BD020 {
    .code = {Category::Backdoor, 20},
    .name = "htaccess runs HTML as a script",
    .description = "Detects an .htaccess directive that attaches a PHP, PHP-FPM or CGI handler to "
                   ".html or .htm, which hosting providers document for legacy sites and which "
                   "an upload directory has no use for",
    .severity = Severity::Medium,
    .patterns = detail_htaccess_handler::patterns,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &BD001, &BD002, &BD003, &BD004, &BD005,
    &BD006, &BD007, &BD008, &BD009,
    &BD011, &BD012, &BD013, &BD014, &BD015,
    &BD016, &BD017, &BD018, &BD019, &BD020
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::backdoor
