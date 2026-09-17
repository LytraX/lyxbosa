// BD019 and BD020: an .htaccess that makes the server run a non-script file as a script.
//
// WHAT EACH BLOCK CHECKS
// ----------------------
//   The collected directive, both extensions it was written with.
//   Every directive form the family has: AddType and AddHandler, with and without the dot, in
//     any case, quoted, continued over a line; SetHandler and ForceType at the top of the file
//     and inside <Files>, <Files ~> and <FilesMatch> blocks; PHP-FPM through a proxy handler;
//     cgi-script and fcgid-script under ExecCGI.
//   Every handler name the hosting stacks write: mod_php's, cPanel's ea-php, CloudLinux's
//     alt-php with LSPHP, LiteSpeed's lsphp, 1&1's x-mapp-php.
//   Every class of extension that is not a script: images, archives, databases, documents,
//     web data, an invented extension, no extension, and `.htaccess` itself.
//   What must stay silent: the lines cPanel, LiteSpeed, Debian and php.net write for PHP's own
//     extensions, the source-highlighting handler, the ExecCGI guard plugins ship, an ordinary
//     cgi-bin, commented-out hosting hints, and a CGI handler in a file that never enables
//     ExecCGI.
//   .html and .htm, which are BD020 and not BD019.
//   The name: the same bytes under any other name raise neither rule; `.htaccess` in another
//     case, with a trailing dot or behind a backslash separator raises it.
//   A deflated zip member named `.htaccess`, read by a real scan.
//
// Directives only. No fixture here carries a script body.

#include "UniqueTempDir.h"
#include <gtest/gtest.h>

#include "analysis/HtaccessHandler.h"
#include "config/Config.h"
#include "core/MatchEngine.h"
#include "core/Scanner.h"
#include "infrastructure/PathUtils.h"

#include "ArchiveFixtures.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <string_view>
#include <vector>

using namespace lyxbosa;
using namespace lyxbosa::test::fixtures;

namespace {

namespace fs = std::filesystem;

class HtaccessHandlerTest : public ::testing::Test {
protected:
    MatchEngine engine;

    void SetUp() override { engine.loadAllBuiltinRules(); }

    // BD019 and BD020 only, so a case reads as the answer the two rules give.
    std::set<std::string> codes(std::string_view content,
                                std::string_view path = "site/wp-content/uploads/.htaccess") {
        std::set<std::string> out;
        for (const auto& m : engine.match(content, path)) {
            if (m.category == "BD019" || m.category == "BD020") out.insert(m.category);
        }
        return out;
    }

    const std::set<std::string> kData = {"BD019"};
    const std::set<std::string> kDocument = {"BD020"};
    const std::set<std::string> kSilent = {};
};

}  // namespace

// ---------------------------------------------------------------------------------------------
// The collected directive
// ---------------------------------------------------------------------------------------------

TEST_F(HtaccessHandlerTest, TheCollectedDirectiveIsReportedForBothExtensions) {
    EXPECT_EQ(codes("AddType application/x-httpd-php .mdb\n"), kData);
    EXPECT_EQ(codes("AddType application/x-httpd-php .zip\n"), kData);
}

// ---------------------------------------------------------------------------------------------
// Directive forms
// ---------------------------------------------------------------------------------------------

// mod_mime: "The extension argument is case-insensitive and can be specified with or without a
// leading dot", and a directive name is case-insensitive too.
TEST_F(HtaccessHandlerTest, AddTypeAndAddHandlerInEverySpelling) {
    EXPECT_EQ(codes("AddType application/x-httpd-php .jpg\n"), kData);
    EXPECT_EQ(codes("AddHandler application/x-httpd-php .jpg\n"), kData);
    EXPECT_EQ(codes("addhandler application/x-httpd-php jpg\n"), kData);
    EXPECT_EQ(codes("ADDTYPE application/x-httpd-php .JPG\n"), kData);
    EXPECT_EQ(codes("AddType \"application/x-httpd-php\" \".jpg\"\n"), kData);
    EXPECT_EQ(codes("  <IfModule mime_module>\n    AddHandler application/x-httpd-php .gif\n  </IfModule>\n"),
              kData);
    // One data extension among script ones is enough.
    EXPECT_EQ(codes("AddHandler application/x-httpd-php .php .phtml .png\n"), kData);
}

// A backslash ending a line continues the directive, so the extension it reaches can sit on
// the next line - in both directions.
TEST_F(HtaccessHandlerTest, ADirectiveContinuedOverALineIsReadWhole) {
    EXPECT_EQ(codes("AddType application/x-httpd-php \\\n    .jpg\n"), kData);
    EXPECT_EQ(codes("AddType application/x-httpd-php \\\r\n    .jpg\r\n"), kData);
    EXPECT_EQ(codes("AddHandler application/x-httpd-ea-php81 \\\n    .php .phtml\n"), kSilent);
}

// SetHandler at the top of an .htaccess reaches every file in the directory: "forces all
// matching files to be processed by the handler", and the container is the whole directory.
TEST_F(HtaccessHandlerTest, SetHandlerAndForceTypeOutsideABlockReachEveryFile) {
    EXPECT_EQ(codes("SetHandler application/x-httpd-php\n"), kData);
    EXPECT_EQ(codes("ForceType application/x-httpd-php\n"), kData);
    // A block closed above the directive does not select for it.
    EXPECT_EQ(codes("<FilesMatch \"\\.php$\">\n  Require all granted\n</FilesMatch>\n"
                    "SetHandler application/x-httpd-php\n"),
              kData);
}

TEST_F(HtaccessHandlerTest, SetHandlerAndForceTypeInsideABlockReachWhatItSelects) {
    EXPECT_EQ(codes("<FilesMatch \"\\.(jpe?g|png)$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n"),
              kData);
    EXPECT_EQ(codes("<Files \"avatar.gif\">\n  ForceType application/x-httpd-php\n</Files>\n"), kData);
    EXPECT_EQ(codes("<Files *.mdb>\n  SetHandler application/x-httpd-php\n</Files>\n"), kData);
    EXPECT_EQ(codes("<Files ~ \"\\.zip$\">\n  SetHandler application/x-httpd-php\n</Files>\n"), kData);
    EXPECT_EQ(codes("<FilesMatch \".*\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n"), kData);
}

// A selector is asked which names it reaches, not searched for a PHP extension: one that
// spells a single upload, an invented extension, or a data name beside a script alternative
// still reaches data.
TEST_F(HtaccessHandlerTest, ASelectorCannotHideADataNameItSpells) {
    EXPECT_EQ(codes("<FilesMatch \"^avatar_[0-9]+\\.jpg$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n"),
              kData);
    EXPECT_EQ(codes("<FilesMatch \"\\.(alfa|xyz)$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n"),
              kData);
    EXPECT_EQ(codes("<FilesMatch \"^(index\\.php|shell\\.jpg)$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n"),
              kData);
    // Beside a script alternative, and spelled so that no name tried reaches it.
    EXPECT_EQ(codes("<FilesMatch \"^(index\\.php|avatar_[0-9]+\\.jpg)$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n"),
              kData);
    // An invented extension beside a document one is the data finding, not the document one.
    EXPECT_EQ(codes("<FilesMatch \"\\.(html|alfa)$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n"),
              kData);
    // A selector naming a file with no extension at all.
    EXPECT_EQ(codes("<Files \"upload\">\n  ForceType application/x-httpd-php\n</Files>\n"), kData);
}

// What a selector reaches cannot always be bounded, and a script handler on names nothing can
// bound is read as reaching data: a regex no name tried matches, and one RE2 cannot compile.
TEST_F(HtaccessHandlerTest, ASelectorNothingCanBoundIsReadAsReachingData) {
    EXPECT_EQ(codes("<FilesMatch \"^[a-f0-9]{32}$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n"),
              kData);
    EXPECT_EQ(codes("<FilesMatch \"(?<=avatar)\\.php$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n"),
              kData);
}

// mod_proxy_fcgi: `SetHandler "proxy:unix:/path/app.sock|fcgi://localhost/"`, allowed in an
// .htaccess where ProxyPass is not.
TEST_F(HtaccessHandlerTest, PhpFpmThroughAProxyHandler) {
    EXPECT_EQ(codes("<FilesMatch \"\\.zip$\">\n"
                    "  SetHandler \"proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost\"\n"
                    "</FilesMatch>\n"),
              kData);
    EXPECT_EQ(codes("SetHandler \"proxy:fcgi://127.0.0.1:9000\"\n"), kData);
    EXPECT_EQ(codes("AddHandler \"proxy:fcgi://127.0.0.1:9000\" .jpg\n"), kData);
    // A proxy to anything but a FastCGI backend runs nothing here.
    EXPECT_EQ(codes("SetHandler \"proxy:http://127.0.0.1:8080/php\"\n"), kSilent);
}

// mod_cgi and mod_fcgid run the file itself, and only where ExecCGI is on. The first case is
// the shape the attacker files in the measured incident trees share: an Options list without
// signs, naming ExecCGI, and an invented extension.
TEST_F(HtaccessHandlerTest, CgiHandlersOnAnInventedExtensionUnderExecCgi) {
    EXPECT_EQ(codes("Options FollowSymLinks MultiViews Indexes ExecCGI\n"
                    "AddType application/x-httpd-cgi .alfa\n"
                    "AddHandler cgi-script .alfa\n"),
              kData);
    EXPECT_EQ(codes("Options +ExecCGI\nAddHandler cgi-script .xyz\n"), kData);
    EXPECT_EQ(codes("Options All\nAddHandler cgi-script .jpg\n"), kData);
    EXPECT_EQ(codes("Options +ExecCGI\nAddHandler fcgid-script .dat\n"), kData);
    EXPECT_EQ(codes("Options +ExecCGI\nSetHandler cgi-script\n"), kData);
}

// ---------------------------------------------------------------------------------------------
// Handler names
// ---------------------------------------------------------------------------------------------

TEST_F(HtaccessHandlerTest, EveryHostingStacksPhpHandlerNameOnADataExtension) {
    for (const char* handler : {
             "application/x-httpd-php",              // mod_php's magic type
             "php-script", "php7-script", "php5-script",   // mod_php's PHP_SCRIPT token
             "application/x-httpd-php5", "x-httpd-php",
             "application/x-httpd-ea-php74",         // cPanel MultiPHP, EasyApache 4
             "application/x-httpd-alt-php74___lsphp",   // CloudLinux alt-php through LSPHP
             "application/x-httpd-lsphp",            // LiteSpeed
             "application/x-httpd-php81",            // LiteSpeed's handler ID for a version
             "x-mapp-php5",                          // 1&1 / IONOS
         }) {
        SCOPED_TRACE(handler);
        EXPECT_EQ(codes(std::string("AddHandler ") + handler + " .jpg\n"), kData);
    }
}

// ---------------------------------------------------------------------------------------------
// Extension classes
// ---------------------------------------------------------------------------------------------

TEST_F(HtaccessHandlerTest, EveryClassOfNonScriptExtension) {
    for (const char* ext : {
             ".jpg", ".png", ".gif", ".svg", ".ico", ".webp",        // images
             ".zip", ".rar", ".gz", ".tar", ".7z",                   // archives
             ".mdb", ".sqlite", ".sql",                              // databases
             ".pdf", ".doc", ".txt", ".csv",                         // documents
             ".css", ".js", ".xml", ".json",                         // web data
             ".alfa", ".xyz",                                        // invented
             ".htaccess",                                            // the file itself
         }) {
        SCOPED_TRACE(ext);
        EXPECT_EQ(codes(std::string("AddType application/x-httpd-php ") + ext + "\n"), kData);
    }
}

// ---------------------------------------------------------------------------------------------
// What must stay silent
// ---------------------------------------------------------------------------------------------

// The block cPanel's MultiPHP Manager writes, in its EasyApache 4 AddHandler and older AddType
// forms, with the versioned extension it lists beside .php.
TEST_F(HtaccessHandlerTest, CpanelGeneratedHandlerBlocksAreSilent) {
    EXPECT_EQ(codes("# php -- BEGIN cPanel-generated handler, do not edit\n"
                    "# Set the \"ea-php81\" package as the default \"PHP\" programming language.\n"
                    "<IfModule mime_module>\n"
                    "  AddHandler application/x-httpd-ea-php81 .php .php81 .phtml\n"
                    "</IfModule>\n"
                    "# php -- END cPanel-generated handler, do not edit\n"),
              kSilent);
    EXPECT_EQ(codes("<IfModule mime_module>\n"
                    "   AddType application/x-httpd-ea-php56 .php .php5 .phtml\n"
                    "</IfModule>\n"),
              kSilent);
    EXPECT_EQ(codes("AddHandler application/x-httpd-ea-php74 .php .php7 .phtml\n"), kSilent);
}

TEST_F(HtaccessHandlerTest, LiteSpeedAndCloudLinuxHandlerLinesAreSilent) {
    EXPECT_EQ(codes("<IfModule LiteSpeed>\n  AddHandler application/x-httpd-lsphp .php\n</IfModule>\n"),
              kSilent);
    EXPECT_EQ(codes("AddHandler application/x-httpd-alt-php74___lsphp .php .php7 .phtml\n"), kSilent);
    EXPECT_EQ(codes("AddType application/x-httpd-php53 .php\n"), kSilent);
}

// Debian's mod_php and PHP-FPM configuration, and php.net's own recipe.
TEST_F(HtaccessHandlerTest, DistributionFilesMatchBlocksForPhpAreSilent) {
    EXPECT_EQ(codes("<FilesMatch \".+\\.ph(?:ar|p|tml)$\">\n"
                    "    SetHandler application/x-httpd-php\n"
                    "</FilesMatch>\n"),
              kSilent);
    EXPECT_EQ(codes("<FilesMatch \".+\\.ph(?:ar|p|tml)$\">\n"
                    "    SetHandler \"proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost\"\n"
                    "</FilesMatch>\n"),
              kSilent);
    EXPECT_EQ(codes("<FilesMatch \\.php$>\n    SetHandler application/x-httpd-php\n</FilesMatch>\n"),
              kSilent);
    EXPECT_EQ(codes("<FilesMatch \"\\.(php[2-6]?|phtml)$\">\n    SetHandler application/x-httpd-php\n</FilesMatch>\n"),
              kSilent);
    EXPECT_EQ(codes("<Files \"index.php\">\n    ForceType application/x-httpd-php\n</Files>\n"), kSilent);
}

// application/x-httpd-php-source highlights a file instead of running it, on any extension.
TEST_F(HtaccessHandlerTest, TheSourceHighlightingHandlerRunsNothing) {
    EXPECT_EQ(codes("<FilesMatch \"\\.phps$\">\n    SetHandler application/x-httpd-php-source\n</FilesMatch>\n"),
              kSilent);
    EXPECT_EQ(codes("AddType application/x-httpd-php-source .phps .txt\n"), kSilent);
}

// The guard stock plugins and CMS trees ship turns ExecCGI off, and every instance measured
// lists .htm beside the script extensions; an ordinary cgi-bin maps CGI extensions.
TEST_F(HtaccessHandlerTest, CgiGuardsAndOrdinaryCgiAreSilent) {
    EXPECT_EQ(codes("Options -ExecCGI\n"
                    "AddHandler cgi-script .php .pl .py .jsp .asp .htm .shtml .sh .cgi\n"),
              kSilent);
    EXPECT_EQ(codes("Options +ExecCGI\nAddHandler cgi-script .cgi .pl .py\n"), kSilent);
    // No ExecCGI in the file, and none turned on elsewhere in it.
    EXPECT_EQ(codes("AddHandler cgi-script .alfa\n"), kSilent);
    EXPECT_EQ(codes("Options Indexes FollowSymLinks\nAddHandler cgi-script .alfa\n"), kSilent);
    EXPECT_EQ(codes("Options +ExecCGI\nOptions -ExecCGI\nAddHandler cgi-script .alfa\n"), kSilent);
}

TEST_F(HtaccessHandlerTest, CommentsNonHandlersAndNoneAreSilent) {
    EXPECT_EQ(codes("# AddType x-mapp-php5 .php\n# AddHandler x-mapp-php5 .php\n"
                    "# AddHandler application/x-httpd-php .jpg\n"),
              kSilent);
    EXPECT_EQ(codes("AddType image/webp .webp\nAddType text/x-php .jpg\n"), kSilent);
    EXPECT_EQ(codes("<FilesMatch \"\\.jpg$\">\n  SetHandler None\n</FilesMatch>\n"), kSilent);
    EXPECT_EQ(codes("AddHandler application/x-httpd-php .inc .php5 .phps\n"), kSilent);
}

// ---------------------------------------------------------------------------------------------
// .html and .htm
// ---------------------------------------------------------------------------------------------

TEST_F(HtaccessHandlerTest, HtmlAndHtmAreTheLowerSeverityRule) {
    EXPECT_EQ(codes("AddHandler application/x-httpd-php .html .htm\n"), kDocument);
    EXPECT_EQ(codes("AddType application/x-httpd-ea-php82 .html\n"), kDocument);
    EXPECT_EQ(codes("<FilesMatch \"\\.html?$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n"),
              kDocument);
    // HTML beside a data extension is the data finding, once.
    EXPECT_EQ(codes("AddHandler application/x-httpd-php .html .jpg\n"), kData);
}

// ---------------------------------------------------------------------------------------------
// The name
// ---------------------------------------------------------------------------------------------

// A directive does something only in the file the server reads per directory.
TEST_F(HtaccessHandlerTest, TheSameBytesUnderAnyOtherNameRaiseNothing) {
    const std::string body = "AddType application/x-httpd-php .mdb\nSetHandler application/x-httpd-php\n";
    ASSERT_EQ(codes(body), kData);
    for (const char* path : {
             "site/uploads/htaccess.txt", "site/uploads/.htaccess.bak", "site/uploads/x.htaccess",
             "site/uploads/-6a9fd699-e4.htaccess", "site/uploads/htaccess", "site/admin/config.php",
             "site/.htaccess/readme.txt",
         }) {
        SCOPED_TRACE(path);
        EXPECT_EQ(codes(body, path), kSilent);
    }
}

// Apache opens the configured name through the filesystem, so on Windows and on a case-blind
// mount `.HTACCESS` is the file it reads, and Windows drops trailing dots and spaces from a
// name. A zip written on Windows separates with a backslash.
TEST_F(HtaccessHandlerTest, TheNameIsReadAsTheServingFilesystemWouldReadIt) {
    const std::string body = "AddType application/x-httpd-php .mdb\n";
    for (const char* path : {
             ".htaccess", "site/uploads/.HTACCESS", "site/uploads/.Htaccess",
             "site/uploads/.htaccess.", "site/uploads/.htaccess ", "site\\uploads\\.htaccess",
         }) {
        SCOPED_TRACE(path);
        EXPECT_EQ(codes(body, path), kData);
    }
}

TEST(HtaccessHandlerNameTest, AccessFileNameIsExactApartFromCaseAndTrailingDotsAndSpaces) {
    using analysis::htaccess::isAccessFileName;
    EXPECT_TRUE(isAccessFileName(".htaccess"));
    EXPECT_TRUE(isAccessFileName(".HtAccess"));
    EXPECT_TRUE(isAccessFileName(".htaccess. ."));
    EXPECT_FALSE(isAccessFileName("htaccess"));
    EXPECT_FALSE(isAccessFileName(".htaccess2"));
    EXPECT_FALSE(isAccessFileName("..htaccess"));
    EXPECT_FALSE(isAccessFileName(""));
}

// ---------------------------------------------------------------------------------------------
// Inside an archive
// ---------------------------------------------------------------------------------------------

namespace {

class ScratchDir {
public:
    ScratchDir() {
        path_ = lyxbosa::test::makeUniqueTempDir("lyxbosa-htaccess");
    }
    ~ScratchDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    const fs::path& path() const { return path_; }

private:
    fs::path path_;
};

std::set<std::string> rowCodes(const ScanResult& result, const std::string& address) {
    std::set<std::string> out;
    for (const auto& file : result.files) {
        if (pathToUtf8(file.path) == address) {
            for (const auto& m : file.matches) out.insert(m.category);
            out.insert("<row>");
        }
    }
    return out;
}

}  // namespace

// A plugin zip that plants an .htaccess in its uploads directory, deflated so the directive is
// not in the container's own bytes: the finding has to come from the member, read by a scan.
// The same bytes under another member name are the control.
TEST(HtaccessHandlerArchiveTest, ADeflatedMemberNamedHtaccessIsReported) {
    ScratchDir dir;
    std::string body = "AddType application/x-httpd-php .mdb\n";
    for (int i = 0; i < 200; ++i) body += "# padding padding padding padding padding padding\n";

    const fs::path zip = dir.path() / "plugin.zip";
    writeZip(zip, {{"plugin/uploads/.htaccess", body}, {"plugin/docs/htaccess.txt", body}},
             std::nullopt, ZIP_CM_DEFLATE);
    for (const auto& [name, method] : compressionMethodsOf(zip)) {
        EXPECT_EQ(method, 8u) << name;
    }
    {
        std::ifstream in(zip, std::ios::binary);
        const std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        ASSERT_EQ(bytes.find("x-httpd-php"), std::string::npos) << "the directive must not be stored";
    }

    AppConfig config = Config::loadFromString(Config::generateDefault());
    config.scan.directories = {pathToUtf8(dir.path())};
    config.scan.recursive = true;
    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    const std::string container = pathToUtf8(zip);
    const auto member = rowCodes(result, container + "!plugin/uploads/.htaccess");
    EXPECT_EQ(member.count("<row>"), 1u);
    EXPECT_EQ(member.count("BD019"), 1u);
    EXPECT_EQ(rowCodes(result, container + "!plugin/docs/htaccess.txt").count("BD019"), 0u);
}
