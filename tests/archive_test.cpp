#include <gtest/gtest.h>

#include "archive/ArchiveFormat.h"
#include "archive/ArchiveIndex.h"
#include "archive/ArchiveScanner.h"
#include "archive/ByteSource.h"
#include "archive/GzipSource.h"
#include "archive/TarReader.h"
#include "archive/ZipReader.h"
#include "config/Config.h"
#include "core/Scanner.h"
#include "infrastructure/ResultPrinter.h"
#include "infrastructure/report/JsonReportWriter.h"

#include "ArchiveFixtures.h"
#include "PlatformSkips.h"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <zip.h>
#include <zlib.h>

using namespace lyxbosa;
using namespace lyxbosa::archive;
using namespace lyxbosa::test::fixtures;

namespace {

namespace fs = std::filesystem;

// A temporary directory that removes itself, so a failing test cannot leave a
// crafted archive lying around on the machine that ran it.
class TempDir {
public:
    TempDir() {
        // A steady_clock tick rather than ::getpid(), which is POSIX-only and was the
        // third unguarded assumption in this suite. The name only has to be unique
        // among concurrent runs, and this is what tests/update_test.cpp already uses.
        const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = fs::temp_directory_path() /
                ("lyxbosa-archive-test-" + std::to_string(tick) + "-" +
                 std::to_string(counter_++));
        fs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }

    const fs::path& path() const { return path_; }

private:
    fs::path path_;
    static inline int counter_ = 0;
};

void writeFile(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

// A member body that deflate genuinely compresses, so the literal the rules match
// does not survive into the container's own bytes. A short body does not: libzip
// stores what it cannot shrink, and the payload is then readable in the zip.
std::string compressibleBody(const std::string& payload) {
    std::string body = payload;
    body += "\n";
    for (int i = 0; i < 400; ++i) {
        body += "// padding padding padding padding padding padding\n";
    }
    return body;
}

bool rawBytesContain(const fs::path& path, std::string_view needle) {
    std::ifstream in(path, std::ios::binary);
    const std::string bytes((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
    return bytes.find(needle) != std::string::npos;
}

AppConfig testConfig(const fs::path& directory) {
    AppConfig config = Config::loadFromString(Config::generateDefault());
    config.scan.directories = {directory.string()};
    config.scan.recursive = true;
    return config;
}

}  // namespace

// ============================================================================
// Member names and buckets
// ============================================================================

TEST(ArchiveIndexTest, NormalisesSeparatorsAndPrefixes) {
    EXPECT_EQ(normalizeMemberName("./site/wp-config.php"), "site/wp-config.php");
    EXPECT_EQ(normalizeMemberName("/var/www/x.php"), "var/www/x.php");
    EXPECT_EQ(normalizeMemberName("site\\wp-content\\x.php"), "site/wp-content/x.php");
}

// The spelling the patterns and the sidecar test read: the prefixes every extractor measured
// writes beneath its destination come off, and a backslash is left as the character it is.
TEST(ArchiveIndexTest, TheFilterNameKeepsEveryBackslash) {
    EXPECT_EQ(memberFilterName("./site/wp-config.php"), "site/wp-config.php");
    EXPECT_EQ(memberFilterName("/var/www/x.php"), "var/www/x.php");
    EXPECT_EQ(memberFilterName(".///./x.php"), "x.php");
    EXPECT_EQ(memberFilterName("site\\wp-content\\x.php"), "site\\wp-content\\x.php");
    EXPECT_EQ(memberFilterName(".\\x.php"), ".\\x.php");
    EXPECT_EQ(memberFilterName("\\x.php"), "\\x.php");
    EXPECT_EQ(memberFilterName(""), "");
}

// The all-backslash reading, by its definition: no forward slash in any name but the trailing
// slash of a directory entry. The `sub/` PHP's addEmptyDir() writes beside backslash-spelled
// files keeps the reading; any other forward slash, in any one name, ends it.
TEST(ArchiveIndexTest, NamesUseOnlyBackslashesByDefinition) {
    const auto entries = [](std::initializer_list<const char*> names) {
        std::vector<Entry> out;
        for (const char* name : names) {
            Entry entry;
            entry.name = name;
            entry.directory = !entry.name.empty() && entry.name.back() == '/';
            out.push_back(entry);
        }
        return out;
    };
    EXPECT_TRUE(namesUseOnlyBackslashes(entries({"site\\index.php", "site\\wp-content\\x.php"})));
    EXPECT_TRUE(namesUseOnlyBackslashes(entries({"sub/", "sub\\ro.txt", "sub\\rw.txt"})));
    EXPECT_TRUE(namesUseOnlyBackslashes(entries({"sub\\inner/", "sub\\inner\\x.php"})));
    EXPECT_TRUE(namesUseOnlyBackslashes(entries({"wp-content\\", "index.php"})));
    EXPECT_TRUE(namesUseOnlyBackslashes(entries({"index.php", "readme.txt"})))
        << "no separator at all: splitting on both changes nothing, and the definition holds";

    EXPECT_FALSE(namesUseOnlyBackslashes(entries({"site\\index.php", "site/other.php"})));
    EXPECT_FALSE(namesUseOnlyBackslashes(entries({"site/wp-content\\x.php"})));
    EXPECT_FALSE(namesUseOnlyBackslashes(entries({"sub//", "sub\\x.php"})))
        << "only one trailing slash is a directory marker";
    EXPECT_FALSE(namesUseOnlyBackslashes(entries({"/abs\\x.php"})));
}

TEST(ArchiveIndexTest, ScriptsAndMarkupAreClassifiedSeparately) {
    EXPECT_TRUE(isScriptName("index.php"));
    EXPECT_TRUE(isScriptName("cgi-bin/handler"));      // no extension at all
    EXPECT_TRUE(isMarkupName("app/main.js"));
    EXPECT_TRUE(isMediaName("uploads/photo.JPEG"));    // case-insensitive
    EXPECT_FALSE(isScriptName("readme.txt"));
}

TEST(ArchiveIndexTest, ScriptInAWritableDirectoryIsHot) {
    // wp-content/uploads is WordPress-only; the test is the directory's role,
    // not the platform's name for it.
    EXPECT_EQ(classifyMember("wp-content/uploads/2024/05/x.php"), Bucket::HotScript);
    EXPECT_EQ(classifyMember("image/catalog/x.php"), Bucket::HotScript);   // OpenCart
    EXPECT_EQ(classifyMember("pub/media/x.php"), Bucket::HotScript);       // Magento
    EXPECT_EQ(classifyMember("wp-includes/version.php"), Bucket::Script);
    EXPECT_EQ(classifyMember("assets/app.js"), Bucket::Markup);
    EXPECT_EQ(classifyMember("uploads/photo.jpg"), Bucket::Other);
}

// ============================================================================
// Classifying an archive from its index alone
// ============================================================================

TEST(ArchiveIndexTest, PayloadArchiveIsNotASiteBackup) {
    IndexSummary summary;
    summary.observe("x.php");
    summary.observe("readme.txt");

    EXPECT_FALSE(summary.siteBackup());
    EXPECT_TRUE(summary.credentials.empty());
}

TEST(ArchiveIndexTest, ASingleSqlDumpIsEnough) {
    IndexSummary summary;
    summary.observe("db/dump.sql");

    EXPECT_TRUE(summary.siteBackup());
    EXPECT_EQ(summary.sqlDumps, 1u);
}

// A PHP count measures size, not exposure. Three vendor plugin bundles in one
// real WordPress theme clear any threshold - js_composer.zip has 435 PHP files -
// and expose nothing: they are public plugin code anyone can download.
TEST(ArchiveIndexTest, VendorBundleIsNotASiteBackupHoweverLarge) {
    IndexSummary summary;
    for (int i = 0; i < 500; ++i) {
        summary.observe("js_composer/include/file" + std::to_string(i) + ".php");
    }

    EXPECT_FALSE(summary.siteBackup());
    EXPECT_FALSE(summary.exposesSecrets());
    EXPECT_EQ(summary.platform(), "");
}

// What separates a backup from a bundle is that it is a copy of an *installed*
// site: the platform's distribution files, its credentials, or its database.
TEST(ArchiveIndexTest, DistributionFilesPlusVolumeMakeItASiteBackup) {
    IndexSummary summary;
    summary.observe("site/wp-includes/version.php");
    for (int i = 0; i < 18; ++i) {
        summary.observe("site/wp-content/file" + std::to_string(i) + ".php");
    }
    EXPECT_FALSE(summary.siteBackup());   // recognised, but only 19 PHP entries

    summary.observe("site/wp-content/file18.php");
    EXPECT_TRUE(summary.siteBackup());
    EXPECT_FALSE(summary.exposesSecrets());   // no config, no dump: a disclosure
}

// A bare basename is not a credential marker. Matching "settings.php" anywhere
// hit wp-admin/network/settings.php - a WordPress core admin page - and reported
// six credential files in an archive that has one.
TEST(ArchiveIndexTest, CredentialMarkersAreQualifiedByPath) {
    IndexSummary summary;
    summary.observe("site/wp-admin/network/settings.php");
    summary.observe("site/wp-content/plugins/x/settings.php");
    EXPECT_TRUE(summary.credentials.empty());

    summary.observe("site/sites/default/settings.php");   // Drupal's, qualified
    ASSERT_EQ(summary.credentials.size(), 1u);
    EXPECT_EQ(summary.credentials[0], "site/sites/default/settings.php");
}

TEST(ArchiveIndexTest, RootCredentialsOnlyCountNearTheArchiveRoot) {
    IndexSummary shallow;
    shallow.observe("backup/web/wp-config.php");
    EXPECT_EQ(shallow.credentials.size(), 1u);

    IndexSummary deep;
    deep.observe("backup/web/vendor/pkg/tests/wp-config.php");
    EXPECT_TRUE(deep.credentials.empty());
}

// Config files do not exist in a stock distribution - they are written at
// install - so the platform is identified from distribution files instead.
TEST(ArchiveIndexTest, PlatformComesFromDistributionFiles) {
    IndexSummary wordpress;
    wordpress.observe("site/wp-includes/version.php");
    wordpress.observe("site/wp-login.php");
    EXPECT_EQ(wordpress.platform(), "WordPress");

    IndexSummary magento;
    magento.observe("shop/bin/magento");
    magento.observe("shop/app/etc/di.xml");
    EXPECT_EQ(magento.platform(), "Magento 2");

    IndexSummary drupal;
    drupal.observe("d/core/lib/Drupal.php");
    EXPECT_EQ(drupal.platform(), "Drupal 8+");

    IndexSummary unknown;
    unknown.observe("some/thing.php");
    EXPECT_EQ(unknown.platform(), "");
}

// ============================================================================
// Format sniffing - by bytes, never by name
// ============================================================================

TEST(ArchiveFormatTest, RecognisesContainersByTheirBytes) {
    std::string tar;
    appendTarMember(tar, "a.php", "<?php");
    tar += endOfTar();

    EXPECT_EQ(sniff(tar), Kind::Tar);
    EXPECT_EQ(sniff(gzipCompress(tar)), Kind::TarGz);
    EXPECT_EQ(sniff(gzipCompress("just some text")), Kind::Gzip);
    EXPECT_EQ(sniff("<?php echo 1;"), Kind::None);
    EXPECT_EQ(sniff("PK\x03\x04 and then rubbish"), Kind::Zip);
}

TEST(ArchiveFormatTest, ExtensionIsOnlyAHintForThePreCount) {
    EXPECT_TRUE(hasArchiveExtension("backup.tar.gz"));
    EXPECT_TRUE(hasArchiveExtension("site.ZIP"));
    EXPECT_FALSE(hasArchiveExtension("shell.php"));
}

// ============================================================================
// tar streaming
// ============================================================================

TEST(TarReaderTest, ReadsMembersInOrder) {
    std::string tar;
    appendTarMember(tar, "site/", "", '5');
    appendTarMember(tar, "site/index.php", "<?php echo 1;");
    appendTarMember(tar, "site/app.js", "console.log(1)");
    tar += endOfTar();

    MemorySource source(tar);
    Budget budget(0, 0, 5 * 1024 * 1024, 0);
    TarReader reader(source, budget);

    Entry entry;
    ASSERT_TRUE(reader.next(entry));
    EXPECT_EQ(entry.name, "site/");
    EXPECT_TRUE(entry.directory);

    ASSERT_TRUE(reader.next(entry));
    EXPECT_EQ(entry.name, "site/index.php");
    std::string body;
    ASSERT_TRUE(reader.readCurrent(body, 0));
    EXPECT_EQ(body, "<?php echo 1;");

    ASSERT_TRUE(reader.next(entry));
    EXPECT_EQ(entry.name, "site/app.js");

    EXPECT_FALSE(reader.next(entry));
    EXPECT_FALSE(reader.corrupt());
}

// GNU tar carries a name too long for the 100-byte field in a member of its own,
// which is most of a deeply nested site backup.
TEST(TarReaderTest, HandlesGnuLongNames) {
    const std::string longName =
        "site/wp-content/plugins/a-plugin-with-a-very-long-name/includes/"
        "deeply/nested/directory/structure/that/exceeds/one/hundred/bytes/x.php";
    ASSERT_GT(longName.size(), 100u);

    std::string tar;
    appendTarMember(tar, "././@LongLink", longName + std::string(1, '\0'), 'L');
    appendTarMember(tar, longName.substr(0, 99), "<?php");
    tar += endOfTar();

    MemorySource source(tar);
    Budget budget(0, 0, 0, 0);
    TarReader reader(source, budget);

    Entry entry;
    ASSERT_TRUE(reader.next(entry));
    EXPECT_EQ(entry.name, longName);
}

TEST(TarReaderTest, TruncatedArchiveIsReportedNotIgnored) {
    std::string tar;
    appendTarMember(tar, "site/index.php", std::string(2000, 'a'));
    tar.resize(700);   // header plus a fragment of the body

    MemorySource source(tar);
    Budget budget(0, 0, 0, 0);
    TarReader reader(source, budget);

    Entry entry;
    ASSERT_TRUE(reader.next(entry));
    std::string body;
    EXPECT_FALSE(reader.readCurrent(body, 0));
    EXPECT_TRUE(reader.corrupt());
}

TEST(GzipSourceTest, InflatesAndCountsCompressedBytes) {
    const std::string payload(200000, 'x');
    const std::string compressed = gzipCompress(payload);
    ASSERT_LT(compressed.size(), payload.size());

    MemorySource source(compressed);
    GzipSource gzip(source);
    ASSERT_TRUE(gzip.ok());

    std::string out(payload.size(), '\0');
    EXPECT_EQ(gzip.readFully(out.data(), out.size()), payload.size());
    EXPECT_EQ(out, payload);

    // Progress through a .tar.gz is measured in compressed bytes, which is the
    // only quantity known exactly without a second pass.
    EXPECT_EQ(gzip.consumed(), compressed.size());
    EXPECT_EQ(gzip.produced(), payload.size());
}

// ============================================================================
// Guards
// ============================================================================

TEST(BudgetTest, RatioGuardWaitsForEnoughOutputToBeSure) {
    Budget budget(0, 100, 0, 0);

    // A few kilobytes out of a few bytes in is not evidence of a bomb.
    budget.addConsumed(40);
    budget.addExpanded(4096);
    EXPECT_FALSE(budget.ratioTripped());

    budget.addExpanded(4 * 1024 * 1024);
    EXPECT_TRUE(budget.ratioTripped());
}

TEST(BudgetTest, ExpansionCapIsOnDecompressedBytes) {
    Budget budget(1024, 0, 0, 0);
    budget.addExpanded(1023);
    EXPECT_FALSE(budget.expansionExhausted());
    budget.addExpanded(1);
    EXPECT_TRUE(budget.expansionExhausted());
    EXPECT_EQ(budget.spent(), SkipReason::Budget);
}

// The regression test the whole guard set exists for: an archive that expands
// past every limit must terminate, and must say why it stopped.
TEST(ArchiveScannerTest, ZipBombTerminatesAndReportsTheReason) {
    TempDir dir;
    const fs::path bomb = dir.path() / "bomb.zip";

    // 64 members of a megabyte of zeros each: 64 MB out of roughly 64 KB in.
    // Nothing here is exotic - it is 42.zip's trick at a size a test can run.
    const std::string zeros(1024 * 1024, '\0');
    std::vector<std::pair<std::string, std::string>> members;
    for (int i = 0; i < 64; ++i) {
        members.emplace_back("member" + std::to_string(i) + ".php", zeros);
    }
    writeZip(bomb, members);
    ASSERT_LT(fs::file_size(bomb), 1024u * 1024u);

    AppConfig config = testConfig(dir.path());
    config.archives.maxExpansion = 4 * 1024 * 1024;
    config.archives.maxRatio = 100;
    config.archives.timeBudgetSeconds = 10;

    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    // It stopped early...
    EXPECT_LT(result.archives.membersScanned, members.size());
    // ...and it said so, by reason, rather than falling silent.
    EXPECT_GT(result.archives.skippedRatio() + result.archives.skippedBudget(), 0u);
    EXPECT_EQ(result.archives.archivesOpened, 1u);
}

TEST(ArchiveScannerTest, MemberOverTheSizeLimitIsSkippedNotInflated) {
    TempDir dir;
    const std::string big(3 * 1024 * 1024, 'a');
    writeZip(dir.path() / "big.zip", {{"big.php", big}, {"small.php", "<?php echo 1;"}});

    AppConfig config = testConfig(dir.path());
    config.archives.maxMemberSize = 1024 * 1024;

    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    EXPECT_EQ(result.archives.skippedSize(), 1u);
    EXPECT_EQ(result.archives.membersScanned, 1u);
}

// ============================================================================
// End to end: the two findings an archive produces
// ============================================================================

TEST(ArchiveScannerTest, WebshellInsideATarGzIsFoundAndAddressedByMember) {
    TempDir dir;

    std::string tar;
    appendTarMember(tar, "site/index.php", "<?php echo 'hello';");
    appendTarMember(tar, "site/wp-content/uploads/shell.php",
                    "<?php @eval($_POST[\"cmd\"]); ?>");
    tar += endOfTar();
    writeFile(dir.path() / "backup.tar.gz", gzipCompress(tar));

    AppConfig config = testConfig(dir.path());
    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    bool found = false;
    for (const auto& file : result.files) {
        if (file.path.string().find("backup.tar.gz!site/wp-content/uploads/shell.php") !=
            std::string::npos) {
            found = true;
            EXPECT_FALSE(file.matches.empty());
        }
    }
    EXPECT_TRUE(found) << "member findings must be addressed archive!member";
}

TEST(ArchiveScannerTest, SiteBackupIsItselfTheFinding) {
    TempDir dir;

    std::string tar;
    appendTarMember(tar, "site/wp-config.php", "<?php define('DB_PASSWORD', 'x');");
    appendTarMember(tar, "site/wp-includes/version.php", "<?php $wp_version='6.5';");
    appendTarMember(tar, "site/db.sql", "CREATE TABLE wp_users (id int);");
    tar += endOfTar();
    writeFile(dir.path() / "backup.tar.gz", gzipCompress(tar));

    AppConfig config = testConfig(dir.path());
    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    bool exposure = false;
    for (const auto& file : result.files) {
        if (file.path.filename() != "backup.tar.gz") continue;
        for (const auto& match : file.matches) {
            if (match.category == "ARC001") {
                exposure = true;
                EXPECT_EQ(match.severity, Severity::Critical);
                // The operator needs to know what it hands over, not how it was
                // found.
                EXPECT_NE(match.context.find("wp-config.php"), std::string::npos);
                EXPECT_NE(match.context.find("WordPress"), std::string::npos);
            }
        }
    }
    EXPECT_TRUE(exposure) << "an exposed backup is a finding in its own right";
}

// A copy of an installed site with its config left out is still a disclosure -
// custom themes, plugins and uploads - but it hands over no credentials, so it
// is not a takeover and not critical.
TEST(ArchiveScannerTest, CmsTreeWithoutItsConfigIsHighNotCritical) {
    TempDir dir;

    std::vector<std::pair<std::string, std::string>> members;
    members.emplace_back("site/wp-includes/version.php", "<?php $wp_version='6.5';");
    for (int i = 0; i < 25; ++i) {
        members.emplace_back("site/wp-content/themes/x/file" + std::to_string(i) + ".php",
                             "<?php echo 1;");
    }
    writeZip(dir.path() / "release.zip", members);

    AppConfig config = testConfig(dir.path());
    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    bool exposure = false;
    for (const auto& file : result.files) {
        if (file.path.filename() != "release.zip") continue;
        for (const auto& match : file.matches) {
            if (match.category == "ARC002") {
                exposure = true;
                EXPECT_EQ(match.severity, Severity::High);
                EXPECT_NE(match.context.find("WordPress"), std::string::npos);
            }
            EXPECT_NE(match.category, "ARC001");
        }
    }
    EXPECT_TRUE(exposure);
}

// The same volume of PHP with nothing identifying an installed site behind it is
// a plugin bundle, and reporting it would drown the archives that matter.
TEST(ArchiveScannerTest, VendorBundleProducesNoExposureFinding) {
    TempDir dir;

    std::vector<std::pair<std::string, std::string>> members;
    for (int i = 0; i < 40; ++i) {
        members.emplace_back("js_composer/include/file" + std::to_string(i) + ".php",
                             "<?php echo 1;");
    }
    writeZip(dir.path() / "js_composer.zip", members);

    AppConfig config = testConfig(dir.path());
    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    for (const auto& file : result.files) {
        for (const auto& match : file.matches) {
            EXPECT_FALSE(match.category.starts_with("ARC"))
                << "public plugin code exposes nothing: " << file.path.string();
        }
    }
}

// An exposed backup is the operator's own data - possibly their only copy, and
// possibly 13 GB of it. The finding says to delete it; the scanner does not move
// it, because moving it is a custody decision and, if the destination is still
// served, not even a fix.
TEST(ArchiveScannerTest, ExposureFindingsAreNeverQuarantined) {
    TempDir dir;
    TempDir quarantine;

    std::string tar;
    appendTarMember(tar, "site/wp-config.php", "<?php define('DB_PASSWORD','x');");
    appendTarMember(tar, "site/db.sql", "CREATE TABLE wp_users (id int);");
    tar += endOfTar();
    const auto backup = dir.path() / "backup.tar.gz";
    writeFile(backup, gzipCompress(tar));

    AppConfig config = testConfig(dir.path());
    config.actions.quarantine.enabled = true;
    config.actions.quarantine.directory = quarantine.path().string();
    config.actions.quarantine.preserveStructure = false;

    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    EXPECT_EQ(result.filesQuarantined, 0u);
    EXPECT_TRUE(fs::exists(backup)) << "the operator's backup must still be there";

    bool reported = false;
    for (const auto& file : result.files) {
        for (const auto& match : file.matches) {
            if (match.category == "ARC001") {
                reported = true;
                EXPECT_TRUE(isExposureFinding(match));
                // The finding carries the remediation, since the tool will not
                // perform it.
                EXPECT_NE(match.context.find("delete it"), std::string::npos);
            }
        }
        EXPECT_FALSE(file.quarantined);
    }
    EXPECT_TRUE(reported);
}

// Malware inside an archive still quarantines the container, which is what
// docs/SCANNING.md says beside the rule about exposed backups. A member cannot be
// moved out of the archive it is in, so the container is what gets contained.
//
// The case has to be a member the container is NOT detectable by. An earlier version
// of this test used a 42-byte body that libzip stored rather than deflated: the
// literal sat in the zip's own bytes, the container matched on its own account, and
// the test passed for a reason other than the one in its name while a member-only
// detection was being left on disk. The assertion below is what keeps that from
// coming back - it is the whole difference between this test and its predecessor.
TEST(ArchiveScannerTest, MalwareInAnArchiveStillQuarantinesTheContainer) {
    TempDir dir;
    TempDir quarantine;

    const auto payload = dir.path() / "payload.zip";
    writeZip(payload, {{"x.php",
                        compressibleBody("<?php eval(base64_decode($_POST['x'])); ?>")}});

    ASSERT_FALSE(rawBytesContain(payload, "base64_decode"))
        << "the payload is readable in the container's raw bytes, so this case would "
           "pass on the container's own match and prove nothing about the member";

    AppConfig config = testConfig(dir.path());
    config.actions.quarantine.enabled = true;
    config.actions.quarantine.directory = quarantine.path().string();
    config.actions.quarantine.preserveStructure = false;

    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    // The member was detected, and it was detected as a member rather than as the
    // container: its path is the `archive.zip!member` form.
    bool memberReported = false;
    for (const auto& file : result.files) {
        if (file.path.string().find("payload.zip!x.php") != std::string::npos) {
            memberReported = true;
            EXPECT_TRUE(hasHostileContent(file));
        }
    }
    EXPECT_TRUE(memberReported);

    EXPECT_EQ(result.filesQuarantined, 1u);
    EXPECT_FALSE(fs::exists(payload));
    EXPECT_TRUE(fs::exists(quarantine.path() / "payload.zip"));

    // And the container appears in the report as a file that was moved, even though
    // it carries no match of its own. Moving a file and then saying so nowhere is
    // the same silence as not moving it.
    bool containerReported = false;
    for (const auto& file : result.files) {
        if (file.path == payload) {
            containerReported = true;
            EXPECT_TRUE(file.quarantined);
            EXPECT_FALSE(file.quarantinePath.empty());
        }
    }
    EXPECT_TRUE(containerReported);
}

// The other direction of the same rule. A backup nested inside a container raises an
// exposure finding about the container, and an exposure finding never moves a file -
// so a member that is exposure-only must not become a reason to move the container
// either. Without this, the repair for the case above would quarantine the
// operator's own data the moment it arrived in a zip.
TEST(ArchiveScannerTest, AnExposedBackupInsideAnArchiveDoesNotMoveTheContainer) {
    TempDir dir;
    TempDir quarantine;

    std::string tar;
    appendTarMember(tar, "site/wp-config.php", "<?php define('DB_PASSWORD','x');");
    appendTarMember(tar, "site/db.sql", "CREATE TABLE wp_users (id int);");
    tar += endOfTar();

    const auto outer = dir.path() / "outer.zip";
    writeZip(outer, {{"site-backup.tar.gz", gzipCompress(tar)}});

    AppConfig config = testConfig(dir.path());
    config.actions.quarantine.enabled = true;
    config.actions.quarantine.directory = quarantine.path().string();
    config.actions.quarantine.preserveStructure = false;

    // Exhaustive, and the case says nothing without it. A `.tar.gz` inside a zip is
    // "not code" to the selection policy, so by default the nested container is never
    // opened, its entries never reach the summary, and the outer zip raises no finding
    // of any kind - which made this case green because nothing was found rather than
    // because an exposure finding was declined. The assertion below is what stops it
    // going quiet that way again.
    config.archives.exhaustive = true;

    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    bool exposureRaised = false;
    for (const auto& file : result.files) {
        for (const auto& match : file.matches) {
            if (isExposureFinding(match)) exposureRaised = true;
        }
    }
    ASSERT_TRUE(exposureRaised)
        << "nothing was found at all, so this proves nothing about a finding that must "
           "not move a file";

    EXPECT_EQ(result.filesQuarantined, 0u);
    EXPECT_TRUE(fs::exists(outer)) << "the operator's backup must still be there";
    for (const auto& file : result.files) {
        EXPECT_FALSE(file.quarantined);
        EXPECT_FALSE(hasHostileContent(file))
            << file.path.string() << " carries a finding that is not an exposure, so "
               "this case is no longer about an exposure-only container";
    }
}

// Whether anything hostile was inside the last container is per-file state, and
// state that outlives the file it describes quarantines the next one for free.
//
// The ordering is not left to the directory listing: the walk hands back every file
// directly in a directory before it descends, so the container is always scanned
// before the file in the subdirectory below it.
TEST(ArchiveScannerTest, AHostileArchiveDoesNotTaintTheFileScannedAfterIt) {
    TempDir dir;
    TempDir quarantine;

    const auto payload = dir.path() / "payload.zip";
    writeZip(payload, {{"x.php",
                        compressibleBody("<?php eval(base64_decode($_POST['x'])); ?>")}});
    ASSERT_FALSE(rawBytesContain(payload, "base64_decode"));

    const auto innocent = dir.path() / "sub" / "index.php";
    writeFile(innocent, "<?php echo 'hello';");

    AppConfig config = testConfig(dir.path());
    config.actions.quarantine.enabled = true;
    config.actions.quarantine.directory = quarantine.path().string();
    config.actions.quarantine.preserveStructure = false;

    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    EXPECT_EQ(result.filesQuarantined, 1u);
    EXPECT_FALSE(fs::exists(payload));
    EXPECT_TRUE(fs::exists(innocent)) << "a clean file was moved because the archive "
                                         "scanned before it was hostile";
}

// The pre-count reads a zip's index and adds exactly what the scan will open, so
// the percentage and the ETA stay honest. Nothing is decompressed to learn it.
TEST(ArchiveScannerTest, PreCountMatchesWhatTheScanOpens) {
    TempDir dir;
    const fs::path zip = dir.path() / "site.zip";
    writeZip(zip, {
        {"app/index.php", "<?php echo 1;"},
        {"app/main.js", "console.log(1)"},
        {"app/logo.png", std::string(2048, '\x89')},   // not code: not selected
        {"app/", ""},                                   // a directory entry
    });

    AppConfig config = testConfig(dir.path());
    const auto counted = ArchiveScanner::countMembers(zip, Kind::Zip,
                                                      config.archives, config.scan);
    EXPECT_EQ(counted.files, 2u);

    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();
    EXPECT_EQ(result.archives.membersScanned, counted.files);
}

TEST(ArchiveScannerTest, DisablingArchivesRestoresOpaqueBytes) {
    TempDir dir;
    writeZip(dir.path() / "payload.zip",
             {{"x.php", "<?php eval(base64_decode($_POST['x'])); ?>"}});

    AppConfig config = testConfig(dir.path());
    config.archives.enabled = false;

    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    EXPECT_EQ(result.archives.archivesOpened, 0u);
    for (const auto& file : result.files) {
        EXPECT_EQ(file.path.string().find('!'), std::string::npos);
    }
}

// ============================================================================
// Skip reasons at the file level
//
// The archive layer got this right first: every member that is not scanned is
// counted by reason. These are the same guarantees one level up, where a single
// `bool skippedSize` used to stand for three different things - and where a file
// the scanner could not open was reported as scanned and clean.
// ============================================================================

namespace {

// Writes a file and returns its path. (The existing writeFile above returns void.)
fs::path writeLooseFile(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    return p;
}

}  // namespace

TEST(FileSkipReasonTest, OversizeFileIsReportedAsASizeSkip) {
    TempDir dir;
    writeLooseFile(dir.path() / "big.php", std::string(64 * 1024, 'a'));
    writeLooseFile(dir.path() / "small.php", "<?php echo 1;");

    AppConfig config = testConfig(dir.path());
    config.scan.maxFileSize = 1024;
    config.archives.enabled = false;

    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    EXPECT_EQ(result.skips.count(SkipReason::Size), 1u);
    EXPECT_EQ(result.filesSkippedSize(), 1u);
    EXPECT_EQ(result.skips.total(), 1u);
}

// The bug this whole mechanism exists to stop. readFile used to return an empty
// string when it could not open the file; the empty string then matched no rule,
// and the file was counted as scanned with no findings - the scanner asserting a
// file was clean without having read a byte of it.
TEST(FileSkipReasonTest, UnreadableFileIsNotReportedAsScannedAndClean) {
    if (const auto why = test::whyCannotDenyOwnAccess()) {
        GTEST_SKIP() << *why << " - a mode-000 file would still be read";
    }

    TempDir dir;
    const fs::path secret = writeLooseFile(dir.path() / "secret.php", "<?php echo 1;");
    fs::permissions(secret, fs::perms::none);

    AppConfig config = testConfig(dir.path());
    config.archives.enabled = false;

    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    // Restore before any assertion can leave the temp dir undeletable.
    fs::permissions(secret, fs::perms::owner_read | fs::perms::owner_write);

    EXPECT_EQ(result.skips.count(SkipReason::Unreadable), 1u);
    ASSERT_EQ(result.files.size(), 1u);
    EXPECT_TRUE(result.files[0].skipped());
    EXPECT_EQ(result.files[0].skipReason, SkipReason::Unreadable);
}

// An excluded file is always counted, so an operator can tell whether a pattern
// took effect - but it is only listed when they ask, because on a real tree the
// excluded files outnumber the findings by orders of magnitude.
TEST(FileSkipReasonTest, ExcludedFilesAreCountedAlwaysAndListedOnRequest) {
    TempDir dir;
    writeLooseFile(dir.path() / "keep.php", "<?php echo 1;");
    writeLooseFile(dir.path() / "drop.php", "<?php echo 2;");

    AppConfig config = testConfig(dir.path());
    config.archives.enabled = false;
    config.scan.exclude = {"drop.php"};

    {
        Scanner scanner(config);
        scanner.setPreCount(false);
        const ScanResult result = scanner.scan();
        EXPECT_EQ(result.skips.count(SkipReason::Excluded), 1u);
        EXPECT_EQ(result.totalFilesScanned, 1u);
        for (const auto& file : result.files) {
            EXPECT_NE(file.skipReason, SkipReason::Excluded) << "not listed by default";
        }
    }

    config.scan.reportExcluded = true;
    {
        Scanner scanner(config);
        scanner.setPreCount(false);
        const ScanResult result = scanner.scan();
        EXPECT_EQ(result.skips.count(SkipReason::Excluded), 1u);
        EXPECT_EQ(result.totalFilesScanned, 1u) << "an excluded file is not work";
        size_t listed = 0;
        for (const auto& file : result.files) {
            if (file.skipReason == SkipReason::Excluded) ++listed;
        }
        EXPECT_EQ(listed, 1u);
    }
}

// A directory the scanner was pointed at and could not read is a fact about the
// scan's coverage. directory_options::skip_permission_denied reported it as an
// empty directory, which is indistinguishable from one that really is empty.
TEST(FileSkipReasonTest, UnreadableDirectoryIsCounted) {
    if (const auto why = test::whyCannotDenyOwnAccess()) {
        GTEST_SKIP() << *why << " - a mode-000 directory would still be read";
    }

    TempDir dir;
    writeLooseFile(dir.path() / "sub" / "inner.php", "<?php echo 1;");
    const fs::path sub = dir.path() / "sub";
    fs::permissions(sub, fs::perms::none);

    AppConfig config = testConfig(dir.path());
    config.archives.enabled = false;

    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    fs::permissions(sub, fs::perms::owner_all);

    EXPECT_EQ(result.directoriesUnreadable, 1u);
}

// The reasons the JSON objects are keyed by must keep their spellings, or every existing
// consumer of a report breaks silently.
TEST(FileSkipReasonTest, ArchiveReasonSpellingsAreStable) {
    EXPECT_EQ(skipReasonToString(SkipReason::Size), "size");
    EXPECT_EQ(skipReasonToString(SkipReason::Depth), "depth");
    EXPECT_EQ(skipReasonToString(SkipReason::Ratio), "ratio");
    EXPECT_EQ(skipReasonToString(SkipReason::Budget), "budget");
    EXPECT_EQ(skipReasonToString(SkipReason::Corrupt), "corrupt");
    EXPECT_EQ(skipReasonToString(SkipReason::Policy), "policy");
    EXPECT_EQ(skipReasonToString(SkipReason::Excluded), "excluded");
    EXPECT_EQ(skipReasonToString(SkipReason::Unreadable), "unreadable");
    EXPECT_EQ(skipReasonToString(SkipReason::Sidecar), "sidecar");
}

TEST(FileSkipReasonTest, TallyFormatsInEnumOrderAndOmitsZeroes) {
    SkipTally tally;
    tally.skip(SkipReason::Size, 487);
    tally.skip(SkipReason::Unreadable, 7);
    EXPECT_EQ(formatSkipTally(tally, kFileSkipOrder), "487 over size limit, 7 unreadable");
    EXPECT_EQ(tally.total(), 494u);

    EXPECT_TRUE(formatSkipTally(SkipTally{}, kFileSkipOrder).empty())
        << "nothing skipped prints nothing";

    // The archive line is pre-existing output and must read exactly as it did: "not
    // code" first, and the original wording for the ratio and depth guards.
    SkipTally members;
    members.skip(SkipReason::Policy, 3980);
    members.skip(SkipReason::Size, 118);
    members.skip(SkipReason::Ratio, 9);
    members.skip(SkipReason::Depth, 5);
    members.skip(SkipReason::Corrupt, 4);
    EXPECT_EQ(formatSkipTally(members, kArchiveSkipOrder),
              "3980 not code, 118 over size limit, 9 compression ratio, "
              "5 too deeply nested, 4 corrupt");

    // The selection reasons lead, the operator's patterns and then the sidecars, and each
    // reads in the words the file level uses for it where the file level has it.
    members.skip(SkipReason::Sidecar, 40);
    members.skip(SkipReason::Excluded, 12);
    EXPECT_EQ(formatSkipTally(members, kArchiveSkipOrder),
              "3980 not code, 12 excluded by filters, 40 sidecar metadata, "
              "118 over size limit, 9 compression ratio, 5 too deeply nested, 4 corrupt");
}

// ============================================================================
// Skip reasons at the member level
//
// A member left shut is counted under the reason the file of its name would be counted under,
// where the two levels share one, and in the same words. The operator's patterns are one such
// reason; the priority policy, the sidecar test and the guards are the archive's own.
// ============================================================================

namespace {

void writeTarGz(const fs::path& path,
                const std::vector<std::pair<std::string, std::string>>& members) {
    std::string tar;
    for (const auto& [name, body] : members) {
        appendTarMember(tar, name, body);
    }
    tar += endOfTar();
    writeFile(path, gzipCompress(tar));
}

ScanResult scanOnce(const AppConfig& config) {
    Scanner scanner(config);
    scanner.setPreCount(false);
    return scanner.scan();
}

// What a scan's JSON report and its text summary say, each rendered by the writer an operator
// is handed.
struct Reported {
    nlohmann::ordered_json json;
    std::string summary;
};

Reported reported(const ScanResult& result) {
    std::ostringstream json;
    JsonReportWriter writer(json);
    writer.begin();
    for (const auto& file : result.files) {
        writer.onFile(file);
    }
    writer.end(result, false);

    std::ostringstream text;
    ResultPrinter(text, /*color=*/false, /*width=*/200).printSummary(result);
    return {nlohmann::ordered_json::parse(json.str()), text.str()};
}

// The line of `text` that begins with `prefix`, without its newline; empty when there is none.
std::string lineStarting(const std::string& text, std::string_view prefix) {
    std::istringstream in(text);
    for (std::string line; std::getline(in, line);) {
        if (line.starts_with(prefix)) {
            return line;
        }
    }
    return {};
}

// The words a one-reason summary line says after the reason's count:
// "Files not scanned: 2 (2 excluded by filters)" says "excluded by filters".
std::string wordsOfTheOnlyReason(const std::string& line) {
    const size_t open = line.find('(');
    const size_t space = line.find(' ', open);
    const size_t close = line.rfind(')');
    if (open == std::string::npos || space == std::string::npos || close == std::string::npos ||
        close < space || line.find(',', open) != std::string::npos) {
        return {};
    }
    return line.substr(space + 1, close - space - 1);
}

}  // namespace

// THE GUARANTEE. A loose file under a scan root and the member stored under the same name inside
// an archive in that root, rejected by one exclude pattern, are counted as excluded at their own
// levels - in the JSON report and in the text summary, in the same words - and neither is counted
// as not code. Two names, because the patterns are asked of a member before the priority policy
// is: a script, and a name the policy would leave shut as not code if it were asked first. Two
// containers, because a zip and a tar reach the question through different loops.
TEST(MemberSkipReasonTest, AFileAndTheMemberOfItsNameOnePatternExcludesAreCountedAlike) {
    TempDir dir;
    const std::vector<std::pair<std::string, std::string>> tree = {
        {"site/index.php", "<?php echo 1;\n"},
        {"site/config-old.php", "<?php echo 2;\n"},
        {"site/notes-old.txt", "old notes\n"},
    };
    for (const auto& [name, body] : tree) {
        writeFile(dir.path() / name, body);
    }
    writeZip(dir.path() / "backup.zip", tree);
    writeTarGz(dir.path() / "backup.tar.gz", tree);

    AppConfig config = testConfig(dir.path());
    config.scan.exclude.push_back("*-old.*");
    const ScanResult result = scanOnce(config);

    EXPECT_EQ(result.skips.count(SkipReason::Excluded), 2u);
    EXPECT_EQ(result.skips.total(), 2u);
    EXPECT_EQ(result.archives.membersScanned, 2u) << "the control: each container was read";
    EXPECT_EQ(result.archives.skippedExcluded(), 4u);
    EXPECT_EQ(result.archives.skippedPolicy(), 0u) << "an excluded member was counted as not code";
    EXPECT_EQ(result.archives.totalSkipped(), 4u);

    const Reported said = reported(result);
    EXPECT_EQ(said.json.at("filesSkipped").at("excluded"), 2);
    const auto& members = said.json.at("archives").at("membersSkipped");
    EXPECT_EQ(members.value("excluded", -1), 4) << members.dump();
    EXPECT_EQ(members.value("policy", -1), 0) << members.dump();

    const std::string files = lineStarting(said.summary, "Files not scanned:");
    const std::string archived = lineStarting(said.summary, "Members not scanned:");
    EXPECT_EQ(files, "Files not scanned: 2 (2 excluded by filters)") << said.summary;
    EXPECT_EQ(archived, "Members not scanned: 4 (4 excluded by filters)") << said.summary;
    EXPECT_FALSE(wordsOfTheOnlyReason(files).empty()) << files;
    EXPECT_EQ(wordsOfTheOnlyReason(archived), wordsOfTheOnlyReason(files))
        << "one reason, described in two different words at the two levels";
}

// The pre-count and the scan ask one function, so with exclusions, a sidecar, directory entries
// and a member past the size cap in one zip they still promise the same members - in the default
// selection and in exhaustive mode - and every entry that is a member is counted exactly once.
TEST(MemberSkipReasonTest, ThePreCountAndTheScanAgreeWithExclusionsPresent) {
    TempDir dir;
    const fs::path zip = dir.path() / "site.zip";
    writeZip(zip, {
        {"site/", ""},                                    // a directory entry, not a member
        {"site/index.php", "<?php echo 1;\n"},            // opened
        {"site/config-old.php", "<?php echo 2;\n"},       // excluded
        {"site/notes-old.txt", "old notes\n"},            // excluded
        {"site/readme.txt", "notes\n"},                   // not code; opened when exhaustive
        {"__MACOSX/site/._index.php", "stub\n"},          // a sidecar
        {"site/big.php", std::string(64 * 1024, 'a')},    // past the member size cap
    });

    for (const bool exhaustive : {false, true}) {
        SCOPED_TRACE(exhaustive ? "exhaustive" : "default selection");
        AppConfig config = testConfig(dir.path());
        config.scan.exclude.push_back("*-old.*");
        config.archives.maxMemberSize = 32 * 1024;
        config.archives.exhaustive = exhaustive;

        const auto counted =
            ArchiveScanner::countMembers(zip, Kind::Zip, config.archives, config.scan);
        const ScanResult result = scanOnce(config);
        const Stats& stats = result.archives;

        EXPECT_EQ(stats.membersScanned, counted.files) << "the pre-count disagrees with the scan";
        EXPECT_EQ(counted.files, exhaustive ? 2u : 1u);
        EXPECT_EQ(stats.skippedExcluded(), 2u);
        EXPECT_EQ(stats.skippedSidecar(), 1u);
        EXPECT_EQ(stats.skippedSize(), 1u);
        EXPECT_EQ(stats.skippedPolicy(), exhaustive ? 0u : 1u);
        EXPECT_EQ(stats.membersScanned + stats.totalSkipped(), 6u) << membersNotScannedLine(stats);
    }
}

// The companion to the guarantee. A member the patterns accept and the priority policy leaves
// shut is still counted as not code, in a zip and in a tar.gz, and exhaustive mode opens it - so
// the operator's reason has not swallowed the policy's.
TEST(MemberSkipReasonTest, ANonCodeMemberThePatternsAcceptIsStillCountedAsNotCode) {
    TempDir dir;
    const std::vector<std::pair<std::string, std::string>> members = {
        {"site/readme.txt", "notes\n"},
        {"site/logo.png", std::string(64, '\x89')},
        {"site/index.php", "<?php echo 1;\n"},
    };
    writeZip(dir.path() / "assets.zip", members);
    writeTarGz(dir.path() / "assets.tar.gz", members);

    for (const bool exhaustive : {false, true}) {
        SCOPED_TRACE(exhaustive ? "exhaustive" : "default selection");
        AppConfig config = testConfig(dir.path());
        config.archives.exhaustive = exhaustive;
        const Stats stats = scanOnce(config).archives;

        EXPECT_EQ(stats.skippedPolicy(), exhaustive ? 0u : 4u);
        EXPECT_EQ(stats.skippedExcluded(), 0u) << membersNotScannedLine(stats);
        EXPECT_EQ(stats.membersScanned, exhaustive ? 6u : 2u);
        EXPECT_EQ(membersNotScannedLine(stats),
                  exhaustive ? "" : "Members not scanned: 4 (4 not code)");
    }
}

// A sidecar is counted as a sidecar, under its own key and in its own words, and never as not
// code: a `._index.php` is named like code, and it stays shut in exhaustive mode too, where
// nothing is left shut for not being code. A sidecar no include pattern names is counted as the
// file of its name is - `Thumbs.db` - because the patterns are asked of a member first.
TEST(MemberSkipReasonTest, ASidecarIsCountedAsASidecarAndNeverAsNotCode) {
    TempDir dir;
    const std::vector<std::pair<std::string, std::string>> members = {
        {"__MACOSX/site/._index.php", "stub\n"},
        {"__MACOSX/site/._logo.png", "stub\n"},
        {"site/._style.css", "stub\n"},
        {"site/Thumbs.db", "thumbnails\n"},
        {"site/index.php", "<?php echo 1;\n"},
    };
    writeZip(dir.path() / "mac.zip", members);
    writeTarGz(dir.path() / "mac.tar.gz", members);

    for (const bool exhaustive : {false, true}) {
        SCOPED_TRACE(exhaustive ? "exhaustive" : "default selection");
        AppConfig config = testConfig(dir.path());
        config.archives.exhaustive = exhaustive;
        const ScanResult result = scanOnce(config);
        const Stats& stats = result.archives;

        EXPECT_EQ(stats.skippedSidecar(), 6u);
        EXPECT_EQ(stats.skippedExcluded(), 2u);
        EXPECT_EQ(stats.skippedPolicy(), 0u) << "a sidecar was counted as not code";
        EXPECT_EQ(stats.membersScanned, 2u);
        EXPECT_EQ(membersUnexamined(stats), 0u) << "a sidecar was counted as a member gone unread";

        const Reported said = reported(result);
        const auto& skipped = said.json.at("archives").at("membersSkipped");
        EXPECT_EQ(skipped.value("sidecar", -1), 6) << skipped.dump();
        EXPECT_EQ(skipped.value("policy", -1), 0) << skipped.dump();
        EXPECT_EQ(lineStarting(said.summary, "Members not scanned:"),
                  "Members not scanned: 8 (2 excluded by filters, 6 sidecar metadata)")
            << said.summary;
    }
}

// A directory entry holds no content, so it is not a member that could have been scanned, and it
// is counted nowhere - not as scanned, not as skipped, not in the pre-count - in a zip, in a tar
// under both of the ways a tar says it, and inside a nested zip. Asked with no include list and
// in exhaustive mode as well, where a directory entry that reached the selection would be opened
// rather than left shut, so that neither answer can hide one.
TEST(MemberSkipReasonTest, ADirectoryEntryIsCountedNowhere) {
    TempDir build;
    const fs::path inner = build.path() / "inner.zip";
    writeZip(inner, {{"a/", ""}, {"a/b/", ""}, {"a/x.php", "<?php echo 1;\n"}});

    TempDir dir;
    const fs::path zip = dir.path() / "site.zip";
    writeZip(zip, {{"site/", ""},
                   {"site/sub/", ""},
                   {"site/index.php", "<?php echo 1;\n"},
                   {"site/inner.zip", readBytes(inner)}});
    std::string tar;
    appendTarMember(tar, "site", "", '5');          // a directory by its type
    appendTarMember(tar, "site/sub/", "", '0');     // and by its trailing slash
    appendTarMember(tar, "site/index.php", "<?php echo 1;\n");
    tar += endOfTar();
    writeFile(dir.path() / "site.tar", tar);

    struct Case {
        const char* label;
        bool everything;              // exhaustive, with no include list
        size_t scanned;
        size_t skipped;
        size_t countedInTheZip;
    };
    for (const Case& c : {
             // index.php in each; the nested zip is not code, so it is left shut unopened
             Case{"default selection", false, 2, 1, 1},
             // index.php in each, the nested zip, and a/x.php inside it
             Case{"exhaustive, no include list", true, 4, 0, 2},
         }) {
        SCOPED_TRACE(c.label);
        AppConfig config = testConfig(dir.path());
        if (c.everything) {
            config.archives.exhaustive = true;
            config.scan.include.clear();
        }

        const ScanResult result = scanOnce(config);
        EXPECT_EQ(result.archives.membersScanned, c.scanned);
        EXPECT_EQ(result.archives.totalSkipped(), c.skipped)
            << membersNotScannedLine(result.archives);
        EXPECT_EQ(ArchiveScanner::countMembers(zip, Kind::Zip, config.archives, config.scan).files,
                  c.countedInTheZip);
    }
}

// An archive with no exclusion and no sidecar is described by the reasons that occurred and by
// no others: the two keys are in the JSON at zero, and the summary line names neither - it reads
// "not code" first and the guards after it, in the words it has always used.
TEST(MemberSkipReasonTest, AReportWithNoExclusionsKeepsTheArchiveSummaryWording) {
    TempDir dir;
    writeZip(dir.path() / "site.zip", {{"site/logo.png", std::string(64, '\x89')},
                                       {"site/big.php", std::string(64 * 1024, 'a')},
                                       {"site/index.php", "<?php echo 1;\n"}});

    AppConfig config = testConfig(dir.path());
    config.archives.maxMemberSize = 32 * 1024;
    const Reported said = reported(scanOnce(config));

    EXPECT_EQ(lineStarting(said.summary, "Members not scanned:"),
              "Members not scanned: 2 (1 not code, 1 over size limit)")
        << said.summary;
    const auto& skipped = said.json.at("archives").at("membersSkipped");
    EXPECT_EQ(skipped.value("excluded", -1), 0) << skipped.dump();
    EXPECT_EQ(skipped.value("sidecar", -1), 0) << skipped.dump();
    EXPECT_EQ(skipped.value("policy", -1), 1) << skipped.dump();
    EXPECT_EQ(skipped.value("size", -1), 1) << skipped.dump();
}
