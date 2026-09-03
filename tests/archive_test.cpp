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

#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <zip.h>
#include <zlib.h>

using namespace lyxbosa;
using namespace lyxbosa::archive;

namespace {

namespace fs = std::filesystem;

// A temporary directory that removes itself, so a failing test cannot leave a
// crafted archive lying around on the machine that ran it.
class TempDir {
public:
    TempDir() {
        path_ = fs::temp_directory_path() /
                ("lyxbosa-archive-test-" + std::to_string(::getpid()) + "-" +
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

// --- tar construction -------------------------------------------------------

void writeOctal(char* field, size_t width, uint64_t value) {
    // tar writes numbers as zero-padded octal with a trailing NUL.
    for (size_t i = width - 1; i-- > 0;) {
        field[i] = static_cast<char>('0' + (value & 7));
        value >>= 3;
    }
    field[width - 1] = '\0';
}

std::string tarHeader(const std::string& name, uint64_t size, char type = '0') {
    std::string block(512, '\0');
    char* raw = block.data();

    std::memcpy(raw, name.data(), std::min<size_t>(name.size(), 99));
    writeOctal(raw + 100, 8, 0644);
    writeOctal(raw + 108, 8, 0);
    writeOctal(raw + 116, 8, 0);
    writeOctal(raw + 124, 12, size);
    writeOctal(raw + 136, 12, 0);
    raw[156] = type;
    std::memcpy(raw + 257, "ustar", 5);
    std::memcpy(raw + 263, "00", 2);

    // The checksum is computed with its own field read as eight spaces.
    std::memset(raw + 148, ' ', 8);
    unsigned sum = 0;
    for (size_t i = 0; i < 512; ++i) {
        sum += static_cast<unsigned char>(block[i]);
    }
    writeOctal(raw + 148, 7, sum);
    raw[155] = ' ';

    return block;
}

void appendTarMember(std::string& tar, const std::string& name, const std::string& body,
                     char type = '0') {
    tar += tarHeader(name, body.size(), type);
    tar += body;
    if (const size_t rem = body.size() % 512; rem != 0) {
        tar.append(512 - rem, '\0');
    }
}

std::string endOfTar() { return std::string(1024, '\0'); }

// --- gzip -------------------------------------------------------------------

std::string gzipCompress(const std::string& input) {
    z_stream stream{};
    // 15 window bits + 16: write a gzip header rather than a zlib one.
    EXPECT_EQ(deflateInit2(&stream, Z_BEST_SPEED, Z_DEFLATED, 15 + 16, 8,
                           Z_DEFAULT_STRATEGY),
              Z_OK);

    std::string out;
    out.resize(deflateBound(&stream, input.size()) + 64);

    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
    stream.avail_in = static_cast<uInt>(input.size());
    stream.next_out = reinterpret_cast<Bytef*>(out.data());
    stream.avail_out = static_cast<uInt>(out.size());

    EXPECT_EQ(deflate(&stream, Z_FINISH), Z_STREAM_END);
    out.resize(stream.total_out);
    deflateEnd(&stream);
    return out;
}

void writeFile(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

// --- zip construction -------------------------------------------------------

// Members are added from buffers this vector keeps alive: libzip does not copy
// them until the archive is written out.
void writeZip(const fs::path& path, const std::vector<std::pair<std::string, std::string>>& members) {
    int err = 0;
    zip_t* za = zip_open(path.string().c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    ASSERT_NE(za, nullptr);

    for (const auto& [name, body] : members) {
        zip_source_t* source = zip_source_buffer(za, body.data(), body.size(), 0);
        ASSERT_NE(source, nullptr);
        ASSERT_GE(zip_file_add(za, name.c_str(), source, ZIP_FL_OVERWRITE), 0);
    }

    ASSERT_EQ(zip_close(za), 0);
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

// Malware inside the same archive is a different matter - but the container is
// still not moved, because a member cannot be quarantined out of it.
TEST(ArchiveScannerTest, MalwareInAnArchiveStillQuarantinesTheContainer) {
    TempDir dir;
    TempDir quarantine;

    const auto payload = dir.path() / "payload.zip";
    writeZip(payload, {{"x.php", "<?php eval(base64_decode($_POST['x'])); ?>"}});

    AppConfig config = testConfig(dir.path());
    config.actions.quarantine.enabled = true;
    config.actions.quarantine.directory = quarantine.path().string();
    config.actions.quarantine.preserveStructure = false;

    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    // The zip's own bytes match the rule too, so it is hostile content, not just
    // a misplaced file.
    EXPECT_EQ(result.filesQuarantined, 1u);
    EXPECT_FALSE(fs::exists(payload));
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
    if (::geteuid() == 0) {
        GTEST_SKIP() << "root can read a mode-000 file, so there is nothing to deny";
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
    if (::geteuid() == 0) {
        GTEST_SKIP() << "root can read a mode-000 directory";
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

// The reasons the archive JSON object is keyed by must keep their spellings, or
// every existing consumer of a report breaks silently.
TEST(FileSkipReasonTest, ArchiveReasonSpellingsAreStable) {
    EXPECT_EQ(skipReasonToString(SkipReason::Size), "size");
    EXPECT_EQ(skipReasonToString(SkipReason::Depth), "depth");
    EXPECT_EQ(skipReasonToString(SkipReason::Ratio), "ratio");
    EXPECT_EQ(skipReasonToString(SkipReason::Budget), "budget");
    EXPECT_EQ(skipReasonToString(SkipReason::Corrupt), "corrupt");
    EXPECT_EQ(skipReasonToString(SkipReason::Policy), "policy");
    EXPECT_EQ(skipReasonToString(SkipReason::Excluded), "excluded");
    EXPECT_EQ(skipReasonToString(SkipReason::Unreadable), "unreadable");
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
}
