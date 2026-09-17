// path_encoding_test.cpp - a path and UTF-8 text, in both directions, on the names that break
// the conversion between them.
//
// WHICH NAMES, AND WHY THOSE. On Windows std::filesystem converts between a path and a narrow
// string in the host's ANSI code page, so whether a name breaks depends on the host as much as
// on the name. The Windows hosts this suite runs on differ exactly there: the CI runner is code
// page 1252 and the machine the defect was found on is 1253. A case written with a Greek name
// alone passes on the Greek host whether the conversion is repaired or not, which is a check
// that cannot fail. So each name is here for what it proves:
//
//   CJK      outside both code pages: the name that aborted a scan on either host
//   Greek    inside 1253 and outside 1252
//   Latin-1  inside 1252 and outside 1253 - so, with Greek, each host has a name only a
//            conversion that does not lean on the code page gets right, and a name that
//            conversion would have got right by luck
//   U+009B   outside both, and a C1 control, so it also crosses the escape a report applies
//   ASCII    inside every code page; the control that nothing else moved
//
// WhatTheCodePageDoesToEachNameOnThisHost says which of them fell outside the code page of the
// host that ran the suite, and fails when none did.
//
// Every name is spelled with escapes. MSVC reads a source file in the host's code page unless
// told otherwise, so a raw character in this file would be a different name on each host.
//
// On Linux and macOS a name is bytes and std::filesystem converts nothing, so the Windows
// failures these cases exist for are passes there by construction. The hostile input that
// belongs to those platforms is a name that is not UTF-8 at all, and it has cases of its own.

#include "UniqueTempDir.h"
#include <gtest/gtest.h>

#include "archive/ArchiveScanner.h"
#include "archive/ArchiveTypes.h"
#include "config/Config.h"
#include "core/FileWalker.h"
#include "core/ScanResult.h"
#include "core/Scanner.h"
#include "infrastructure/PathUtils.h"
#include "infrastructure/Terminal.h"
#include "infrastructure/TerminalCaps.h"
#include "infrastructure/report/JsonReportWriter.h"
#include "rules/filename.h"
#include "system/CliArgs.h"
#include "use-cases/CheckUseCase.h"
#include "use-cases/ScanUseCase.h"
#include "use-cases/ValidateConfigUseCase.h"
#include "utils/SafeText.h"

#include "ArchiveFixtures.h"
#include "PlatformSkips.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace lyxbosa;

namespace {

namespace fs = std::filesystem;
namespace fixtures = lyxbosa::test::fixtures;

struct Name {
    const char* label;   // for a failure message
    std::string utf8;    // as a configuration file, a command line or an archive spells it
    std::wstring wide;   // as NTFS stores it
};

const std::vector<Name>& names() {
    static const std::vector<Name> kNames = {
        {"CJK", "\xE8\xAB\x8B\xE6\xB1\x82\xE6\x9B\xB8",
         {wchar_t(0x8ACB), wchar_t(0x6C42), wchar_t(0x66F8)}},
        {"Greek", "\xCE\xB1\xCF\x81\xCF\x87\xCE\xB5\xCE\xAF\xCE\xBF",
         {wchar_t(0x03B1), wchar_t(0x03C1), wchar_t(0x03C7), wchar_t(0x03B5), wchar_t(0x03AF),
          wchar_t(0x03BF)}},
        {"Latin-1", "R\xC3\xA9sum\xC3\xA9",
         {L'R', wchar_t(0x00E9), L's', L'u', L'm', wchar_t(0x00E9)}},
        {"C1 control", "k\xC2\x9B" "2J", {L'k', wchar_t(0x009B), L'2', L'J'}},
        {"ASCII", "index", {L'i', L'n', L'd', L'e', L'x'}},
    };
    return kNames;
}

// The name as the filesystem spells it, with an ASCII suffix, built WITHOUT pathFromUtf8() -
// which is what is under test, and which could not be the witness against itself.
fs::path nativeName(const Name& name, std::string_view suffix = "") {
#ifdef _WIN32
    return fs::path(name.wide + std::wstring(suffix.begin(), suffix.end()));
#else
    return fs::path(name.utf8 + std::string(suffix));
#endif
}

// A temporary directory that removes itself, named from a steady_clock tick like the ones in
// the other suites so that two test binaries running at once do not collide.
class TempDir {
public:
    TempDir() {
        path_ = lyxbosa::test::makeUniqueTempDir("lyxbosa-path-encoding-test");
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    const fs::path& path() const { return path_; }

private:
    fs::path path_;
};

void writeFile(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

constexpr const char* kBenign = "<?php echo 1;\n";

// The shipped configuration over one root, handed over as main() hands a root over: UTF-8.
AppConfig configFor(const fs::path& root) {
    AppConfig config = Config::loadFromString(Config::generateDefault());
    config.scan.directories = {pathToUtf8(root)};
    config.scan.recursive = true;
    config.actions.quarantine.enabled = false;
    return config;
}

ScanResult runScan(const AppConfig& config) {
    Scanner scanner(config);
    scanner.setPreCount(false);
    return scanner.scan();
}

// One file's row as a program reading the JSON report sees it, and the path that program would
// open: the bytes when the report carries them, the rendering when it says it did not need to.
fs::path reopenedFromReport(const ScanResult& result, const FileResult& file) {
    std::ostringstream json;
    JsonReportWriter writer(json);
    writer.begin();
    writer.onFile(file);
    writer.end(result, false);

    const std::string document = json.str();
    EXPECT_TRUE(safe_text::isValidUtf8(document));
    if (!nlohmann::json::accept(document)) {
        ADD_FAILURE() << "the report is not a JSON document: " << safe_text::sanitize(document);
        return {};
    }
    const nlohmann::json record = nlohmann::json::parse(document).at("files").at(0);
    const std::string hex = record.value("pathBytesHex", std::string());
    EXPECT_EQ(hex.empty(), !pathDisplayIsLossy(file.path))
        << "the report carries the bytes when it does not need to, or not when it does";
    if (hex.empty()) {
        return pathFromUtf8(record.value("path", std::string()));
    }
    std::string bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        bytes += static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16));
    }
    return pathFromUtf8(bytes);
}

std::string randomBytes(size_t size) {
    std::mt19937 generator(20260916);
    std::string out(size, '\0');
    for (char& c : out) {
        c = static_cast<char>(generator() & 0xff);
    }
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// The two conversions.
// ---------------------------------------------------------------------------

TEST(PathEncodingTest, EachDirectionIsTheOthersInverse) {
    for (const Name& name : names()) {
        SCOPED_TRACE(name.label);
        const fs::path native = nativeName(name, ".php");
        const std::string utf8 = name.utf8 + ".php";

        // Against the filesystem's own spelling, and not only against each other: two
        // conversions that both went through the code page would round-trip every name the
        // code page holds and get every one of them wrong. Compared as native strings, because
        // gtest prints a path through path::string() - which is the abort, on a failure.
        EXPECT_EQ(pathFromUtf8(utf8).native(), native.native());
        EXPECT_EQ(pathToUtf8(native), utf8);

        EXPECT_EQ(pathToUtf8(pathFromUtf8(utf8)), utf8);
        EXPECT_EQ(pathFromUtf8(pathToUtf8(native)).native(), native.native());

        // Beside a separator, in a path of several components.
        const fs::path nested = fs::path("site") / native / "x.php";
        EXPECT_EQ(pathFromUtf8(pathToUtf8(nested)).native(), nested.native());
        EXPECT_EQ(pathToUtf8(nested.parent_path().filename()), utf8);
    }
    EXPECT_TRUE(pathFromUtf8("").empty());
    EXPECT_EQ(pathToUtf8(fs::path()), "");
}

TEST(PathEncodingTest, WhatOneEncodingCannotHoldIsLostTheDocumentedWay) {
#ifdef _WIN32
    // UTF-16 has no way to carry bytes that are not UTF-8, so each ill-formed byte becomes
    // U+FFFD. PathUtils.h says so, and this keeps it saying something true.
    EXPECT_EQ(pathFromUtf8("a\xC0\xAF" "b").native(),
              (std::wstring{L'a', wchar_t(0xFFFD), wchar_t(0xFFFD), L'b'}));
    // An unpaired surrogate - which NTFS accepts in a name - has no UTF-8 spelling, and is the
    // one path pathToUtf8() cannot round-trip.
    const fs::path lone(std::wstring{L'a', wchar_t(0xD800), L'b'});
    EXPECT_EQ(pathToUtf8(lone), "a\xEF\xBF\xBD" "b");
#else
    // A name is bytes here, and bytes that are not UTF-8 go through both directions untouched,
    // for pathForDisplay() to escape and pathBytesHex() to carry.
    const std::string illFormed = "a\xC0\xAF" "b";
    EXPECT_EQ(pathFromUtf8(illFormed).native(), illFormed);
    EXPECT_EQ(pathToUtf8(fs::path(illFormed)), illFormed);
    EXPECT_TRUE(pathDisplayIsLossy(pathFromUtf8(illFormed)));
#endif
}

TEST(PathEncodingTest, WhatTheCodePageDoesToEachNameOnThisHost) {
#ifdef _WIN32
    const UINT codePage = GetACP();
    if (codePage == CP_UTF8) {
        GTEST_SKIP() << "this process runs with the UTF-8 code page, which holds every name, so "
                        "path::string() cannot throw on one here and the hazard the cases in "
                        "this file are about cannot be observed";
    }

    std::string outside;
    for (const Name& name : names()) {
        BOOL usedDefault = FALSE;
        const int size = WideCharToMultiByte(codePage, WC_NO_BEST_FIT_CHARS, name.wide.data(),
                                             static_cast<int>(name.wide.size()), nullptr, 0,
                                             nullptr, &usedDefault);
        const bool holds = size > 0 && !usedDefault;

        // The abort itself, observed rather than described: the narrow conversion throws for
        // exactly the names this code page cannot hold.
        bool threw = false;
        try {
            (void)fs::path(name.wide).string();
        } catch (const std::system_error&) {
            threw = true;
        }
        EXPECT_EQ(threw, !holds) << name.label << " on code page " << codePage;
        if (!holds) {
            outside += (outside.empty() ? "" : ", ") + std::string(name.label);
        }
    }
    std::printf("[   INFO   ] code page %u; outside it: %s\n", codePage,
                outside.empty() ? "none" : outside.c_str());
    EXPECT_FALSE(outside.empty())
        << "code page " << codePage << " holds every name in this file, so no case here "
        << "observes the conversion it is about";
    EXPECT_EQ(outside.find("ASCII"), std::string::npos)
        << "the ASCII control fell outside the code page, so the names prove nothing here";
#else
    // Nothing is converted: the narrow spelling of every name is the name.
    for (const Name& name : names()) {
        EXPECT_EQ(fs::path(name.utf8).string(), name.utf8) << name.label;
    }
#endif
}

// ---------------------------------------------------------------------------
// The walk, the filters and the report.
// ---------------------------------------------------------------------------

TEST(PathEncodingTest, ATreeNamedOutsideTheCodePageIsScannedToTheEnd) {
    TempDir root;
    for (const Name& name : names()) {
        writeFile(root.path() / nativeName(name, ".php"), kBenign);
    }
    // A name as a directory, where only a pattern holding `**` reads it - and the shipped
    // configuration has two.
    writeFile(root.path() / nativeName(names().front()) / "index.php", kBenign);

    // The counting thread left on. It asks the same questions of every name as the walk does,
    // and an exception there does not reach the scan: it ends the process.
    Scanner scanner(configFor(root.path()));
    std::ostringstream json;
    JsonReportWriter writer(json);
    writer.begin();
    scanner.setFileResultCallback([&writer](const FileResult& file) { writer.onFile(file); });

    ScanResult result;
    ASSERT_NO_THROW(result = scanner.scan());
    writer.end(result, false);

    EXPECT_EQ(result.totalFilesScanned, names().size() + 1);
    EXPECT_TRUE(result.rootsMissing.empty());
    EXPECT_EQ(result.entriesUnreadable, 0u);
    EXPECT_EQ(result.directoriesUnreadable, 0u);
    EXPECT_TRUE(nlohmann::json::accept(json.str())) << safe_text::sanitize(json.str());
}

TEST(PathEncodingTest, APatternWrittenInUtf8MatchesTheNameItSpellsAndNoOther) {
    TempDir root;
    for (const Name& name : names()) {
        writeFile(root.path() / nativeName(name, ".php"), kBenign);
    }

    // Three names excluded by patterns spelled the way a configuration file spells them. The
    // other two must be caught by neither - one of them is a name the host's code page holds
    // and one is ASCII.
    AppConfig config = configFor(root.path());
    config.scan.reportExcluded = true;
    std::set<std::string> expectedExcluded;
    for (const Name& name : names()) {
        if (std::string(name.label) == "Latin-1" || std::string(name.label) == "ASCII") {
            continue;
        }
        config.scan.exclude.push_back("*" + name.utf8 + "*");
        expectedExcluded.insert(name.utf8 + ".php");
    }

    const ScanResult result = runScan(config);

    std::set<std::string> excluded;
    for (const auto& file : result.files) {
        if (file.skipReason == SkipReason::Excluded) {
            excluded.insert(pathToUtf8(file.path.filename()));
        }
    }
    EXPECT_EQ(excluded, expectedExcluded);
    EXPECT_EQ(result.totalFilesScanned, names().size() - expectedExcluded.size());

    // And every row names its file well enough for a program to open it again - the C1 name
    // through the bytes the report carries beside the escaped rendering.
    for (const auto& file : result.files) {
        SCOPED_TRACE(pathForDisplay(file.path));
        const fs::path reopened = reopenedFromReport(result, file);
        EXPECT_TRUE(fs::exists(reopened))
            << "a program reading this report cannot get back to the file it names";
        EXPECT_EQ(reopened.native(), file.path.native());
    }
}

TEST(PathEncodingTest, ARootOrAFileNamedOnTheCommandLineIsTheOneReached) {
    for (const Name& name : names()) {
        SCOPED_TRACE(name.label);
        TempDir root;
        const fs::path directory = root.path() / nativeName(name);
        const fs::path file = root.path() / nativeName(name, ".php");
        writeFile(directory / "index.php", kBenign);
        writeFile(file, kBenign);

        const Terminal terminal(/*useAnsi=*/false);
        const TerminalCaps caps = TerminalCaps::detect();

        // As main() hands every argument over, on every platform: UTF-8. On Windows that is
        // wmain()'s conversion, which this process cannot be started through; the release
        // binary is what observes it.
        CliArgs scan;
        scan.directories.push_back(pathToUtf8(directory));
        scan.force = true;
        scan.quarantine = false;
        scan.quiet = true;
        scan.noPreCount = true;
        testing::internal::CaptureStdout();
        testing::internal::CaptureStderr();
        const int scanCode = ScanUseCase(terminal, caps).execute(scan);
        const std::string scanOut = testing::internal::GetCapturedStdout();
        const std::string scanErr = testing::internal::GetCapturedStderr();
        EXPECT_EQ(scanCode, 0) << safe_text::sanitize(scanErr);
        EXPECT_EQ(scanErr.find("not usable"), std::string::npos) << safe_text::sanitize(scanErr);

        CliArgs check;
        check.checkFile = pathToUtf8(file);
        testing::internal::CaptureStdout();
        testing::internal::CaptureStderr();
        const int checkCode = CheckUseCase(terminal, caps).execute(check);
        const std::string checkOut = testing::internal::GetCapturedStdout();
        const std::string checkErr = testing::internal::GetCapturedStderr();
        EXPECT_EQ(checkCode, 0) << safe_text::sanitize(checkErr);
        EXPECT_NE(checkOut.find("No matches found in: " + pathForDisplay(file)),
                  std::string::npos)
            << safe_text::sanitize(checkOut) << safe_text::sanitize(checkErr);
    }
}

TEST(PathEncodingTest, AConfigurationFileNamedOutsideTheCodePageLoadsOrIsNamedMissing) {
    for (const Name& name : names()) {
        SCOPED_TRACE(name.label);
        TempDir root;
        const fs::path file = root.path() / nativeName(name, ".yaml");
        writeFile(file, Config::generateDefault());
        EXPECT_NO_THROW((void)Config::loadFromFile(pathFromUtf8(pathToUtf8(file))));

        // The refusal is a ConfigError naming the file, which the command prints. Anything
        // else - the std::system_error path::string() threw here - escapes every catch a
        // command has and ends the process.
        const fs::path missing = root.path() / nativeName(name, "-missing.yaml");
        try {
            (void)Config::loadFromFile(missing);
            ADD_FAILURE() << "a configuration file that does not exist was loaded";
        } catch (const ConfigError& error) {
            EXPECT_NE(std::string(error.what()).find(pathForDisplay(missing)), std::string::npos)
                << safe_text::sanitize(error.what());
        }
    }
}

TEST(PathEncodingTest, AQuarantineDirectoryWrittenInUtf8IsTheDirectoryUsed) {
    constexpr const char* kShell = "<?php eval(base64_decode($_POST['x'])); ?>\n";
    for (const Name& name : names()) {
        SCOPED_TRACE(name.label);
        TempDir root;
        const fs::path scanned = root.path() / "scanned";
        const fs::path shell = scanned / "shell.php";
        writeFile(shell, kShell);
        if (const auto why = test::whyTheFixtureIsNotOnDisk(shell, kShell)) {
            GTEST_SKIP() << *why;
        }

        const fs::path quarantine = root.path() / nativeName(name, "-quarantine");
        AppConfig config = configFor(scanned);
        config.actions.quarantine.enabled = true;
        config.actions.quarantine.directory = pathToUtf8(quarantine);
        config.actions.quarantine.preserveStructure = false;

        const ScanResult result = runScan(config);
        ASSERT_EQ(result.filesQuarantined, 1u);
        ASSERT_EQ(result.files.size(), 1u);
        EXPECT_TRUE(fs::is_directory(quarantine));
        EXPECT_EQ(result.files.front().quarantinePath.parent_path().native(), quarantine.native());
        EXPECT_TRUE(fs::exists(result.files.front().quarantinePath));
    }
}

// ---------------------------------------------------------------------------
// Archives: the container's own name, and the names it stores.
// ---------------------------------------------------------------------------

TEST(PathEncodingTest, AMemberIsReportedUnderTheNameTheArchiveStores) {
    TempDir root;
    const fs::path zip = root.path() / "members.zip";

    // Each name twice, carrying the `;` FN002 answers for: once as a member the policy leaves
    // shut, whose row is written without reading it, and once as one it opens. The two rows are
    // addressed by two different pieces of code.
    std::vector<std::pair<std::string, std::string>> members;
    std::set<std::string> expected;
    for (const Name& name : names()) {
        for (const std::string member : {name.utf8 + ";1.mdb", "site/" + name.utf8 + ";2.php"}) {
            ASSERT_FALSE(rules::filename::examine(member).empty())
                << "the fixture's own name raises nothing, so no row would be written for it";
            members.emplace_back(member, kBenign);
            expected.insert(pathToUtf8(zip) + "!" + member);
        }
    }
    fixtures::writeZip(zip, members);

    const ScanResult result = runScan(configFor(root.path()));
    EXPECT_EQ(result.archives.archivesUnreadable, 0u);

    std::set<std::string> reported;
    for (const auto& file : result.files) {
        const std::string address = pathToUtf8(file.path);
        if (address.find('!') == std::string::npos) {
            continue;
        }
        reported.insert(address);

        SCOPED_TRACE(pathForDisplay(file.path));
        // The path itself holds the characters, not a spelling of their bytes in the code page.
        EXPECT_EQ(file.path.native(), pathFromUtf8(address).native());

        // And a program reading the report gets the same address back, through the bytes where
        // the C1 control made the rendering one-way.
        std::ostringstream json;
        JsonReportWriter writer(json);
        writer.begin();
        writer.onFile(file);
        writer.end(result, false);
        ASSERT_TRUE(nlohmann::json::accept(json.str())) << safe_text::sanitize(json.str());
        const nlohmann::json record = nlohmann::json::parse(json.str()).at("files").at(0);
        EXPECT_EQ(record.value("path", std::string()), pathForDisplay(file.path));
        const std::string hex = record.value("pathBytesHex", std::string());
        EXPECT_EQ(hex.empty(), !pathDisplayIsLossy(file.path));
        if (!hex.empty()) {
            EXPECT_EQ(hex, pathBytesHex(pathFromUtf8(address)));
        }
    }
    EXPECT_EQ(reported, expected);
}

TEST(PathEncodingTest, AnArchiveNamedOutsideTheCodePageIsOpenedFromItsPath) {
    for (const Name& name : names()) {
        SCOPED_TRACE(name.label);
        TempDir root;
        const fs::path zip = root.path() / nativeName(name, ".zip");
        // Incompressible padding, so the container is past the size limit below whatever the
        // deflater makes of it.
        fixtures::writeZip(zip, {{"a;1.php", kBenign}, {"padding.bin", randomBytes(8192)}});

        // Past the size limit, so the container is opened from its path - the one route that
        // hands libzip a file name - rather than from bytes already read.
        AppConfig config = configFor(root.path());
        config.scan.maxFileSize = 1024;
        ASSERT_GT(fs::file_size(zip), config.scan.maxFileSize);

        // The pre-count opens the same file by the same name, on a thread of its own.
        const auto counted = archive::ArchiveScanner::countMembers(
            zip, archive::Kind::Zip, config.archives, config.scan);
        EXPECT_EQ(counted.files, 1u) << "the index was not read";

        const ScanResult result = runScan(config);
        EXPECT_EQ(result.archives.archivesOpened, 1u);
        EXPECT_EQ(result.archives.archivesUnreadable, 0u)
            << "a container named outside the code page was reported unreadable";
        const std::string member = pathToUtf8(zip) + "!a;1.php";
        bool found = false;
        for (const auto& file : result.files) {
            found = found || pathToUtf8(file.path) == member;
        }
        EXPECT_TRUE(found) << "the member's row is missing, so nothing inside was read";

        // `check` on the same file takes the same route.
        Scanner scanner(config);
        std::vector<FileResult> checked;
        scanner.setFileResultCallback([&checked](const FileResult& file) {
            checked.push_back(file);
        });
        const FileResult file = scanner.scanFile(zip);
        ASSERT_TRUE(file.archive.has_value());
        EXPECT_EQ(file.archive->archivesUnreadable, 0u);
        EXPECT_EQ(checked.size(), 1u);
    }
}

TEST(PathEncodingTest, AMemberNameThatIsNotUtf8IsReportedAsFarAsThePlatformCanSpellIt) {
    // A tar header holds bytes, so this is the member name that is not UTF-8 - the archive's
    // counterpart of a POSIX file name that is not.
    TempDir root;
    const fs::path tar = root.path() / "ill-formed.tar";
    const std::string member = "a;b\xC0\xAF" ".mdb";
    std::string bytes;
    fixtures::appendTarMember(bytes, member, kBenign);
    bytes += fixtures::endOfTar();
    writeFile(tar, bytes);

    const ScanResult result = runScan(configFor(root.path()));
    const FileResult* row = nullptr;
    for (const auto& file : result.files) {
        if (pathToUtf8(file.path).find('!') != std::string::npos) {
            row = &file;
        }
    }
    ASSERT_NE(row, nullptr) << "the member's name was not judged";

    // Judged on the bytes the archive stores, on every platform.
    bool fn002 = false;
    for (const auto& match : row->matches) {
        fn002 = fn002 || match.category == "FN002";
    }
    EXPECT_TRUE(fn002);

#ifdef _WIN32
    // UTF-16 cannot hold the two ill-formed bytes, so the address says U+FFFD twice - the loss
    // PathUtils.h documents. The finding above does not depend on it.
    EXPECT_EQ(pathToUtf8(row->path), pathToUtf8(tar) + "!a;b\xEF\xBF\xBD\xEF\xBF\xBD.mdb");
#else
    // The bytes are the address, escaped for a terminal and carried whole for a program.
    const std::string address = pathToUtf8(tar) + "!" + member;
    EXPECT_EQ(pathToUtf8(row->path), address);
    EXPECT_TRUE(pathDisplayIsLossy(row->path));
    EXPECT_EQ(pathBytesHex(row->path), pathBytesHex(fs::path(address)));
#endif
}

// ---------------------------------------------------------------------------
// The configuration file is read as UTF-8. Where a path is UTF-16, a value that becomes a path
// and is not UTF-8 names nothing, and the file is refused; where a path is bytes, it is a name.
// ---------------------------------------------------------------------------

namespace {

// Greek as code page 1253 spells it - what an editor on a Greek Windows installation writes when
// the file is saved in the system encoding. Not UTF-8: 0xe1 begins no sequence there.
const std::string kGreekInCodePage1253 = "\xE1\xF1\xF7\xE5\xDF\xEF";

std::string forwardSlashes(std::string text) {
    std::replace(text.begin(), text.end(), '\\', '/');
    return text;
}

// The shipped configuration, scanning one root spelled exactly as `root` is.
std::string configScanning(const std::string& root) {
    std::string yaml = Config::generateDefault();
    const std::string placeholder = "    - /var/www\n";
    const size_t at = yaml.find(placeholder);
    EXPECT_NE(at, std::string::npos) << "the shipped configuration no longer has its placeholder";
    if (at != std::string::npos) {
        yaml.replace(at, placeholder.size(), "    - \"" + root + "\"\n");
    }
    return yaml;
}

struct CommandRun {
    int code = 0;
    std::string out;
    std::string err;
};

CommandRun validateConfig(const fs::path& file) {
    CliArgs args;
    args.validateConfigFile = pathToUtf8(file);
    const Terminal terminal(/*useAnsi=*/false);
    CommandRun run;
    testing::internal::CaptureStdout();
    testing::internal::CaptureStderr();
    run.code = ValidateConfigUseCase(terminal).execute(args);
    run.out = testing::internal::GetCapturedStdout();
    run.err = testing::internal::GetCapturedStderr();
    return run;
}

CommandRun scanWithConfig(const fs::path& file) {
    CliArgs args;
    args.configFile = pathToUtf8(file);
    args.force = true;
    args.quarantine = false;
    args.quiet = true;
    args.noPreCount = true;
    args.outputFormat = ReportFormat::Json;
    args.outputFormatExplicit = true;
    const Terminal terminal(/*useAnsi=*/false);
    const TerminalCaps caps = TerminalCaps::detect();
    CommandRun run;
    testing::internal::CaptureStdout();
    testing::internal::CaptureStderr();
    run.code = ScanUseCase(terminal, caps).execute(args);
    run.out = testing::internal::GetCapturedStdout();
    run.err = testing::internal::GetCapturedStderr();
    return run;
}

size_t filesScannedIn(const std::string& report) {
    if (!nlohmann::json::accept(report)) {
        ADD_FAILURE() << "the report is not a JSON document: " << safe_text::sanitize(report);
        return 0;
    }
    return nlohmann::json::parse(report).value("totalFilesScanned", size_t{0});
}

}  // namespace

TEST(ConfigurationEncodingTest, EveryValueThatBecomesAPathIsNamedWhenItIsNotUtf8) {
    // The wording, once in full: the key and the entry, the value escaped, the byte and its
    // offset in whyNotPlainText()'s words, and what to do.
    AppConfig roots;
    roots.scan.directories = {"/srv/site", "/srv/" + kGreekInCodePage1253};
    const auto refusal = Config::pathValueNotUtf8(roots);
    ASSERT_TRUE(refusal);
    EXPECT_EQ(*refusal,
              "scan.directories entry 2 (\"/srv/\\xe1\\xf1\\xf7\\xe5\\xdf\\xef\") is not valid "
              "UTF-8 (byte 0xe1 at offset 5). On Windows a configuration value that names a "
              "path, or is matched against one, is read as UTF-8, and no file name can hold "
              "these bytes; save the configuration file as UTF-8");

    // Every other key a path is read from, each named as itself.
    const std::string bad = "x" + kGreekInCodePage1253;
    struct Case {
        const char* key;
        void (*plant)(AppConfig&, const std::string&);
    };
    const Case cases[] = {
        {"scan.include entry 1", [](AppConfig& c, const std::string& v) { c.scan.include = {v}; }},
        {"scan.exclude entry 2",
         [](AppConfig& c, const std::string& v) { c.scan.exclude = {"node_modules/**", v}; }},
        {"actions.quarantine.directory",
         [](AppConfig& c, const std::string& v) { c.actions.quarantine.directory = v; }},
        {"actions.report.file",
         [](AppConfig& c, const std::string& v) { c.actions.report.file = v; }},
    };
    for (const Case& planted : cases) {
        SCOPED_TRACE(planted.key);
        AppConfig config;
        planted.plant(config, bad);
        const auto problem = Config::pathValueNotUtf8(config);
        ASSERT_TRUE(problem);
        EXPECT_EQ(problem->rfind(std::string(planted.key) + " (\"x\\xe1", 0), 0u) << *problem;
        EXPECT_NE(problem->find("is not valid UTF-8 (byte 0xe1 at offset 1)"), std::string::npos)
            << *problem;
        EXPECT_NE(problem->find("save the configuration file as UTF-8"), std::string::npos);
    }
}

TEST(ConfigurationEncodingTest, OnlyTheEncodingOfAPathValueIsAskedAbout) {
    // Well-formed UTF-8 in every value a path is read from: Greek, CJK, and control characters,
    // which a real directory name may hold and which an operator may need to scan.
    for (const std::string value :
         {std::string("/srv/\xCE\xB1\xCF\x81\xCF\x87\xCE\xB5\xCE\xAF\xCE\xBF"),
          std::string("/srv/\xE8\xAB\x8B\xE6\xB1\x82\xE6\x9B\xB8"), std::string("/srv/k\xC2\x9B" "2J"),
          std::string("/srv/e\x1B]0;x\x07"), std::string("/srv/del\x7F"), std::string("C:\\www"),
          std::string()}) {
        AppConfig config;
        config.scan.directories = {value};
        config.scan.include = {"*" + value};
        config.scan.exclude = {value + "/**"};
        config.actions.quarantine.directory = value;
        config.actions.report.file = value;
        EXPECT_FALSE(Config::pathValueNotUtf8(config)) << safe_text::sanitize(value);
    }

    // A value that does not name a file is not this question's, however it is spelled.
    AppConfig config;
    config.actions.alert.to = kGreekInCodePage1253;
    RuleConfig rule;
    rule.name = "needle";
    PatternConfig pattern;
    pattern.value = kGreekInCodePage1253;
    rule.patterns.push_back(pattern);
    config.rules.push_back(rule);
    EXPECT_FALSE(Config::pathValueNotUtf8(config));
}

TEST(ConfigurationEncodingTest, ScanAndValidateConfigGiveOneAnswerAboutACodePageGreekRoot) {
    TempDir root;
    const fs::path parent = root.path() / "roots";
    fs::create_directories(parent);
    const std::string rootText = forwardSlashes(pathToUtf8(parent)) + "/" + kGreekInCodePage1253;
    if (!kPathsAreUtf16) {
        // Where a path is bytes, those bytes are this directory's name.
        writeFile(pathFromUtf8(rootText) / "index.php", kBenign);
    }
    const fs::path file = root.path() / "saved-in-1253.yaml";
    writeFile(file, configScanning(rootText));

    const CommandRun validate = validateConfig(file);
    const CommandRun scan = scanWithConfig(file);

    if (kPathsAreUtf16) {
        AppConfig named;
        named.scan.directories = {rootText};
        const auto problem = Config::pathValueNotUtf8(named);
        ASSERT_TRUE(problem);
        const std::string refusal = "Error: " + *problem + "\n";
        EXPECT_EQ(validate.code, 1);
        EXPECT_EQ(scan.code, 1);
        // One function, one sentence: the same bytes on standard error from both commands.
        EXPECT_EQ(validate.err, refusal) << safe_text::sanitize(validate.err);
        EXPECT_EQ(scan.err, refusal) << safe_text::sanitize(scan.err);
        EXPECT_EQ(validate.err.find("\xEF\xBF\xBD"), std::string::npos)
            << "the refusal spells the value with U+FFFD rather than naming its bytes";
    } else {
        EXPECT_EQ(validate.code, 0) << safe_text::sanitize(validate.err);
        EXPECT_NE(validate.out.find("Configuration is valid."), std::string::npos);
        EXPECT_EQ(scan.code, 0) << safe_text::sanitize(scan.err);
        EXPECT_EQ(filesScannedIn(scan.out), 1u) << "the directory those bytes name was not read";
    }
}

TEST(ConfigurationEncodingTest, AUtf8GreekRootLoadsAndIsScannedOnEveryPlatform) {
    TempDir root;
    const fs::path directory = root.path() / nativeName(names()[1]);   // Greek
    writeFile(directory / "index.php", kBenign);
    const fs::path file = root.path() / "saved-in-utf-8.yaml";
    writeFile(file, configScanning(forwardSlashes(pathToUtf8(directory))));

    const CommandRun validate = validateConfig(file);
    EXPECT_EQ(validate.code, 0) << safe_text::sanitize(validate.err);
    EXPECT_NE(validate.out.find("Configuration is valid."), std::string::npos);

    const CommandRun scan = scanWithConfig(file);
    EXPECT_EQ(scan.code, 0) << safe_text::sanitize(scan.err);
    EXPECT_EQ(filesScannedIn(scan.out), 1u);
}
