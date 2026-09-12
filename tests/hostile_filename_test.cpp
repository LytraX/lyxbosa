// hostile_filename_test.cpp - the FN rules, watched in both directions.
//
// A detection rule that has never been watched declining something is not yet a rule,
// and this file is written to that shape: every case that asserts a rule fires has a
// neighbour asserting it stays quiet, and the quiet half is built out of the exact
// characters that would have destroyed the rule set's precision if they had been let
// in.
//
// WHERE THE NAMES COME FROM. The hostile ones are real: 22,728 files an automated
// vulnerability scanner left in an upload directory on a production server were
// measured by name, 83 of them are attack-shaped, and the ones below are taken from
// those 83 unchanged. They carry the generator's own id suffix, so none of them is a
// customer document name - which is the reason they can be written down here at all.
//
// The benign ones are synthetic and have to be. 89 of the names in that same directory
// were ordinary customer uploads that a looser rule set fired on, 60 of them carrying
// an apostrophe and 29 an ampersand, and a customer file name can carry a person's
// name - so what is reproduced here is their SHAPE, in the ordinary style of a
// business document, and never one of the names themselves.
//
// THE LINE, AND WHY IT IS WHERE IT IS. Adding the apostrophe and the ampersand to the
// character set takes it from 83 files at 100% precision to 175 at 49%. Everything
// below the "the measured line" heading exists to make that failure impossible to
// reintroduce quietly.

#include <gtest/gtest.h>

#include "config/Config.h"
#include "core/ScanResult.h"
#include "core/Scanner.h"
#include "infrastructure/report/CsvReportWriter.h"
#include "infrastructure/report/JsonReportWriter.h"
#include "rules/Registry.hpp"
#include "rules/filename.h"
#include "utils/SafeText.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace lyxbosa;
namespace fn = lyxbosa::rules::filename;

namespace {

namespace fs = std::filesystem;

// Which FN codes a name raises, as a set, so a case can say "exactly these".
std::set<std::string> codesFor(std::string_view name) {
    std::set<std::string> out;
    for (const auto& finding : fn::examine(name)) {
        out.insert(std::string(finding.code));
    }
    return out;
}

bool fires(std::string_view name) { return !fn::examine(name).empty(); }

// ---------------------------------------------------------------------------
// The observed names, one per rule, exactly as they were on the server.
//
// Written as escapes where a byte is not printable, because a source file that held a
// raw newline inside a string literal would not compile and one that held a raw 0xC0
// would not be valid UTF-8 - which is the very defect the last section of this file is
// about.
// ---------------------------------------------------------------------------

struct Observed {
    const char* code;     // the rule this name is the control for
    const char* name;     // as it was on disk
    const char* what;     // what makes it that rule's case, for a failure message
};

const Observed kObserved[] = {
    {"FN001", "x$(sleep 20)y-6a9fe85b-f3.mdb",      "a command substitution"},
    {"FN001", "a`id`b-6a9fcad7-a4.mdb",             "a backtick pair"},
    {"FN002", "a;b-6a9fcadc-a2.mdb",                "a command separator"},
    {"FN002", "a|id-6a9fcbb1-66.mdb",               "a pipe"},
    {"FN002", "x\" ; id ; \"-6a9fc603-67.mdb",      "a quote breakout"},
    {"FN002", "a\\zz-6a9ff58b-7f.php",              "a backslash"},
    {"FN003", "zz.php\n-6a9ff590-7f.mdb",           "a newline"},
    {"FN003", "zz.php\r-6a9ff58f-38.mdb",           "a carriage return"},
    {"FN004", "--help-6a9fce0f-e9.mdb",             "a leading double dash"},
    {"FN004", "-6a9fd699-e4.htaccess",              "a leading dash"},
    // U+FF0F FULLWIDTH SOLIDUS, and the re-encoded overlong slash U+00C0 U+00AF.
    {"FN005", "a\xEF\xBC\x8F..\xEF\xBC\x8Fpublic\xEF\xBC\x8Fuploads\xEF\xBC\x8Fzz-6a9ff595-bf.php",
     "a fullwidth solidus traversal"},
    {"FN005", "a\xC3\x80\xC2\xAF..\xC3\x80\xC2\xAF..\xC3\x80\xC2\xAFpublic\xC3\x80\xC2\xAFzz-6a9ff594-ee.php",
     "a re-encoded overlong slash traversal"},
    {"FN006", "x.php%00-6a9fd5fc-b7.mdb",           "a percent-encoded NUL"},
    {"FN006", "a%00b-6a9fcae1-29.mdb",              "a percent-encoded NUL mid-name"},
};

// ---------------------------------------------------------------------------
// The benign corpus: ordinary business document names, every one of which carries an
// apostrophe or an ampersand, plus the specific shapes that a looser rule would have
// caught. Generated rather than listed, because eight names is not a measurement - the
// case reports its own size so a reader never has to count them.
// ---------------------------------------------------------------------------

std::vector<std::string> benignNames() {
    // Every one of these carries the apostrophe or the ampersand that the measurement
    // says must never fire on its own.
    const std::vector<std::string> parties = {
        "O'Brien & Sons", "Marks & Spencer", "L'Atelier", "Smith & Co",
        "Children's Trust", "AT&T", "Dave's Deli", "Barnes & Noble",
        "Q&A with O'Neill", "Macy's",
    };
    const std::vector<std::string> subjects = {
        "Invoice", "Q3 Report", "Terms & Conditions", "Employee's Handbook",
        "Board Minutes", "Budget", "Statement of Work", "Proposal",
    };
    const std::vector<std::string> qualifiers = {
        "", " 2024", " (rev 2)", " FINAL", " - draft",
    };
    const std::vector<std::string> extensions = {
        ".pdf", ".docx", ".xlsx", ".csv", ".txt", ".pptx",
    };

    std::vector<std::string> names;
    names.reserve(parties.size() * subjects.size() * qualifiers.size() * extensions.size());
    for (const auto& party : parties) {
        for (const auto& subject : subjects) {
            for (const auto& qualifier : qualifiers) {
                for (const auto& extension : extensions) {
                    names.push_back(party + " - " + subject + qualifier + extension);
                }
            }
        }
    }

    // And the awkward ones, each here because a rule was nearly written that fired on
    // it. These are shapes, invented for this file; none is a name from any tree.
    for (const std::string& awkward : {
             // A bare dollar, which the measured character set contained and FN001
             // deliberately does not: this is the lock file Word and Excel write
             // beside an open document, and it is in every office tree there is.
             std::string("~$O'Brien & Sons - Board Minutes.docx"),
             std::string("~$Q3 Report.xlsx"),
             // A dot-dot with no separator beside it. A doubled extension dot is the
             // only name in 268,853 real files that a bare dot-dot rule fired on.
             std::string("scan_0042_page_2_final..jpg"),
             std::string("archive..tar.gz"),
             // A percent that is not %00.
             std::string("100% Cotton - spec sheet.pdf"),
             std::string("Discount 15%25 applied.csv"),
             // Valid UTF-8 that is not ASCII. Mangling one of these would wreck every
             // finding quoted from a file with Greek, Japanese or French in it.
             std::string("\xCE\x95\xCE\xBA\xCE\xB8\xCE\xB5\xCF\x83\xCE\xB7 2024.pdf"),
             std::string("\xE8\xAB\x8B\xE6\xB1\x82\xE6\x9B\xB8.pdf"),
             std::string("R\xC3\xA9sum\xC3\xA9 - Dave's.docx"),
             // A dash that is not leading, and an em dash that is not a dash at all.
             std::string("Q3 - 2024 - O'Neill.pdf"),
             std::string("Report \xE2\x80\x94 Smith & Co.pdf"),
             // Ordinary web-root files, which is the other tree this tool is pointed at.
             std::string("index.php"),
             std::string("wp-config.php"),
             std::string("jquery-3.7.1.min.js"),
             std::string(".htaccess"),
             std::string("style.css"),
         }) {
        names.push_back(awkward);
    }

    return names;
}

// A temporary directory that removes itself. Same shape as the ones in
// quarantine_test.cpp and archive_test.cpp, and named from a steady_clock tick for the
// same reason: two test binaries can be running at once.
class TempDir {
public:
    TempDir() {
        const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = fs::temp_directory_path() /
                ("lyxbosa-hostile-name-test-" + std::to_string(tick) + "-" +
                 std::to_string(counter_++));
        fs::create_directories(path_);
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
    static inline int counter_ = 0;
};

// Why this platform cannot put a file with this name on disk, as a sentence, or
// nullopt when it can.
//
// Windows refuses `"` `|` `<` `>` `:` `*` `?` and every byte below 0x20 in a name,
// which is most of what the FN rules are about - so on Windows several of these cases
// have nothing to observe. They say which name the filesystem refused and skip, rather
// than passing on a scan of a directory that turned out to be empty: a case that
// cannot fail is the shape AGENTS.md records five earlier instances of. The pure cases
// over examine() run on every platform and carry the rules' own coverage; what these
// add is that the walk, the filters and the report agree with them.
std::optional<std::string> whyCannotCreate(const fs::path& dir, const std::string& name) {
    const fs::path target = dir / fs::path(name);
    std::error_code ec;
    {
        std::ofstream out(target, std::ios::binary);
        if (out) {
            out << "bytes\n";
        }
    }
    if (!fs::exists(target, ec)) {
        return "this filesystem refused a file named with " + safe_text::sanitize(name) +
               ", so the walk cannot be shown a name of that shape here";
    }

    // Created is not the same as created under the name that was asked for, and the
    // difference is a whole class of Windows behaviour a POSIX host cannot show you.
    // NTFS silently strips a trailing space and a trailing dot. And a name given as
    // bytes is CONVERTED on the way in, because the filesystem stores UTF-16 and the
    // narrow API reads those bytes in the host's code page - so a sequence that is not
    // valid UTF-8 does not exist on Windows at all; what exists is whatever characters
    // that code page maps the bytes to. A case that went on to scan the directory would
    // be scanning a differently-named file and asserting about it, which is passing
    // while blind.
    //
    // Asked of pathToUtf8(), which is the spelling every rule and every report sees,
    // rather than of path::string(), which on Windows hands back the code page bytes
    // and so would call a converted name identical to the one that was asked for.
    bool exact = false;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (pathToUtf8(entry.path().filename()) == name) {
            exact = true;
            break;
        }
    }
    if (!exact) {
        // Removed, so the caller's tree holds only names it can reason about. Left
        // behind, a converted name is a file the scan finds and the case did not
        // account for - which turns a clean skip into a confusing failure elsewhere.
        fs::remove(target, ec);
        return "this filesystem changed the name " + safe_text::sanitize(name) +
               " on the way in - it stores names in an encoding that cannot hold those "
               "bytes, or strips what it will not keep - so no file of that shape "
               "exists here to be scanned";
    }
    return std::nullopt;
}

void writeFile(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

// A webshell the content rules answer for.
const char* kWebshell = "<?php eval(base64_decode($_POST['x'])); ?>";

// Why the bytes just written are not the bytes now on disk, as a sentence, or nullopt.
//
// A fixture in this file is a real webshell, and on a host with resident antivirus it is
// a real webshell to that too: Microsoft Defender takes one out of `%TEMP%` between the
// write and the scan, and the case then fails with `hasHostileContent` false - which
// reads as "the rules stopped matching a signature they have always matched" and is an
// hour of looking in the wrong place. It is an environmental fact, not a defect in the
// scanner, so the case says which and skips.
std::optional<std::string> whyTheFixtureIsNotOnDisk(const fs::path& path,
                                                    const std::string& expected) {
    std::error_code ec;
    if (!fs::exists(path, ec)) {
        return "another program removed the webshell fixture at " +
               pathForDisplay(path) + " between writing it and scanning it - resident "
               "antivirus does this to a real signature - so nothing here can be "
               "observed about what the rules would have said";
    }
    std::ifstream in(path, std::ios::binary);
    const std::string actual((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
    if (actual != expected) {
        return "the webshell fixture at " + pathForDisplay(path) + " is not the bytes "
               "that were written to it - something on this host rewrote or emptied it - "
               "so this case cannot observe what the rules would have said";
    }
    return std::nullopt;
}

AppConfig scanConfig(const fs::path& root) {
    AppConfig config = Config::loadFromString(Config::generateDefault());
    config.scan.directories.clear();
    config.scan.directories.push_back(root.string());
    config.scan.recursive = true;
    return config;
}

ScanResult runScan(const AppConfig& config) {
    Scanner scanner(config);
    scanner.setPreCount(false);
    return scanner.scan();
}

const FileResult* findByName(const ScanResult& result, const std::string& name) {
    for (const auto& file : result.files) {
        if (file.path.filename().string() == name) {
            return &file;
        }
    }
    return nullptr;
}

}  // namespace

// ---------------------------------------------------------------------------
// Every rule fires on a real observed name.
// ---------------------------------------------------------------------------

class ObservedNameTest : public ::testing::TestWithParam<Observed> {};

TEST_P(ObservedNameTest, RaisesTheRuleItIsTheControlFor) {
    const Observed& observed = GetParam();
    const auto codes = codesFor(observed.name);
    EXPECT_TRUE(codes.count(observed.code) == 1)
        << observed.code << " did not fire on an observed name carrying "
        << observed.what;
}

INSTANTIATE_TEST_SUITE_P(Observed, ObservedNameTest, ::testing::ValuesIn(kObserved));

TEST(HostileFilenameTest, EveryRuleHasAnObservedControl) {
    // The parameterised case above proves each name raises its rule. This one proves
    // the table has not lost a rule: six rules ship, and a seventh added without a
    // control would otherwise be watched by nothing at all.
    std::set<std::string> covered;
    for (const auto& observed : kObserved) {
        covered.insert(observed.code);
    }
    EXPECT_EQ(covered.size(), fn::RULE_COUNT)
        << "a rule ships with no observed name to watch it fire on";
}

// ---------------------------------------------------------------------------
// The measured line: the apostrophe and the ampersand, alone, never fire.
// ---------------------------------------------------------------------------

TEST(HostileFilenameTest, TheBenignCorpusIsSilent) {
    const auto names = benignNames();
    ASSERT_GT(names.size(), 1000u)
        << "the benign corpus is too small to be a measurement of anything";

    std::vector<std::string> fired;
    for (const auto& name : names) {
        if (fires(name)) {
            fired.push_back(name);
        }
    }

    EXPECT_TRUE(fired.empty())
        << fired.size() << " of " << names.size()
        << " ordinary business file names raised a finding; the first is "
        << (fired.empty() ? std::string{} : safe_text::sanitize(fired.front()));

    // Said out loud so a reader of the test log knows what the silence is worth. This
    // is a control and not a false-positive rate: the corpus is synthetic, and it is
    // synthetic because the real names it stands in for can carry a person's name.
    RecordProperty("benign_names_checked", static_cast<int>(names.size()));
}

TEST(HostileFilenameTest, EveryBenignNameCarriesTheCharactersThatWouldHaveBrokenIt) {
    // Without this the case above could pass by holding names that exercise nothing.
    // 60 of the 89 real false positives carried an apostrophe and 29 an ampersand, so
    // the corpus has to carry both in quantity or its silence means nothing.
    size_t apostrophes = 0;
    size_t ampersands = 0;
    for (const auto& name : benignNames()) {
        if (name.find('\'') != std::string::npos) ++apostrophes;
        if (name.find('&') != std::string::npos) ++ampersands;
    }
    EXPECT_GT(apostrophes, 500u) << "too few apostrophes to stand in for the 60 observed";
    EXPECT_GT(ampersands, 500u) << "too few ampersands to stand in for the 29 observed";
}

TEST(HostileFilenameTest, AnApostropheOrAmpersandAloneIsNotAFinding) {
    // The line, pinned as a case rather than left to the corpus above. Crossing it is
    // the one change to these rules that the measurement forbids outright.
    EXPECT_FALSE(fires("O'Brien.pdf"));
    EXPECT_FALSE(fires("Smith & Co.pdf"));
    EXPECT_FALSE(fires("Q&A.docx"));
    EXPECT_FALSE(fires("it's & it's & it's.txt"));

    // In combination with something else they are not the reason it fires - the other
    // thing is - and that is the only way either character may take part in a rule.
    EXPECT_TRUE(fires("O'Brien$(id).pdf"));
    EXPECT_EQ(codesFor("O'Brien$(id).pdf"), (std::set<std::string>{"FN001"}));
}

TEST(HostileFilenameTest, ABareDollarIsNotAFinding) {
    // The office lock file. In the measured character set a bare `$` fired; here it
    // must not, and no observed name needs it to be caught.
    EXPECT_FALSE(fires("~$Quarterly Report.docx"));
    EXPECT_FALSE(fires("$RECYCLE.BIN"));
    EXPECT_FALSE(fires("price$.csv"));

    EXPECT_TRUE(fires("x$(id).mdb"));
    EXPECT_TRUE(fires("x${IFS}y.mdb"));
}

TEST(HostileFilenameTest, ABareDotDotIsNotATraversal) {
    // A name has no separators in it, so a dot-dot on its own traverses nothing. The
    // shape below is the only one in 268,853 real file names that a bare dot-dot rule
    // fired on, and it is a doubled extension dot.
    EXPECT_FALSE(fires("scan_0042_page_2_final..jpg"));
    EXPECT_FALSE(fires("..hidden"));
    EXPECT_FALSE(fires("a..b..c.txt"));

    // Against a separator that is not one, it is.
    EXPECT_TRUE(fires("a\xEF\xBC\x8F..\xEF\xBC\x8F" "b.php"));
    EXPECT_TRUE(fires("a..\xEF\xBC\x8F" "b.php"));
    EXPECT_TRUE(fires("a%2e%2e%2fb.php"));
}

// ---------------------------------------------------------------------------
// Each rule, watched staying silent on the benign name closest to what it catches.
// ---------------------------------------------------------------------------

struct SilentCase {
    const char* code;   // the rule that must NOT fire
    const char* name;   // a benign name that is near-miss for it
};

const SilentCase kSilent[] = {
    {"FN001", "~$O'Brien & Sons - Invoice.docx"},
    {"FN001", "price$.csv"},
    {"FN002", "Q&A with O'Neill - Board Minutes.pdf"},
    {"FN002", "Smith & Co, Terms & Conditions.pdf"},
    {"FN003", "Children's Trust - Budget (rev 2).xlsx"},
    {"FN004", "Q3 - 2024 - O'Neill.pdf"},
    {"FN004", "Report \xE2\x80\x94 Smith & Co.pdf"},
    {"FN005", "scan_0042_page_2_final..jpg"},
    {"FN005", "archive..tar.gz"},
    {"FN006", "100% Cotton - spec sheet.pdf"},
    {"FN006", "Discount 15%25 applied.csv"},
};

class SilentNameTest : public ::testing::TestWithParam<SilentCase> {};

TEST_P(SilentNameTest, StaysQuietOnAnOrdinaryName) {
    const SilentCase& silent = GetParam();
    const auto codes = codesFor(silent.name);
    EXPECT_EQ(codes.count(silent.code), 0u)
        << silent.code << " fired on an ordinary business file name";
}

INSTANTIATE_TEST_SUITE_P(Silent, SilentNameTest, ::testing::ValuesIn(kSilent));

TEST(HostileFilenameTest, EveryRuleHasASilentControl) {
    std::set<std::string> covered;
    for (const auto& silent : kSilent) {
        covered.insert(silent.code);
    }
    EXPECT_EQ(covered.size(), fn::RULE_COUNT)
        << "a rule ships with no benign name to watch it decline";
}

// ---------------------------------------------------------------------------
// The name is the file's, not the directory's.
// ---------------------------------------------------------------------------

TEST(HostileFilenameTest, OnlyTheFinalComponentIsExamined) {
    // A hostile directory name is a finding about that directory, and this tool
    // reports files. Reading the whole path here would put the same finding on every
    // file underneath one bad directory - thousands of rows for one fact.
    EXPECT_FALSE(fires(fn::finalComponent("/var/www/x$(id)/index.php")));
    EXPECT_TRUE(fires(fn::finalComponent("/var/www/ok/x$(id).php")));
}

TEST(HostileFilenameTest, OnPosixABackslashIsPartOfTheNameAndNotASeparator) {
#ifdef _WIN32
    // Windows forbids a backslash inside a component, so there it is always a
    // separator and the split is exact.
    EXPECT_EQ(fn::finalComponent("C:\\www\\a\\b.php"), "b.php");
#else
    // On POSIX it is a character in a name. Splitting on it would take the observed
    // name `a\zz-<id>.php` to `zz-<id>.php` and hand FN002 a clean file - the same
    // mistake, in the same direction, that MatchEngine::filterPath() is written to
    // avoid for the context filters.
    EXPECT_EQ(fn::finalComponent("/var/www/a\\zz.php"), "a\\zz.php");
    EXPECT_TRUE(fires(fn::finalComponent("/var/www/a\\zz.php")));
#endif
}

// ---------------------------------------------------------------------------
// A name finding travels as a normal finding, and does NOT move the file.
// ---------------------------------------------------------------------------

TEST(HostileFilenameTest, AHostileNameAloneDoesNotQuarantineTheFile) {
    TempDir root;
    TempDir quarantine;

    const std::string hostile = "a;sleep 12;b-6a9fd4b2-32.mdb";
    if (const auto why = whyCannotCreate(root.path(), hostile)) {
        GTEST_SKIP() << *why;
    }

    AppConfig config = scanConfig(root.path());
    config.actions.quarantine.enabled = true;
    config.actions.quarantine.directory = quarantine.path().string();

    const ScanResult result = runScan(config);

    const FileResult* file = findByName(result, hostile);
    ASSERT_NE(file, nullptr) << "the hostile name raised no row at all";
    EXPECT_FALSE(file->matches.empty());
    EXPECT_TRUE(hasHostileName(*file));

    // The decision this whole rule set turns on. The bytes may be the customer's Access
    // database; the hostile part is written on the outside of it, and moving it takes
    // the command substitution into the quarantine directory - which is the directory
    // an operator is most likely to sweep later with a shell loop.
    EXPECT_FALSE(file->quarantined) << "a file was moved for what it is called";
    EXPECT_FALSE(file->quarantineFailed)
        << "a move was attempted and failed, which is not the same as never attempting one";
    EXPECT_EQ(result.filesQuarantined, 0u);
    EXPECT_EQ(result.filesQuarantineFailed, 0u);
    EXPECT_FALSE(hasHostileContent(*file));
}

TEST(HostileFilenameTest, AHostileNameOnAWebshellStillQuarantinesIt) {
    // The other direction, and the reason the question is asked per match rather than
    // per file: a file can carry both, and the content finding must still win.
    TempDir root;
    TempDir quarantine;

    const std::string hostile = "a$(id)b-6a9fcad5-93.php";
    if (const auto why = whyCannotCreate(root.path(), hostile)) {
        GTEST_SKIP() << *why;
    }
    writeFile(root.path() / fs::path(hostile), kWebshell);
    if (const auto why = whyTheFixtureIsNotOnDisk(root.path() / fs::path(hostile),
                                                  kWebshell)) {
        GTEST_SKIP() << *why;
    }

    AppConfig config = scanConfig(root.path());
    config.actions.quarantine.enabled = true;
    config.actions.quarantine.directory = quarantine.path().string();

    const ScanResult result = runScan(config);

    const FileResult* file = findByName(result, hostile);
    ASSERT_NE(file, nullptr);
    EXPECT_TRUE(hasHostileName(*file));
    EXPECT_TRUE(hasHostileContent(*file));
    EXPECT_TRUE(file->quarantined) << "a webshell stayed in the web root because its "
                                      "name happened to be a finding too";
    EXPECT_EQ(result.filesQuarantined, 1u);
}

TEST(HostileFilenameTest, TheRollupCountsFilesAndNotMatches) {
    TempDir root;

    // Two names, one of which raises two rules. The summary counter is files, so that
    // it can be compared with filesWithMatches directly above it.
    const std::vector<std::string> names = {
        "a$(id);b-6a9fcbe3-aa.mdb",   // FN001 and FN002
        "a|b-6a9fcadd-a7.mdb",        // FN002 only
    };
    for (const auto& name : names) {
        if (const auto why = whyCannotCreate(root.path(), name)) {
            GTEST_SKIP() << *why;
        }
    }
    writeFile(root.path() / "clean.php", "<?php echo 1; ?>\n");

    const ScanResult result = runScan(scanConfig(root.path()));

    EXPECT_EQ(result.filesWithHostileNames, 2u);
    EXPECT_EQ(result.filesWithMatches, 2u);
    EXPECT_EQ(result.totalMatches, 3u) << "one name raises two rules; both are findings";
}

TEST(HostileFilenameTest, AFileTheIncludeListDoesNotCoverStillHasItsNameRead) {
    // 73 of the 83 observed names are `.mdb`, and no include pattern covers a `.mdb`.
    // The include list decides what gets OPENED - the shipped configuration says so in
    // its own comment - and a name needs no open. Without this the rule set would be
    // blind to 88% of the evidence it was built from.
    TempDir root;
    const std::string hostile = "t$(sleep 8)-6a9fc8ee-15.mdb";
    if (const auto why = whyCannotCreate(root.path(), hostile)) {
        GTEST_SKIP() << *why;
    }

    const ScanResult result = runScan(scanConfig(root.path()));

    const FileResult* file = findByName(result, hostile);
    ASSERT_NE(file, nullptr) << "an excluded-by-include file with a hostile name was "
                                "not reported at all";
    EXPECT_TRUE(hasHostileName(*file));

    // And it still says the bytes were never read. Both facts, neither taking the
    // other's place: a report that said only "finding" would read as though the file
    // had been examined.
    ASSERT_TRUE(file->skipReason.has_value());
    EXPECT_EQ(*file->skipReason, SkipReason::Excluded);
}

TEST(HostileFilenameTest, AnExcludePatternIsStillObeyed) {
    // The other half of that split. An `exclude` pattern is the operator writing down
    // something they do not want looked at, and answering anyway - even about
    // something as cheap as a name - is the tool overruling them.
    //
    // The name is a `.php`, so it passes the include list and reaches the exclude
    // list; that ordering is the point, since a name the include list never covered
    // would prove nothing about excludes.
    TempDir root;
    const std::string hostile = "a$(id)-6a9fcbae-e3.php";
    if (const auto why = whyCannotCreate(root.path(), hostile)) {
        GTEST_SKIP() << *why;
    }

    AppConfig config = scanConfig(root.path());
    ASSERT_EQ(runScan(config).filesWithHostileNames, 1u)
        << "the control direction: without the exclude, this name is a finding";

    config.scan.exclude.push_back("*.php");
    const ScanResult result = runScan(config);
    EXPECT_EQ(findByName(result, hostile), nullptr)
        << "a file an exclude pattern named was reported anyway";
    EXPECT_EQ(result.filesWithHostileNames, 0u);
}

TEST(HostileFilenameTest, DisablingARuleSilencesItAndLeavesTheOthers) {
    TempDir root;
    const std::string both = "a$(id);b-6a9fcbe3-aa.mdb";   // FN001 and FN002
    if (const auto why = whyCannotCreate(root.path(), both)) {
        GTEST_SKIP() << *why;
    }

    AppConfig config = scanConfig(root.path());
    config.builtinRules.disable.push_back("FN002");

    const ScanResult result = runScan(config);
    const FileResult* file = findByName(result, both);
    ASSERT_NE(file, nullptr);

    std::set<std::string> raised;
    for (const auto& match : file->matches) {
        raised.insert(match.category);
    }
    EXPECT_EQ(raised.count("FN002"), 0u) << "a disabled rule fired";
    EXPECT_EQ(raised.count("FN001"), 1u) << "disabling one rule silenced another";
}

TEST(HostileFilenameTest, EveryRuleIsInTheRegistryUnderItsOwnCode) {
    // The codes are what a report prints and what `disable` is written against, so a
    // rule that is not reachable by code is a rule an operator cannot turn off.
    for (const auto* rule : rules::getRulesByCategory(rules::Category::Filename)) {
        const std::string code = rule->code.toString();
        EXPECT_NE(rules::getRuleByCode(code), nullptr) << code << " does not resolve";
        EXPECT_FALSE(rule->name.empty());
        EXPECT_FALSE(rule->description.empty());
        EXPECT_TRUE(rule->patterns.empty())
            << code << " carries content patterns; an FN rule reads a name";
        EXPECT_EQ(rule->analyzer, nullptr);
    }
    EXPECT_EQ(rules::getRulesByCategory(rules::Category::Filename).size(), fn::RULE_COUNT);
}

// ---------------------------------------------------------------------------
// The escaper: bytes that are not valid UTF-8.
// ---------------------------------------------------------------------------

TEST(SafeTextUtf8Test, InvalidUtf8IsEscapedAndValidUtf8IsNot) {
    // The defect this replaced: bytes >= 0x80 were written through raw whatever they
    // were, so a name carrying 0xC0 0xAF produced a document a standard parser refuses.
    EXPECT_EQ(safe_text::sanitize(std::string("a\xC0\xAF" "b")), "a\\xc0\\xafb");
    EXPECT_TRUE(safe_text::needsSanitizing(std::string("a\xC0\xAF" "b")));

    // A lone continuation byte, a truncated sequence and a byte no lead can be.
    EXPECT_EQ(safe_text::sanitize(std::string("\x80")), "\\x80");
    EXPECT_EQ(safe_text::sanitize(std::string("\xE2\x82")), "\\xe2\\x82");
    EXPECT_EQ(safe_text::sanitize(std::string("\xFF")), "\\xff");

    // Overlong forms and surrogates are rejected along with structural breakage.
    // `C0 AF` decodes to '/' in a decoder that accepts it, which is exactly why it
    // must not be laundered through as text.
    EXPECT_EQ(safe_text::sanitize(std::string("\xC1\xBF")), "\\xc1\\xbf");
    EXPECT_EQ(safe_text::sanitize(std::string("\xED\xA0\x80")), "\\xed\\xa0\\x80");
    EXPECT_EQ(safe_text::sanitize(std::string("\xF5\x80\x80\x80")),
              "\\xf5\\x80\\x80\\x80");

    // The other direction, and the one that matters more often: well-formed UTF-8 is
    // left exactly alone, whatever plane it is in.
    const std::string greek = "\xCE\x95\xCE\xBB\xCE\xBB\xCE\xAC\xCE\xB4\xCE\xB1";
    EXPECT_EQ(safe_text::sanitize(greek), greek);
    EXPECT_FALSE(safe_text::needsSanitizing(greek));
    const std::string emoji = "\xF0\x9F\x94\x92";
    EXPECT_EQ(safe_text::sanitize(emoji), emoji);
    EXPECT_FALSE(safe_text::needsSanitizing(emoji));
    const std::string kanji = "\xE8\xAB\x8B\xE6\xB1\x82\xE6\x9B\xB8";
    EXPECT_EQ(safe_text::sanitize(kanji), kanji);
    EXPECT_FALSE(safe_text::needsSanitizing(kanji));

    // Control bytes keep the escape they always had, so the two halves of the one
    // question are now answered the same way.
    EXPECT_EQ(safe_text::sanitize(std::string("a\nb")), "a\\x0ab");
}

TEST(SafeTextUtf8Test, NeedsSanitizingAgreesWithSanitizeExactly) {
    // The cheap test and the expensive one answering differently IS the defect, not a
    // symptom of it: pathForDisplay() skips the copy when needsSanitizing() says no,
    // so a byte the one missed reached a report raw however correct the other was.
    const std::vector<std::string> cases = {
        "plain.php", "a\nb", "a\xC0\xAF" "b", "\xCE\x95\xCE\xBB\xCE\xBB",
        "\x80", "\xE2\x82\xAC", "\xE2\x82", "\xF0\x9F\x94\x92", "\xF0\x9F\x94",
        "\x7f", "O'Brien & Sons.pdf", "\xED\xA0\x80", "\xC1\xBF",
    };
    for (const auto& value : cases) {
        EXPECT_EQ(safe_text::needsSanitizing(value), safe_text::sanitize(value) != value)
            << "the two disagree about " << safe_text::sanitize(value);
    }
}

TEST(SafeTextUtf8Test, AReportOfANameThatIsNotUtf8IsStillUtf8) {
    // Reproduced end to end rather than at the escaper alone, because the defect was
    // never in one function - it was that the JSON writer trusted what reached it.
    // Linux accepts any byte but NUL and '/' in a name, so this is one `touch` away on
    // any host this tool runs on; the production corpus that produced these rules
    // happens to have no such name, so it is reachable and not demonstrated by it.
    TempDir root;
    const std::string invalid = std::string("a;b\xC0\xAF" "c.mdb");
    if (const auto why = whyCannotCreate(root.path(), invalid)) {
        GTEST_SKIP() << *why;
    }

    const ScanResult result = runScan(scanConfig(root.path()));
    ASSERT_FALSE(result.files.empty());

    std::ostringstream json;
    {
        JsonReportWriter writer(json);
        writer.begin();
        for (const auto& file : result.files) {
            writer.onFile(file);
        }
        writer.end(result, false);
    }

    const std::string document = json.str();
    EXPECT_TRUE(safe_text::isValidUtf8(document))
        << "the JSON document is not valid UTF-8, so a standard parser refuses it";
    // Doubled, because the escape safe_text writes is itself a backslash and RFC 8259
    // escaping doubles it. That is what a JSON consumer reads back as one backslash.
    EXPECT_NE(document.find("a;b\\\\xc0\\\\xafc.mdb"), std::string::npos)
        << "the invalid bytes are not in the report in any form, so an operator "
           "cannot get from the row back to the file";
    EXPECT_EQ(document.find('\xC0'), std::string::npos) << "a raw 0xC0 reached the report";

    // The same file through the CSV writer, because two formats answering one question
    // differently is how this was found in the first place.
    std::ostringstream csv;
    {
        CsvReportWriter writer(csv);
        writer.begin();
        for (const auto& file : result.files) {
            writer.onFile(file);
        }
        writer.end(result, false);
    }
    EXPECT_TRUE(safe_text::isValidUtf8(csv.str()));
    EXPECT_NE(csv.str().find("a;b\\xc0\\xafc.mdb"), std::string::npos);
}

// ---------------------------------------------------------------------------
// A name is untrusted text on its way to a terminal, and untrusted bytes on its way to
// a program. Those are two needs and the report owes both.
// ---------------------------------------------------------------------------

// Undo the hex a report carries beside a path it could not render exactly.
std::string unhex(std::string_view hex) {
    const auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    std::string out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out += static_cast<char>((hi << 4) | lo);
    }
    return out;
}

// The value of `key` in the first JSON object that has one, or empty, with RFC 8259
// escaping undone. Crude on purpose - a real parser here would be testing the parser -
// but the unescaping is not optional: a Windows path is all backslashes, JSON doubles
// every one of them, and a case that skipped this step compared `C:\\Users` against
// `C:\Users` and called the report wrong.
std::string jsonValue(const std::string& document, const std::string& key) {
    const std::string needle = "\"" + key + "\": \"";
    const size_t at = document.find(needle);
    if (at == std::string::npos) return {};

    std::string out;
    for (size_t i = at + needle.size(); i < document.size(); ++i) {
        const char c = document[i];
        if (c == '"') break;
        if (c != '\\') {
            out += c;
            continue;
        }
        if (++i >= document.size()) break;
        switch (document[i]) {
            case '"':  out += '"';  break;
            case '\\': out += '\\'; break;
            case '/':  out += '/';  break;
            case 'b':  out += '\b'; break;
            case 'f':  out += '\f'; break;
            case 'n':  out += '\n'; break;
            case 'r':  out += '\r'; break;
            case 't':  out += '\t'; break;
            default:   out += document[i]; break;   // \uXXXX is not produced here
        }
    }
    return out;
}

TEST(HostileFilenameTest, AnEscapeSequenceInANameNeverReachesAStreamRaw) {
    // The reason every path goes through one escape, spelled as a case. A name is
    // attacker-chosen on a compromised host and carries ESC exactly as file content
    // does: `<ESC>]52;c;<base64><BEL>` writes the analyst's clipboard on the way past,
    // and `<ESC>[2J` wipes the screen the findings were just printed on.
    TempDir root;
    const std::string hostile = std::string("e\x1B]52;c;aGk=\x07;f.php");
    if (const auto why = whyCannotCreate(root.path(), hostile)) {
        GTEST_SKIP() << *why;
    }

    const ScanResult result = runScan(scanConfig(root.path()));
    ASSERT_FALSE(result.files.empty());

    std::ostringstream json;
    {
        JsonReportWriter writer(json);
        writer.begin();
        for (const auto& file : result.files) writer.onFile(file);
        writer.end(result, false);
    }
    std::ostringstream csv;
    {
        CsvReportWriter writer(csv);
        writer.begin();
        for (const auto& file : result.files) writer.onFile(file);
        writer.end(result, false);
    }

    for (const auto* document : {&json, &csv}) {
        const std::string text = document->str();
        EXPECT_EQ(text.find('\x1B'), std::string::npos) << "a raw ESC reached a report";
        EXPECT_EQ(text.find('\x07'), std::string::npos) << "a raw BEL reached a report";
    }
    EXPECT_NE(json.str().find("\\\\x1b"), std::string::npos)
        << "the escape is not in the report in any form";
}

TEST(HostileFilenameTest, EveryReportedFileCanBeReopenedFromTheReportAlone) {
    // The other need, and the one the rendering cannot meet. An external program reading
    // this report has to open, match or delete the exact file - and `path` is escaped,
    // one-way, because the document has to stay valid UTF-8 for a parser to accept it at
    // all. So a path the escape could not carry exactly is accompanied by its bytes.
    TempDir root;
    const std::vector<std::string> names = {
        std::string("a;b\xC0\xAF" "c.mdb"),          // not valid UTF-8
        std::string("g\nh;i.mdb"),                   // a control byte
        std::string("plain-O'Brien & Sons;x.mdb"),   // ordinary bytes, still a finding
    };
    size_t created = 0;
    for (const auto& name : names) {
        if (!whyCannotCreate(root.path(), name)) ++created;
    }
    if (created == 0) {
        GTEST_SKIP() << "this filesystem refused every name in this case";
    }

    const ScanResult result = runScan(scanConfig(root.path()));
    ASSERT_EQ(result.files.size(), created);

    for (const auto& file : result.files) {
        std::ostringstream json;
        JsonReportWriter writer(json);
        writer.begin();
        writer.onFile(file);
        writer.end(result, false);
        const std::string document = json.str();

        EXPECT_TRUE(safe_text::isValidUtf8(document))
            << "the document a parser has to accept is not valid UTF-8";

        const std::string hex = jsonValue(document, "pathBytesHex");
        const std::string reconstructed =
            hex.empty() ? jsonValue(document, "path") : unhex(hex);

        // The presence of the hex is itself the statement that `path` is a rendering.
        EXPECT_EQ(hex.empty(), !pathDisplayIsLossy(file.path))
            << "the report carries the bytes when it does not need to, or not when it does";

        ASSERT_FALSE(reconstructed.empty());
        EXPECT_TRUE(fs::exists(fs::path(reconstructed)))
            << "a program reading this report cannot get back to the file it names";
        EXPECT_EQ(fs::path(reconstructed), file.path);
    }
}

TEST(SafeTextUtf8Test, TheEscapeIsOneWayAndIsNotDocumentedOtherwise) {
    // Stated as a case so that nobody writes a consumer that tries to reverse it. A
    // backslash already in the input is written through unchanged, so a file whose
    // name really is those six characters renders identically to one named with a
    // newline. Doubling the backslash would fix that and would rewrite every path in
    // every Windows report, where the separator IS a backslash - for an ambiguity a
    // listing of the named directory settles in one command.
    EXPECT_EQ(safe_text::sanitize(std::string("a\nb")),
              safe_text::sanitize(std::string("a\\x0ab")));
}
