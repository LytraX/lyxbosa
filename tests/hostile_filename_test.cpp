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

#include "archive/ArchiveIndex.h"
#include "config/Config.h"
#include "core/ScanResult.h"
#include "core/Scanner.h"
#include "infrastructure/report/CsvReportWriter.h"
#include "infrastructure/report/JsonReportWriter.h"
#include "infrastructure/ResultPrinter.h"
#include "rules/Registry.hpp"
#include "rules/filename.h"
#include "utils/SafeText.h"

#include "ArchiveFixtures.h"
#include "PlatformSkips.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
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

// The name a parameterised case over a file name is listed and failed under.
//
// Left to itself gtest names each case by its index and prints the parameter as the bytes of
// the struct, so a failure read `RaisesTheRuleItIsTheControlFor/3` beside "24-byte object"
// and a hex dump of three pointers - the name under test, the only thing the reader needed,
// was nowhere. It cannot be used as it is either: gtest accepts only letters, digits and
// underscores in a case name, and these names are made of everything else. So the case is
// called by its rule, its position, and the name's ASCII letters and digits with each run of
// anything else as one underscore - `FN001_00_x_sleep_20_y_6a9fe85b_f3_mdb`. The position is
// what keeps it unique: two names differing only in punctuation collapse to the same
// letters, and gtest refuses a duplicate at registration rather than running either.
std::string caseName(std::string_view code, size_t index, std::string_view name) {
    constexpr size_t kLetters = 48;
    std::string out(code);
    out += index < 10 ? "_0" : "_";
    out += std::to_string(index);
    out += '_';
    std::string letters;
    for (const char c : name) {
        const auto u = static_cast<unsigned char>(c);
        const bool keep = u < 0x80 && std::isalnum(u);
        if (keep) {
            letters += c;
        } else if (!letters.empty() && letters.back() != '_') {
            letters += '_';
        }
        if (letters.size() >= kLetters) break;
    }
    while (!letters.empty() && letters.back() == '_') {
        letters.pop_back();
    }
    return out + (letters.empty() ? "no_letters" : letters);
}

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

// What gtest prints for `GetParam()` in the listing and beside a failure. Escaped, because
// the names carry the newlines and control bytes they are the cases for.
void PrintTo(const Observed& observed, std::ostream* os) {
    *os << observed.code << " \"" << safe_text::sanitize(observed.name) << "\" ("
        << observed.what << ")";
}

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

INSTANTIATE_TEST_SUITE_P(Observed, ObservedNameTest, ::testing::ValuesIn(kObserved),
                         [](const ::testing::TestParamInfo<Observed>& info) {
                             return caseName(info.param.code, info.index, info.param.name);
                         });

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

void PrintTo(const SilentCase& silent, std::ostream* os) {
    *os << silent.code << " \"" << safe_text::sanitize(silent.name) << "\"";
}

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

INSTANTIATE_TEST_SUITE_P(Silent, SilentNameTest, ::testing::ValuesIn(kSilent),
                         [](const ::testing::TestParamInfo<SilentCase>& info) {
                             return caseName(info.param.code, info.index, info.param.name);
                         });

// The names the two suites above are listed under. gtest refuses an invalid or duplicated
// name when the binary starts, so a generator that broke either rule would stop every case
// rather than fail one; this says what the names are for, where a reader looks.
TEST(HostileFilenameTest, EveryParameterisedCaseIsNamedForItsFileName) {
    EXPECT_EQ(caseName("FN001", 0, "x$(sleep 20)y-6a9fe85b-f3.mdb"),
              "FN001_00_x_sleep_20_y_6a9fe85b_f3_mdb");
    EXPECT_EQ(caseName("FN003", 6, "zz.php\n-6a9ff590-7f.mdb"), "FN003_06_zz_php_6a9ff590_7f_mdb");
    EXPECT_EQ(caseName("FN004", 12, "--"), "FN004_12_no_letters");

    // Two names that differ only in what is not a letter collapse to the same letters, and
    // the position is what still tells them apart.
    EXPECT_NE(caseName("FN002", 2, "a;b.mdb"), caseName("FN002", 3, "a|b.mdb"));

    std::set<std::string> seen;
    const auto check = [&seen](const std::string& name) {
        EXPECT_TRUE(seen.insert(name).second) << "duplicate case name " << name;
        EXPECT_TRUE(std::all_of(name.begin(), name.end(), [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
        })) << name;
    };
    for (size_t i = 0; i < std::size(kObserved); ++i) {
        check(caseName(kObserved[i].code, i, kObserved[i].name));
    }
    for (size_t i = 0; i < std::size(kSilent); ++i) {
        check(caseName(kSilent[i].code, i, kSilent[i].name));
    }
}

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
    if (const auto why = test::whyTheFixtureIsNotOnDisk(root.path() / fs::path(hostile),
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
    // The name is a `.php`, which the include list covers. A name it does not cover is
    // held to the same exclude, and MemberNameTest below asks that of a `.mdb`.
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
        // C1 controls, their neighbours in the Latin-1 block, and a C1 lead that is cut off.
        "\xC2\x80", "a\xC2\x9B" "31mb", "\xC2\x9F", "\xC2\x85", "\xC2\xA0", "\xC2\xBF",
        "caf\xC3\xA9", "\xC2", "\xC2\x9B\xC2",
    };
    for (const auto& value : cases) {
        EXPECT_EQ(safe_text::needsSanitizing(value), safe_text::sanitize(value) != value)
            << "the two disagree about " << safe_text::sanitize(value);
    }
}

// The question the loader and the report writers ask of a rule's name, held to the escaper
// over the same cases: a string it refuses is exactly one the escaper would have rewritten,
// in both directions, so "refused at load" and "would have been escaped" cannot drift into
// two definitions of plain text. With line breaks allowed only tab, LF and CR move.
TEST(SafeTextUtf8Test, WhyNotPlainTextAgreesWithNeedsSanitizingExactly) {
    const std::vector<std::string> cases = {
        "plain.php", "a\nb", "a\tb", "a\rb", "a\x1b[2Jb", "a\xC0\xAF" "b",
        "\xCE\x95\xCE\xBB\xCE\xBB", "\x80", "\xE2\x82\xAC", "\xE2\x82", "\xF0\x9F\x94\x92",
        "\xF0\x9F\x94", "\x7f", "O'Brien, \"Sons\".pdf", "\xED\xA0\x80", "\xC1\xBF",
        std::string("a\0b", 3), "",
        "\xC2\x80", "a\xC2\x9B" "31mb", "\xC2\x9F", "\xC2\x85", "\xC2\xA0", "\xC2\xBF",
        "caf\xC3\xA9", "\xC2", "\xC2\x9B\xC2", "a\n\xC2\x85" "b",
    };
    for (const auto& value : cases) {
        EXPECT_EQ(safe_text::whyNotPlainText(value).has_value(),
                  safe_text::needsSanitizing(value))
            << "the two disagree about " << safe_text::sanitize(value);

        // Each line break stood in for by a letter rather than removed, so that no two bytes
        // either side of one can close into a sequence that was not there.
        std::string lettered = value;
        for (char& c : lettered) {
            if (c == '\t' || c == '\n' || c == '\r') c = 'x';
        }
        EXPECT_EQ(safe_text::whyNotPlainText(value, /*lineBreaks=*/true).has_value(),
                  safe_text::needsSanitizing(lettered))
            << "line breaks changed more than line breaks for " << safe_text::sanitize(value);
    }

    // What it says, which the configuration refusal quotes: the first offending byte, its
    // offset, and never the byte itself.
    EXPECT_EQ(safe_text::whyNotPlainText("ab\x1b" "c"),
              "carries a control character (0x1b at offset 2)");
    EXPECT_EQ(safe_text::whyNotPlainText("\xCE\x95" "\xC0\xAF"),
              "is not valid UTF-8 (byte 0xc0 at offset 2)");
    EXPECT_FALSE(safe_text::whyNotPlainText("\xCE\x95\xCE\xBB\xCE\xBB"));
    EXPECT_EQ(safe_text::whyNotPlainText("ab\xC2\x9B" "31m"),
              "carries a control character (U+009B, 0xc2 0x9b at offset 2)");
    EXPECT_EQ(safe_text::whyNotPlainText("\xC2\x85", /*lineBreaks=*/true),
              "carries a control character (U+0085, 0xc2 0x85 at offset 0)");
}

// U+0080 to U+009F are well-formed UTF-8 and are controls: U+009B introduces a control
// sequence exactly as ESC [ does, and GNU screen acts on it. Every one of the 32 is escaped
// byte by byte and every neighbour in the Latin-1 block is left alone, and what comes out is
// still UTF-8 - a JSON document that carries it has to stay parseable.
TEST(SafeTextUtf8Test, EveryC1ControlIsEscapedAndNothingBesideItIs) {
    static constexpr char kHex[] = "0123456789abcdef";
    for (int second = 0x80; second <= 0xBF; ++second) {
        const std::string character = {'\xC2', static_cast<char>(second)};
        const std::string value = "a" + character + "[2Jb";
        SCOPED_TRACE(second);
        if (second <= 0x9F) {
            const std::string escaped =
                std::string("a\\xc2\\x") + kHex[second >> 4] + kHex[second & 0xf] + "[2Jb";
            EXPECT_EQ(safe_text::sanitize(value), escaped);
            EXPECT_TRUE(safe_text::needsSanitizing(value));
            EXPECT_TRUE(safe_text::whyNotPlainText(value, /*lineBreaks=*/true));
        } else {
            EXPECT_EQ(safe_text::sanitize(value), value);
            EXPECT_FALSE(safe_text::needsSanitizing(value));
            EXPECT_FALSE(safe_text::whyNotPlainText(value));
        }
        EXPECT_TRUE(safe_text::isValidUtf8(safe_text::sanitize(value)));
        EXPECT_EQ(safe_text::sanitize(value).find("\xC2\x80"), std::string::npos);
    }

    // A cut never lands inside the escape it produced, and never leaves the lead byte behind.
    const std::string long_name = std::string(40, 'x') + "\xC2\x9B" "2J" + std::string(40, 'y');
    for (size_t limit = 38; limit < 52; ++limit) {
        SCOPED_TRACE(limit);
        const std::string cut = safe_text::sanitizeAndTruncate(long_name, limit);
        EXPECT_TRUE(safe_text::isValidUtf8(cut));
        EXPECT_EQ(cut.find('\xC2'), std::string::npos);
        const size_t backslash = cut.rfind('\\');
        if (backslash != std::string::npos) {
            EXPECT_GE(cut.size() - backslash, 4u) << cut;
        }
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
    // The same OSC spelled with the 8-bit introducer, U+009D, and a CSI with U+009B. Both are
    // valid UTF-8, which is why the escape once let them through.
    const std::string c1 = std::string("p\xC2\x9D" "52;c;aGk=\xC2\x9C;\xC2\x9B" "2Jq.php");
    if (const auto why = whyCannotCreate(root.path(), c1)) {
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

    // The readable report a terminal is handed, both of its views.
    std::ostringstream text;
    {
        ResultPrinter printer(text, /*color=*/false, /*width=*/200);
        for (const auto& file : result.files) {
            printer.printFileResult(file);
            printer.printFileResultCompact(file);
        }
    }

    for (const auto* document : {&json, &csv, &text}) {
        const std::string written = document->str();
        EXPECT_EQ(written.find('\x1B'), std::string::npos) << "a raw ESC reached a report";
        EXPECT_EQ(written.find('\x07'), std::string::npos) << "a raw BEL reached a report";
        for (const char* control : {"\xC2\x9B", "\xC2\x9C", "\xC2\x9D"}) {
            EXPECT_EQ(written.find(control), std::string::npos)
                << "a raw C1 control reached a report:\n" << safe_text::sanitize(written);
        }
        EXPECT_TRUE(safe_text::isValidUtf8(written));
    }
    EXPECT_NE(json.str().find("\\\\x1b"), std::string::npos)
        << "the escape is not in the report in any form";
    EXPECT_NE(json.str().find("p\\\\xc2\\\\x9d52;c;aGk=\\\\xc2\\\\x9c;\\\\xc2\\\\x9b2Jq.php"),
              std::string::npos)
        << json.str();
    EXPECT_NE(text.str().find("p\\xc2\\x9d52;c;aGk=\\xc2\\x9c;\\xc2\\x9b2Jq.php"),
              std::string::npos)
        << text.str();
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
        std::string("k\xC2\x9B" "2Jl;m.mdb"),        // a C1 control: valid UTF-8, and escaped
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

        // Read the way a program consuming the report reads it: parsed, not searched. The
        // report's whitespace is not part of what it promises.
        ASSERT_TRUE(nlohmann::json::accept(document)) << document;
        const nlohmann::json parsed = nlohmann::json::parse(document);
        ASSERT_EQ(parsed.at("files").size(), 1u) << document;
        const nlohmann::json& record = parsed.at("files").at(0);
        const std::string hex = record.value("pathBytesHex", std::string());
        const std::string reconstructed =
            hex.empty() ? record.value("path", std::string()) : unhex(hex);

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

// ---------------------------------------------------------------------------
// Member names. A member of an uploaded zip named with a command substitution is the same
// evidence as a file on disk named that way, and the same rules read it - from the name the
// archive stores, which is known from its index or header without opening the member.
// ---------------------------------------------------------------------------

namespace {

using lyxbosa::test::fixtures::appendTarMember;
using lyxbosa::test::fixtures::endOfTar;
using lyxbosa::test::fixtures::gzipCompress;
using lyxbosa::test::fixtures::readBytes;
using lyxbosa::test::fixtures::writeZip;

// The row for the member stored as `stored` inside `container`. Its address is built the way
// the archive scanner builds it - the container's UTF-8 path, `!`, and the normalised name -
// so that the comparison is of one construction with itself on every platform.
const FileResult* findMember(const ScanResult& result, const fs::path& container,
                             const std::string& stored) {
    const fs::path address(pathToUtf8(container) + "!" + archive::normalizeMemberName(stored));
    for (const auto& file : result.files) {
        if (file.path == address) {
            return &file;
        }
    }
    return nullptr;
}

std::set<std::string> codesOf(const FileResult& file) {
    std::set<std::string> out;
    for (const auto& match : file.matches) {
        out.insert(match.category);
    }
    return out;
}

// A tar.gz holding `members` in order, written to `path`.
void writeTarGz(const fs::path& path,
                const std::vector<std::pair<std::string, std::string>>& members) {
    std::string tar;
    for (const auto& [name, body] : members) {
        appendTarMember(tar, name, body);
    }
    tar += endOfTar();
    writeFile(path, gzipCompress(tar));
}

// Every row a scan produced, spelled for a failure message.
std::string listRows(const ScanResult& result) {
    std::string out;
    for (const auto& file : result.files) {
        out += "  " + pathForDisplay(file.path) + " [";
        for (const auto& match : file.matches) {
            out += match.category + " ";
        }
        out += "]\n";
    }
    return out;
}

}  // namespace

// Every observed name, as a member of a zip and of a tar.gz, raises exactly the rules it raises
// as a name on disk. This runs on Windows too, where most of these names cannot be created on
// disk at all: an archive can hold a quote, a pipe and a newline wherever it is scanned.
TEST(MemberNameTest, EveryObservedNameRaisesItsRulesAsAMember) {
    TempDir root;
    std::vector<std::pair<std::string, std::string>> members;
    for (const auto& observed : kObserved) {
        members.emplace_back(std::string("uploads/") + observed.name, "ordinary bytes\n");
    }
    const fs::path zip = root.path() / "upload.zip";
    const fs::path tgz = root.path() / "upload.tar.gz";
    writeZip(zip, members);
    writeTarGz(tgz, members);

    const ScanResult result = runScan(scanConfig(root.path()));

    for (const fs::path& container : {zip, tgz}) {
        for (const auto& observed : kObserved) {
            SCOPED_TRACE(container.filename().string() + " " + safe_text::sanitize(observed.name));
            const std::string member = std::string("uploads/") + observed.name;
            const FileResult* row = findMember(result, container, member);
            ASSERT_NE(row, nullptr) << "no row for the member\n" << listRows(result);
            EXPECT_EQ(codesOf(*row), codesFor(observed.name));
            EXPECT_EQ(codesOf(*row).count(observed.code), 1u);
            EXPECT_TRUE(hasHostileName(*row));
            EXPECT_FALSE(hasHostileContent(*row));
            // A `.mdb` or a `.htaccess` is not code, so the policy never opened it, and the
            // row says so rather than reading as a member that was examined. A `.php` was
            // opened, and its row carries no reason.
            const bool opened = archive::classifyMember(archive::normalizeMemberName(member)) !=
                                archive::Bucket::Other;
            EXPECT_EQ(row->skipReason.has_value(), !opened);
            if (!opened && row->skipReason) {
                EXPECT_EQ(*row->skipReason, SkipReason::Policy);
            }
        }
    }

    const size_t rows = 2 * std::size(kObserved);
    EXPECT_EQ(result.files.size(), rows) << listRows(result);
    EXPECT_EQ(result.filesWithMatches, rows);
    EXPECT_EQ(result.filesWithHostileNames, rows);
    // Every member is still counted where it was counted before, once: read, or left shut.
    EXPECT_EQ(result.archives.membersScanned + result.archives.skippedPolicy(), rows);
    EXPECT_GT(result.archives.skippedPolicy(), 0u);
    EXPECT_GT(result.archives.membersScanned, 0u);
    EXPECT_EQ(result.filesQuarantined, 0u);
}

// The measured line, inside an archive: 2,400 ordinary business names, every one carrying an
// apostrophe or an ampersand, filed in folders, in a zip and in a tar.gz - read by name, and
// read in full under --exhaustive-archives so that silence is not a member left shut.
TEST(MemberNameTest, OrdinaryBusinessNamesInAnArchiveRaiseNothing) {
    // The documents only. The corpus also carries the ordinary web-root names a loose tree
    // has - `wp-config.php`, `index.php` - and an archive holding those beside thousands of
    // entries is, correctly, a site backup with an exposure finding of its own, which is not
    // what this case is about.
    std::vector<std::string> names;
    for (const auto& name : benignNames()) {
        if (archive::classifyMember(name) == archive::Bucket::Other && name != ".htaccess") {
            names.push_back(name);
        }
    }
    ASSERT_GT(names.size(), 1000u);
    size_t apostrophes = 0;
    size_t ampersands = 0;
    for (const auto& name : names) {
        apostrophes += name.find('\'') != std::string::npos;
        ampersands += name.find('&') != std::string::npos;
    }
    ASSERT_GT(apostrophes, 500u);
    ASSERT_GT(ampersands, 500u);

    TempDir root;
    std::vector<std::pair<std::string, std::string>> members;
    const std::vector<std::string> folders = {"Invoices/", "Board & Committees/2024/",
                                              "Dave's Deli/", ""};
    for (size_t i = 0; i < names.size(); ++i) {
        members.emplace_back(folders[i % folders.size()] + names[i],
                             "Quarterly figures, nothing executable.\n");
    }
    const fs::path zip = root.path() / "Clients & Partners' Documents.zip";
    const fs::path tgz = root.path() / "O'Brien & Sons archive.tar.gz";
    writeZip(zip, members);
    writeTarGz(tgz, members);

    for (const bool exhaustive : {false, true}) {
        SCOPED_TRACE(exhaustive ? "exhaustive" : "default selection");
        AppConfig config = scanConfig(root.path());
        config.archives.exhaustive = exhaustive;
        // Thousands of near-identical small documents compress far past 100:1 in a tar.gz,
        // and the ratio guard would stop the stream part-way. Every member is to be read here.
        config.archives.maxRatio = 0;
        const ScanResult result = runScan(config);

        EXPECT_EQ(result.files.size(), 0u) << listRows(result);
        EXPECT_EQ(result.filesWithMatches, 0u);
        EXPECT_EQ(result.filesWithHostileNames, 0u);
        // Every member is accounted for, read or left shut by selection alone - so every name
        // was read and nothing stopped part-way. Exhaustive mode opens every member the
        // include list covers; the `.docx`, `.xlsx` and `.pptx` it does not cover stay shut
        // there too, and their names are read all the same.
        EXPECT_EQ(result.archives.membersScanned + result.archives.skippedPolicy(),
                  2 * names.size());
        EXPECT_EQ(result.archives.totalSkipped(), result.archives.skippedPolicy())
            << archive::membersNotScannedLine(result.archives);
        EXPECT_EQ(result.archives.archivesTruncated, 0u);
        if (exhaustive) {
            EXPECT_GT(result.archives.membersScanned, names.size())
                << "exhaustive mode read too few members for its silence to mean anything";
        }
        RecordProperty(exhaustive ? "members_read_exhaustive" : "members_read_default",
                       static_cast<int>(result.archives.membersScanned));
    }
    RecordProperty("benign_member_names_checked", static_cast<int>(2 * names.size()));
}

// Which members have their names read is the file level's answer. What decides what is opened -
// the priority policy, a sidecar, the member size cap, the budget - does not decide what a name
// may say, and each such member's row carries the reason its bytes were not read.
TEST(MemberNameTest, AMemberThatIsNotOpenedStillHasItsNameReadAndSaysWhy) {
    TempDir root;
    const fs::path zip = root.path() / "upload.zip";
    writeZip(zip, {
        {"a.php", "<?php echo 1;\n"},                          // read first, spends the budget
        {"x$(id).mdb", "db\n"},                                // policy: not code
        {"__MACOSX/._y$(id).php", "sidecar\n"},                // policy: container metadata
        {"big;id.php", std::string(64 * 1024, 'a')},           // size
        {"late`id`.php", "<?php echo 2;\n"},                   // budget
    });

    AppConfig config = scanConfig(root.path());
    config.archives.maxMemberSize = 32 * 1024;
    config.archives.maxExpansion = 1;   // spent by the first member read
    const ScanResult result = runScan(config);

    const auto expect = [&](const std::string& member, SkipReason why, const char* code) {
        SCOPED_TRACE(member);
        const FileResult* row = findMember(result, zip, member);
        ASSERT_NE(row, nullptr) << listRows(result);
        ASSERT_TRUE(row->skipReason.has_value());
        EXPECT_EQ(*row->skipReason, why);
        EXPECT_EQ(codesOf(*row), (std::set<std::string>{code}));
    };
    expect("x$(id).mdb", SkipReason::Policy, "FN001");
    expect("__MACOSX/._y$(id).php", SkipReason::Policy, "FN001");
    expect("big;id.php", SkipReason::Size, "FN002");
    expect("late`id`.php", SkipReason::Budget, "FN001");

    EXPECT_EQ(findMember(result, zip, "a.php"), nullptr) << "a clean name is not a row";
    EXPECT_EQ(result.files.size(), 4u) << listRows(result);
    // Counted once each where the archive layer counts them, and nowhere else.
    EXPECT_EQ(result.archives.skippedPolicy(), 2u);
    EXPECT_EQ(result.archives.skippedSize(), 1u);
    EXPECT_EQ(result.archives.skippedBudget(), 1u);
    EXPECT_EQ(result.skips.total(), 0u) << "a member's reason became a file-level skip";
}

// An opened member's name finding leads its row, ahead of what its bytes raised - one row per
// member, as one row per loose file.
TEST(MemberNameTest, AnOpenedMemberCarriesItsNameAheadOfItsContent) {
    TempDir root;
    const fs::path zip = root.path() / "upload.zip";
    writeZip(zip, {{"wp/x$(id).php", kWebshell}});

    const ScanResult result = runScan(scanConfig(root.path()));
    const FileResult* row = findMember(result, zip, "wp/x$(id).php");
    ASSERT_NE(row, nullptr) << listRows(result);
    ASSERT_GE(row->matches.size(), 2u);
    EXPECT_EQ(row->matches.front().category, "FN001");
    EXPECT_TRUE(hasHostileContent(*row));
    EXPECT_FALSE(row->skipReason.has_value());
    EXPECT_EQ(result.filesWithHostileNames, 1u);
}

// An `exclude` pattern is the operator writing down what not to look at, and it is obeyed for a
// member exactly as for a loose file - including a file the include list does not cover, whose
// name the loose-file walk used to read from inside the excluded tree anyway.
TEST(MemberNameTest, AnExcludePatternKeepsANameOutLooseOrInsideAnArchive) {
    TempDir root;
    const std::string loose = "x$(id)-loose.mdb";
    if (const auto why = whyCannotCreate(root.path(), loose)) {
        GTEST_SKIP() << *why;
    }
    const fs::path zip = root.path() / "upload.zip";
    writeZip(zip, {{"docs/x$(id).mdb", "db\n"}, {"site/a;b.php", "<?php echo 1;\n"}});

    AppConfig config = scanConfig(root.path());
    {
        const ScanResult result = runScan(config);
        ASSERT_NE(findByName(result, loose), nullptr) << "the control direction";
        ASSERT_NE(findMember(result, zip, "docs/x$(id).mdb"), nullptr) << "the control direction";
    }

    config.scan.exclude.push_back("*.mdb");
    const ScanResult result = runScan(config);
    EXPECT_EQ(findByName(result, loose), nullptr)
        << "an excluded file the include list does not cover had its name reported";
    EXPECT_EQ(findMember(result, zip, "docs/x$(id).mdb"), nullptr)
        << "an excluded member had its name reported";
    EXPECT_NE(findMember(result, zip, "site/a;b.php"), nullptr)
        << "the exclude reached a member it does not name";
    EXPECT_EQ(result.filesWithHostileNames, 1u) << listRows(result);
}

// Inside an archive the separator is the format's, so a backslash in a stored name is a
// character of it on every platform - including Windows, where a backslash on disk is always a
// separator and finalComponent() splits on it. The observed `a\zz-<id>.php` split there would
// be `zz-<id>.php`, which raises nothing.
TEST(MemberNameTest, OnEveryPlatformABackslashInAStoredNameIsPartOfTheName) {
    EXPECT_EQ(fn::memberFinalComponent("uploads/a\\zz-1.php"), "a\\zz-1.php");
    EXPECT_EQ(fn::memberFinalComponent("a\\b\\c.php"), "a\\b\\c.php");
    EXPECT_EQ(fn::memberFinalComponent("site/wp-content\\"), "wp-content\\");
    EXPECT_EQ(fn::memberFinalComponent("plain.php"), "plain.php");
    EXPECT_EQ(fn::memberFinalComponent("dir/"), "");
#ifdef _WIN32
    EXPECT_EQ(fn::finalComponent("uploads/a\\zz-1.php"), "zz-1.php")
        << "the disk split is not the member split here, which is why there are two";
#endif

    TempDir root;
    const fs::path zip = root.path() / "upload.zip";
    const fs::path tgz = root.path() / "upload.tar.gz";
    writeZip(zip, {{"uploads/a\\zz-1.php", "<?php echo 1;\n"}});
    writeTarGz(tgz, {{"uploads/a\\zz-1.php", "<?php echo 1;\n"}});
    const ScanResult result = runScan(scanConfig(root.path()));

    for (const fs::path& container : {zip, tgz}) {
        SCOPED_TRACE(container.filename().string());
        // The address is the one every member row has always had, which normalises a
        // backslash to a slash for display; the rule reads the name as stored.
        const FileResult* row = findMember(result, container, "uploads/a/zz-1.php");
        ASSERT_NE(row, nullptr) << listRows(result);
        EXPECT_EQ(codesOf(*row), (std::set<std::string>{"FN002"}));
        ASSERT_FALSE(row->matches.empty());
        EXPECT_EQ(row->matches.front().matchedText, "\\");
        EXPECT_FALSE(row->skipReason.has_value()) << "a .php member is opened";
    }
}

// A name finding never moves a file, so a container whose members raise nothing but name
// findings stays where it is - with a member that was opened and one that was not. The
// companion: a webshell under an ordinary name beside them still moves the container, and the
// name rows then say their bytes left with it.
TEST(MemberNameTest, ANameFindingNeverMovesItsContainerAndContentStillDoes) {
    TempDir root;
    TempDir quarantine;
    const fs::path names = root.path() / "names.zip";
    writeZip(names, {{"x$(id).mdb", "db\n"}, {"a;b.php", "<?php echo 1;\n"}});

    const fs::path mixed = root.path() / "sub" / "mixed.zip";
    fs::create_directories(mixed.parent_path());
    std::string shell = kWebshell;
    shell += "\n";
    for (int i = 0; i < 400; ++i) {
        shell += "// padding padding padding padding padding padding\n";
    }
    writeZip(mixed, {{"wp/shell.php", shell}, {"wp/x`id`.mdb", "db\n"}});
    ASSERT_EQ(readBytes(mixed).find("base64_decode"), std::string::npos)
        << "the payload is readable in the container's own bytes, so the move would not be "
           "the member's doing";

    AppConfig config = scanConfig(root.path());
    config.actions.quarantine.enabled = true;
    config.actions.quarantine.directory = quarantine.path().string();
    config.actions.quarantine.preserveStructure = false;
    const ScanResult result = runScan(config);

    EXPECT_TRUE(fs::exists(names)) << "a container was moved for its members' names";
    for (const std::string member : {"x$(id).mdb", "a;b.php"}) {
        const FileResult* row = findMember(result, names, member);
        ASSERT_NE(row, nullptr) << listRows(result);
        EXPECT_FALSE(row->containerQuarantine.has_value())
            << member << " says a decision was taken about a container nothing selected";
    }

    EXPECT_FALSE(fs::exists(mixed)) << "the webshell's container was not moved";
    EXPECT_EQ(result.filesQuarantined, 1u);
    const FileResult* named = findMember(result, mixed, "wp/x`id`.mdb");
    ASSERT_NE(named, nullptr) << listRows(result);
    ASSERT_TRUE(named->containerQuarantine.has_value());
    EXPECT_EQ(*named->containerQuarantine, ContainerQuarantine::Moved);
}

// Nesting: a name is read at every depth the scan reaches, and a member of an archive nested
// past max_depth is never reached, so it says nothing and the depth skip is what is counted.
TEST(MemberNameTest, ANameIsReadAtEveryDepthTheScanReaches) {
    TempDir root;
    TempDir build;
    const fs::path inner = build.path() / "inner.zip";
    writeZip(inner, {{"$(sleep 5).txt", "hello\n"}});
    const fs::path middle = build.path() / "middle.tar.gz";
    writeTarGz(middle, {{"inner.zip", readBytes(inner)}, {"-rf.txt", "x\n"}});
    const fs::path outer = root.path() / "outer.zip";
    writeZip(outer, {{"nested/middle.tar.gz", readBytes(middle)}});

    AppConfig config = scanConfig(root.path());
    // Exhaustive, because a nested archive is not code to the priority policy and is never
    // opened by default - which would make this case silent for a reason it is not about.
    config.archives.exhaustive = true;
    config.archives.maxDepth = 3;
    {
        const ScanResult result = runScan(config);
        const fs::path twoDown(pathToUtf8(outer) + "!nested/middle.tar.gz");
        const fs::path threeDown(pathToUtf8(twoDown) + "!inner.zip");
        const FileResult* dash = findMember(result, twoDown, "-rf.txt");
        const FileResult* sleep = findMember(result, threeDown, "$(sleep 5).txt");
        ASSERT_NE(dash, nullptr) << listRows(result);
        ASSERT_NE(sleep, nullptr) << listRows(result);
        EXPECT_EQ(codesOf(*dash), (std::set<std::string>{"FN004"}));
        EXPECT_EQ(codesOf(*sleep), (std::set<std::string>{"FN001"}));
        EXPECT_EQ(result.filesWithHostileNames, 2u) << listRows(result);
    }

    config.archives.maxDepth = 2;
    const ScanResult shallow = runScan(config);
    EXPECT_EQ(shallow.filesWithHostileNames, 1u) << listRows(shallow);
    EXPECT_EQ(shallow.archives.skippedDepth(), 1u);
}
