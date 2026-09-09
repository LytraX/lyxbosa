// A scan root that is not there.
//
// THE DEFECT THESE CASES EXIST FOR
// --------------------------------
// FileWalker::walkDirectory returned 0 for a root that failed exists() or
// is_directory(), so `lyxbosa scan /typo/in/a/cron/entry` printed "Files scanned: 0",
// "No matches found" and exited 0 - the same three things a scan of a clean tree
// prints. The walk's success was defined by what it managed to open, which is the
// shape AGENTS.md records five earlier instances of.
//
// WHY EVERY CASE HERE HAS A COMPANION
// -----------------------------------
// A case asserting the new non-zero exit is worth nothing on its own: a scan command
// that refused everything would pass it. So each assertion that the scanner now says
// "not there" is paired with one that it still says the other thing -
//
//   an empty directory that exists is still walked, and still exits 0
//   a tree with a finding in it still exits 2, and the new branch does not swallow it
//   a root that exists and cannot be READ is still counted the way it was, because
//     that is a different fact: the tree was there and the host refused it, which is
//     a coverage warning rather than a path the operator got wrong
//   the recursion step still steps over a directory that is gone, because a
//     subdirectory vanishing under a running scan is a race and not an operator error
//
// The exit-code cases drive ScanUseCase rather than Scanner, because the exit code is
// the interface a cron entry reads and it is decided there.

#include <gtest/gtest.h>

#include "config/Config.h"
#include "core/FileWalker.h"
#include "core/Scanner.h"
#include "system/CliArgs.h"
#include "use-cases/ScanUseCase.h"

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

#ifndef _WIN32
#include <unistd.h>
#endif

using namespace lyxbosa;

namespace {

namespace fs = std::filesystem;

class TempDir {
public:
    TempDir() {
        path_ = fs::temp_directory_path() /
                ("lyxbosa-root-test-" + std::to_string(counter_++) + "-" +
                 std::to_string(fs::hash_value(fs::temp_directory_path())));
        fs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        // A case that made a directory unreadable has to be able to clean up after
        // itself, and it cannot until the bits go back.
        fs::permissions(path_, fs::perms::owner_all, fs::perm_options::add, ec);
        fs::remove_all(path_, ec);
    }
    const fs::path& path() const { return path_; }
    fs::path file(const std::string& name) const { return path_ / name; }

private:
    fs::path path_;
    static inline int counter_ = 0;
};

void writeFile(const fs::path& path, std::string_view content) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

// Matches rule RCE004. Kept here rather than in a fixture file so a case that is about
// exit code 2 can be read without going to look for what makes it 2.
constexpr std::string_view kFinding = "<?php eval($_POST[\"x\"]); ?>\n";

AppConfig configFor(const std::vector<std::string>& directories) {
    AppConfig config = Config::loadFromString(Config::generateDefault());
    config.scan.directories = directories;
    config.scan.recursive = true;
    config.archives.enabled = false;
    return config;
}

ScanResult scanOf(const std::vector<std::string>& directories) {
    Scanner scanner(configFor(directories));
    scanner.setPreCount(false);
    return scanner.scan();
}

// Why this platform cannot make a directory the current user may not read, or nullopt
// when it can. Two reasons, and a case that hits either has to say so rather than pass
// without observing anything: root ignores the permission bits, and Windows has no
// POSIX mode for std::filesystem::permissions to clear.
std::optional<std::string> whyCannotDenyOwnReads() {
#ifdef _WIN32
    return "Windows has no POSIX permission bits, so a mode-000 directory is still "
           "readable and no refusal can be observed";
#else
    if (::geteuid() == 0) {
        return "running as root - a mode-000 directory is still readable, so no "
               "refusal can be observed";
    }
    return std::nullopt;
#endif
}

// The exit code `lyxbosa scan` would return for these arguments. Every field that
// would make the command wait for a human or write to the console is pinned here, so
// a case says only what it is about.
int scanExitCode(const std::vector<std::string>& directories, const fs::path& report) {
    CliArgs args;
    args.directories = directories;
    args.force = true;              // no confirmation prompt, and no update check
    args.quarantine = false;        // never move a file out of a test's temp directory
    args.silent = true;             // the report is the file below and nothing else
    args.outputFile = report.string();
    args.noPreCount = true;

    const Terminal terminal(/*useAnsi=*/false);
    const TerminalCaps caps = TerminalCaps::detect();
    return ScanUseCase(terminal, caps).execute(args);
}

}  // namespace

// ===========================================================================
// What counts as a usable root
// ===========================================================================

TEST(RootReasonTest, ADirectoryThatIsThereHasNoReason) {
    TempDir dir;
    EXPECT_FALSE(rootUnusableReason(dir.path()).has_value());
}

TEST(RootReasonTest, AbsentAndNotADirectoryAreDifferentReasons) {
    TempDir dir;
    const auto absent = rootUnusableReason(dir.file("nothing-here"));
    ASSERT_TRUE(absent.has_value());
    EXPECT_EQ(*absent, "no such directory");

    writeFile(dir.file("a-file"), "x");
    const auto notADirectory = rootUnusableReason(dir.file("a-file"));
    ASSERT_TRUE(notADirectory.has_value());
    EXPECT_EQ(*notADirectory, "not a directory");
}

// ===========================================================================
// What the walk records
// ===========================================================================

TEST(ScanRootTest, AnAbsentRootIsRecordedAndNothingIsWalked) {
    TempDir dir;
    const ScanResult result = scanOf({dir.file("nothing-here").string()});

    ASSERT_EQ(result.rootsMissing.size(), 1u);
    EXPECT_EQ(result.rootsMissing[0], dir.file("nothing-here"));
    EXPECT_EQ(result.totalDirectoriesScanned, 0u);
    EXPECT_EQ(result.totalFilesScanned, 0u);
}

// The companion. Without it the case above would pass against a walker that recorded
// every root as missing and scanned nothing at all.
TEST(ScanRootTest, AnEmptyRootThatIsThereIsWalkedAndRecordsNothing) {
    TempDir dir;
    const ScanResult result = scanOf({dir.path().string()});

    EXPECT_TRUE(result.rootsMissing.empty());
    EXPECT_EQ(result.totalDirectoriesScanned, 1u);
    EXPECT_EQ(result.totalFilesScanned, 0u);
}

TEST(ScanRootTest, AFileNamedAsARootIsRecordedRatherThanWalked) {
    TempDir dir;
    writeFile(dir.file("not-a-directory"), kFinding);

    const ScanResult result = scanOf({dir.file("not-a-directory").string()});

    ASSERT_EQ(result.rootsMissing.size(), 1u);
    EXPECT_EQ(result.totalFilesScanned, 0u)
        << "a file named as a root is the operator's error, not a one-file scan";
}

TEST(ScanRootTest, OneAbsentRootAmongFourLeavesTheOtherThreeWalked) {
    TempDir dir;
    for (const char* name : {"a", "b", "c"}) {
        writeFile(dir.path() / name / "page.php", kFinding);
    }

    const ScanResult result = scanOf({(dir.path() / "a").string(),
                                      (dir.path() / "b").string(),
                                      dir.file("gone").string(),
                                      (dir.path() / "c").string()});

    ASSERT_EQ(result.rootsMissing.size(), 1u);
    EXPECT_EQ(result.rootsMissing[0], dir.file("gone"));
    EXPECT_EQ(result.totalDirectoriesScanned, 3u);
    EXPECT_EQ(result.totalFilesScanned, 3u)
        << "the roots that are there are still walked; the command refuses above this";
}

// The distinction the whole change turns on. A root that is there and cannot be read
// is the host refusing, which is already counted and must stay counted the way it is -
// folding it in here would make a scan of / as an ordinary user an error.
TEST(ScanRootTest, AnUnreadableRootIsCountedAsUnreadableAndNotAsMissing) {
    if (const auto why = whyCannotDenyOwnReads()) {
        GTEST_SKIP() << *why;
    }

    TempDir dir;
    writeFile(dir.path() / "locked" / "page.php", kFinding);
    const fs::path locked = dir.path() / "locked";
    fs::permissions(locked, fs::perms::none);

    const ScanResult result = scanOf({locked.string()});

    // Restore before any assertion can leave the temp directory undeletable.
    fs::permissions(locked, fs::perms::owner_all);

    EXPECT_TRUE(result.rootsMissing.empty())
        << "a tree that is there and was refused is not a path the operator got wrong";
    EXPECT_EQ(result.directoriesUnreadable, 1u);
    EXPECT_EQ(result.totalDirectoriesScanned, 1u);
}

// The other half of the same distinction, at the recursion step. walkDirectory() is
// called for every subdirectory the walk descends into, and one that disappears while
// the scan is running is a race rather than an operator error - so it must keep
// returning 0 quietly, and must not learn to complain.
TEST(ScanRootTest, TheRecursionStepStillStepsOverAPathThatIsGone) {
    TempDir dir;
    const FileWalker walker(configFor({dir.path().string()}).scan);

    bool stopped = false;
    size_t unreadable = 0;
    size_t files = 0;
    const size_t walked = walker.walkDirectory(
        dir.file("never-existed"),
        [&files](const FileInfo&) {
            ++files;
            return true;
        },
        stopped, &unreadable);

    EXPECT_EQ(walked, 0u);
    EXPECT_EQ(files, 0u);
    EXPECT_EQ(unreadable, 0u);
    EXPECT_FALSE(stopped);
}

// ===========================================================================
// The exit code, which is what a cron entry actually reads
// ===========================================================================

TEST(ScanExitTest, AMissingRootDoesNotExitZero) {
    TempDir dir;
    EXPECT_EQ(scanExitCode({dir.file("nothing-here").string()}, dir.file("report.txt")), 1);
}

// The companion that makes the case above mean something: a command that refused every
// scan would pass it and fail this.
TEST(ScanExitTest, AnOrdinaryCleanScanStillExitsZero) {
    TempDir dir;
    writeFile(dir.path() / "tree" / "page.php", "<?php echo 1;\n");
    EXPECT_EQ(scanExitCode({(dir.path() / "tree").string()}, dir.file("report.txt")), 0);
}

// And the third answer, so the new branch cannot be swallowing findings.
TEST(ScanExitTest, AScanThatFindsSomethingStillExitsTwo) {
    TempDir dir;
    writeFile(dir.path() / "tree" / "page.php", kFinding);
    EXPECT_EQ(scanExitCode({(dir.path() / "tree").string()}, dir.file("report.txt")), 2);
}

TEST(ScanExitTest, OneMissingRootAmongFourRefusesTheWholeScan) {
    TempDir dir;
    for (const char* name : {"a", "b", "c"}) {
        writeFile(dir.path() / name / "page.php", kFinding);
    }
    const int code = scanExitCode({(dir.path() / "a").string(),
                                   (dir.path() / "b").string(),
                                   dir.file("gone").string(),
                                   (dir.path() / "c").string()},
                                  dir.file("report.txt"));

    EXPECT_EQ(code, 1) << "one root that is not there refuses the run rather than "
                          "scanning three of four and calling it the scan";
    EXPECT_FALSE(fs::exists(dir.file("report.txt")))
        << "a refused run must not leave a report describing a scan that never ran";
}

// An unreadable root is a warning and not a refusal, and the exit code says so today.
// Recorded here so that a later round which decides otherwise has to change a case
// rather than discovering it in the field.
TEST(ScanExitTest, AnUnreadableRootStillExitsZero) {
    if (const auto why = whyCannotDenyOwnReads()) {
        GTEST_SKIP() << *why;
    }

    TempDir dir;
    writeFile(dir.path() / "locked" / "page.php", kFinding);
    const fs::path locked = dir.path() / "locked";
    fs::permissions(locked, fs::perms::none);

    const int code = scanExitCode({locked.string()}, dir.file("report.txt"));

    fs::permissions(locked, fs::perms::owner_all);

    EXPECT_EQ(code, 0);
}
