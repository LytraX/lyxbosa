#include <gtest/gtest.h>

#include "config/Config.h"
#include "core/Quarantine.h"
#include "core/Scanner.h"

#include "PlatformSkips.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

using namespace lyxbosa;

namespace {

namespace fs = std::filesystem;

// A temporary directory that removes itself. Same shape as the one in
// archive_test.cpp, and named from a steady_clock tick for the same reason: two test
// binaries can be running at once and ::getpid() is POSIX-only.
class TempDir {
public:
    explicit TempDir(const fs::path& parent = fs::temp_directory_path()) {
        const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = parent / ("lyxbosa-quarantine-test-" + std::to_string(tick) + "-" +
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

void writeFile(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

std::string readFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

// A webshell the rules answer for, carrying a marker that says which sample it is.
// The whole point of these cases is that counting files cannot tell two samples
// apart and reading them can.
std::string shellCarrying(const std::string& marker) {
    return "<?php /* " + marker + " */ eval(base64_decode($_POST['x'])); ?>";
}

// Every marker present anywhere under `dir`, sorted. Content, not count: the defect
// these cases exist for reported "Files quarantined: 2" while holding one file.
std::vector<std::string> markersUnder(const fs::path& dir, const std::vector<std::string>& all) {
    std::vector<std::string> found;
    for (const auto& entry : fs::recursive_directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        const std::string bytes = readFile(entry.path());
        for (const auto& marker : all) {
            if (bytes.find(marker) != std::string::npos) {
                found.push_back(marker);
            }
        }
    }
    std::sort(found.begin(), found.end());
    return found;
}

size_t regularFilesUnder(const fs::path& dir) {
    size_t count = 0;
    for (const auto& entry : fs::recursive_directory_iterator(dir)) {
        if (entry.is_regular_file()) ++count;
    }
    return count;
}

AppConfig quarantineConfig(const std::vector<fs::path>& roots,
                           const fs::path& quarantineDir,
                           bool preserveStructure = true) {
    AppConfig config = Config::loadFromString(Config::generateDefault());
    config.scan.directories.clear();
    for (const auto& root : roots) {
        config.scan.directories.push_back(root.string());
    }
    config.scan.recursive = true;
    config.actions.quarantine.enabled = true;
    config.actions.quarantine.directory = quarantineDir.string();
    config.actions.quarantine.preserveStructure = preserveStructure;
    return config;
}

ScanResult runScan(const AppConfig& config) {
    Scanner scanner(config);
    scanner.setPreCount(false);
    return scanner.scan();
}

// Nullopt when this machine has a second filesystem to move a file onto. A rename
// cannot cross one - that is what EXDEV is - so the fallback path in
// moveWithoutReplacing() is only reachable where two mounts exist, and a case that
// silently ran on one mount would be asserting nothing about the boundary it names.
#ifdef _WIN32
std::optional<std::string> whyNoSecondFilesystem(fs::path&) {
    return "a second volume cannot be assumed on a Windows test machine, and "
           "MoveFileExW crosses one itself with MOVEFILE_COPY_ALLOWED rather than "
           "taking the copy path this case is about";
}
#else
std::optional<std::string> whyNoSecondFilesystem(fs::path& elsewhere) {
    // /dev/shm is a tmpfs on any Linux with POSIX shared memory, and is a different
    // device from the one temp_directory_path() lands on unless /tmp is that same
    // tmpfs - which is exactly the case that has to say so rather than pass.
    const fs::path candidate("/dev/shm");
    struct ::stat here {};
    struct ::stat there {};
    if (::stat(fs::temp_directory_path().string().c_str(), &here) != 0 ||
        ::stat(candidate.string().c_str(), &there) != 0) {
        return "no second filesystem could be stat'd, so a cross-device move cannot "
               "be set up here";
    }
    if (here.st_dev == there.st_dev) {
        return "the temporary directory and /dev/shm are the same filesystem on this "
               "machine, so no rename here can return EXDEV";
    }
    elsewhere = candidate;
    return std::nullopt;
}
#endif

}  // namespace

// ============================================================================
// The destination: it cannot collide, and it says where the file came from
// ============================================================================

// The reproduction. Two scan roots holding the same relative path is not exotic -
// it is `/var/www/a` and `/var/www/b` on any shared host - and the destination used
// to be built from the path relative to whichever root the file came from, so both
// files landed on one name and the second silently replaced the first.
TEST(QuarantineTest, TwoRootsWithTheSameRelativePathBothSurvive) {
    TempDir tree;
    TempDir quarantine;

    const fs::path rootA = tree.path() / "rootA";
    const fs::path rootB = tree.path() / "rootB";
    writeFile(rootA / "wp" / "shell.php", shellCarrying("SAMPLE-ALPHA"));
    writeFile(rootB / "wp" / "shell.php", shellCarrying("SAMPLE-BRAVO"));

    const ScanResult result = runScan(quarantineConfig({rootA, rootB}, quarantine.path()));

    EXPECT_EQ(result.filesQuarantined, 2u);
    EXPECT_FALSE(fs::exists(rootA / "wp" / "shell.php"));
    EXPECT_FALSE(fs::exists(rootB / "wp" / "shell.php"));

    // By content. The count was already 2 before this was fixed, and one of the two
    // files had been deleted by the other.
    const std::vector<std::string> expected{"SAMPLE-ALPHA", "SAMPLE-BRAVO"};
    EXPECT_EQ(markersUnder(quarantine.path(), expected), expected);
    EXPECT_EQ(regularFilesUnder(quarantine.path()), 2u);
}

// The normal way an operator uses a quarantine directory is to point every run at
// the same one. Two runs over the same path - a site reinfected, or a scan repeated
// after the first was interrupted - used to collide exactly the way two roots did.
TEST(QuarantineTest, ASecondRunDoesNotOverwriteTheFirstRunsEvidence) {
    TempDir tree;
    TempDir quarantine;

    const fs::path root = tree.path() / "site";
    const fs::path shell = root / "wp" / "shell.php";
    const AppConfig config = quarantineConfig({root}, quarantine.path());

    writeFile(shell, shellCarrying("FIRST-INFECTION"));
    EXPECT_EQ(runScan(config).filesQuarantined, 1u);

    writeFile(shell, shellCarrying("SECOND-INFECTION"));
    EXPECT_EQ(runScan(config).filesQuarantined, 1u);

    const std::vector<std::string> expected{"FIRST-INFECTION", "SECOND-INFECTION"};
    EXPECT_EQ(markersUnder(quarantine.path(), expected), expected);
    EXPECT_EQ(regularFilesUnder(quarantine.path()), 2u);
}

// Containment is only half of what quarantine is for. The other half is that an
// analyst can say afterwards which file on which machine each sample was, and a
// destination built from the path relative to the scan root cannot answer that even
// when nothing collides, because the root is the part it dropped.
TEST(QuarantineTest, TheDestinationNamesTheOriginalPath) {
    TempDir tree;
    TempDir quarantine;

    const fs::path root = tree.path() / "srv";
    const fs::path shell = root / "www" / "wp-content" / "shell.php";
    writeFile(shell, shellCarrying("TRACEABLE"));

    const ScanResult result = runScan(quarantineConfig({root}, quarantine.path()));
    ASSERT_EQ(result.filesQuarantined, 1u);

    std::optional<fs::path> destination;
    for (const auto& file : result.files) {
        if (file.quarantined) {
            destination = fs::path(file.quarantinePath);
        }
    }
    ASSERT_TRUE(destination.has_value());

    // Every component of the original path, the scan root included, is still there.
    //
    // On Windows the root NAME is a component too: `relative_path()` drops it, so
    // building the expectation from that alone would assert that C:\x\y and D:\x\y
    // mirror onto one destination - the precise collision this mechanism exists to
    // prevent. Spelled out here rather than borrowed from the implementation, so the
    // case stays an independent statement of the rule rather than a tautology.
    const fs::path canonical = fs::weakly_canonical(shell);
    fs::path expected = quarantine.path();
#ifdef _WIN32
    std::wstring volume = canonical.root_name().native();
    for (wchar_t& ch : volume) {
        if (ch == L':' || ch == L'\\' || ch == L'/') ch = L'_';
    }
    while (!volume.empty() && volume.back() == L'_') volume.pop_back();
    if (!volume.empty()) expected /= volume;
#endif
    expected /= canonical.relative_path();
    EXPECT_EQ(destination->lexically_normal(), expected.lexically_normal());
    EXPECT_TRUE(fs::exists(*destination));
    EXPECT_NE(readFile(*destination).find("TRACEABLE"), std::string::npos);
}

// destinationFor() on its own: two sources that differ only in the part the old code
// threw away must not arrive at one destination.
TEST(QuarantineTest, DestinationsDifferWhereTheSourcesDo) {
    const fs::path quarantineDir("/quarantine");
    const fs::path a = quarantine::destinationFor(quarantineDir, "/var/www/a/wp/x.php", true);
    const fs::path b = quarantine::destinationFor(quarantineDir, "/var/www/b/wp/x.php", true);

    EXPECT_NE(a, b);

    // And a `..` in the operator's own path cannot walk the destination out of the
    // directory they named.
    const fs::path escaped =
        quarantine::destinationFor(quarantineDir, "/var/www/../../etc/passwd", true)
            .lexically_normal();
    const auto [mismatch, ignored] =
        std::mismatch(quarantineDir.begin(), quarantineDir.end(),
                      escaped.begin(), escaped.end());
    EXPECT_EQ(mismatch, quarantineDir.end())
        << escaped.string() << " escaped " << quarantineDir.string();
}

// Flat is the operator asking for a directory of samples rather than a mirrored
// tree. It gives up knowing where each one came from, which is the cost of the
// choice - but it must still not lose one of them.
TEST(QuarantineTest, TheFlatLayoutKeepsBothSamples) {
    TempDir tree;
    TempDir quarantine;

    const fs::path root = tree.path() / "site";
    writeFile(root / "one" / "shell.php", shellCarrying("FLAT-ALPHA"));
    writeFile(root / "two" / "shell.php", shellCarrying("FLAT-BRAVO"));

    const ScanResult result =
        runScan(quarantineConfig({root}, quarantine.path(), /*preserveStructure=*/false));

    EXPECT_EQ(result.filesQuarantined, 2u);
    const std::vector<std::string> expected{"FLAT-ALPHA", "FLAT-BRAVO"};
    EXPECT_EQ(markersUnder(quarantine.path(), expected), expected);
    EXPECT_EQ(regularFilesUnder(quarantine.path()), 2u);
}

// ============================================================================
// The move: it refuses rather than replaces
// ============================================================================

// The primitive, asked directly. `if (!exists(dest)) rename(...)` would also pass
// this case; what it could not do is hold when something else creates the
// destination between the two statements, which is why the refusal is the kernel's
// and not a question this code asks first.
TEST(QuarantineTest, AMoveRefusesAnOccupiedDestination) {
    TempDir dir;

    const fs::path source = dir.path() / "source.php";
    const fs::path dest = dir.path() / "dest.php";
    writeFile(source, "SOURCE-BYTES");
    writeFile(dest, "DESTINATION-BYTES");

    EXPECT_EQ(quarantine::moveWithoutReplacing(source, dest),
              quarantine::MoveResult::DestinationExists);

    // Neither file was touched: not the one that was already there, and not the one
    // that was refused.
    EXPECT_EQ(readFile(dest), "DESTINATION-BYTES");
    EXPECT_EQ(readFile(source), "SOURCE-BYTES");
}

TEST(QuarantineTest, AMoveOntoAFreeNameSucceeds) {
    TempDir dir;

    const fs::path source = dir.path() / "source.php";
    const fs::path dest = dir.path() / "dest.php";
    writeFile(source, "SOURCE-BYTES");

    EXPECT_EQ(quarantine::moveWithoutReplacing(source, dest),
              quarantine::MoveResult::Moved);
    EXPECT_FALSE(fs::exists(source));
    EXPECT_EQ(readFile(dest), "SOURCE-BYTES");
}

// A rename cannot cross a filesystem boundary at all, so the refusal there is an
// exclusive create with the bytes copied through it. Both answers have to hold on
// that path too, or a quarantine directory on its own mount - which is how an
// analyst would set one up - is back to overwriting evidence.
TEST(QuarantineTest, TheRefusalHoldsAcrossAFilesystemBoundary) {
    fs::path elsewhere;
    if (const auto why = whyNoSecondFilesystem(elsewhere); why.has_value()) {
        GTEST_SKIP() << *why;
    }

    TempDir here;
    TempDir there(elsewhere);

    const fs::path source = here.path() / "source.php";
    const fs::path dest = there.path() / "dest.php";

    writeFile(source, "SOURCE-BYTES");
    EXPECT_EQ(quarantine::moveWithoutReplacing(source, dest),
              quarantine::MoveResult::Moved);
    EXPECT_FALSE(fs::exists(source));
    EXPECT_EQ(readFile(dest), "SOURCE-BYTES");

    // And a second one onto the same name is refused rather than written over.
    writeFile(source, "SECOND-SOURCE-BYTES");
    EXPECT_EQ(quarantine::moveWithoutReplacing(source, dest),
              quarantine::MoveResult::DestinationExists);
    EXPECT_EQ(readFile(dest), "SOURCE-BYTES");
    EXPECT_EQ(readFile(source), "SECOND-SOURCE-BYTES");
}

// A whole scan with the quarantine directory on the other filesystem, so the
// disambiguation loop is exercised over the copy path rather than over a rename.
TEST(QuarantineTest, ASecondRunAcrossAFilesystemBoundaryKeepsBothSamples) {
    fs::path elsewhere;
    if (const auto why = whyNoSecondFilesystem(elsewhere); why.has_value()) {
        GTEST_SKIP() << *why;
    }

    TempDir tree;
    TempDir quarantine(elsewhere);

    const fs::path root = tree.path() / "site";
    const fs::path shell = root / "wp" / "shell.php";
    const AppConfig config = quarantineConfig({root}, quarantine.path());

    writeFile(shell, shellCarrying("XDEV-FIRST"));
    EXPECT_EQ(runScan(config).filesQuarantined, 1u);

    writeFile(shell, shellCarrying("XDEV-SECOND"));
    EXPECT_EQ(runScan(config).filesQuarantined, 1u);

    const std::vector<std::string> expected{"XDEV-FIRST", "XDEV-SECOND"};
    EXPECT_EQ(markersUnder(quarantine.path(), expected), expected);
    EXPECT_EQ(regularFilesUnder(quarantine.path()), 2u);
}

// ============================================================================
// An exposure finding still never moves anything
// ============================================================================

// The rule beside the one being fixed: an exposed backup is the operator's data and
// possibly their only copy, so a finding about where a file sits never moves it.
TEST(QuarantineTest, AnExposureFindingAloneStillMovesNothing) {
    FileResult result;
    result.path = "/var/www/backup.tar.gz";

    FileMatch exposure;
    exposure.ruleName = "ARC001";
    exposure.patternType = std::string(kExposurePatternType);
    result.matches.push_back(exposure);

    EXPECT_TRUE(isExposureFinding(result.matches.front()));
    EXPECT_FALSE(hasHostileContent(result));

    FileMatch webshell;
    webshell.ruleName = "WS001";
    webshell.patternType = "builtin";
    result.matches.push_back(webshell);

    EXPECT_TRUE(hasHostileContent(result));
}
