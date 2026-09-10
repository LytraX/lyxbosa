// A file whose path is at or past MAX_PATH, on Windows.
//
// THE DEFECT THIS CASE EXISTS FOR
// -------------------------------
// Fifteen files in the stock CMS trees have paths of 260 to 271 characters. On Windows
// the scanner could not open any of them - `check` said "File not found", a scan counted
// them unreadable - while Python opened every one, and the corpus suite refused, correctly,
// to report a false-positive figure over a tree it had not fully read. The machine had
// LongPathsEnabled set in the registry. Windows wants two things before a process may
// open such a path with the ordinary Win32 calls std::filesystem and std::ifstream make:
// that registry value, and a longPathAware entry in the executable's manifest. The
// scanner had no manifest at all; Python ships one, which is why the two disagreed about
// the same file.
//
// The manifest is cmake/lyxbosa.manifest, and CMakeLists.txt attaches it to every
// executable through one function, so the release binary and this test binary cannot
// drift apart on it - a fix present in only one of them is a fix nobody can test.
//
// WHAT THIS CASE CAN AND CANNOT OBSERVE
// -------------------------------------
// The property is "the scanner reads a file at a path over 260 characters", and this
// process is the binary under test, so its own manifest is what is being exercised. Of
// the two conditions only the manifest is the binary's to provide. On a machine where the
// registry value is off no manifest makes the path open, the property is unobservable,
// and the case says which half it could not meet and skips - the discipline
// tests/PlatformSkips.h applies to the permission cases, because a case that cannot fail
// is the shape AGENTS.md records earlier instances of.
//
// With the value on and the manifest missing, the set-up itself cannot create the path.
// That is reported as the failure it is and not as a skip: this binary not being
// long-path aware is exactly the defect.
//
// On Linux the limit is PATH_MAX, 4096, and the path here is well inside it. The case
// passes there by observing the property, not by skipping it - and what it cannot do
// there is fail for the Windows reason, so a green Linux run says nothing about Windows.

#include <gtest/gtest.h>

#include "config/Config.h"
#include "core/Scanner.h"
#include "infrastructure/PathUtils.h"

#include "PlatformSkips.h"

#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <string_view>

using namespace lyxbosa;

namespace {

namespace fs = std::filesystem;

// Matches rule RCE004, so the case can tell a file that was read from one that was
// merely listed.
constexpr std::string_view kFinding = "<?php eval($_POST[\"x\"]); ?>\n";

// Where MAX_PATH bites, and a margin over it: the fifteen files measured ran 260 to 271.
constexpr size_t kMaxPath = 260;
constexpr size_t kAtLeast = 280;

// A tree deep enough that the file's path is past kAtLeast. Short components, because
// a single component has a limit of its own (255 on both platforms) and the property
// here is the length of the whole path.
class LongPathTree {
public:
    LongPathTree() {
        root_ = fs::temp_directory_path() /
                ("lyxbosa-long-path-" + std::to_string(std::random_device{}()));
        fs::path dir = root_;
        while (pathToUtf8(dir / kLeaf).size() < kAtLeast) {
            dir /= "component-0123456789";
        }
        dir_ = dir;
        file_ = dir / kLeaf;
    }
    ~LongPathTree() {
        std::error_code ec;
        fs::remove_all(root_, ec);
    }

    const fs::path& root() const { return root_; }
    const fs::path& dir() const { return dir_; }
    const fs::path& file() const { return file_; }

private:
    static constexpr std::string_view kLeaf = "deep.php";
    fs::path root_;
    fs::path dir_;
    fs::path file_;
};

AppConfig configFor(const fs::path& root) {
    AppConfig config = Config::loadFromString(Config::generateDefault());
    config.scan.directories = {root.string()};
    config.scan.recursive = true;
    config.archives.enabled = false;
    config.actions.quarantine.enabled = false;
    return config;
}

}  // namespace

TEST(LongPathTest, AFileAtAPathPastMaxPathIsReadAndItsFindingReported) {
    if (const auto why = test::whyCannotObserveLongPaths()) {
        GTEST_SKIP() << *why;
    }

    LongPathTree tree;
    const std::string shown = pathToUtf8(tree.file());
    ASSERT_GT(shown.size(), kMaxPath)
        << "the fixture is " << shown.size() << " characters, which observes nothing";

    // Set-up is this binary opening the path, so a refusal here is the defect itself
    // and not a reason to skip: with the registry value on, only the manifest is missing.
    std::error_code ec;
    fs::create_directories(tree.dir(), ec);
    ASSERT_FALSE(ec) << "this test binary could not create a " << shown.size()
                     << "-character path (" << ec.message() << "); with LongPathsEnabled "
                     << "on, that is its own manifest missing";
    {
        std::ofstream out(tree.file(), std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(out.good()) << "this test binary could not create " << shown;
        out.write(kFinding.data(), static_cast<std::streamsize>(kFinding.size()));
    }
    ASSERT_TRUE(fs::exists(tree.file())) << shown;

    Scanner scanner(configFor(tree.root()));
    scanner.setPreCount(false);

    // What `check` does: one path, straight to the reader.
    const FileResult single = scanner.scanFile(tree.file());
    EXPECT_FALSE(single.skipped())
        << "scanFile could not read a " << shown.size() << "-character path";
    EXPECT_EQ(single.matches.size(), 1u) << "read, but the finding in it was not reported";

    // What `scan` does: the walk has to list it and the reader has to open it.
    const ScanResult result = scanner.scan();
    EXPECT_EQ(result.skips.count(SkipReason::Unreadable), 0u)
        << "the walk listed the file and the reader could not open it";
    EXPECT_EQ(result.totalFilesScanned, 1u);
    EXPECT_EQ(result.filesWithMatches, 1u);
}
