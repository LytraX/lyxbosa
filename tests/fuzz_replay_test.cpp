#include <gtest/gtest.h>

// fuzz_replay_test.cpp - the seed corpus, replayed in the ordinary suite.
//
// An open-ended fuzz job in CI is a job people learn to ignore: it is slow, it is
// non-deterministic, and a red one is usually the budget rather than a defect. What is
// worth having every time anybody types `ctest` is the opposite - a fixed set of inputs,
// run once each, in about a second, failing loudly when an input that used to be safe
// stops being.
//
// It runs the SAME code the fuzzer runs. fuzz/FuzzTargets.h holds the bodies and
// fuzz/archive_fuzzer.cpp is four lines of libFuzzer entry point around one of them. A
// replay that re-implemented the harness would be a second harness that resembles the
// first, and the crashing input would be replayed through something that was never
// crashing.
//
// WHAT IT CANNOT DO, so that nobody reads more into a green run than is there:
//
// this binary is built by the ordinary compiler with no sanitizers. It therefore catches
// a crash, a hang and an assertion, and it does NOT catch an out-of-bounds read that
// happens to land on a mapped page - which is most of them, and the reason the campaign
// exists at all. The sanitizer replay is `docker/fuzz/fuzz.sh replay`.

#include "FuzzTargets.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace lyxbosa;

namespace {

namespace fs = std::filesystem;

#ifndef LYXBOSA_FUZZ_DIR
#error "LYXBOSA_FUZZ_DIR must be defined by CMake: the replay has no corpus without it"
#endif

// Where the corpus is read from: the compiled-in path, or $LYXBOSA_FUZZ_DIR when it is
// set.
//
// The override is what makes the two control cases below observable. AGENTS.md is blunt
// about this - a check that has never been seen to say the other thing is not yet a check
// - and the way to watch these fail is to point them at a corpus that has been broken on
// purpose. Without the override that means editing a tracked seed, and a harness that
// mutates tracked files is exactly what AGENTS.md records destroying three rounds of
// uncommitted work. With it the doctored copy lives in a scratch directory and the tree
// is never touched.
//
// It is also how the container replays a minimised corpus, and how a crashing input can
// be replayed before anybody decides it is worth committing.
const fs::path& corpusRoot() {
    static const fs::path root = [] {
        if (const char* override = std::getenv("LYXBOSA_FUZZ_DIR");
            override != nullptr && *override != '\0') {
            return fs::path(override);
        }
        return fs::path(LYXBOSA_FUZZ_DIR);
    }();
    return root;
}

// Every seed, plus every regression a campaign has already produced. Regressions are
// separate from seeds because they are not generated: fuzz/make-seeds.py owns the seeds
// and --check asserts nobody edited one by hand, while a regression is a crashing input
// somebody minimised and committed, and it must never be regenerated away.
std::vector<fs::path> inputsUnder(const std::string& group) {
    std::vector<fs::path> files;
    for (const char* kind : {"seeds", "regressions"}) {
        const fs::path directory = corpusRoot() / kind / group;
        std::error_code ec;
        if (!fs::is_directory(directory, ec)) continue;
        for (const auto& entry : fs::directory_iterator(directory, ec)) {
            if (entry.is_regular_file()) files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());
    return files;
}

std::vector<uint8_t> readFile(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(stream)),
                                 std::istreambuf_iterator<char>());
}

// The smallest corpus this test will accept before it calls itself a pass.
//
// A replay that finds no files runs no inputs, reports no failures, and reads exactly
// like a green run - the same shape as a status check that read a 404 as success. So the
// count is asserted rather than assumed. The numbers are floors well under what
// make-seeds.py writes today, so adding a seed never has to touch them and deleting the
// directory always fails.
constexpr size_t kMinArchiveInputs = 20;
constexpr size_t kMinContentInputs = 10;

}  // namespace

TEST(FuzzReplay, EverySeedArchiveIsHandledWithoutCrashing) {
    const auto files = inputsUnder("archive");
    ASSERT_GE(files.size(), kMinArchiveInputs)
        << "the archive corpus under " << corpusRoot() << " is missing or shrank; "
        << "a replay with no inputs passes silently, so it fails here instead";

    size_t entered = 0;
    for (const auto& file : files) {
        const auto bytes = readFile(file);
        SCOPED_TRACE(file.string());
        const auto seen = fuzz::runArchiveTarget(bytes.data(), bytes.size());
        if (seen.kind != archive::Kind::None) ++entered;
    }

    // Most of the corpus must still be recognised as a container. A seed set that has
    // drifted into bytes sniff() turns away is a corpus that no longer enters the code
    // it was written for, and it would keep passing for ever.
    EXPECT_GE(entered, files.size() / 2)
        << "only " << entered << " of " << files.size()
        << " archive inputs were recognised as containers at all";
}

TEST(FuzzReplay, EverySeedContentIsMatchedWithoutCrashing) {
    const auto files = inputsUnder("content");
    ASSERT_GE(files.size(), kMinContentInputs)
        << "the content corpus under " << corpusRoot() << " is missing or shrank";

    for (const auto& file : files) {
        const auto bytes = readFile(file);
        SCOPED_TRACE(file.string());
        const auto seen = fuzz::runContentTarget(bytes.data(), bytes.size());
        EXPECT_TRUE(seen.handled);
    }
}

// The positive control for the two cases above.
//
// They assert that nothing crashed, and "nothing crashed" is also what a harness that
// does nothing at all reports. These assert that the harness reaches through libzip, into
// a member, through the rule engine and back out with a finding - so a runArchiveTarget
// stubbed to `return {}`, a rule set that failed to load, or a member limit that
// accidentally rejects everything fails here rather than passing quietly.
TEST(FuzzReplay, TheHarnessActuallyReachesTheScanner) {
    const auto shell = readFile(corpusRoot() / "seeds/archive/zip-webshell.zip");
    ASSERT_FALSE(shell.empty());

    const auto seen = fuzz::runArchiveTarget(shell.data(), shell.size());
    EXPECT_EQ(seen.kind, archive::Kind::Zip);
    EXPECT_TRUE(seen.handled);
    EXPECT_EQ(seen.membersScanned, 1u) << "the member was never opened";
    EXPECT_GT(seen.findings, 0u) << "the rule engine never ran over the member's bytes";
}

TEST(FuzzReplay, TheContentHarnessActuallyReachesTheRules) {
    const auto assembled =
        readFile(corpusRoot() / "seeds/content/php-assembled.php");
    ASSERT_FALSE(assembled.empty());

    const auto seen = fuzz::runContentTarget(assembled.data(), assembled.size());
    EXPECT_TRUE(seen.handled);
    EXPECT_GT(seen.findings, 0u)
        << "an assembled base64_decode produced no finding: the rule set did not load";
}

// Empty and one-byte inputs, which every fuzzer produces in its first second and which a
// harness is most likely to mishandle at the boundary.
TEST(FuzzReplay, DegenerateInputsAreRefusedNotParsed) {
    EXPECT_EQ(fuzz::runArchiveTarget(nullptr, 0).kind, archive::Kind::None);
    EXPECT_EQ(fuzz::runContentTarget(nullptr, 0).findings, 0u);

    for (int byte = 0; byte < 256; ++byte) {
        const uint8_t one = static_cast<uint8_t>(byte);
        EXPECT_EQ(fuzz::runArchiveTarget(&one, 1).kind, archive::Kind::None);
        EXPECT_TRUE(fuzz::runContentTarget(&one, 1).handled);
    }
}
