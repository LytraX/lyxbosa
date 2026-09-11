// What FileWalker::walkDirectory promises, and the depth it now survives.
//
// THE DEFECT THESE CASES EXIST FOR
// --------------------------------
// walkDirectory() descended by calling itself, once per directory level, so the cost of
// a tree's depth was paid in C++ call frames. Directory depth is attacker-controlled - a
// mkdir loop is three lines of shell - which makes a stack overflow in a scanner a denial
// of service on the tool somebody is running to investigate an incident.
//
// It was not only theoretical. Scanner::scan() runs a second walk on a spawned thread to
// pre-count files, and a spawned thread's stack is 8 MB under glibc but 128 KB under musl,
// so the same tree that the glibc build walked could take the static musl build's counting
// thread off the end of its stack. The walk is now an explicit stack of directories, which
// removes the ceiling rather than raising it: on both C libraries, on any thread, and on
// Windows.
//
// WHAT THE DEPTH CASE CAN AND CANNOT OBSERVE
// ------------------------------------------
// Depth alone cannot observe it here. The test binary is a glibc build whose main thread
// has 8 MB, and the filesystem caps an absolute path long before 8 MB of frames run out -
// PATH_MAX is 4096 bytes, so two-byte components stop a real tree at roughly two thousand
// levels. A case that merely built a deep tree and walked it on the main thread would pass
// against the recursive version and observe nothing.
//
// So the case supplies the other half itself: it walks the tree on a thread whose stack is
// 128 KiB, which is exactly what musl gives a thread, and which no amount of PATH_MAX
// headroom can enlarge. kDepth levels of the old walk did not fit in that and do not fit
// now; kDepth levels of the new one cost one frame.
//
// And because a case that has never been observed to fail is not yet a case, its companion
// - TheSmallStackIsTooSmallToRecurseOnAtThisDepth - asserts the other thing: that a walk
// shaped like the old one, recursing kDepth times with frames no larger than the old walk's
// measured frame, dies on that same thread. Without it, a 128 KiB stack that had
// quietly become a 128 MiB one would leave the depth case passing while blind.

#include <gtest/gtest.h>

#include "config/Config.h"
#include "core/FileWalker.h"

#include "PlatformSkips.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <vector>

#ifndef _WIN32
#include <pthread.h>
#endif

using namespace lyxbosa;

namespace {

namespace fs = std::filesystem;

// A temporary tree that cleans itself up without recursing either. fs::remove_all walks
// with recursive_directory_iterator, which holds an open directory handle per level, and
// a fixture that cannot delete its own deep tree would leave one behind on every run.
class TempTree {
public:
    TempTree() {
        path_ = fs::temp_directory_path() /
                ("lyxbosa-walk-test-" + std::to_string(test::getpid_portable()) + "-" +
                 std::to_string(counter_++));
        fs::create_directories(path_);
    }
    ~TempTree() {
        std::error_code ec;
        // Permissions first: a case that made a directory unreadable cannot delete it
        // until the bits go back.
        for (const auto& locked : locked_) {
            fs::permissions(locked, fs::perms::owner_all, fs::perm_options::add, ec);
        }
        // Deepest first, by path length, so every directory is empty when it is removed.
        std::vector<fs::path> all;
        collect(path_, all);
        std::sort(all.begin(), all.end(), [](const fs::path& a, const fs::path& b) {
            return a.native().size() > b.native().size();
        });
        for (const auto& p : all) {
            fs::remove(p, ec);
        }
        fs::remove(path_, ec);
    }

    const fs::path& path() const { return path_; }

    // A chain of `levels` single-character directories with one file at the bottom.
    // Single characters because PATH_MAX, not the walk, is what stops this.
    fs::path chain(size_t levels, std::string_view leafContent) {
        fs::path dir = path_;
        for (size_t i = 0; i < levels; ++i) {
            dir /= "d";
            std::error_code ec;
            fs::create_directory(dir, ec);
            if (ec) {
                return {};  // the caller asserts on this
            }
        }
        write(dir / "page.php", leafContent);
        return dir;
    }

    void write(const fs::path& file, std::string_view content) {
        std::error_code ec;
        fs::create_directories(file.parent_path(), ec);
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

    // Remembered so the destructor can put the bits back before deleting.
    void lock(const fs::path& dir) {
        locked_.push_back(dir);
        fs::permissions(dir, fs::perms::none);
    }

private:
    static void collect(const fs::path& dir, std::vector<fs::path>& out) {
        std::error_code ec;
        // An iterative sweep for the same reason the walk is one.
        std::vector<fs::path> pending{dir};
        while (!pending.empty()) {
            const fs::path current = std::move(pending.back());
            pending.pop_back();
            for (const auto& entry : fs::directory_iterator(current, ec)) {
                out.push_back(entry.path());
                if (entry.is_directory(ec) && !entry.is_symlink(ec)) {
                    pending.push_back(entry.path());
                }
            }
        }
    }

    fs::path path_;
    std::vector<fs::path> locked_;
    static inline int counter_ = 0;
};

ScanConfig configFor(const fs::path& root) {
    AppConfig config = Config::loadFromString(Config::generateDefault());
    config.scan.directories = {root.string()};
    config.scan.recursive = true;
    return config.scan;
}

// Everything one walk saw, so a case can assert about any of it without repeating the
// callback four times.
struct Walked {
    size_t directories = 0;
    size_t unreadable = 0;
    bool stopped = false;
    std::vector<fs::path> files;

    bool sawFilename(std::string_view name) const {
        return std::any_of(files.begin(), files.end(), [name](const fs::path& p) {
            return p.filename() == name;
        });
    }
};

Walked walkOf(const ScanConfig& scan, const fs::path& root, size_t stopAfter = 0) {
    Walked out;
    const FileWalker walker(scan);
    out.directories = walker.walkDirectory(
        root,
        [&out, stopAfter](const FileInfo& info) {
            out.files.push_back(info.path);
            return stopAfter == 0 || out.files.size() < stopAfter;
        },
        out.stopped, &out.unreadable);
    return out;
}

// Matches rule RCE004 - irrelevant to the walk, which never reads a file, but it keeps
// the fixtures identical to the ones the scanner cases use.
constexpr std::string_view kFinding = "<?php eval($_POST[\"x\"]); ?>\n";

#ifndef _WIN32

// Exactly what musl gives a thread it was not told a size for. The number is the whole
// point of these two cases: it is not a margin chosen to make them pass.
constexpr size_t kMuslThreadStack = 128 * 1024;

// Deep enough that kDepth frames of the old walk cannot fit in kMuslThreadStack, and
// shallow enough that the absolute path stays far inside PATH_MAX: the fixture's path
// is roughly 50 bytes and each level adds two, so this lands near 1,850 of 4,096.
constexpr size_t kDepth = 900;

void* runOnSmallStack(void* work) {
    (*static_cast<std::function<void()>*>(work))();
    return nullptr;
}

// Run `work` on a thread with musl's default stack size. Returns false when the host
// refused the thread, which is a reason to skip rather than a result.
bool onAMuslSizedStack(std::function<void()> work, std::string& why) {
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        why = "pthread_attr_init failed";
        return false;
    }
    if (pthread_attr_setstacksize(&attr, kMuslThreadStack) != 0) {
        pthread_attr_destroy(&attr);
        why = "this host would not accept a " + std::to_string(kMuslThreadStack) +
              "-byte thread stack, so the musl condition cannot be reproduced";
        return false;
    }
    pthread_t thread{};
    const int created = pthread_create(&thread, &attr, runOnSmallStack, &work);
    pthread_attr_destroy(&attr);
    if (created != 0) {
        why = "pthread_create failed";
        return false;
    }
    pthread_join(thread, nullptr);
    return true;
}

// The smallest frame the old walkDirectory was measured to use: 0xf0 bytes in a debug
// build, 0x198 in a release one. A recursion that runs out of stack at this size would
// certainly have run out at the real one.
constexpr size_t kOldFrameBytes = 240;

static_assert(kDepth * kOldFrameBytes > kMuslThreadStack,
              "the depth case is asking for fewer frames than the small stack holds, so "
              "it would pass against the recursive walk and observe nothing");

// A stand-in for the walk that was here before: it calls itself once per level and
// carries a frame that has to still be there when the call returns.
//
// That last part is the whole difficulty, and getting it wrong is how this case first
// failed. Written as `return frame[n] + recurse(level - 1)` the frame is dead at the
// call, GCC's tail-recursion pass rewrites the function into an accumulator loop, and
// the probe then reports that 900 frames fit in 128 KiB - which is true of a loop and
// says nothing about a recursion. The debug build kept the recursion and the case
// passed; the release build did not and it failed, under musl, where the whole point of
// the case lies. So the frame is read again AFTER the call, with a barrier that stops
// the compiler reasoning about it, and the call is not the last thing the function does.
__attribute__((noinline)) size_t recurseLikeTheOldWalk(size_t level) {
    volatile char frame[kOldFrameBytes];
    frame[0] = static_cast<char>(level & 0xff);
    if (level == 0) {
        return static_cast<size_t>(frame[0]);
    }
    const size_t deeper = recurseLikeTheOldWalk(level - 1);
    __asm__ volatile("" : : "r"(&frame[0]) : "memory");
    return deeper + static_cast<size_t>(frame[0]);
}

#endif  // !_WIN32

}  // namespace

// ===========================================================================
// Depth, and the companion that gives the depth case its teeth
// ===========================================================================

#ifndef _WIN32

TEST(FileWalkerDepthTest, ADeepTreeIsWalkedOnAStackTooSmallToRecurseOnIt) {
    TempTree tree;
    const fs::path leaf = tree.chain(kDepth, kFinding);
    ASSERT_FALSE(leaf.empty())
        << "the fixture could not create " << kDepth << " levels, so nothing is observed";
    ASSERT_LT(leaf.native().size(), 4000u)
        << "the fixture is " << leaf.native().size() << " bytes and PATH_MAX is 4096; "
        << "this case would be measuring the filesystem rather than the walk";

    Walked seen;
    std::string why;
    const bool ran = onAMuslSizedStack(
        [&] { seen = walkOf(configFor(tree.path()), tree.path()); }, why);
    if (!ran) {
        GTEST_SKIP() << why;
    }

    EXPECT_EQ(seen.directories, kDepth + 1)
        << "every level of the chain is entered, the root included";
    EXPECT_EQ(seen.unreadable, 0u);
    EXPECT_FALSE(seen.stopped);
    EXPECT_TRUE(seen.sawFilename("page.php"))
        << "the walk reached the bottom of a " << kDepth << "-level tree";
}

// The companion. Without it the case above would pass on a thread whose stack had
// quietly become large enough to recurse on, and would be observing nothing.
TEST(FileWalkerDepthTest, TheSmallStackIsTooSmallToRecurseOnAtThisDepth) {
    std::string why;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) == 0) {
        if (pthread_attr_setstacksize(&attr, kMuslThreadStack) != 0) {
            pthread_attr_destroy(&attr);
            GTEST_SKIP() << "this host would not accept a " << kMuslThreadStack
                         << "-byte thread stack";
        }
        pthread_attr_destroy(&attr);
    }

    // The recursion runs in a forked child, because what it does is overflow a stack and
    // that is not survivable in this process.
    EXPECT_DEATH(
        {
            std::string ignored;
            onAMuslSizedStack([] { (void)recurseLikeTheOldWalk(kDepth); }, ignored);
            std::_Exit(0);
        },
        "")
        << kDepth << " frames of " << kOldFrameBytes << " bytes fitted in a "
        << kMuslThreadStack << "-byte stack, so the depth case above is not observing "
        << "what it claims to - most likely the compiler turned the probe into a loop";
}

#endif  // !_WIN32

// ===========================================================================
// What the walk counts
// ===========================================================================

TEST(FileWalkerTest, TheDirectoryCountIsEveryDirectoryEntered) {
    TempTree tree;
    tree.write(tree.path() / "a" / "page.php", kFinding);
    tree.write(tree.path() / "a" / "b" / "page.php", kFinding);
    tree.write(tree.path() / "c" / "page.php", kFinding);
    tree.write(tree.path() / "top.php", kFinding);

    const Walked seen = walkOf(configFor(tree.path()), tree.path());

    EXPECT_EQ(seen.directories, 4u) << "the root, a, a/b and c";
    EXPECT_EQ(seen.files.size(), 4u);
    EXPECT_EQ(seen.unreadable, 0u);
}

TEST(FileWalkerTest, ANonRecursiveWalkEntersOnlyTheRoot) {
    TempTree tree;
    tree.write(tree.path() / "top.php", kFinding);
    tree.write(tree.path() / "a" / "page.php", kFinding);

    ScanConfig scan = configFor(tree.path());
    scan.recursive = false;
    const Walked seen = walkOf(scan, tree.path());

    EXPECT_EQ(seen.directories, 1u);
    EXPECT_EQ(seen.files.size(), 1u);
    EXPECT_TRUE(seen.sawFilename("top.php"));
}

// ===========================================================================
// The stop flag
// ===========================================================================

TEST(FileWalkerTest, AFalseCallbackStopsTheWalkAndSetsTheFlag) {
    TempTree tree;
    // Four subtrees, so a walk that only stopped descending would still be caught by
    // the file count.
    for (const char* name : {"a", "b", "c", "d"}) {
        tree.write(tree.path() / name / "one.php", kFinding);
        tree.write(tree.path() / name / "deeper" / "two.php", kFinding);
    }

    const Walked seen = walkOf(configFor(tree.path()), tree.path(), /*stopAfter=*/1);

    EXPECT_TRUE(seen.stopped);
    EXPECT_EQ(seen.files.size(), 1u)
        << "the walk went on calling back after the callback said to stop";
}

// The companion, so the case above could not pass against a walk that stopped on its own
// after one file whatever the callback said.
TEST(FileWalkerTest, ACallbackThatNeverRefusesSeesEveryFile) {
    TempTree tree;
    for (const char* name : {"a", "b", "c", "d"}) {
        tree.write(tree.path() / name / "one.php", kFinding);
        tree.write(tree.path() / name / "deeper" / "two.php", kFinding);
    }

    const Walked seen = walkOf(configFor(tree.path()), tree.path());

    EXPECT_FALSE(seen.stopped);
    EXPECT_EQ(seen.files.size(), 8u);
    EXPECT_EQ(seen.directories, 9u) << "the root, four subtrees and their four deeper";
}

// ===========================================================================
// The unreadable-directory count
// ===========================================================================

TEST(FileWalkerTest, AnUnreadableSubdirectoryIsCountedAndTheWalkContinues) {
    if (const auto why = test::whyCannotDenyOwnAccess()) {
        GTEST_SKIP() << *why << " - a mode-000 directory would still be read";
    }

    TempTree tree;
    tree.write(tree.path() / "readable" / "page.php", kFinding);
    tree.write(tree.path() / "locked" / "hidden.php", kFinding);
    tree.lock(tree.path() / "locked");

    const Walked seen = walkOf(configFor(tree.path()), tree.path());

    EXPECT_EQ(seen.unreadable, 1u);
    EXPECT_TRUE(seen.sawFilename("page.php"))
        << "one directory the host refused ended the walk of its siblings";
    EXPECT_FALSE(seen.sawFilename("hidden.php"));
    EXPECT_EQ(seen.directories, 3u)
        << "a directory that was entered and could not be listed was still entered";
}

// A subdirectory that is gone is a race and not a refusal, and the two must not be
// reported as the same thing. Removed from inside the callback, which the walk's order
// makes deterministic: every file of a directory is reported before any of its
// subdirectories is entered.
TEST(FileWalkerTest, ASubdirectoryThatVanishesMidWalkIsQuiet) {
    TempTree tree;
    tree.write(tree.path() / "trigger.php", kFinding);
    fs::create_directories(tree.path() / "doomed");

    Walked seen;
    const FileWalker walker(configFor(tree.path()));
    seen.directories = walker.walkDirectory(
        tree.path(),
        [&](const FileInfo& info) {
            seen.files.push_back(info.path);
            std::error_code ec;
            fs::remove(tree.path() / "doomed", ec);
            return true;
        },
        seen.stopped, &seen.unreadable);

    EXPECT_EQ(seen.unreadable, 0u)
        << "a subdirectory that disappeared under a running scan is not a coverage gap";
    EXPECT_EQ(seen.directories, 1u) << "only the root was entered";
    EXPECT_FALSE(seen.stopped);
}

// ===========================================================================
// Symlinks, under both settings
// ===========================================================================

TEST(FileWalkerSymlinkTest, ALinkedDirectoryIsNotDescendedByDefault) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }

    TempTree tree;
    tree.write(tree.path() / "real" / "target.php", kFinding);
    tree.write(tree.path() / "tree" / "own.php", kFinding);
    std::error_code ec;
    fs::create_directory_symlink(tree.path() / "real", tree.path() / "tree" / "link", ec);
    ASSERT_FALSE(ec) << ec.message();

    const Walked seen = walkOf(configFor(tree.path() / "tree"), tree.path() / "tree");

    EXPECT_EQ(seen.directories, 1u) << "the link was followed with followSymlinks off";
    EXPECT_TRUE(seen.sawFilename("own.php"));
    EXPECT_FALSE(seen.sawFilename("target.php"));
}

TEST(FileWalkerSymlinkTest, ALinkedDirectoryIsDescendedWhenFollowSymlinksIsSet) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }

    TempTree tree;
    tree.write(tree.path() / "real" / "target.php", kFinding);
    tree.write(tree.path() / "tree" / "own.php", kFinding);
    std::error_code ec;
    fs::create_directory_symlink(tree.path() / "real", tree.path() / "tree" / "link", ec);
    ASSERT_FALSE(ec) << ec.message();

    ScanConfig scan = configFor(tree.path() / "tree");
    scan.followSymlinks = true;
    const Walked seen = walkOf(scan, tree.path() / "tree");

    EXPECT_EQ(seen.directories, 2u) << "the linked directory was entered";
    EXPECT_TRUE(seen.sawFilename("own.php"));
    EXPECT_TRUE(seen.sawFilename("target.php"));
}

TEST(FileWalkerSymlinkTest, ALinkedFileIsReportedOnlyWhenFollowSymlinksIsSet) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }

    TempTree tree;
    tree.write(tree.path() / "real.php", kFinding);
    fs::create_directories(tree.path() / "tree");
    std::error_code ec;
    fs::create_symlink(tree.path() / "real.php", tree.path() / "tree" / "link.php", ec);
    ASSERT_FALSE(ec) << ec.message();

    const Walked without = walkOf(configFor(tree.path() / "tree"), tree.path() / "tree");
    EXPECT_FALSE(without.sawFilename("link.php"));

    ScanConfig scan = configFor(tree.path() / "tree");
    scan.followSymlinks = true;
    const Walked with = walkOf(scan, tree.path() / "tree");
    ASSERT_TRUE(with.sawFilename("link.php"));
    ASSERT_EQ(with.files.size(), 1u);
    EXPECT_TRUE(with.files[0].filename() == "link.php");
}

// ===========================================================================
// The order the walk now promises
// ===========================================================================

// Pinned because it is a contract the header states, not because anything downstream
// reads it: the scanner accumulates counts and appends findings, the reporters iterate
// whatever they are given, and no other case asserts a sequence.
TEST(FileWalkerTest, EveryFileOfADirectoryIsReportedBeforeAnySubdirectoryIsEntered) {
    TempTree tree;
    for (const char* name : {"one.php", "two.php", "three.php"}) {
        tree.write(tree.path() / name, kFinding);
    }
    tree.write(tree.path() / "sub" / "deep.php", kFinding);

    const Walked seen = walkOf(configFor(tree.path()), tree.path());

    ASSERT_EQ(seen.files.size(), 4u);
    EXPECT_EQ(seen.files.back().filename(), "deep.php")
        << "the subdirectory was entered before the root's own files were reported";
}
