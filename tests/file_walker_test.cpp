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
#include "core/Interrupt.h"

#include "PlatformSkips.h"

#include <algorithm>
#include <cstdio>
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

// ===========================================================================
// Loops, cancellation, and the fixtures that let a case about them fail
// ===========================================================================

// The interrupt flag is process-global and the cases below set it deliberately, so every
// one of them puts it back. Running the test binary directly runs every case in one
// process, where a leaked flag would stop the next walk before it entered anything - and
// that walk would then pass its assertions for entirely the wrong reason.
struct InterruptGuard {
    InterruptGuard() { g_interrupted.store(false, std::memory_order_relaxed); }
    ~InterruptGuard() { g_interrupted.store(false, std::memory_order_relaxed); }
    InterruptGuard(const InterruptGuard&) = delete;
    InterruptGuard& operator=(const InterruptGuard&) = delete;
};

struct BoundedWalk {
    size_t directories = 0;   // entered, as walkDirectory counted them
    size_t cycleSkipped = 0;  // refused because entering would have closed a loop
    size_t files = 0;
    bool stopped = false;
    bool boundHit = false;
};

// A walk that cannot run away, and the reason the bound is shaped like this.
//
// A case about a loop is a case that, against the walk before this repair, does not
// fail - it runs until somebody kills it, and a suite that hangs is worse than one that
// is missing. So the bound is counted in directories rather than in seconds: it is
// deterministic on a loaded machine, it is four orders of magnitude below the 2.2e12
// directories the unfixed walk produced on the fixture below, and it turns "runs
// forever" into one failed expectation.
//
// It is enforced through the interrupt flag, which is the other half of this repair, and
// that dependency is worth naming rather than hiding: the cancellation fix is what lets
// a loop case fail instead of hang.
BoundedWalk boundedWalk(const ScanConfig& scan, const fs::path& root, size_t bound) {
    InterruptGuard guard;
    BoundedWalk out;
    FileWalker walker(scan);

    size_t entered = 0;
    walker.setDirectoryCallback([&](const fs::path&) {
        if (++entered >= bound) {
            out.boundHit = true;
            g_interrupted.store(true, std::memory_order_relaxed);
        }
    });

    out.directories = walker.walkDirectory(
        root, [&out](const FileInfo&) { ++out.files; return true; }, out.stopped,
        /*unreadableDirs=*/nullptr, &out.cycleSkipped);
    return out;
}

// The same bound around the counting traversal, which is a second full walk on a
// spawned thread and was asked for by name in the review.
struct BoundedCount {
    CountResult result;
    size_t entered = 0;
    bool boundHit = false;
};

BoundedCount boundedCount(const ScanConfig& scan, size_t bound) {
    InterruptGuard guard;
    BoundedCount out;
    FileWalker walker(scan);
    walker.setDirectoryCallback([&](const fs::path&) {
        if (++out.entered >= bound) {
            out.boundHit = true;
            g_interrupted.store(true, std::memory_order_relaxed);
        }
    });
    out.result = walker.countFiles();
    return out;
}

// Walks `root` and raises the interrupt from the directory callback once `atDirectory`
// directories have been entered. Zero never raises it, which is how each case below gets
// its companion: the same fixture, the same helper, and the other answer.
struct InterruptedWalk {
    size_t directories = 0;
    size_t entered = 0;
    size_t files = 0;
    bool stopped = false;
};

InterruptedWalk walkInterruptingAt(const ScanConfig& scan, const fs::path& root,
                                   size_t atDirectory) {
    InterruptGuard guard;
    InterruptedWalk out;
    FileWalker walker(scan);
    walker.setDirectoryCallback([&](const fs::path&) {
        if (atDirectory != 0 && ++out.entered == atDirectory) {
            g_interrupted.store(true, std::memory_order_relaxed);
        } else if (atDirectory == 0) {
            ++out.entered;
        }
    });
    out.directories = walker.walkDirectory(
        root,
        // Deliberately never refuses. These cases are about the walk noticing the flag
        // itself; a callback that stopped the walk would be the old mechanism answering
        // and the case would observe nothing new.
        [&out](const FileInfo&) { ++out.files; return true; }, out.stopped);
    return out;
}

// `count` sibling directories under `root`, holding no regular file anywhere - the tree
// the old walk could not be stopped in, because it reached no file callback.
void makeDirectoryOnlyTree(const fs::path& root, size_t count) {
    fs::create_directories(root);
    for (size_t i = 0; i < count; ++i) {
        char name[16];
        std::snprintf(name, sizeof(name), "d%03zu", i);
        fs::create_directory(root / name);
    }
}

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

// ===========================================================================
// Loops: a directory the walk will not re-enter
// ===========================================================================
//
// THE DEFECT THESE CASES EXIST FOR
// --------------------------------
// With follow_symlinks on, a linked directory was queued with no question asked about
// which directory it actually was, so a link pointing back up the path the walk was
// already on queued that path again. The reproduction in the review is a directory
// holding two symlinks to `.`: measured here before the repair, the walk entered 33,120
// directories a second and would have entered 2^41 of them - two years and a month of
// walking - because the kernel stops symlink resolution at 40 links and every one of
// those 2.2e12 paths is distinct and finite. Memory was not the symptom and looking for
// it there would have missed this: a depth-first stack over a binary tree 41 deep holds
// 41 paths, and the resident set moved by 24 KB across eight seconds of it.
//
// WHY EVERY CASE HERE HAS A COMPANION
// -----------------------------------
// Refusing every symlinked directory would satisfy every assertion that a loop is now
// refused, and would quietly halve what an operator who asked for follow_symlinks gets.
// So each refusal is paired with a link that closes no loop and is still entered, and
// with the default configuration, where nothing is refused because nothing was queued.

TEST(FileWalkerCycleTest, TwoLinksToTheWalkedDirectoryAreRefusedAndTheWalkEnds) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }

    // The review's reproduction, exactly: one directory, two links to itself.
    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(root / "own.php", kFinding);
    std::error_code ec;
    fs::create_directory_symlink(".", root / "a", ec);
    ASSERT_FALSE(ec) << ec.message();
    fs::create_directory_symlink(".", root / "b", ec);
    ASSERT_FALSE(ec) << ec.message();

    ScanConfig scan = configFor(root);
    scan.followSymlinks = true;
    const BoundedWalk seen = boundedWalk(scan, root, /*bound=*/1000);

    EXPECT_FALSE(seen.boundHit)
        << "the walk was still entering directories after 1000 of them in a tree that "
           "holds one, so the loop was followed rather than refused";
    EXPECT_EQ(seen.directories, 1u);
    EXPECT_EQ(seen.cycleSkipped, 2u) << "both links back to the walked directory";
    EXPECT_EQ(seen.files, 1u) << "the one real file, read once";
}

// The chain and not just the self-link: the loop closes on a grandparent here, which a
// check that only compared a directory against its immediate parent would miss.
TEST(FileWalkerCycleTest, ALinkBackToAGrandparentIsRefusedToo) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }

    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(root / "one" / "two" / "deep.php", kFinding);
    std::error_code ec;
    fs::create_directory_symlink(root, root / "one" / "two" / "up", ec);
    ASSERT_FALSE(ec) << ec.message();

    ScanConfig scan = configFor(root);
    scan.followSymlinks = true;
    const BoundedWalk seen = boundedWalk(scan, root, /*bound=*/1000);

    EXPECT_FALSE(seen.boundHit) << "the link to the root was followed";
    EXPECT_EQ(seen.directories, 3u) << "tree, one and two";
    EXPECT_EQ(seen.cycleSkipped, 1u);
    EXPECT_EQ(seen.files, 1u);
}

// The companion for both cases above. Without it, a walk that had learned to refuse
// every symlinked directory would pass them and cover half of what it was asked to.
TEST(FileWalkerCycleTest, ALinkedDirectoryThatClosesNoLoopIsStillEntered) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }

    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(root / "own.php", kFinding);
    tree.write(tree.path() / "real" / "target.php", kFinding);
    std::error_code ec;
    fs::create_directory_symlink(tree.path() / "real", root / "link", ec);
    ASSERT_FALSE(ec) << ec.message();

    ScanConfig scan = configFor(root);
    scan.followSymlinks = true;
    const BoundedWalk seen = boundedWalk(scan, root, /*bound=*/1000);

    EXPECT_FALSE(seen.boundHit);
    EXPECT_EQ(seen.directories, 2u) << "the linked directory is not a loop and is walked";
    EXPECT_EQ(seen.cycleSkipped, 0u) << "nothing here leads back into the path being walked";
    EXPECT_EQ(seen.files, 2u);
}

// The default configuration over the same fixture. Nothing is queued, so nothing is
// refused, and the count must say zero rather than inheriting the case above it.
TEST(FileWalkerCycleTest, NothingIsRefusedAsALoopWhenLinksAreNotFollowed) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }

    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(root / "own.php", kFinding);
    std::error_code ec;
    fs::create_directory_symlink(".", root / "a", ec);
    ASSERT_FALSE(ec) << ec.message();

    const BoundedWalk seen = boundedWalk(configFor(root), root, /*bound=*/1000);

    EXPECT_FALSE(seen.boundHit);
    EXPECT_EQ(seen.directories, 1u);
    EXPECT_EQ(seen.cycleSkipped, 0u)
        << "the link was never a candidate, so refusing it is not a fact about this scan";
}

// The counting traversal, by name, because the review asked for it and because it is the
// walk that runs on a spawned thread where nothing about it reaches the terminal.
TEST(FileWalkerCycleTest, TheCountingTraversalRefusesTheSameLoop) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }

    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(root / "own.php", kFinding);
    std::error_code ec;
    fs::create_directory_symlink(".", root / "a", ec);
    ASSERT_FALSE(ec) << ec.message();
    fs::create_directory_symlink(".", root / "b", ec);
    ASSERT_FALSE(ec) << ec.message();

    ScanConfig scan = configFor(root);
    scan.followSymlinks = true;
    const BoundedCount counted = boundedCount(scan, /*bound=*/1000);

    EXPECT_FALSE(counted.boundHit) << "countFiles() followed the loop";
    EXPECT_EQ(counted.entered, 1u);
    EXPECT_EQ(counted.result.files, 1u) << "counted once, not once per path to it";
}

// ===========================================================================
// Cancellation: a walk that can be stopped without a file in the tree
// ===========================================================================
//
// THE DEFECT THESE CASES EXIST FOR
// --------------------------------
// The only thing that set the walk's stop flag was the file callback returning false.
// The callback is reached by a regular file, so a tree holding only directories reached
// it never and the walk could not be stopped at all - measured before the repair: a
// scan of 200,400 directories with no symlink and no file in them ignored SIGINT for
// ten seconds and had to be killed, and a single-root run of the same tree "honoured"
// the signal 1.22 seconds later only because the walk had finished by then, exiting 0
// and reporting a clean completed scan.
//
// Nothing about that needs a symlink, which is why it is a separate repair with its own
// fixtures: the same tree with a ten-million-entry directory in it is the other half,
// and a check made only between directories would not answer it.

TEST(FileWalkerInterruptTest, AnInterruptStopsAWalkOfATreeWithNoFileInIt) {
    TempTree tree;
    const fs::path root = tree.path() / "tree";
    makeDirectoryOnlyTree(root, 60);

    const InterruptedWalk seen = walkInterruptingAt(configFor(root), root, /*atDirectory=*/5);

    EXPECT_TRUE(seen.stopped) << "the walk ran to the end of a tree it was told to leave";
    EXPECT_LE(seen.directories, 6u)
        << "the interrupt was raised after 5 directories and the walk entered "
        << seen.directories << " of the 61 in this tree";
    EXPECT_EQ(seen.files, 0u) << "there is no file here to have stopped it";
}

// The per-entry half. The flag goes up as the one directory is entered, before any of
// its entries has been read, and the observable is how many files the callback was
// handed: none, if the walk checks between entries, and all fifty if it only checks
// between directories. The callback never refuses, so it is not what stopped anything.
TEST(FileWalkerInterruptTest, AnInterruptIsNoticedWhileOneDirectoryIsBeingRead) {
    TempTree tree;
    const fs::path root = tree.path() / "tree";
    for (int i = 0; i < 50; ++i) {
        tree.write(root / ("page" + std::to_string(i) + ".php"), kFinding);
    }

    const InterruptedWalk seen = walkInterruptingAt(configFor(root), root, /*atDirectory=*/1);

    EXPECT_TRUE(seen.stopped);
    EXPECT_EQ(seen.files, 0u)
        << "the walk read " << seen.files
        << " entries of a directory it had already been told to stop reading";
}

TEST(FileWalkerInterruptTest, TheCountingTraversalStopsOnAnInterruptToo) {
    TempTree tree;
    const fs::path root = tree.path() / "tree";
    makeDirectoryOnlyTree(root, 60);

    InterruptGuard guard;
    FileWalker walker(configFor(root));
    size_t entered = 0;
    walker.setDirectoryCallback([&entered](const fs::path&) {
        if (++entered == 5) {
            g_interrupted.store(true, std::memory_order_relaxed);
        }
    });
    walker.countFiles();

    EXPECT_LE(entered, 6u) << "countFiles() entered " << entered
                           << " directories after being told to stop at 5";
}

// The companions. Without these three, every case above would pass against a walk that
// had learned to stop after five directories whatever the flag said - which is the same
// coverage loss as the loop cases' companion, reached from the other side.
TEST(FileWalkerInterruptTest, AWalkThatIsNotInterruptedEntersEveryDirectory) {
    TempTree tree;
    const fs::path root = tree.path() / "tree";
    makeDirectoryOnlyTree(root, 60);

    const InterruptedWalk seen = walkInterruptingAt(configFor(root), root, /*atDirectory=*/0);

    EXPECT_FALSE(seen.stopped);
    EXPECT_EQ(seen.directories, 61u) << "the root and its 60 subdirectories";
}

TEST(FileWalkerInterruptTest, AWalkThatIsNotInterruptedReadsEveryEntryOfADirectory) {
    TempTree tree;
    const fs::path root = tree.path() / "tree";
    for (int i = 0; i < 50; ++i) {
        tree.write(root / ("page" + std::to_string(i) + ".php"), kFinding);
    }

    const InterruptedWalk seen = walkInterruptingAt(configFor(root), root, /*atDirectory=*/0);

    EXPECT_FALSE(seen.stopped);
    EXPECT_EQ(seen.files, 50u);
}

TEST(FileWalkerInterruptTest, ACountThatIsNotInterruptedCountsEveryFile) {
    TempTree tree;
    const fs::path root = tree.path() / "tree";
    makeDirectoryOnlyTree(root, 10);
    for (int i = 0; i < 10; ++i) {
        tree.write(root / ("d00" + std::to_string(i)) / "page.php", kFinding);
    }

    const BoundedCount counted = boundedCount(configFor(root), /*bound=*/1000);

    EXPECT_FALSE(counted.boundHit);
    EXPECT_EQ(counted.entered, 11u);
    EXPECT_EQ(counted.result.files, 10u);
}
