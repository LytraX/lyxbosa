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

#ifndef _WIN32
#include <fnmatch.h>
#endif

#include "PlatformSkips.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <utility>
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

    // Listable and not searchable: the names in `dir` can be read, and nothing can be asked
    // of the paths they name.
    void forbidSearch(const fs::path& dir) {
        locked_.push_back(dir);
        fs::permissions(dir, fs::perms::owner_read);
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
                // Only what is a directory in itself. The question the walk used to ask -
                // a directory, and not is_symlink() - is true of a junction on Windows, so
                // this sweep descended one: a junction to its own parent never ended, and a
                // volume mount point would have handed every file on the volume to the
                // remove() below. symlink_status() calls both of them something else.
                if (entry.symlink_status(ec).type() == fs::file_type::directory) {
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
    size_t linksNotFollowed = 0;
    size_t unreadableEntries = 0;  // entries whose type the host would not give
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
        out.stopped, &out.unreadable, /*cycleSkippedDirs=*/nullptr, &out.linksNotFollowed,
        &out.unreadableEntries);
    return out;
}

// Matches rule RCE004 - irrelevant to the walk, which never reads a file, but it keeps
// the fixtures identical to the ones the scanner cases use.
constexpr std::string_view kFinding = "<?php eval($_POST[\"x\"]); ?>\n";

// For the cases about links, which assert what the walk reached and never what a rule
// found. Harmless on purpose: resident antivirus takes a file holding kFinding out of a
// temporary directory between writing it and walking it, and a file taken there would
// read as a link the walk did not go through.
constexpr std::string_view kHarmless = "<?php echo 1; ?>\n";

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
    size_t directories = 0;       // entered, as walkDirectory counted them
    size_t cycleSkipped = 0;      // refused because entering would have closed a loop
    size_t linksNotFollowed = 0;  // refused because followSymlinks is off
    size_t files = 0;
    std::vector<fs::path> entered;  // in the order the walk entered them
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

    walker.setDirectoryCallback([&](const fs::path& dir) {
        out.entered.push_back(dir);
        if (out.entered.size() >= bound) {
            out.boundHit = true;
            g_interrupted.store(true, std::memory_order_relaxed);
        }
    });

    out.directories = walker.walkDirectory(
        root, [&out](const FileInfo&) { ++out.files; return true; }, out.stopped,
        /*unreadableDirs=*/nullptr, &out.cycleSkipped, &out.linksNotFollowed);
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
// Entries whose type cannot be read, and entries that are neither file nor directory
// ===========================================================================
//
// THE DEFECTS THESE CASES EXIST FOR
// ---------------------------------
// The walk asked each entry is_directory() and then is_regular_file(), and passed by an
// entry for which both were false - whether they were false because it is a FIFO or because
// the host refused to say. Measured before the repair: an app execution alias on Windows, a
// link on Linux to something behind a directory this user may not search, and a link to
// itself each left every count at zero, in the walk and in the pre-count, and the scan
// exited 0. The real %LOCALAPPDATA%\Microsoft\WindowsApps held 100 aliases, and none of them
// was reported.
//
// Both questions also wrote into the error_code the directory iterator had been given, and
// the walk read it after the loop to decide whether the directory could be listed. So the
// last entry's answer became the directory's: a directory whose last entry was a dangling
// link - an ordinary thing in a web root - was counted unreadable, and so were 28 of the 29
// directories under WindowsApps, every one of which had been read.
//
// And a subdirectory of a directory this user may list and not search was dropped as though
// it had vanished mid-walk: the stat that asks which directory it is failed, and every stat
// failure was taken for a race. A file beside it was counted as unreadable; the subdirectory
// and everything below it were counted as nothing.
//
// WHY THE DIRECTORY CASES PUT THE ENTRY ALONE
// -------------------------------------------
// An entry's answer leaked into its directory only when it was the LAST in the listing, and
// listing order is the file system's - newest first on tmpfs, name order on NTFS, hash order
// on ext4. The only entry in a directory is the last one on every file system, so that is
// the fixture, rather than a name chosen to sort last on one of them.

// Counted wherever the walk asks the entry its type and is refused. That is under either
// setting for an entry that is not a link - the app execution alias the Windows fixture is -
// and only with followSymlinks on for a link, which a walk that does not follow links asks
// nothing but whether it is one. There, the same entry is a link not followed.
TEST(FileWalkerUnknownTypeTest, AnEntryWhoseTypeCannotBeReadIsCountedWhereItsTypeIsAsked) {
    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(root / "own.php", kHarmless);
    const test::EntryOfUnknownType unknown(root / "unknown", tree.path() / "elsewhere");
    if (unknown.whyNot()) {
        GTEST_SKIP() << *unknown.whyNot();
    }

    for (const bool follow : {false, true}) {
        ScanConfig scan = configFor(root);
        scan.followSymlinks = follow;
        const Walked seen = walkOf(scan, root);

        const bool asked = follow || !unknown.isLink();
        EXPECT_EQ(seen.unreadableEntries, asked ? 1u : 0u)
            << (asked ? "the entry was passed by as though it were not in the listing"
                      : "a link the walk does not follow was followed to ask its type")
            << ", followSymlinks " << follow;
        EXPECT_EQ(seen.linksNotFollowed, asked ? 0u : 1u)
            << "followSymlinks " << follow;
        EXPECT_EQ(seen.files.size(), 1u) << "own.php, and the entry was not handed over as a file";
        EXPECT_EQ(seen.unreadable, 0u) << "the directory it sits in was read";
        EXPECT_EQ(seen.directories, 1u);
        EXPECT_EQ(FileWalker(scan).countFiles().files, 1u)
            << "the pre-count is the same walk, and counts the entry as no file of work";
    }
}

// The companion. A link that leads nowhere is answered - nothing is there - and a walk that
// counted every refusal, that one included, would satisfy the case above and put a line into
// every scan of a tree with a stale link in it.
TEST(FileWalkerUnknownTypeTest, ALinkThatLeadsNowhereIsNotAnEntryOfUnknownType) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }

    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(root / "own.php", kHarmless);
    std::error_code ec;
    fs::create_symlink(tree.path() / "nowhere.php", root / "gone.php", ec);
    ASSERT_FALSE(ec) << ec.message();

    for (const bool follow : {false, true}) {
        ScanConfig scan = configFor(root);
        scan.followSymlinks = follow;
        const Walked seen = walkOf(scan, root);

        EXPECT_EQ(seen.unreadableEntries, 0u) << "followSymlinks " << follow;
        EXPECT_EQ(seen.files.size(), 1u);
        EXPECT_EQ(seen.unreadable, 0u);
    }
}

// A link that leads back through itself leads nowhere too, and says so in a different word:
// ELOOP on POSIX and ERROR_CANT_RESOLVE_FILENAME on Windows, where not found is what a
// dangling link says. One link to itself, and one into a ring of three that lies outside the
// tree, so a walk that knew only a link naming itself would fail on the second.
//
// Against a walk that asks is_directory() before it asks whether an entry is a link, both are
// counted as entries whose type could not be read with followSymlinks off - the setting under
// which the scan would never have read through either. Measured on v3.2.0: one of each in a
// tree, and entriesUnreadable was 2 under both settings. The companions are
// EveryLinkNotFollowedIsCountedAndNothingElseIs, where the same two links sit beside links
// that do lead somewhere and those are still counted, and
// ALinkIntoADirectoryThisUserMayNotSearchIsCountedByWhetherTheWalkWouldFollowIt, where a
// refusal that is not a loop is still counted under each setting.
TEST(FileWalkerUnknownTypeTest, ALinkThatLoopsIsPassedByUnderEitherSetting) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }

    TempTree tree;
    const fs::path root = tree.path() / "tree";
    const fs::path ring = tree.path() / "ring";
    tree.write(root / "own.php", kHarmless);
    fs::create_directories(ring);
    std::error_code ec;
    fs::create_symlink("self.php", root / "self.php", ec);
    ASSERT_FALSE(ec) << ec.message();
    fs::create_symlink(ring / "b", ring / "a", ec);
    ASSERT_FALSE(ec) << ec.message();
    fs::create_symlink(ring / "c", ring / "b", ec);
    ASSERT_FALSE(ec) << ec.message();
    fs::create_symlink(ring / "a", ring / "c", ec);
    ASSERT_FALSE(ec) << ec.message();
    fs::create_symlink(ring / "a", root / "ring", ec);
    ASSERT_FALSE(ec) << ec.message();

    for (const bool follow : {false, true}) {
        ScanConfig scan = configFor(root);
        scan.followSymlinks = follow;
        const Walked seen = walkOf(scan, root);

        EXPECT_EQ(seen.unreadableEntries, 0u)
            << "a link that loops was counted as content the scan could not read, "
               "followSymlinks " << follow;
        EXPECT_EQ(seen.linksNotFollowed, 0u)
            << "a link that loops leads to nothing a scan could have read, followSymlinks "
            << follow;
        EXPECT_EQ(seen.unreadable, 0u) << "followSymlinks " << follow;
        EXPECT_EQ(seen.directories, 1u) << "followSymlinks " << follow;
        EXPECT_EQ(seen.files.size(), 1u) << "own.php alone, followSymlinks " << follow;
        EXPECT_EQ(FileWalker(scan).countFiles().files, 1u)
            << "the pre-count, followSymlinks " << follow;
    }
}

// A link to a file and a link to a directory, both inside a directory this user may not
// search, and a link to that directory itself. The first two cannot say what they lead to;
// the third can - it is a directory - and it is the directory that cannot be listed.
//
// Which count holds the first two is decided by whether the walk would have gone through
// them. With followSymlinks off it would not, so they are links not followed: the operator
// asked for exactly that, and what is behind them was never going to be read. With it on the
// walk meant to read what they lead to and could not ask what that is, so they are entries of
// unknown type. Against a walk that asked is_directory() first they were entries of unknown
// type under both settings; against one that had learned to pass every refused link by as
// though it looped, they are counted nowhere under either, and so this case fails both.
TEST(FileWalkerUnknownTypeTest,
     ALinkIntoADirectoryThisUserMayNotSearchIsCountedByWhetherTheWalkWouldFollowIt) {
    if (const auto why = test::whyCannotDenyOwnAccess()) {
        GTEST_SKIP() << *why << " - a link into a mode-000 directory would still be followed";
    }
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }

    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(root / "own.php", kHarmless);
    tree.write(tree.path() / "locked" / "target.php", kHarmless);
    tree.write(tree.path() / "locked" / "dir" / "inner.php", kHarmless);
    std::error_code ec;
    fs::create_symlink(tree.path() / "locked" / "target.php", root / "link.php", ec);
    ASSERT_FALSE(ec) << ec.message();
    fs::create_directory_symlink(tree.path() / "locked" / "dir", root / "linkdir", ec);
    ASSERT_FALSE(ec) << ec.message();
    fs::create_directory_symlink(tree.path() / "locked", root / "lockeddir", ec);
    ASSERT_FALSE(ec) << ec.message();
    tree.lock(tree.path() / "locked");

    const ScanConfig byDefault = configFor(root);
    const Walked notFollowed = walkOf(byDefault, root);
    EXPECT_EQ(notFollowed.linksNotFollowed, 3u) << "all three are links the walk did not follow";
    EXPECT_EQ(notFollowed.unreadableEntries, 0u)
        << "a link the walk was told not to follow was followed to ask its type";
    EXPECT_EQ(notFollowed.unreadable, 0u) << "nothing was entered, so nothing failed to list";
    EXPECT_EQ(notFollowed.directories, 1u);
    EXPECT_EQ(notFollowed.files.size(), 1u);
    EXPECT_EQ(FileWalker(byDefault).countFiles().files, 1u) << "the pre-count, by default";

    ScanConfig following = configFor(root);
    following.followSymlinks = true;
    const Walked followed = walkOf(following, root);
    EXPECT_EQ(followed.unreadableEntries, 2u) << "link.php and linkdir";
    EXPECT_EQ(followed.linksNotFollowed, 0u) << "every link was followed";
    EXPECT_EQ(followed.unreadable, 1u) << "lockeddir, which was entered and could not be listed";
    EXPECT_EQ(followed.directories, 2u) << "the root and lockeddir";
    EXPECT_EQ(followed.files.size(), 1u);
    EXPECT_EQ(FileWalker(following).countFiles().files, 1u) << "the pre-count, following";

    // A walk that enters no subdirectory refused nothing by not entering lockeddir, which says
    // it is a directory. The other two do not say what they are, and either may be a file.
    ScanConfig flat = configFor(root);
    flat.recursive = false;
    const Walked notRecursive = walkOf(flat, root);
    EXPECT_EQ(notRecursive.linksNotFollowed, 2u) << "link.php and linkdir, and not lockeddir";
    EXPECT_EQ(notRecursive.unreadableEntries, 0u);
}

// The directory it sat in was read. Against the walk that shared the iterator's error_code
// this directory was counted unreadable. The other direction - a directory that really
// cannot be listed is still counted - is AnUnreadableSubdirectoryIsCountedAndTheWalkContinues.
//
// With followSymlinks on, which is the setting under which the entry has no readable type on
// every platform: see AnEntryWhoseTypeCannotBeReadIsCountedWhereItsTypeIsAsked.
TEST(FileWalkerUnknownTypeTest, ADirectoryWhoseLastEntryHasNoReadableTypeWasStillRead) {
    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(root / "own.php", kHarmless);
    fs::create_directories(root / "sub");
    const test::EntryOfUnknownType unknown(root / "sub" / "unknown", tree.path() / "elsewhere");
    if (unknown.whyNot()) {
        GTEST_SKIP() << *unknown.whyNot();
    }

    ScanConfig scan = configFor(root);
    scan.followSymlinks = true;
    const Walked seen = walkOf(scan, root);

    EXPECT_EQ(seen.directories, 2u) << "the root and sub";
    EXPECT_EQ(seen.unreadable, 0u)
        << "sub was listed, and the answer about its only entry was read as the listing's";
    EXPECT_EQ(seen.unreadableEntries, 1u);
}

// The same leak from the entry nobody would think to look at: a dangling link, which is not
// counted anywhere, alone in a directory that was read.
TEST(FileWalkerUnknownTypeTest, ADirectoryWhoseLastEntryIsADanglingLinkWasStillRead) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }

    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(root / "own.php", kHarmless);
    fs::create_directories(root / "sub");
    std::error_code ec;
    fs::create_symlink(tree.path() / "nowhere.php", root / "sub" / "gone.php", ec);
    ASSERT_FALSE(ec) << ec.message();

    const Walked seen = walkOf(configFor(root), root);

    EXPECT_EQ(seen.directories, 2u);
    EXPECT_EQ(seen.unreadable, 0u) << "a directory holding one stale link was reported unreadable";
    EXPECT_EQ(seen.unreadableEntries, 0u);
}

// Listable and not searchable. The file inside is handed over and counted unreadable when its
// size cannot be read; the subdirectory is entered and counted unreadable when it cannot be
// listed - and is not dropped as a subdirectory that vanished, which is what a failed stat
// used to be taken for. The other direction, a subdirectory that really did vanish and is
// still quiet, is ASubdirectoryThatVanishesMidWalkIsQuiet above.
TEST(FileWalkerTest, ASubdirectoryOfADirectoryThatCannotBeSearchedIsUnreadable) {
    if (const auto why = test::whyCannotDenyOwnAccess()) {
        GTEST_SKIP() << *why << " - a directory without search permission would still be searched";
    }

    TempTree tree;
    const fs::path root = tree.path() / "tree";
    const fs::path half = root / "half";
    tree.write(root / "own.php", kHarmless);
    tree.write(half / "file.php", kHarmless);
    tree.write(half / "sub" / "deep.php", kHarmless);
    tree.forbidSearch(half);

    // The subdirectory has to be named a directory by the listing itself, or its type is asked
    // with the same stat the permission refuses and it is an entry of unknown type - which is
    // the cases above, and which this case would report as a defect it is not about.
    std::error_code ec;
    bool listingSaysDirectory = false;
    for (const auto& entry : fs::directory_iterator(half, ec)) {
        std::error_code typeEc;
        if (entry.path().filename() == "sub") {
            listingSaysDirectory = entry.is_directory(typeEc) && !typeEc;
        }
    }
    if (!listingSaysDirectory) {
        GTEST_SKIP() << "this file system does not name an entry's type in its listing, so a "
                        "subdirectory that cannot be searched is an entry of unknown type here "
                        "and not the case this observes";
    }

    const Walked seen = walkOf(configFor(root), root);

    EXPECT_EQ(seen.unreadable, 1u) << "sub was dropped as though it had vanished";
    EXPECT_EQ(seen.directories, 3u) << "the root, half and sub, which was entered and not listed";
    EXPECT_TRUE(seen.sawFilename("file.php")) << "the file beside it is handed over, unreadable";
    EXPECT_FALSE(seen.sawFilename("deep.php"));
    EXPECT_EQ(seen.unreadableEntries, 0u) << "the listing named both entries' types";
}

// Answered, and neither a file nor a directory. Not handed over, because a scan reads bytes
// and these have none of their own - reading a FIFO waits for a writer that may never come -
// and not counted, because nothing was left unread. The companion in the other direction is
// AnEntryWhoseTypeCannotBeReadIsCountedUnderEitherSetting: a walk that counted every entry
// that is not a file or a directory passes that and fails this.
TEST(FileWalkerSpecialFileTest, AFifoASocketAndALinkToADeviceAreNeitherHandedOverNorCounted) {
    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(root / "own.php", kHarmless);
    if (const auto why = test::whyCannotMakeSpecialFiles(root)) {
        GTEST_SKIP() << *why;
    }
    std::error_code ec;
    fs::create_symlink("/dev/null", root / "null", ec);
    ASSERT_FALSE(ec) << ec.message();

    for (const bool follow : {false, true}) {
        ScanConfig scan = configFor(root);
        scan.followSymlinks = follow;
        const Walked seen = walkOf(scan, root);

        ASSERT_EQ(seen.files.size(), 1u) << "a special file was handed to the scanner to read, "
                                            "followSymlinks " << follow;
        EXPECT_TRUE(seen.sawFilename("own.php"));
        EXPECT_EQ(seen.unreadableEntries, 0u) << "each of them answered its type";
        EXPECT_EQ(seen.unreadable, 0u);
        EXPECT_EQ(seen.linksNotFollowed, 0u) << "a link to a device leads to nothing to read";
        EXPECT_FALSE(seen.stopped);
    }
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

// What a link the walk did not go through costs, counted. Every one that leads to content:
// the directory link and the file link, and not the links that lead nowhere - one dangling,
// one to itself - which are not content this scan declined to read. The companions are in the
// same case - following counts nothing, and a walk that enters no subdirectory has refused no
// directory link by not entering it - because each is the other half of one number.
TEST(FileWalkerSymlinkTest, EveryLinkNotFollowedIsCountedAndNothingElseIs) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }

    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(tree.path() / "real" / "target.php", kHarmless);
    tree.write(tree.path() / "real.php", kHarmless);
    tree.write(root / "own.php", kHarmless);
    std::error_code ec;
    fs::create_directory_symlink(tree.path() / "real", root / "dirlink", ec);
    ASSERT_FALSE(ec) << ec.message();
    fs::create_symlink(tree.path() / "real.php", root / "filelink.php", ec);
    ASSERT_FALSE(ec) << ec.message();
    fs::create_symlink(tree.path() / "nowhere.php", root / "dangling.php", ec);
    ASSERT_FALSE(ec) << ec.message();
    fs::create_symlink("self.php", root / "self.php", ec);
    ASSERT_FALSE(ec) << ec.message();

    const ScanConfig defaults = configFor(root);
    const Walked byDefault = walkOf(defaults, root);
    EXPECT_EQ(byDefault.linksNotFollowed, 2u) << "the directory link and the file link";
    EXPECT_EQ(byDefault.unreadableEntries, 0u) << "neither link that leads nowhere is unreadable";
    EXPECT_EQ(byDefault.files.size(), 1u) << "own.php, and nothing reached through a link";
    EXPECT_EQ(FileWalker(defaults).countFiles().files, 1u) << "the pre-count, by default";

    ScanConfig following = configFor(root);
    following.followSymlinks = true;
    const Walked followed = walkOf(following, root);
    EXPECT_EQ(followed.linksNotFollowed, 0u) << "every link was followed";
    EXPECT_EQ(followed.unreadableEntries, 0u);
    EXPECT_EQ(followed.files.size(), 3u) << "own.php, target.php and filelink.php";
    EXPECT_EQ(FileWalker(following).countFiles().files, 3u) << "the pre-count, following";

    ScanConfig flat = configFor(root);
    flat.recursive = false;
    const Walked notRecursive = walkOf(flat, root);
    EXPECT_EQ(notRecursive.linksNotFollowed, 1u)
        << "the file link only: a walk that enters no subdirectory refused nothing by not "
           "entering the directory link";
}

// A root that is a link is the tree the operator named, and is walked whatever the setting
// says - by walk() and by the counting traversal, which is the same walk on another
// thread. Refusing it would report a clean scan of nothing.
namespace {

void expectARootThatIsALinkIsWalked(const fs::path& root) {
    for (const bool follow : {false, true}) {
        ScanConfig scan = configFor(root);
        scan.followSymlinks = follow;
        const FileWalker walker(scan);

        size_t files = 0;
        size_t links = 0;
        std::vector<fs::path> missing;
        const size_t directories = walker.walk(
            [&files](const FileInfo&) { ++files; return true; }, /*unreadableDirs=*/nullptr,
            &missing, /*cycleSkippedDirs=*/nullptr, &links);
        const CountResult counted = walker.countFiles();

        EXPECT_TRUE(missing.empty()) << "followSymlinks " << follow;
        EXPECT_EQ(directories, 2u) << "the root and its subdirectory, followSymlinks " << follow;
        EXPECT_EQ(files, 2u) << "followSymlinks " << follow;
        EXPECT_EQ(counted.files, 2u) << "the count, followSymlinks " << follow;
        EXPECT_EQ(links, 0u) << "a root that was walked is not a link that was refused";
    }
}

}  // namespace

TEST(FileWalkerSymlinkTest, ARootThatIsASymbolicLinkIsWalkedWhateverFollowSymlinksSays) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }

    TempTree tree;
    tree.write(tree.path() / "real" / "own.php", kHarmless);
    tree.write(tree.path() / "real" / "sub" / "deep.php", kHarmless);
    std::error_code ec;
    fs::create_directory_symlink(tree.path() / "real", tree.path() / "root", ec);
    ASSERT_FALSE(ec) << ec.message();

    expectARootThatIsALinkIsWalked(tree.path() / "root");
}

// ===========================================================================
// Junctions and volume mount points
// ===========================================================================
//
// THE DEFECT THESE CASES EXIST FOR
// --------------------------------
// The walk decided a directory was a link by asking is_symlink(). Microsoft's library
// reports a directory junction as file_type::junction, for which is_symlink() is false, so
// on Windows a junction was descended with follow_symlinks off - measured with the MSVC
// build, where a tree holding one read the file behind it under both settings while a
// directory symbolic link beside it was refused. A junction needs no privilege to create.
//
// A volume mount point carries the same reparse tag and is not a link, so the cases pair a
// junction that must now be refused with a mount point that must still be entered: a walk
// that had learned to refuse the tag, rather than the junction, would pass the first and
// drop a volume from every scan.
//
// Junctions exist only on Windows. On every other platform each case skips and says so.

TEST(FileWalkerJunctionTest, AJunctionIsNotDescendedByDefault) {
    TempTree tree;
    tree.write(tree.path() / "real" / "target.php", kHarmless);
    tree.write(tree.path() / "tree" / "own.php", kHarmless);
    if (const auto why =
            test::whyCannotCreateJunction(tree.path() / "tree" / "link", tree.path() / "real")) {
        GTEST_SKIP() << *why;
    }

    const Walked seen = walkOf(configFor(tree.path() / "tree"), tree.path() / "tree");

    EXPECT_EQ(seen.directories, 1u) << "the junction was followed with followSymlinks off";
    EXPECT_TRUE(seen.sawFilename("own.php"));
    EXPECT_FALSE(seen.sawFilename("target.php"));
    EXPECT_EQ(seen.linksNotFollowed, 1u) << "and the refusal is counted";
}

TEST(FileWalkerJunctionTest, AJunctionIsDescendedWhenFollowSymlinksIsSet) {
    TempTree tree;
    tree.write(tree.path() / "real" / "target.php", kHarmless);
    tree.write(tree.path() / "tree" / "own.php", kHarmless);
    if (const auto why =
            test::whyCannotCreateJunction(tree.path() / "tree" / "link", tree.path() / "real")) {
        GTEST_SKIP() << *why;
    }

    ScanConfig scan = configFor(tree.path() / "tree");
    scan.followSymlinks = true;
    const Walked seen = walkOf(scan, tree.path() / "tree");

    EXPECT_EQ(seen.directories, 2u) << "the junction was entered";
    EXPECT_TRUE(seen.sawFilename("target.php"));
    EXPECT_EQ(seen.linksNotFollowed, 0u);
}

// What a mount point stores is the root of a volume and nothing after it. A junction to a
// directory INSIDE a volume, spelled through that volume's GUID path, begins exactly the
// same way - so a walk that asked only how the stored path begins would take this for a
// mount point and walk through a link the operator did not ask it to follow.
TEST(FileWalkerJunctionTest, AJunctionSpelledThroughItsVolumeGuidPathIsStillAJunction) {
    TempTree tree;
    tree.write(tree.path() / "real" / "target.php", kHarmless);
    tree.write(tree.path() / "tree" / "own.php", kHarmless);
    if (const auto why = test::whyCannotCreateJunctionThroughVolumeGuid(
            tree.path() / "tree" / "link", tree.path() / "real")) {
        GTEST_SKIP() << *why;
    }

    const Walked seen = walkOf(configFor(tree.path() / "tree"), tree.path() / "tree");

    EXPECT_EQ(seen.directories, 1u)
        << "a junction whose stored path names a directory inside a volume was walked as "
           "though it were the volume's mount point";
    EXPECT_FALSE(seen.sawFilename("target.php"));
    EXPECT_EQ(seen.linksNotFollowed, 1u);
}

// The companion that keeps the two cases above honest, under both settings.
//
// The mount point attaches the whole volume holding the temporary directory, so the walk is
// bounded at two directories - the root, then the volume - and the interrupt goes up as
// the volume is entered, before one entry of it is read. The reparse point is removed
// before the tree is deleted, so nothing that cleans up can be led into the volume either.
TEST(FileWalkerJunctionTest, AVolumeMountPointIsWalkedWhateverFollowSymlinksSays) {
    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(root / "own.php", kHarmless);
    const fs::path mount = root / "volume";
    if (const auto why = test::whyCannotCreateVolumeMountPoint(mount, tree.path())) {
        GTEST_SKIP() << *why;
    }
    // Declared after the tree, so it is destroyed first.
    struct Unmount {
        fs::path path;
        ~Unmount() { test::removeReparsePoint(path); }
    } unmount{mount};

    for (const bool follow : {false, true}) {
        ScanConfig scan = configFor(root);
        scan.followSymlinks = follow;
        const BoundedWalk seen = boundedWalk(scan, root, /*bound=*/2);

        ASSERT_EQ(seen.entered.size(), 2u)
            << "the volume mount point was not entered with followSymlinks " << follow
            << ", so everything on the volume behind it was left out of the scan";
        EXPECT_EQ(seen.entered[1], mount);
        EXPECT_EQ(seen.linksNotFollowed, 0u) << "a mount point is not a link, followSymlinks "
                                             << follow;
        EXPECT_EQ(seen.files, 1u) << "own.php, and nothing read from the volume";
    }
}

TEST(FileWalkerJunctionTest, ARootThatIsAJunctionIsWalkedWhateverFollowSymlinksSays) {
    TempTree tree;
    tree.write(tree.path() / "real" / "own.php", kHarmless);
    tree.write(tree.path() / "real" / "sub" / "deep.php", kHarmless);
    if (const auto why =
            test::whyCannotCreateJunction(tree.path() / "root", tree.path() / "real")) {
        GTEST_SKIP() << *why;
    }

    expectARootThatIsALinkIsWalked(tree.path() / "root");
}

// The counting traversal, by name, for the reason its loop case gives: it runs on a
// spawned thread, and a count that went through a junction the scan then refused would be
// a progress total the scan never reaches.
TEST(FileWalkerJunctionTest, TheCountingTraversalGoesThroughAJunctionOnlyWhenAsked) {
    TempTree tree;
    tree.write(tree.path() / "real" / "target.php", kHarmless);
    const fs::path root = tree.path() / "tree";
    tree.write(root / "own.php", kHarmless);
    if (const auto why = test::whyCannotCreateJunction(root / "link", tree.path() / "real")) {
        GTEST_SKIP() << *why;
    }

    const BoundedCount byDefault = boundedCount(configFor(root), /*bound=*/1000);
    EXPECT_EQ(byDefault.result.files, 1u) << "countFiles() went through the junction";
    EXPECT_EQ(byDefault.entered, 1u);

    ScanConfig scan = configFor(root);
    scan.followSymlinks = true;
    const BoundedCount followed = boundedCount(scan, /*bound=*/1000);
    EXPECT_EQ(followed.result.files, 2u);
    EXPECT_EQ(followed.entered, 2u);
}

// A junction that leads back through itself leads nowhere, exactly as a symbolic link that
// does: see ALinkThatLoopsIsPassedByUnderEitherSetting. It is its own case because Windows
// says so in its own word - ERROR_CANT_RESOLVE_FILENAME, which Microsoft's library does not
// equate with too_many_symbolic_link_levels - and because a junction needs no privilege, so
// this runs on a host where the symbolic link case skips. One junction to itself, and one into
// a ring of three outside the tree. Against a walk that asked is_directory() first, both were
// entries of unknown type under both settings.
TEST(FileWalkerJunctionTest, AJunctionThatLoopsIsPassedByUnderEitherSetting) {
    TempTree tree;
    const fs::path root = tree.path() / "tree";
    const fs::path ring = tree.path() / "ring";
    tree.write(root / "own.php", kHarmless);
    fs::create_directories(ring);
    const std::pair<fs::path, fs::path> junctions[] = {
        {root / "self", root / "self"}, {ring / "a", ring / "b"}, {ring / "b", ring / "c"},
        {ring / "c", ring / "a"},       {root / "ring", ring / "a"},
    };
    for (const auto& [link, target] : junctions) {
        if (const auto why = test::whyCannotCreateJunction(link, target)) {
            GTEST_SKIP() << *why;
        }
    }

    for (const bool follow : {false, true}) {
        ScanConfig scan = configFor(root);
        scan.followSymlinks = follow;
        const Walked seen = walkOf(scan, root);

        EXPECT_EQ(seen.unreadableEntries, 0u)
            << "a junction that loops was counted as content the scan could not read, "
               "followSymlinks " << follow;
        EXPECT_EQ(seen.linksNotFollowed, 0u) << "followSymlinks " << follow;
        EXPECT_EQ(seen.unreadable, 0u) << "followSymlinks " << follow;
        EXPECT_EQ(seen.directories, 1u) << "followSymlinks " << follow;
        EXPECT_EQ(seen.files.size(), 1u) << "followSymlinks " << follow;
        EXPECT_EQ(FileWalker(scan).countFiles().files, 1u)
            << "the pre-count, followSymlinks " << follow;
    }
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

// The loop through a junction. Whether a loop ends was never a question of what kind of
// link closed it - the walk compares the volume serial and file id of what a path leads to
// - and this is that claim observed rather than trusted: the review's reproduction with
// two junctions in place of the two symbolic links. Against a walk without the identity
// check it does not end, so it is bounded like its neighbours.
TEST(FileWalkerCycleTest, TwoJunctionsToTheWalkedDirectoryAreRefusedAndTheWalkEnds) {
    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(root / "own.php", kHarmless);
    for (const char* name : {"a", "b"}) {
        if (const auto why = test::whyCannotCreateJunction(root / name, root)) {
            GTEST_SKIP() << *why;
        }
    }

    ScanConfig scan = configFor(root);
    scan.followSymlinks = true;
    const BoundedWalk seen = boundedWalk(scan, root, /*bound=*/1000);

    EXPECT_FALSE(seen.boundHit)
        << "the walk was still entering directories after 1000 of them in a tree that "
           "holds one, so the loop through the junctions was followed rather than refused";
    EXPECT_EQ(seen.directories, 1u);
    EXPECT_EQ(seen.cycleSkipped, 2u) << "both junctions back to the walked directory";
    EXPECT_EQ(seen.files, 1u) << "the one real file, read once";
}

// The same fixture by default. Before junctions were links this walk queued both of them
// and refused them as a loop - the refusal was right, and it was also the only thing that
// stopped a walk the operator had told not to follow links from going through them. Now
// neither is a candidate: nothing is refused as a loop and both are counted as not followed.
TEST(FileWalkerCycleTest, JunctionsToTheWalkedDirectoryAreNotCandidatesByDefault) {
    TempTree tree;
    const fs::path root = tree.path() / "tree";
    tree.write(root / "own.php", kHarmless);
    for (const char* name : {"a", "b"}) {
        if (const auto why = test::whyCannotCreateJunction(root / name, root)) {
            GTEST_SKIP() << *why;
        }
    }

    const BoundedWalk seen = boundedWalk(configFor(root), root, /*bound=*/1000);

    EXPECT_FALSE(seen.boundHit);
    EXPECT_EQ(seen.directories, 1u);
    EXPECT_EQ(seen.cycleSkipped, 0u)
        << "the junctions were queued with followSymlinks off and only the loop check "
           "stopped the walk going through them";
    EXPECT_EQ(seen.linksNotFollowed, 2u);
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

// ---------------------------------------------------------------------------
// An archive member's name against the operator's patterns
// ---------------------------------------------------------------------------
//
// A member name is a string whose only separator is `/`, and FileWalker::globMatch() is the one
// matcher that reads it, on every platform - so its answers are held to fnmatch(3)'s, over every
// pattern below and every name below.


namespace {

const std::vector<std::string> kGlobPatterns = {
    "*", "**", "*.php", "*.min.js", "*.php*", "vendor/**", "vendor/*", "node_modules/**",
    "*/vendor/*", "wp-content/*/x.php", "?", "??.php", "a?c", "[abc].php", "[!abc].php",
    "[^abc].php", "[a-c]*", "[]a]x", "[!]a]x", "[a-]x", "[[:digit:]]*", "[[:alpha:]][[:alnum:]]*",
    "[[:upper:]]*", "x[", "x[a", "\\*.php", "a\\?c", "a\\", "vendor\\*", "*\\*", "[\\]]x",
    ".*", "*.", "", "a/b", "a*/b", "**/x.php", "*x.php", "vendor/**/x.php",
};

const std::vector<std::string> kGlobNames = {
    "", "x.php", "a.b.php", ".htaccess", "vendor/x.php", "vendor/lib/x.php", "vendor\\x.php",
    "vendor\\lib\\x.php", "src\\vendor\\x.php", "wp-content/plugins/x.php", "wp-content/a/x.php",
    "a/b", "ab/b", "abc", "a?c", "a*c", "*.php", "b.php", "d.php", "]x", "ax", "-x", "!x",
    "1x", "Ax", "x[", "x[a", "a\\", "a\\b", "jquery.min.js", "x.php.bak", "node_modules/a/b.js",
    "src/vendor/lib", "./x.php", "/x.php", "..\\..\\x.php", "a/vendor/b", ".x", "x.", "[a]x",
};

}  // namespace

// fnmatch(3)'s answers over the two tables above with FNM_PATHNAME, as glibc gives them: one row
// per pattern, one column per name, '1' where the name matches. Recorded, so that every platform
// is held to the same answers; where fnmatch(3) exists the case asks it as well, so the record
// cannot drift away from what it records.
constexpr std::string_view kFnmatchAnswers[] = {
    "1111001110000111111111111111111000010111",
    "1111001110000111111111111111111000010111",
    "0110001110000000111000000000000000010000",
    "0000000000000000000000000000010000000000",
    "0110001110000000111000000000001000010000",
    "0000100000000000000000000000000000000000",
    "0000100000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000010001000",
    "0000000001100000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000111000000000000000000000000",
    "0000000000000000010000000000000000000000",
    "0100000000000000101000000000000000000000",
    "0100000000000000101000000000000000000000",
    "0010000000000111010010000001100000000000",
    "0000000000000000000110000000000000000000",
    "0000000000000000000001111000000000000100",
    "0000000000000000000011000000000000000000",
    "0000000000000000000000010000000000000000",
    "0000001110000100000010001000010000000000",
    "0000000000000000000000001000000000000000",
    "0000000000000000000000000100000000000000",
    "0000000000000000000000000010000000000000",
    "0000000000000000100000000000000000000000",
    "0000000000000010000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0000000000000000000100000000000000000000",
    "0001000000000000000000000000000000010100",
    "0000000000000000000000000000000000000010",
    "1000000000000000000000000000000000000000",
    "0000000000010000000000000000000000000000",
    "0000000000011000000000000000000000000000",
    "0000100000000000000000000000000001100000",
    "0100001110000000000000000000000000010000",
    "0000010000000000000000000000000000000000",
};

TEST(FileWalkerMemberFilterTest, GlobMatchAnswersAsFnmatchWithPathnameDoes) {
    ASSERT_EQ(std::size(kFnmatchAnswers), kGlobPatterns.size());
    size_t compared = 0;
    for (size_t i = 0; i < kGlobPatterns.size(); ++i) {
        ASSERT_EQ(kFnmatchAnswers[i].size(), kGlobNames.size()) << "row " << i;
        for (size_t j = 0; j < kGlobNames.size(); ++j) {
            const bool expected = kFnmatchAnswers[i][j] == '1';
            EXPECT_EQ(FileWalker::globMatch(kGlobPatterns[i], kGlobNames[j]), expected)
                << "pattern '" << kGlobPatterns[i] << "' name '" << kGlobNames[j] << "'";
#ifndef _WIN32
            EXPECT_EQ(fnmatch(kGlobPatterns[i].c_str(), kGlobNames[j].c_str(), FNM_PATHNAME) == 0,
                      expected)
                << "the recorded answer is not fnmatch(3)'s: pattern '" << kGlobPatterns[i]
                << "' name '" << kGlobNames[j] << "'";
#endif
            ++compared;
        }
    }
    EXPECT_EQ(compared, 1560u);
}

// The answers the default patterns give, stated directly so every platform checks them.
TEST(FileWalkerMemberFilterTest, AStarNeverCrossesASlashAndABackslashIsACharacter) {
    EXPECT_TRUE(FileWalker::globMatch("vendor/**", "vendor/x.php"));
    EXPECT_FALSE(FileWalker::globMatch("vendor/**", "vendor/lib/x.php"));
    EXPECT_FALSE(FileWalker::globMatch("vendor/**", "vendor\\x.php"));
    EXPECT_TRUE(FileWalker::globMatch("*.min.js", "wp-includes\\js\\jquery.min.js"))
        << "a backslash is a character, which `*` matches like any other";
    EXPECT_FALSE(FileWalker::globMatch("*.php", "a/b.php"));
    EXPECT_TRUE(FileWalker::globMatch("*.php", "a\\b.php"));
    EXPECT_TRUE(FileWalker::globMatch("[!a]x", "\\x"));
    EXPECT_FALSE(FileWalker::globMatch("?", "/"));
    EXPECT_FALSE(FileWalker::globMatch("[/]", "/"));
}

// The verdict for a member, with the default patterns: a directory the name really has is
// excluded as the pattern says, a backslash-spelled one is not, and the include list reads the
// final component after the last `/` only.
TEST(FileWalkerMemberFilterTest, AMembersVerdictReadsItsNameWithSlashesAsTheOnlySeparator) {
    ScanConfig scan = Config::loadFromString(Config::generateDefault()).scan;
    const FileWalker walker(scan);
    using Verdict = FileWalker::FilterVerdict;

    EXPECT_EQ(walker.memberFilterVerdict("vendor/x.php"), Verdict::Excluded);
    EXPECT_EQ(walker.memberFilterVerdict("node_modules/x.js"), Verdict::Excluded);
    EXPECT_EQ(walker.memberFilterVerdict("vendor/lib/x.php"), Verdict::Accepted);
    EXPECT_EQ(walker.memberFilterVerdict("vendor\\x.php"), Verdict::Accepted);
    EXPECT_EQ(walker.memberFilterVerdict("site\\wp-includes\\js\\jquery.min.js"), Verdict::Excluded);
    EXPECT_EQ(walker.memberFilterVerdict("site/x.php"), Verdict::Accepted);
    EXPECT_EQ(walker.memberFilterVerdict("site/uploads/table.mdb"), Verdict::NotIncluded);

    // `!ext`, the include pattern for a file with no extension, reads the final component as
    // std::filesystem reads a name: `id_rsa` has none, `deploy\.ssh\id_rsa` has `.ssh\id_rsa`.
    EXPECT_EQ(walker.memberFilterVerdict("home/deploy/.ssh/id_rsa"), Verdict::Accepted);
    EXPECT_EQ(walker.memberFilterVerdict("home/deploy\\.ssh\\id_rsa"), Verdict::NotIncluded);
    EXPECT_EQ(walker.memberFilterVerdict("cgi-bin/handler"), Verdict::Accepted);
}
