#include "FileWalker.h"
#include "Interrupt.h"
#include <algorithm>
#include <cstdint>
#include <cstring>

#ifdef _WIN32
// Portable fnmatch replacement for Windows
// Supports *, ?, and ** (recursive) glob patterns
static bool portable_fnmatch(const char* pattern, const char* str) {
    while (*pattern && *str) {
        if (*pattern == '*') {
            if (*(pattern + 1) == '*') {
                // ** matches everything including path separators
                pattern += 2;
                if (*pattern == '/' || *pattern == '\\') pattern++;
                if (!*pattern) return true;
                for (const char* s = str; *s; ++s) {
                    if (portable_fnmatch(pattern, s)) return true;
                }
                return false;
            }
            // * matches everything except path separators
            pattern++;
            if (!*pattern) {
                // trailing * — match if no more separators
                while (*str) {
                    if (*str == '/' || *str == '\\') return false;
                    str++;
                }
                return true;
            }
            for (const char* s = str; *s; ++s) {
                if (*s == '/' || *s == '\\') return false;
                if (portable_fnmatch(pattern, s)) return true;
            }
            return portable_fnmatch(pattern, str);
        }
        if (*pattern == '?') {
            if (*str == '/' || *str == '\\') return false;
            pattern++;
            str++;
            continue;
        }
        char pc = *pattern, sc = *str;
        if (pc == '\\') pc = '/';
        if (sc == '\\') sc = '/';
        if (pc != sc) return false;
        pattern++;
        str++;
    }
    while (*pattern == '*') pattern++;
    return !*pattern && !*str;
}
#else
#include <fnmatch.h>
#endif

// For the directory identity below. Separate from the block above, which is about
// glob matching and nothing else.
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace lyxbosa {

namespace {

// ---------------------------------------------------------------------------
// Directory identity, and why the walk asks for it at all
// ---------------------------------------------------------------------------
//
// Two paths reach the same directory when the host says they do, and the host says it
// in numbers rather than in paths: (st_dev, st_ino) on POSIX, a volume serial and a
// file id on Windows. Paths cannot answer it - a symlink's path is not its target's -
// and std::filesystem::equivalent() answers it one pair at a time, which would make a
// walk that has entered N directories ask N questions about the next one.
//
// One asymmetry decides everything else here. A false "same" makes the walk refuse a
// directory that closes no loop, and that refusal is a silent coverage loss - the
// failure this file's other comments exist to prevent. A false "different" only leaves
// a loop uncaught, and the interrupt check in walkDirectory() is what bounds that. So
// an identity this host will not produce is not an identity that matches something: it
// is absent, it compares equal to nothing, and the directory is entered.
struct DirectoryId {
    uint64_t volume = 0;
    uint64_t idHigh = 0;  // always 0 on POSIX; the high half of a 128-bit id on Windows
    uint64_t idLow = 0;

    bool operator==(const DirectoryId& other) const = default;
};

// Both things the walk needs to know about a path it has just taken off its stack.
//
// Asked as one call because the walk already paid for a stat here - it asked
// is_directory() of every popped path so that a subdirectory removed mid-walk stays
// quiet - and asking a second time would double that syscall on every directory of
// every scan, including the ones with no symlink in them.
struct DirectoryProbe {
    bool isDirectory = false;
    std::optional<DirectoryId> id;
};

DirectoryProbe probeDirectory(const std::filesystem::path& dir) {
    DirectoryProbe out;

#ifdef _WIN32
    const DWORD attributes = ::GetFileAttributesW(dir.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        return out;
    }
    out.isDirectory = true;

    // FILE_FLAG_BACKUP_SEMANTICS is what lets CreateFileW open a directory at all. The
    // access mask is zero because nothing here reads a byte - this asks for metadata -
    // and every share mode is granted so that a directory another process is writing
    // does not become unopenable because a scan looked at it.
    const HANDLE handle =
        ::CreateFileW(dir.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return out;  // a directory whose identity the host would not give: entered, not refused
    }

#if defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0602)
    // The 128-bit id first: ReFS file ids do not fit in the 64-bit index below, so on
    // that filesystem the older call can report two different directories as one - and
    // a false "same" is the coverage loss this must not produce.
    FILE_ID_INFO wide{};
    if (::GetFileInformationByHandleEx(handle, FileIdInfo, &wide, sizeof(wide))) {
        uint64_t low = 0;
        uint64_t high = 0;
        std::memcpy(&low, wide.FileId.Identifier, sizeof(low));
        std::memcpy(&high, wide.FileId.Identifier + sizeof(low), sizeof(high));
        out.id = DirectoryId{wide.VolumeSerialNumber, high, low};
    } else
#endif
    {
        // Filesystems that carry no 128-bit id refuse FileIdInfo, and some network
        // redirectors refuse it too, so the older pair is the fallback rather than the
        // failure. An SDK too old to declare FILE_ID_INFO takes this branch always.
        BY_HANDLE_FILE_INFORMATION info{};
        if (::GetFileInformationByHandle(handle, &info)) {
            out.id = DirectoryId{info.dwVolumeSerialNumber, 0,
                                 (static_cast<uint64_t>(info.nFileIndexHigh) << 32) |
                                     static_cast<uint64_t>(info.nFileIndexLow)};
        }
    }
    ::CloseHandle(handle);
#else
    // stat() and not lstat(): the walk wants the identity of whatever the path leads
    // to, and for a symlinked directory that is the target. That is the whole question.
    struct ::stat info {};
    if (::stat(dir.c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) {
        return out;
    }
    out.isDirectory = true;
    out.id = DirectoryId{static_cast<uint64_t>(info.st_dev), 0,
                         static_cast<uint64_t>(info.st_ino)};
#endif

    return out;
}

}  // namespace

FileWalker::FileWalker(const ScanConfig& config)
    : config_(config) {
}

std::optional<std::string> rootUnusableReason(const std::filesystem::path& dir) {
    namespace fs = std::filesystem;

    // The error_code overloads, because a root on a filesystem that is not answering
    // is a root this cannot walk either, and that has to be a reason rather than an
    // exception thrown out of a scan.
    std::error_code ec;
    if (!fs::exists(dir, ec) || ec) {
        return "no such directory";
    }
    if (!fs::is_directory(dir, ec) || ec) {
        return "not a directory";
    }
    return std::nullopt;
}

size_t FileWalker::walk(FileCallback callback, size_t* unreadableDirs,
                        std::vector<std::filesystem::path>* missingRoots,
                        size_t* cycleSkippedDirs) const {
    size_t dirCount = 0;
    bool stopped = false;

    for (const auto& dir : config_.directories) {
        // A root the operator named and that is not there is recorded rather than
        // walked past. walkDirectory() returns 0 for the same shape and must keep
        // doing so - it is the recursion step as well, and a subdirectory that
        // disappears mid-walk is a race - so the distinction is drawn here, which is
        // the only place that knows a path came from the operator.
        if (rootUnusableReason(dir)) {
            if (missingRoots) {
                missingRoots->push_back(dir);
            }
            continue;
        }
        dirCount += walkDirectory(dir, callback, stopped, unreadableDirs, cycleSkippedDirs);
        // `stopped` is set by a callback that refused and by the interrupt flag, and
        // either way the roots after this one are not walked. Which of the two it was
        // is interrupted()'s answer and not this loop's; Scanner::scan() asks it.
        if (stopped) break;
    }

    return dirCount;
}

size_t FileWalker::walkDirectory(const std::filesystem::path& dir, FileCallback callback, bool& stopped,
                                 size_t* unreadableDirs, size_t* cycleSkippedDirs) const {
    namespace fs = std::filesystem;

    // An explicit stack of directories still to read, rather than one C++ call frame
    // per directory level.
    //
    // Directory depth is attacker-controlled - a mkdir loop is three lines of shell -
    // so a recursive walk turns a tree into a stack overflow, and the tool that
    // crashes is the one somebody is running to investigate an incident. It was
    // reachable in practice rather than in theory: Scanner::scan() runs a second walk
    // on a spawned thread to pre-count files, glibc gives that thread 8 MB of stack
    // and musl gives it 128 KB, so the static musl build died with SIGSEGV on a tree
    // the glibc build walked without noticing. Raising the thread's stack would have
    // moved the ceiling; an explicit stack removes it, on both C libraries, on any
    // thread, and on Windows.
    //
    // Only directories are held here, never the files in them. A walk that buffered
    // each directory's entries would trade a depth limit for a width one, and width
    // is attacker-controlled in exactly the same way: this way a directory of ten
    // million files costs the walk nothing at all.
    //
    // ORDER. Files are reported for the whole of one directory before the walk
    // descends into any of its subdirectories, where the recursive version descended
    // at the point a subdirectory appeared in the listing. Within each of those two
    // groups the host's own listing order is preserved - children are pushed in
    // reverse so they come back off the stack in the order they were read - and the
    // traversal is still depth-first. Nothing downstream reads the walk's order: the
    // scanner accumulates counts and appends findings, the reporters iterate whatever
    // they are given, and no case asserts a sequence.
    //
    // DEPTH. Each queued directory carries how far below `dir` it sits, which is what
    // lets the cycle check below reconstruct the current directory's ancestors from a
    // stack that holds siblings too. It costs one size_t per queued directory - paid on
    // every scan, including the ones with no symlink in them - and the alternative was
    // a second marker entry per level, which costs the same and adds a second kind of
    // thing to the stack.
    struct PendingDir {
        fs::path path;
        size_t depth = 0;
    };
    std::vector<PendingDir> pending;
    pending.push_back({dir, 0});

    // Subdirectories of the directory currently being read, in listing order. Held
    // outside the loop so one buffer serves the whole walk.
    std::vector<fs::path> children;

    // The identity of every directory on the path from `dir` down to the one being
    // read, and nothing else - ANCESTORS, not everything the walk has ever entered.
    //
    // That is the whole of the scope decision and it is a trade, not a detail. A set of
    // every directory ever entered would additionally stop a linked sibling subtree
    // from being read twice, which is real work saved. It would also refuse the second
    // path to a bind mount, which legitimately presents one directory at two places, and
    // refusing it would drop that subtree from the scan without a word. Dropping
    // coverage silently is the failure this scanner has been repaired for four times.
    // The ancestor chain cannot do that: it refuses a directory only when the directory
    // is already open above it on this very path, so everything it refuses is being
    // walked anyway and nothing is lost.
    //
    // What it does not bound is amplification without a cycle - k levels of two links
    // each is 2^k distinct paths and every one of them terminates. Cancellation is the
    // answer to that, which is why the interrupt checks below are a separate repair
    // rather than a consequence of this one.
    //
    // Held as optionals so that an identity the host would not give matches nothing.
    // Compared by a linear scan because this is as long as the tree is deep - the
    // kernel stops symlink resolution at 40 links and PATH_MAX stops a real tree at
    // about two thousand levels - and a scan over a handful of 24-byte values beats
    // hashing one.
    std::vector<std::optional<DirectoryId>> chain;

    size_t dirCount = 0;

    std::error_code ec;

    // Deliberately *not* skip_permission_denied. That option's whole job is to
    // report a directory the scanner cannot read as no error at all, which left
    // an unreadable tree indistinguishable from an empty one - the scan quietly
    // covered less than the operator asked for and said nothing.
    //
    // The error_code overload of directory_iterator does not throw either way, so
    // dropping the option costs nothing in robustness: the walk still continues
    // past a directory it cannot open. It just knows that it did.
    //
    // directory_options::follow_directory_symlink used to be added here when the
    // setting was on, alongside the push below that queues a linked directory. Only one
    // of the two ever did anything: the option is consulted by
    // recursive_directory_iterator, and this walk uses the plain one, which yields the
    // same entries with the same is_directory() and is_symlink() answers whichever way
    // the option is set. Measured on this host rather than read off the standard, and
    // with the recursive iterator beside it as the control - it yields 4 entries with
    // the option off and 5 with it on, where the plain one yields the same 3 both
    // times. So the push is what follows a linked directory, and the option was a
    // second thing that looked like it did.
    const auto options = fs::directory_options::none;

    auto processEntry = [&](const fs::directory_entry& entry) -> bool {
        if (stopped) return false;

        // The interrupt, per entry rather than only per directory.
        //
        // A directory can hold ten million entries and reading it is one pass with no
        // way out, so a check between directories is not a check at all on the tree
        // that needs one. It is not enough to leave this to the file callback either:
        // the callback is reached only by a regular file, so a tree of nothing but
        // directories reaches it never - which is exactly the tree an attacker builds,
        // and exactly the reproduction that made Ctrl+C do nothing.
        //
        // The load is relaxed and the flag is one word: ten million of them cost about
        // ten milliseconds against ten million readdir and stat calls.
        if (interrupted()) {
            stopped = true;
            return false;
        }

        if (entry.is_directory(ec)) {
            // A linked directory is queued only when the operator asked for it. Whether
            // queueing it would close a loop is not decided here: the answer needs the
            // directory's identity and the identities of everything above it, and the
            // loop below is where both are known.
            if (config_.recursive && (!entry.is_symlink(ec) || config_.followSymlinks)) {
                children.push_back(entry.path());
            }
            return true;
        }

        if (!entry.is_regular_file(ec)) {
            return true;
        }

        // Check symlink handling
        if (entry.is_symlink(ec) && !config_.followSymlinks) {
            return true;
        }

        FileInfo info;
        info.path = entry.path();
        info.isSymlink = entry.is_symlink(ec);

        // Filters first. An excluded file is excluded whatever its size - deciding
        // that a 6 GB file the operator told us to ignore was "skipped for size"
        // is backwards, and it is the size skip that gets read as a coverage gap.
        if (!matchesFilters(entry.path())) {
            info.size = 0;
            info.skip = SkipReason::Excluded;
            if (!callback(info)) {
                stopped = true;
                return false;
            }
            return true;
        }

        // `ec` and oversize are two different facts and must not share a branch.
        // Conflated, a failed file_size() left `fileSize` unspecified (0 on
        // libstdc++), so the file was reported as a size skip and then, because
        // 0 > maxFileSize is false, read anyway - and reported scanned and clean.
        std::error_code sizeEc;
        auto fileSize = entry.file_size(sizeEc);
        if (sizeEc) {
            info.size = 0;
            info.skip = SkipReason::Unreadable;
        } else {
            info.size = fileSize;
            if (config_.maxFileSize > 0 && fileSize > config_.maxFileSize) {
                info.skip = SkipReason::Size;
            }
        }

        if (!callback(info)) {
            stopped = true;
            return false;
        }
        return true;
    };

    while (!pending.empty() && !stopped) {
        // The interrupt, per directory. The check inside processEntry covers one
        // enormous directory; this one covers a great many small ones, and a tree of
        // empty directories reaches no entry at all.
        if (interrupted()) {
            stopped = true;
            break;
        }

        const PendingDir current = std::move(pending.back());
        pending.pop_back();

        // The ancestors of `current` are exactly the directories at depths 0 to
        // depth-1, and after a depth-first pop those are exactly the first `depth`
        // entries of the chain: whatever the previous iteration left below that point
        // was on a path through the same directories. Truncating here is what retires
        // a subtree's identities without a second pass or a marker on the stack.
        chain.resize(current.depth);

        // One call, two answers: whether this is still a directory, and which directory
        // it is. Quiet about a path that is not one by the time the walk reaches it - a
        // subdirectory can vanish under a running scan, and that is a race and nobody's
        // error; a root the operator named and got wrong is walk()'s question, because
        // walk() is the only place that knows a path came from the operator.
        const DirectoryProbe probe = probeDirectory(current.path);
        if (!probe.isDirectory) {
            continue;
        }

        // The loop check. `probe.id` is absent when the host would not name this
        // directory, and an absent identity matches nothing, so such a directory is
        // entered rather than refused: a missed loop costs time, which the interrupt
        // above bounds, and a wrong refusal costs coverage, which nothing recovers.
        if (probe.id && std::any_of(chain.begin(), chain.end(),
                                    [&probe](const std::optional<DirectoryId>& ancestor) {
                                        return ancestor && *ancestor == *probe.id;
                                    })) {
            // Counted rather than inferred. It is not in dirCount, because the walk did
            // not enter it, and no other number here goes down when this happens - so
            // without a counter of its own the refusal is indistinguishable from a tree
            // that simply had one fewer directory in it.
            if (cycleSkippedDirs) {
                ++*cycleSkippedDirs;
            }
            continue;
        }
        chain.push_back(probe.id);

        if (dirCallback_) {
            dirCallback_(current.path);
        }

        ++dirCount;
        children.clear();

        try {
            for (const auto& entry : fs::directory_iterator(current.path, options, ec)) {
                if (!processEntry(entry)) break;
            }
            // directory_options::skip_permission_denied means the iterator swallows an
            // unreadable subdirectory silently; `ec` is where it says so.
            if (ec && unreadableDirs) {
                ++*unreadableDirs;
            }
        } catch (const fs::filesystem_error&) {
            // A directory the scanner was pointed at and could not read is a fact about
            // the scan's coverage, not nothing.
            if (unreadableDirs) {
                ++*unreadableDirs;
            }
        }

        // Reversed, so the deepest-first stack hands them back in listing order.
        for (auto child = children.rbegin(); child != children.rend(); ++child) {
            pending.push_back({std::move(*child), current.depth + 1});
        }
    }

    return dirCount;
}

bool FileWalker::matchesFilters(const std::filesystem::path& path) const {
    // If no include filters, include everything
    // If include filters exist, file must match at least one
    bool included = config_.include.empty();

    if (!included) {
        for (const auto& pattern : config_.include) {
            if (matchesGlob(pattern, path)) {
                included = true;
                break;
            }
        }
    }

    if (!included) {
        return false;
    }

    // Check exclude patterns
    for (const auto& pattern : config_.exclude) {
        if (matchesGlob(pattern, path)) {
            return false;
        }
    }

    return true;
}

CountResult FileWalker::countFiles(const CountProgressCallback& onProgress,
                                   const CountAugmentCallback& augment) const {
    CountResult result;

    // Counting is a full traversal in its own right and can run for minutes on a
    // large tree, so it has to honour an interrupt too - otherwise Ctrl+C during
    // the count appears to do nothing until the count finishes.
    //
    // This callback is not the whole of that and never was: it is reached by a regular
    // file, so a tree of directories and directory symlinks reaches it never and the
    // count ran on regardless. walkDirectory() polls the flag itself now, which is what
    // stops this traversal as well as the scanning one - and the count is the traversal
    // that runs on a spawned thread, so it is also the one whose refusal to stop is
    // invisible from the terminal.
    walk([&result, &onProgress, &augment](const FileInfo& info) {
        if (interrupted()) {
            return false;
        }
        // The walk now reports excluded files so they can be tallied; they are not
        // work, so they must not enter the total the progress bar divides by.
        if (info.skip == SkipReason::Excluded) {
            return true;
        }
        ++result.files;
        result.bytes += info.size;
        if (augment) {
            augment(info, result);
        }
        if (onProgress && (result.files % 512) == 0) {
            onProgress(result.files);
        }
        return true;  // Continue counting
    });

    return result;
}

bool FileWalker::matchesGlob(const std::string& pattern, const std::filesystem::path& path) {
    // Handle special "!ext" pattern (files without extension)
    if (pattern == "!ext") {
        return !path.has_extension();
    }

    // Try matching against filename only first
    std::string filename = path.filename().string();
#ifdef _WIN32
    if (portable_fnmatch(pattern.c_str(), filename.c_str())) {
        return true;
    }

    // For patterns with **, try matching against full path
    if (pattern.find("**") != std::string::npos) {
        std::string fullPath = path.string();
        if (portable_fnmatch(pattern.c_str(), fullPath.c_str())) {
            return true;
        }
    }
#else
    if (fnmatch(pattern.c_str(), filename.c_str(), FNM_PATHNAME) == 0) {
        return true;
    }

    // For patterns with **, try matching against full path
    if (pattern.find("**") != std::string::npos) {
        std::string fullPath = path.string();
        if (fnmatch(pattern.c_str(), fullPath.c_str(), FNM_PATHNAME) == 0) {
            return true;
        }
    }
#endif

    return false;
}

}  // namespace lyxbosa
