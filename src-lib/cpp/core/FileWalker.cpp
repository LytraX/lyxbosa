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

// For the directory identity and the link classification below. Separate from the block
// above, which is about glob matching and nothing else.
#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#include <cwctype>
#include <string_view>
#else
#include <sys/stat.h>
#include <cerrno>
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
//
// Quiet means gone, and only gone. A path the host will not describe for any other reason
// - on POSIX, a subdirectory of a directory this user may list and may not search - comes
// back as a directory with no identity, so the walk enters it and the listing fails and is
// counted as unreadable on its own terms. Calling that one gone dropped the subdirectory
// and everything under it without a word, while a file beside it in the same directory was
// counted as unreadable.
struct DirectoryProbe {
    bool isDirectory = false;
    std::optional<DirectoryId> id;
};

DirectoryProbe probeDirectory(const std::filesystem::path& dir) {
    DirectoryProbe out;

#ifdef _WIN32
    const DWORD attributes = ::GetFileAttributesW(dir.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD error = ::GetLastError();
        out.isDirectory = error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND;
        return out;
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
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
    if (::stat(dir.c_str(), &info) != 0) {
        const int error = errno;
        out.isDirectory = error != ENOENT && error != ENOTDIR;
        return out;
    }
    if (!S_ISDIR(info.st_mode)) {
        return out;
    }
    out.isDirectory = true;
    out.id = DirectoryId{static_cast<uint64_t>(info.st_dev), 0,
                         static_cast<uint64_t>(info.st_ino)};
#endif

    return out;
}

// ---------------------------------------------------------------------------
// Which entries scan.follow_symlinks governs
// ---------------------------------------------------------------------------
//
// A link, to this walk, is a name that stands for a path somewhere else. On POSIX that is
// a symbolic link and nothing more. On Windows two reparse tags make one:
//
//   IO_REPARSE_TAG_SYMLINK      a symbolic link, to a file or to a directory
//   IO_REPARSE_TAG_MOUNT_POINT  a directory junction - unless what it stores is the root
//                               of a volume, which makes it a volume mount point
//
// A junction is a link in every way the setting cares about: anybody who can write to a
// directory can make one, with no privilege, pointing anywhere on the machine. So it takes
// the same rule as a directory symbolic link. std::filesystem does not say so by itself -
// Microsoft's library reports a junction as file_type::junction, is_symlink() is false for
// it, and a walk that asked is_symlink() alone descended one with follow_symlinks off.
// That was measured with the MSVC build, not read off the library.
//
// A volume mount point carries the same tag and is not a link. It is how Windows attaches
// a volume at a folder - what a mount is on Linux, where the walk crosses mounts without
// asking - and the volume behind it holds content reachable by no other path under the
// root. Refusing it would drop that content from the scan. It is told from a junction by
// what the file system stores for it, a volume GUID path and nothing after it, and never
// by the entry's name.
//
// Every other reparse tag is not a link. OneDrive and other cloud placeholders,
// deduplicated files and the rest are the file or directory they present themselves as,
// and treating a reparse point as a link merely because it is one would drop real content
// without a word. An app execution alias is not a link either, and it presents nothing: the
// library cannot open one to ask its type, so walkDirectory() counts it as an entry whose
// type could not be read.
//
// When the file system will not say what a mount-point-tagged entry stores, the entry is
// not a link and the walk goes through it. The asymmetry is DirectoryId's: walking a link
// the operator did not ask for costs time, which the loop check and the interrupt bound,
// and refusing a directory that was not a link costs coverage, which nothing recovers.
#ifdef _WIN32

// `\??\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\`, the form the mount manager writes
// into a volume mount point. A junction to a directory INSIDE a volume named that way has
// more after the brace and is a junction.
bool isVolumeRoot(std::wstring_view target) {
    constexpr std::wstring_view prefix = L"\\??\\Volume{";
    constexpr size_t guidLength = 36;
    if (!target.empty() && target.back() == L'\\') {
        target.remove_suffix(1);
    }
    if (target.size() != prefix.size() + guidLength + 1 || target.back() != L'}') {
        return false;
    }
    if (::_wcsnicmp(target.data(), prefix.data(), prefix.size()) != 0) {
        return false;
    }
    for (size_t i = 0; i < guidLength; ++i) {
        const wchar_t c = target[prefix.size() + i];
        const bool dash = (i == 8 || i == 13 || i == 18 || i == 23);
        if (dash ? c != L'-' : !std::iswxdigit(c)) {
            return false;
        }
    }
    return true;
}

// Whether the mount-point-tagged entry at `path` is a junction, asked of the reparse data
// the file system stores for it. False for a volume mount point, for any other tag, and
// for data that cannot be read - see above for why that last one is not a link.
bool isJunction(const std::filesystem::path& path) {
    // FILE_FLAG_OPEN_REPARSE_POINT opens the junction itself rather than what it leads
    // to, and FSCTL_GET_REPARSE_POINT needs no access right beyond opening it.
    const HANDLE handle = ::CreateFileW(
        path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    // On the heap: 16 KiB is more than a walk running on a small thread should put on its
    // stack, and this is reached only by entries that are already reparse points.
    std::vector<unsigned char> data(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    DWORD returned = 0;
    const BOOL read = ::DeviceIoControl(handle, FSCTL_GET_REPARSE_POINT, nullptr, 0,
                                        data.data(), static_cast<DWORD>(data.size()),
                                        &returned, nullptr);
    ::CloseHandle(handle);

    // The layout ntifs.h declares and user mode has no header for: the tag, a data length
    // and a reserved word, then four USHORTs - substitute name offset and length, print
    // name offset and length - and the names, offsets counted from the end of those four.
    constexpr size_t namesStart = 16;
    if (!read || returned < namesStart) {
        return false;
    }
    ULONG tag = 0;
    std::memcpy(&tag, data.data(), sizeof(tag));
    if (tag != IO_REPARSE_TAG_MOUNT_POINT) {
        return false;
    }
    USHORT offset = 0;
    USHORT length = 0;
    std::memcpy(&offset, data.data() + 8, sizeof(offset));
    std::memcpy(&length, data.data() + 10, sizeof(length));
    if (namesStart + size_t{offset} + size_t{length} > returned) {
        return false;
    }
    std::wstring substitute(length / sizeof(wchar_t), L'\0');
    std::memcpy(substitute.data(), data.data() + namesStart + offset,
                substitute.size() * sizeof(wchar_t));
    return !isVolumeRoot(substitute);
}

#endif  // _WIN32

bool isLink(const std::filesystem::directory_entry& entry) {
    std::error_code ec;
#ifdef _WIN32
    // The type the directory listing reported for the entry itself. It costs nothing - the
    // listing already carried the reparse tag - and it settles every entry except the
    // ambiguous one: symlink is IO_REPARSE_TAG_SYMLINK, and a reparse point with any tag
    // but the two above comes back as the directory or file it presents itself as.
    const std::filesystem::file_type own = entry.symlink_status(ec).type();
    if (ec) {
        return false;
    }
    if (own == std::filesystem::file_type::symlink) {
        return true;
    }
    if (own == std::filesystem::file_type::directory ||
        own == std::filesystem::file_type::regular) {
        return false;
    }
    // What is left is IO_REPARSE_TAG_MOUNT_POINT, which Microsoft's library names
    // file_type::junction for both of its uses. Only the file system can tell them apart.
    return isJunction(entry.path());
#else
    return entry.is_symlink(ec);
#endif
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
                        size_t* cycleSkippedDirs, size_t* linksNotFollowed,
                        size_t* unreadableEntries) const {
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
        // A root that is itself a link is walked whatever followSymlinks says, on the same
        // grounds: the operator named that path, so it is the tree they asked for, and
        // refusing it would report a clean scan of nothing. The setting is about links the
        // walk finds inside the tree, and walkDirectory() applies it only to those.
        dirCount += walkDirectory(dir, callback, stopped, unreadableDirs, cycleSkippedDirs,
                                  linksNotFollowed, unreadableEntries);
        // `stopped` is set by a callback that refused and by the interrupt flag, and
        // either way the roots after this one are not walked. Which of the two it was
        // is interrupted()'s answer and not this loop's; Scanner::scan() asks it.
        if (stopped) break;
    }

    return dirCount;
}

size_t FileWalker::walkDirectory(const std::filesystem::path& dir, FileCallback callback, bool& stopped,
                                 size_t* unreadableDirs, size_t* cycleSkippedDirs,
                                 size_t* linksNotFollowed, size_t* unreadableEntries) const {
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

    // An entry whose type the host would not give.
    //
    // The walk asks every entry two questions - is it a directory, is it a regular file - and
    // a refusal answers neither. Measured: an app execution alias on Windows refuses both with
    // ERROR_CANT_ACCESS_FILE, and on Linux a link refuses them with EACCES when what it leads
    // to sits behind a directory this user may not search, and with ELOOP when it leads back
    // to itself. Each of those was passed by as though it were not in the listing.
    //
    // Counted on its own rather than in either tally beside it, because each of those is a
    // claim about what the entry was. SkipReason::Unreadable is a file handed to the scanner:
    // it enters Files scanned and the progress total, gets a report row, and has FN rules
    // asked of its name as a file's. directoriesUnreadable is a directory the walk entered and
    // could not list. Nobody can say which of the two this was - behind the refusal there may
    // be one file or a whole tree - so it is neither, and the count says only what is known:
    // the scan did not read it. The directory it was listed in was read, and is not touched.
    //
    // A refusal that says the path leads nowhere is not one of these. A dangling link and an
    // entry removed since the listing are answered - nothing is there - and the library calls
    // that file_type::not_found on both platforms. The status is asked again to learn which it
    // was, so that the library's own definition of not found decides it rather than a list of
    // error numbers per host; and only here, so an entry whose type was read never pays for it.
    auto noteTypeRefused = [&](const fs::directory_entry& entry) {
        std::error_code again;
        if (entry.status(again).type() != fs::file_type::not_found && unreadableEntries) {
            ++*unreadableEntries;
        }
    };

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

        // Its own error_code, and never the iterator's. The iterator's says whether this
        // directory could be listed; this one says whether one entry in it could be asked
        // about. Shared, the last entry's answer was what the walk read as the directory's,
        // so a directory whose last entry was a dangling link reported itself unreadable.
        std::error_code typeEc;
        const bool directory = entry.is_directory(typeEc);
        if (typeEc) {
            noteTypeRefused(entry);
            return true;
        }

        if (directory) {
            // A linked directory is queued only when the operator asked for it - and a
            // link is what isLink() says, which on Windows includes a junction and does not
            // include a volume mount point. Whether queueing it would close a loop is not
            // decided here: the answer needs the directory's identity and the identities
            // of everything above it, and the loop below is where both are known.
            //
            // A link refused here is counted, because nothing else about the scan moves
            // when it happens: the tree behind it is simply absent from every total. Only
            // in a recursive walk, where the link would otherwise have been entered - a
            // walk that enters no subdirectory has refused nothing by not entering this one.
            if (config_.recursive) {
                if (config_.followSymlinks || !isLink(entry)) {
                    children.push_back(entry.path());
                } else if (linksNotFollowed) {
                    ++*linksNotFollowed;
                }
            }
            return true;
        }

        const bool regular = entry.is_regular_file(typeEc);
        if (typeEc) {
            noteTypeRefused(entry);
            return true;
        }

        if (!regular) {
            // Neither, and the host said so: a FIFO, a socket, a character or block device, or
            // a link to one. Passed by without a count, and deliberately.
            //
            // None of these is content a scan leaves unread. A scan reads a file's bytes and
            // these have none of their own: opening a FIFO waits for a writer that may never
            // come, which would hang the scan; a device yields whatever the device produces
            // for as long as it is read; and a socket does not open at all. So the walk must
            // never hand one to the callback, and passing one by leaves nothing out. A count
            // would add a line to every scan of a home directory where a database or PHP-FPM
            // left a socket, saying something no operator can act on - which is what separates
            // these from an entry of unknown type, which may be exactly the file a count
            // exists to reveal.
            //
            // Windows cannot always say this much. Microsoft's library cannot open an AF_UNIX
            // socket file to ask its type and refuses exactly as it does for an app execution
            // alias, so there such a socket is an entry of unknown type, and counted.
            return true;
        }

        // A linked file under the same rule and into the same count. A link that leads
        // nowhere never gets this far - the library answers not found for it above - and is
        // not a link to content this scan declined to read.
        const bool link = isLink(entry);
        if (link && !config_.followSymlinks) {
            if (linksNotFollowed) {
                ++*linksNotFollowed;
            }
            return true;
        }

        FileInfo info;
        info.path = entry.path();
        info.isSymlink = link;

        // Filters first. An excluded file is excluded whatever its size - deciding
        // that a 6 GB file the operator told us to ignore was "skipped for size"
        // is backwards, and it is the size skip that gets read as a coverage gap.
        const FilterVerdict verdict = filterVerdict(entry.path());
        if (verdict != FilterVerdict::Accepted) {
            info.size = 0;
            info.skip = SkipReason::Excluded;
            info.excludedByPattern = (verdict == FilterVerdict::Excluded);
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

        // The iterator's alone: set when this directory could not be opened for listing. A
        // listing that fails part-way throws from the increment instead, and is caught below.
        std::error_code listEc;
        try {
            for (const auto& entry : fs::directory_iterator(current.path, options, listEc)) {
                if (!processEntry(entry)) break;
            }
            if (listEc && unreadableDirs) {
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

FileWalker::FilterVerdict FileWalker::filterVerdict(
    const std::filesystem::path& path) const {
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
        return FilterVerdict::NotIncluded;
    }

    // Check exclude patterns
    for (const auto& pattern : config_.exclude) {
        if (matchesGlob(pattern, path)) {
            return FilterVerdict::Excluded;
        }
    }

    return FilterVerdict::Accepted;
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
