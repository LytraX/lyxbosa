#pragma once

#include <filesystem>
#include <string>

// Moving a file into quarantine is evidence handling, not tidying. Two properties
// are wanted and they are separate problems, so they are two functions here.
//
//   destinationFor()      a destination that does not collide, and that still says
//                         which original the file was
//   moveWithoutReplacing() a move that refuses rather than overwrites, whatever is
//                         already at the destination
//
// Either one alone is not enough. A unique-looking destination computed from a
// path is still only as unique as the paths it was given; and a refusing move that
// keeps being handed the same destination cannot contain the second file. Together
// they give the operator a quarantine directory in which nothing has been silently
// replaced, and in which every file names where it came from.
namespace lyxbosa::quarantine {

// What happened to one attempt at one destination.
enum class MoveResult {
    Moved,               // the file is at `dest` and no longer at `source`
    DestinationExists,   // something was already there; nothing was read or written
    Failed,              // the platform refused for some other reason
};

// Where `source` belongs under `quarantineDir`.
//
// With `preserveStructure`, the source's whole absolute path is mirrored under the
// quarantine directory: `/var/www/a/wp/shell.php` lands at
// `<quarantine>/var/www/a/wp/shell.php`. Mirroring the *absolute* path rather than
// the path relative to the scan root is what makes this injective - distinct files
// cannot arrive at one destination - and it is also the only form that answers the
// question an analyst asks of a quarantined file, which is where it was taken from.
// A path relative to a scan root cannot answer that even when nothing collides,
// because the root is exactly the part it dropped.
//
// A Windows root name becomes one ordinary component (`C:` -> `C`,
// `\\server\share` -> `server_share`), so a drive letter is not lost either.
//
// Without `preserveStructure` the operator has asked for a flat directory and gets
// the filename alone; where the file came from is then not recoverable from the
// destination, which is the cost of that choice.
//
// The result is always inside `quarantineDir`: the source is normalised first, so
// no `..` in the operator's own path can walk the destination out of the directory
// they named.
std::filesystem::path destinationFor(const std::filesystem::path& quarantineDir,
                                     const std::filesystem::path& source,
                                     bool preserveStructure);

// `dest` with `n` inserted before the extension - `shell.php` -> `shell.1.php`.
// Used to step past a destination that is already taken.
std::filesystem::path withDisambiguator(const std::filesystem::path& dest, int n);

// Move `source` onto `dest`, never over anything already there.
//
// The refusal is the platform's, taken atomically, and is never a question this
// code asks first: `if (!exists(dest)) rename(...)` is a time-of-check-to-time-of-
// use race that protects against a second file in the same run and against nothing
// running beside it.
//
//   Linux    renameat2(RENAME_NOREPLACE) - a rename that fails with EEXIST rather
//            than replacing. Nothing is copied and nothing is unlinked.
//   macOS    renamex_np(RENAME_EXCL), the same thing under its own name.
//   Windows  MoveFileExW *without* MOVEFILE_REPLACE_EXISTING, which already refuses
//            by default, and with MOVEFILE_COPY_ALLOWED so it crosses volumes itself.
//
// Across a filesystem boundary a rename cannot work at all - EXDEV - and the same is
// true of the flag-bearing renames above. The POSIX arms fall back to creating the
// destination with O_CREAT|O_EXCL, which is the same refusal expressed as an
// exclusive create, copying the bytes through it, flushing, and only then unlinking
// the source. That fallback also covers a kernel or filesystem that does not
// implement the rename flag (ENOSYS, EINVAL, EOPNOTSUPP - overlayfs and some FUSE
// and NFS mounts), because the answer to "this filesystem cannot refuse" must not be
// a plain rename that replaces.
//
// The source is unlinked last, so an interruption leaves the evidence in two places
// rather than none. If the unlink fails the copy is removed again and the result is
// Failed: a quarantine that reports success while the original is still live is the
// failure this whole file exists to prevent.
MoveResult moveWithoutReplacing(const std::filesystem::path& source,
                                const std::filesystem::path& dest);

}  // namespace lyxbosa::quarantine
