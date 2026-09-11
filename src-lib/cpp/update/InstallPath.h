#pragma once

// InstallPath.h - where this binary is, whether it may be replaced, and the replace.
//
// THE REPLACE, AND WHY IT IS SHAPED LIKE indexio.write_jsonl_atomic
// -------------------------------------------------------------------
// Write the new file beside the target, verify it there, fsync it, then rename over the
// old one. On Linux and macOS the rename is atomic and a running process keeps its
// inode, so a crash at any point leaves the old binary in place and running. The one
// thing never done is to write into the target itself: a partial write over a scanner
// somebody is running during an incident is not a failure they can recover from with
// the tool they were using.
//
// The directory is fsynced after the rename as well as the file before it. Without the
// second fsync the rename can be lost by a power failure that the file's own fsync
// survived, which leaves the directory entry pointing at the old inode and the new file
// under a temporary name - recoverable, but not the guarantee this claims to give.
//
// THE SAME THING ON WINDOWS, IN TWO MOVES
// ----------------------------------------
// Windows will not overwrite or delete a file that is mapped as a running image, and a
// rename over the running .exe is refused for the same reason. It will RENAME the
// running file, because that changes the directory entry and not the file. So the
// replace there is two moves rather than one rename:
//
//     lyxbosa.exe          ->  lyxbosa.exe.old      (the running image, moved aside)
//     lyxbosa.exe.update-N ->  lyxbosa.exe          (the verified download, into place)
//
// Both stay inside the install directory, so both stay on one volume; MoveFileExW does
// not move across volumes with the flags used here, and a copy-and-delete would not be
// the operation this claims to be. MOVEFILE_WRITE_THROUGH on each move is the directory
// fsync's counterpart: the call does not return until the rename has reached the disk.
//
// Between the two moves the target does not exist. If the second move fails - the
// volume filled, a real-time scanner grabbed the file, a permission changed - the first
// is undone: the .old is moved back and the message says what happened. A user left with
// no lyxbosa.exe at all is a worse outcome than a failed update, and the rollback has a
// test that drives it rather than a comment that claims it.
//
// The .old cannot be deleted by the process running from it, so it is reaped later:
// every start of the binary removes it if nothing has it open, silently, and the replace
// itself tries once too for the case where the target was not the running image. Its
// name is fixed, so at most one of them ever exists - the next update replaces it - and
// a failure to remove it is never fatal and never printed, because the ordinary reason
// is that another copy of the old binary is still running.
//
// A freshly written executable is opened by Defender's real-time scanner within a
// moment of being closed, and a move can fail against that open with a sharing
// violation. Each move is therefore retried against a lock for a bounded time,
// kReplaceRetryFor, and the real reason is reported on giving up. A lock is never
// treated as success and the retry never loops without end.
//
// REFUSING RATHER THAN ESCALATING
// --------------------------------
// If the target cannot be replaced by the current user, `update` says so and stops. It
// does not re-exec under sudo, prompt for a password, or suggest one. A scanner that
// rewrites a system binary because a version check said so is a footgun, and the
// version check is the least trustworthy input in the program.
//
// And if a package manager owns the path, it declines. An updater fighting apt leaves a
// package database describing a file that is no longer there, and the next `apt upgrade`
// either reverts the update or fails; either way the user is worse off than with no
// updater at all.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace lyxbosa {

// The file this process is running from, resolved through symlinks so that replacing it
// replaces the real file rather than a link. Empty when the platform cannot say, which
// is a refusal rather than a guess: argv[0] is caller-controlled and is not an answer.
std::filesystem::path runningExecutablePath();

// The package manager that owns `path`, or empty when none does.
//
// A path list rather than a call to dpkg or rpm, and the trade is deliberate. Asking
// the package manager is exact but needs the package manager to be installed, to be
// fast, and to be spawned as a subprocess from a program that is about to replace
// itself. The list is a heuristic, and it is wrong in one direction only: a binary
// hand-copied into /usr/bin is refused when it did not have to be, which costs the user
// a manual download. The other direction - installing over a file dpkg believes it owns
// - is the one that breaks a system, so the heuristic errs towards refusing.
//
// /usr/local/bin is deliberately NOT on the list. The FHS reserves it for the local
// administrator and no distribution package installs there, so it is precisely the
// hand-installed case this is meant to allow.
std::string_view packageManagerOwning(const std::filesystem::path& path);

// Whether the current user could actually replace `target`.
//
// The question is about the DIRECTORY, not the file: an atomic replace renames a new
// file over the old one, which needs write permission on the containing directory and
// none at all on the file itself. And it is answered by writing, not by looking at
// permission bits - the same argument UpdateState.h makes about its own probe. A
// read-only mount, a full filesystem, an immutable attribute and a container's
// restrictions are all invisible to a stat and all decide this.
struct ReplaceAccess {
    bool ok = false;
    std::string reason;  // empty when ok
};
ReplaceAccess canReplace(const std::filesystem::path& target);

// The permission bits of an existing file, so a replacement can carry them. Nullopt
// when the file cannot be stat'ed.
std::optional<uint32_t> fileMode(const std::filesystem::path& path);

// A staging path beside `target`, in the same directory so the rename stays within one
// filesystem. A rename across filesystems is not atomic and not even permitted, which
// is why /tmp is not used for this however convenient it looks.
std::filesystem::path stagingPathFor(const std::filesystem::path& target);

// Give `staged` the permission bits of `target`, and its owner where this process is
// allowed to. Returns an empty string on success and the reason otherwise.
//
// It is separate from the replace because it has to happen BEFORE the staged file is
// executed: a download arrives 0644 from the umask of whoever ran the update, and
// exec on a file without its execute bit fails with a permission error that looks
// exactly like a binary that will not run on this host. Two different problems, one
// message, and the wrong one.
std::string adoptTargetOwnership(const std::filesystem::path& staged,
                                 const std::filesystem::path& target);

// fsync `staged`, rename it over `target`, then fsync the directory. Returns an empty
// string on success and the reason otherwise. On failure `target` is untouched.
//
// It applies adoptTargetOwnership again rather than assuming a caller did, so that it
// is correct on its own; doing it twice costs one fchmod.
//
// On Windows it is the two moves described at the top of this file, with the same
// contract: an empty string means the new binary is in place, and anything else means
// `target` still holds the old one - put back, if it had to be.
std::string replaceAtomically(const std::filesystem::path& staged,
                              const std::filesystem::path& target);

// Where the running binary is moved to while the new one takes its place: `target`
// with ".old" appended, in the same directory. Nothing on POSIX ever creates it; it is
// declared everywhere so that the reaper below has one definition and one test.
std::filesystem::path movedAsidePathFor(const std::filesystem::path& target);

// Remove the moved-aside copy of `target` if it exists and nothing has it open. Returns
// true when no such file remains, false when one does - which is not an error and is
// never reported to a user: the common cause is a copy of the old binary still running.
// Called on every start (src-cli/lyxbosa.cpp) and after every replace.
bool reapMovedAsideBinary(const std::filesystem::path& target);

#ifdef _WIN32
// How long a move is retried against a file something else has open before the reason
// is reported. The last Windows round measured Defender taking a freshly written file
// within a second of it being closed; five times that is a bound, not a loop. Each move
// gets its own budget, so a replace that needs the rollback can take up to three of
// them.
inline constexpr std::chrono::milliseconds kReplaceRetryFor{5000};

// The two-move replace, with its retry bound as a parameter so that a test can drive
// the rollback in a fraction of the time a user would wait. replaceAtomically() is this
// with kReplaceRetryFor.
std::string replaceByMovingAside(const std::filesystem::path& staged,
                                 const std::filesystem::path& target,
                                 std::chrono::milliseconds retryFor);
#endif

// Run `binary --version` and report whether it exited 0.
//
// This is what catches a release that verifies perfectly and cannot run here - most
// realistically a glibc newer than the host's, since the release binaries are built on
// AlmaLinux 8 and a user may be older still. Without it the update replaces a working
// scanner with one that will not start, on a host somebody is in the middle of an
// incident on, and the tool they would use to fix it is the one just broken.
//
// On Windows the same, through CreateProcessW with every standard handle on NUL. One
// thing it can meet there that it cannot on Linux: Defender's cloud check can hold the
// first execution of a never-seen binary while it asks for a verdict, and if that
// outlasts the ten-second bound the update refuses with StagedBinaryUnusable. The old
// binary is untouched by then and a second `update` finds the verdict cached.
//
// It executes bytes that have already passed the signature and the hash check, and that
// are about to be installed and run anyway, so it does not widen what this program will
// execute - it only moves the moment forward to where the old binary is still there.
bool stagedBinaryRuns(const std::filesystem::path& binary);

}  // namespace lyxbosa
