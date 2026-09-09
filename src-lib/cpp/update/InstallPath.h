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
std::string replaceAtomically(const std::filesystem::path& staged,
                              const std::filesystem::path& target);

// Run `binary --version` and report whether it exited 0.
//
// This is what catches a release that verifies perfectly and cannot run here - most
// realistically a glibc newer than the host's, since the release binaries are built on
// AlmaLinux 8 and a user may be older still. Without it the update replaces a working
// scanner with one that will not start, on a host somebody is in the middle of an
// incident on, and the tool they would use to fix it is the one just broken.
//
// It executes bytes that have already passed the signature and the hash check, and that
// are about to be installed and run anyway, so it does not widen what this program will
// execute - it only moves the moment forward to where the old binary is still there.
bool stagedBinaryRuns(const std::filesystem::path& binary);

}  // namespace lyxbosa
