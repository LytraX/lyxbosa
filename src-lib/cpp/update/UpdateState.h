#pragma once

// UpdateState.h - the cache file that makes "at most once per interval" true.
//
// Two properties decide the design, and both are requirements rather than taste:
//
//   The timestamp is written BEFORE the request, not after. A check that records
//   only its successes checks again on every run for as long as the network is
//   unreachable - which is precisely the egress-filtered container the design set out
//   not to hammer. reserve() is that write, and it doubles as the proof that the file
//   is writable at all: docs/tasks/UPDATE_PLAN.md 5 says "no cached state file
//   writable: never, silently", and the only honest way to know is to write one.
//
//   The write is atomic. A half-written state file read on the next run is a parse
//   failure, and a parse failure here means "never checked" - back to checking every
//   run. Temp file, then rename, the same discipline as indexio.write_jsonl_atomic.
//
// The format is `key=value` lines rather than JSON because everything that reads it
// has to be total: an unknown key, a missing key, a truncated line, a timestamp that
// is not a number and a file full of zero bytes all have to mean "we do not know",
// and none of them may throw into a scan. A key this version does not recognise is
// ignored rather than refused, so a file written by a newer binary cannot push an older
// one back to acting on every run - and a key it no longer relies on is still read, so
// the reverse is true too.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace lyxbosa {

struct UpdateState {
    uint64_t lastCheckEpoch = 0;   // when we last asked, 0 for never
    std::string latestVersion;     // what the answer was, empty when we never got one

    // When the "this host could run the standard build" line was last said, or nullopt
    // for never. A timestamp rather than a flag because the line is repeated on an
    // interval - see kPortableNoticeIntervalSeconds in UpdatePolicy.h for the interval
    // and for why once-ever was the wrong shape.
    std::optional<uint64_t> portableNoticeEpoch;

    // The same fact as written by a binary from before that timestamp existed: said,
    // with no when. Read so that an upgrade does not repeat a line the operator already
    // dismissed; ignored entirely once portableNoticeEpoch is set, which is the first
    // thing the next qualifying run does.
    //
    // It is still WRITTEN, beside the timestamp, and that is for a reader rather than
    // for this version: a binary rolled back to one that only knows the flag keeps its
    // own once-ever contract instead of re-announcing. The file is a cache under
    // XDG_CACHE_HOME and safe to delete, so one extra line is the whole cost.
    bool portableNoticeShownLegacy = false;
};

// Where the state lives when nothing overrides it.
//
// LYXBOSA_UPDATE_STATE names the file outright, which is how a test drives this
// without a home directory and how an operator points it at a writable path on a
// host where the cache directory is not one. Empty when no location can be worked
// out at all - no HOME, no XDG_CACHE_HOME, no LOCALAPPDATA - and an empty path is
// treated as "not writable", so the check silently does not happen.
std::filesystem::path defaultUpdateStatePath();

// Read the state. Returns nullopt for a missing, unreadable or unparseable file;
// every one of those means "we have never checked", which is the safe answer.
// Never throws.
std::optional<UpdateState> readUpdateState(const std::filesystem::path& path);

// Write the state atomically, creating the parent directory. Returns false on any
// failure, including a path that is empty. Never throws.
//
// The whole file, from whatever is in `state`, so every field not set in the caller's
// copy is erased. Nothing outside this file calls it, and the three record functions
// below are why: each reads before it modifies, which is the only safe way to change one
// field of a file several unrelated features share. A test that needs a file of a
// particular shape calls this directly, which is what it is still declared for.
bool writeUpdateState(const std::filesystem::path& path, const UpdateState& state);

// Record that a check is about to happen, keeping whatever version the previous
// state knew about. Returns false when the file could not be written - which is the
// answer to "is the state writable", and the caller must then not check at all.
bool reserveUpdateCheck(const std::filesystem::path& path, uint64_t nowEpoch);

// Record what a completed check found: the time it ran and the version it saw, keeping
// everything else the file already holds. Returns false when it could not be written,
// which every caller treats as best-effort - an answer that could not be cached still
// answered, it just does not spare the next scan a request.
//
// EVERY writer of that pair goes through here, and that is the point of the function
// rather than the convenience of it. Three call sites each built an UpdateState from
// nothing and wrote it, which wrote two correct fields and silently erased every other
// field the file held - the portable-build notice's timestamp among them, so a successful
// update check reset a cadence it has no business touching. Each of the three looked
// right on its own. The same argument as corpus/indexio.py one layer out: read inside the
// operation, immediately before writing, and leave no path that does not.
bool recordLatestVersion(const std::filesystem::path& path, uint64_t nowEpoch,
                         const std::string& version);

// Record that the portable-build notice has been said at `nowEpoch`, keeping everything
// else the file already holds. Returns false when it could not be written, which is the
// answer to "is the state writable" for a run that is not also doing an update check -
// and a notice that cannot be recorded must not be printed, or it prints on every run.
//
// Written BEFORE the line reaches the terminal, for the same reason the update check
// reserves before it asks: the failure that matters is the one that repeats.
//
// The epoch is a parameter and not a clock read in here, so that a test can place the
// last-said time an interval either side of now without sleeping.
bool recordPortableNoticeShown(const std::filesystem::path& path, uint64_t nowEpoch);

// Seconds since the Unix epoch. A free function so tests drive time explicitly.
uint64_t currentEpochSeconds();

}  // namespace lyxbosa
