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
// and none of them may throw into a scan.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace lyxbosa {

struct UpdateState {
    uint64_t lastCheckEpoch = 0;   // when we last asked, 0 for never
    std::string latestVersion;     // what the answer was, empty when we never got one

    // Whether the "this host could run the standard build" line has been said. It is
    // said once and never again, so this is a flag and not a timestamp: there is no
    // interval after which repeating it would be more use than the first time was.
    bool portableNoticeShown = false;
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
bool writeUpdateState(const std::filesystem::path& path, const UpdateState& state);

// Record that a check is about to happen, keeping whatever version the previous
// state knew about. Returns false when the file could not be written - which is the
// answer to "is the state writable", and the caller must then not check at all.
bool reserveUpdateCheck(const std::filesystem::path& path, uint64_t nowEpoch);

// Record that the portable-build notice has been said, keeping everything else the
// file already holds. Returns false when it could not be written, which is the answer
// to "is the state writable" for a run that is not also doing an update check - and a
// notice that cannot be recorded must not be printed, or it prints on every run.
//
// Written BEFORE the line reaches the terminal, for the same reason the update check
// reserves before it asks: the failure that matters is the one that repeats.
bool recordPortableNoticeShown(const std::filesystem::path& path);

// Seconds since the Unix epoch. A free function so tests drive time explicitly.
uint64_t currentEpochSeconds();

}  // namespace lyxbosa
