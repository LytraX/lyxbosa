#pragma once

// UpdateCheck.h - running the check without ever letting it matter.
//
// The contract, which is the round's whole point:
//
//   It cannot fail a scan. A source that throws, hangs, returns nonsense or is not
//   there at all produces no notice and nothing else.
//   It cannot change an exit code. Nothing here returns a status to the caller.
//   It cannot delay output. resultIfReady() never blocks, so the notice is written
//   from whatever is known when the report is finished and never from waiting.
//
// A scanner that exits non-zero because GitHub was slow is a broken scanner, and so
// is one that takes two seconds longer to print because GitHub was slow.
//
// The destructor is the one place that waits, and it is not an exception to any of
// the above: the handle outlives the report, so by the time it runs the last byte has
// been printed. See kUpdateAnswerGrace.

#include "update/UpdatePolicy.h"
#include "update/UpdateState.h"
#include "update/Version.h"
#include "update/VersionSource.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <thread>

namespace lyxbosa {

// About two seconds. Long enough for a TLS handshake and a small response on a
// working connection, short enough that a wedged one is not worth noticing.
inline constexpr std::chrono::milliseconds kUpdateCheckTimeout{2000};

// How long teardown will wait for an answer the interval has already been spent on.
//
// THE DEFECT THIS EXISTS FOR
// The timestamp is written BEFORE the request - it has to be, or an unreachable
// network means a request on every run - and the answer was written only if the fetch
// finished. The destructor cancelled the worker the moment the scan ended, so a scan
// that finished before its request did burned the interval and learned nothing: the
// state file said a check had happened and never said what it found. Every later scan
// inside that interval then read an empty cache and stayed silent. For anyone whose
// scans are quick, the notice was not rare - it was unreachable.
//
// WHAT THIS COSTS
// Not output. The handle is a local of the scan command and outlives the report, so
// this wait begins after the last byte has been printed; nothing a person is reading
// is held back, and the exit code was decided before it. What it costs is up to this
// much extra process lifetime, at most once per interval, and only on a run that was
// allowed to check at all - interactive, on a terminal, not CI, and none of --force,
// --quiet or --silent. It is also skipped entirely for the common case where the
// worker has already finished, which is every scan slower than one request.
//
// One second, against a request measured at about a quarter of one. Four times the
// observed cost leaves room for a slow handshake without turning a cancelled network
// into a pause somebody notices; past it the answer is abandoned exactly as before.
inline constexpr std::chrono::milliseconds kUpdateAnswerGrace{1000};

struct UpdateCheckResult {
    FetchOutcome outcome;
    std::optional<Version> latest;   // set only when a version was fetched and parsed
    bool newerAvailable = false;
};

// Ask, compare, and answer. Synchronous; used directly by `update --check` and by
// the background worker. Never throws - a source that does is reported as a failed
// request, because a scan is not a place to find out that a version check has
// opinions.
UpdateCheckResult fetchAndCompare(VersionSource& source, const Version& running,
                                  std::chrono::milliseconds timeout);

// The sentence a scan prints, or "" when there is nothing to say.
//
// Two sources, in that order: the answer this run got, and failing that the answer a
// previous run cached. The second one is why most scans say something useful without
// making a request at all - one scan a day asks, and every scan that day can still
// tell you. It is also what stops a scan that finished before the request did from
// throwing the answer away: the reply is not waited for, so on a fast scan there
// often is no fresh result, and the cache is the whole reason that is survivable.
//
// Every failure shape - no transport, a refused request, an unparseable answer, a
// check that never finished, an empty cache - is nothing to say. Only a strictly
// newer release is worth a line.
std::string updateNotice(const std::optional<UpdateCheckResult>& fresh,
                         const std::optional<Version>& known,
                         const Version& running);

// A check running beside a scan.
class BackgroundUpdateCheck {
public:
    BackgroundUpdateCheck(std::shared_ptr<VersionSource> source, Version running,
                          std::filesystem::path statePath, uint64_t startedAtEpoch,
                          std::chrono::milliseconds timeout = kUpdateCheckTimeout,
                          std::chrono::milliseconds grace = kUpdateAnswerGrace);

    // Waits up to `grace` for an answer, then cancels and joins. Cancellation is
    // prompt: the flag is what the source is required to watch, and the real one polls
    // it every 50 ms and abandons the transfer when it is set. So the bound on
    // teardown is the grace, not the timeout - and a check already finished costs
    // nothing at all.
    ~BackgroundUpdateCheck();

    BackgroundUpdateCheck(const BackgroundUpdateCheck&) = delete;
    BackgroundUpdateCheck& operator=(const BackgroundUpdateCheck&) = delete;

    // The result if the worker has finished, nullopt if it has not. Never blocks,
    // and calling it does not make the caller start waiting.
    std::optional<UpdateCheckResult> resultIfReady() const;

private:
    std::shared_ptr<VersionSource> source_;
    Version running_;
    std::filesystem::path statePath_;
    uint64_t startedAtEpoch_ = 0;
    std::chrono::milliseconds timeout_;
    std::chrono::milliseconds grace_;

    std::atomic<bool> cancel_{false};
    std::atomic<bool> done_{false};
    UpdateCheckResult result_;   // published by done_, read only after it is set
    std::thread worker_;
};

// Everything a caller needs afterwards, and nothing it could misuse.
struct UpdateCheckHandle {
    // The request, when one was started. Null means no request was made - and in that
    // case nothing was sent and nothing was written.
    std::unique_ptr<BackgroundUpdateCheck> live;

    // What a previous run already learned, when it is worth repeating. Empty when the
    // cache holds nothing, holds something unparseable, or holds a version this build
    // is not older than.
    std::optional<Version> known;

    // Whether this run may say anything at all. False for every run that must be
    // silent - `check`, an unattended or redirected or CI run, a development build,
    // updates.check off - and true for a run that was merely inside its interval,
    // which is entitled to repeat what it already knows without asking again.
    bool mayNotify = false;

    UpdateDecision decision = UpdateDecision::SkipDisabled;
};

// Decide whether to check and, if so, start one. This is the scan's entry point;
// `update --check` calls fetchAndCompare directly, because a person who typed the
// command is waiting for the answer and wants the reason when there is not one.
//
// The state file is written BEFORE the request rather than after it. That write is
// how "at most once per interval" survives a failure: a check that recorded only its
// successes would run again on every single invocation for as long as the network is
// unreachable. It is also the only honest answer to "is the state writable" - which
// is why the probe is a write and not a stat.
//
// The reservation throttles the REQUEST. It must not also throttle the notice, and
// that is a second write rather than a change to this one: the worker records what it
// learned, and kUpdateAnswerGrace is what gives it the chance to.
UpdateCheckHandle startUpdateCheck(
    UpdateCheckContext context,
    std::shared_ptr<VersionSource> source,
    const std::filesystem::path& statePath,
    std::chrono::milliseconds timeout = kUpdateCheckTimeout,
    std::chrono::milliseconds grace = kUpdateAnswerGrace);

}  // namespace lyxbosa
