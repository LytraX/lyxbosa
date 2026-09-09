#include "update/UpdateCheck.h"

#include "core/Interrupt.h"

#include <fmt/format.h>

#include <exception>
#include <utility>

namespace lyxbosa {

UpdateCheckResult fetchAndCompare(VersionSource& source, const Version& running,
                                  std::chrono::milliseconds timeout) {
    UpdateCheckResult result;

    // A source that throws is a source that failed. It is not a reason for a scan to
    // stop, and std::thread would call std::terminate on an escaping exception.
    try {
        std::atomic<bool> neverCancelled{false};
        result.outcome = source.fetchLatest(timeout, neverCancelled);
    } catch (const std::exception& e) {
        result.outcome.status = FetchOutcome::Status::RequestFailed;
        result.outcome.detail = e.what();
        return result;
    } catch (...) {
        result.outcome.status = FetchOutcome::Status::RequestFailed;
        result.outcome.detail = "the version check failed";
        return result;
    }

    if (!result.outcome.ok()) {
        return result;
    }

    const auto parsed = parseVersion(result.outcome.version);
    if (!parsed) {
        // A well-formed response carrying something that is not a version is the
        // same problem as a malformed one, and gets the same silence.
        result.outcome.status = FetchOutcome::Status::BadResponse;
        result.outcome.detail =
            fmt::format("'{}' is not a version this scanner knows how to compare",
                        result.outcome.version);
        return result;
    }

    result.latest = *parsed;
    result.newerAvailable = running < *parsed;
    return result;
}

std::string updateNotice(const std::optional<UpdateCheckResult>& fresh,
                         const std::optional<Version>& known,
                         const Version& running) {
    std::optional<Version> newest;
    if (fresh && fresh->latest && fresh->newerAvailable) {
        newest = *fresh->latest;
    } else if (known && running < *known) {
        newest = *known;
    }
    if (!newest) {
        return {};
    }
    // The second line is indented to sit under the first, which the scan prints
    // behind a "Note: " prefix. Six spaces, because that prefix is six characters.
    return fmt::format(
        "A newer release is available: {} (this is {}).\n"
        "      https://github.com/LytraX/lyxbosa/releases\n",
        toString(*newest), toString(running));
}

// A source cannot be cancelled before it starts looking, so the flag is passed
// through rather than checked here; every implementation is required to watch it.
BackgroundUpdateCheck::BackgroundUpdateCheck(std::shared_ptr<VersionSource> source,
                                             Version running,
                                             std::filesystem::path statePath,
                                             uint64_t startedAtEpoch,
                                             std::chrono::milliseconds timeout,
                                             std::chrono::milliseconds grace)
    : source_(std::move(source)),
      running_(running),
      statePath_(std::move(statePath)),
      startedAtEpoch_(startedAtEpoch),
      timeout_(timeout),
      grace_(grace) {
    worker_ = std::thread([this] {
        UpdateCheckResult result;
        try {
            result.outcome = source_->fetchLatest(timeout_, cancel_);
            if (result.outcome.ok()) {
                if (const auto parsed = parseVersion(result.outcome.version)) {
                    result.latest = *parsed;
                    result.newerAvailable = running_ < *parsed;

                    // Best effort, and deliberately not checked: the timestamp that
                    // makes the interval work was already written by the reservation.
                    // This adds what the answer was - which THIS scan does not depend
                    // on, and every later scan inside the interval does. It is the
                    // only record of it, which is why the destructor now gives this
                    // line a chance to run rather than cancelling on top of it.
                    UpdateState state;
                    state.lastCheckEpoch = startedAtEpoch_;
                    state.latestVersion = toString(*parsed);
                    writeUpdateState(statePath_, state);
                } else {
                    result.outcome.status = FetchOutcome::Status::BadResponse;
                }
            }
        } catch (...) {
            // Nothing a version check can throw is worth a scan.
            result.outcome.status = FetchOutcome::Status::RequestFailed;
        }

        result_ = std::move(result);
        done_.store(true, std::memory_order_release);
    });
}

BackgroundUpdateCheck::~BackgroundUpdateCheck() {
    // Wait for an answer the interval has already been spent on, rather than throwing
    // away one that is nearly here - see kUpdateAnswerGrace for why that is not a
    // delay anybody is waiting through, and what it costs.
    //
    // Ctrl+C ends the wait immediately. A person who interrupted a scan is asking for
    // the process to be over, and a second of tidiness after that reads as a hang.
    // Polling rather than a condition variable because done_ is already the worker's
    // one publication point, and a second one would be a second thing to keep in step.
    const auto deadline = std::chrono::steady_clock::now() + grace_;
    while (!done_.load(std::memory_order_acquire) && !interrupted() &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    cancel_.store(true, std::memory_order_relaxed);
    if (worker_.joinable()) {
        worker_.join();
    }
}

std::optional<UpdateCheckResult> BackgroundUpdateCheck::resultIfReady() const {
    if (!done_.load(std::memory_order_acquire)) {
        return std::nullopt;
    }
    return result_;
}

UpdateCheckHandle startUpdateCheck(
    UpdateCheckContext context,
    std::shared_ptr<VersionSource> source,
    const std::filesystem::path& statePath,
    std::chrono::milliseconds timeout,
    std::chrono::milliseconds grace) {

    UpdateCheckHandle handle;

    // Reading the state has no side effect, so it happens before the decision; the
    // write does not, so it happens after.
    const auto cached = readUpdateState(statePath);
    if (cached) {
        if (cached->lastCheckEpoch != 0) {
            context.lastCheckEpoch = cached->lastCheckEpoch;
        }
        if (const auto parsed = parseVersion(cached->latestVersion)) {
            if (context.running < *parsed) {
                handle.known = *parsed;
            }
        }
    }

    // Everything except the write probe. A run that fails here has touched nothing.
    context.stateWritable = true;
    handle.decision = decideUpdateCheck(context);

    // A run that was merely inside its interval is still allowed to repeat what it
    // already knows; every other skip means this run says nothing at all.
    handle.mayNotify = handle.decision == UpdateDecision::Check ||
                       handle.decision == UpdateDecision::SkipWithinInterval;

    if (handle.decision != UpdateDecision::Check) {
        return handle;
    }

    // An explicit `update --check` is a person asking, and answers without a cache:
    // the caller runs it synchronously and an unwritable cache must not silence it.
    if (context.callSite != UpdateCallSite::ExplicitRequest) {
        // The write that is also the probe. If it fails there is no interval, so
        // there is no check - silently, rather than a check on every run from here on.
        if (!reserveUpdateCheck(statePath, context.nowEpoch)) {
            context.stateWritable = false;
            handle.decision = UpdateDecision::SkipNoWritableState;
            handle.mayNotify = true;  // it may still repeat what it read
            return handle;
        }
    }

    handle.live = std::make_unique<BackgroundUpdateCheck>(
        std::move(source), context.running, statePath, context.nowEpoch, timeout, grace);
    return handle;
}

}  // namespace lyxbosa
