#pragma once

// The `update` command. Two exit codes and no output games:
//
//   0  up to date
//   2  a newer release is available
//   1  anything else - a failed request, a development build, or the download that
//      is not implemented
//
// The exit code is the interface, so that a monitoring script can use this without
// reading the text - the same discipline the scan exit codes already follow.

#include "infrastructure/Terminal.h"
#include "system/CliArgs.h"
#include "update/UpdateCheck.h"
#include "update/UpdateState.h"
#include "update/VersionSource.h"

#include <fmt/base.h>
#include <memory>
#include <utility>

namespace lyxbosa {

class UpdateUseCase {
public:
    // The source is injected so the command is testable without a socket; the
    // default is the real one.
    explicit UpdateUseCase(const Terminal& terminal,
                           std::shared_ptr<VersionSource> source = nullptr)
        : terminal_(terminal),
          source_(source ? std::move(source)
                         : std::static_pointer_cast<VersionSource>(
                               std::make_shared<HttpVersionSource>())) {}

    int execute(const CliArgs& args) {
        // `lyxbosa update` refuses rather than being absent. A user who reads about
        // the command and gets "unknown command" learns less than one who is told
        // what does exist - and the README describes a command that is coming.
        if (!args.updateCheckOnly) {
            terminal_.printErr(Terminal::error(),
                "Downloading and replacing the binary is not implemented yet.\n");
            fmt::print(stderr,
                "Use 'lyxbosa update --check' to find out whether a newer release\n"
                "exists, and https://github.com/LytraX/lyxbosa/releases to fetch it.\n");
            return 1;
        }

        const Version running = runningVersion();

        // 0.0.0 is what a build that did not come from a tag reports, and
        // docs/RELEASING.md says so. Every published release is numerically newer
        // than it, so comparing would tell every developer that everything is an
        // update. Saying which build this is beats saying something false.
        if (!running.isRelease()) {
            terminal_.printErr(Terminal::warning(),
                "This is a development build ({}), not a release build.\n", LYXBOSA_VERSION);
            fmt::print(stderr,
                "There is no released version to compare it against. Release builds\n"
                "carry the tag they were built from; see docs/RELEASING.md.\n");
            return 1;
        }

        const auto result = fetchAndCompare(*source_, running, kUpdateCheckTimeout);

        if (!result.outcome.ok() || !result.latest) {
            terminal_.printErr(Terminal::error(),
                "Could not find out: {}\n",
                result.outcome.detail.empty() ? "the request did not succeed"
                                              : result.outcome.detail);
            return 1;
        }

        // Best effort: an explicit check that cannot write the cache still answers,
        // it just does not spare the next scan a request.
        UpdateState state;
        state.lastCheckEpoch = currentEpochSeconds();
        state.latestVersion = toString(*result.latest);
        writeUpdateState(defaultUpdateStatePath(), state);

        if (result.newerAvailable) {
            terminal_.print(Terminal::warning(),
                "A newer release is available: {} (this is {}).\n",
                toString(*result.latest), toString(running));
            fmt::print("https://github.com/LytraX/lyxbosa/releases\n");
            return 2;
        }

        terminal_.print(Terminal::success(), "Up to date ({}).\n", toString(running));
        // A published release older than the running one is not an error and not an
        // update; it happens on a build made between a tag and its release.
        if (*result.latest < running) {
            fmt::print("The newest published release is {}.\n", toString(*result.latest));
        }
        return 0;
    }

private:
    const Terminal& terminal_;
    std::shared_ptr<VersionSource> source_;
};

}  // namespace lyxbosa
