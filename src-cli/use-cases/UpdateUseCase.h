#pragma once

// The `update` command. Three exit codes and no output games:
//
//   0  nothing needed doing, or the binary was replaced
//   2  `--check` only: a newer release is available
//   1  anything else - a failed request, a development build, and every refusal
//
// The exit code is the interface, so that a monitoring script can use this without
// reading the text - the same discipline the scan exit codes already follow. A refusal
// exits 1 rather than 0 on purpose: a script that asked for an update and did not get
// one has to be able to tell.

#include "infrastructure/Terminal.h"
#include "infrastructure/TerminalCaps.h"
#include "system/CliArgs.h"
#include "update/ReleaseAssets.h"
#include "update/UpdateApply.h"
#include "update/UpdateCheck.h"
#include "update/UpdateState.h"
#include "update/VersionSource.h"

#include <fmt/base.h>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

namespace lyxbosa {

class UpdateUseCase {
public:
    // Both seams are injected so the command is testable without a socket; the
    // defaults are the real ones.
    UpdateUseCase(const Terminal& terminal, const TerminalCaps& caps,
                  std::shared_ptr<VersionSource> source = nullptr,
                  std::shared_ptr<AssetSource> assets = nullptr)
        : terminal_(terminal),
          caps_(caps),
          source_(source ? std::move(source)
                         : std::static_pointer_cast<VersionSource>(
                               std::make_shared<HttpVersionSource>())),
          assets_(assets ? std::move(assets)
                         : std::static_pointer_cast<AssetSource>(
                               std::make_shared<HttpAssetSource>())) {}

    int execute(const CliArgs& args) {
        if (usingTestOrigin()) {
            // Loud, because a build that reads this variable must never be mistaken
            // for one that talks to GitHub. It cannot install anything unsigned - the
            // keyring is compiled in - but it can install something signed from
            // somewhere else, and nobody should discover that from the outcome.
            terminal_.printErr(Terminal::warning(),
                "This build reads $LYXBOSA_UPDATE_ORIGIN instead of github.com.\n"
                "It is a local demonstration build and must not be installed anywhere.\n\n");
        }

        return args.updateCheckOnly ? runCheck() : runApply(args);
    }

private:
    int runCheck() {
        const Version running = runningVersion();

        // 0.0.0 is what a build that did not come from a tag reports, and
        // docs/RELEASING.md says so. Every published release is numerically newer
        // than it, so comparing would tell every developer that everything is an
        // update. Saying which build this is beats saying something false.
        if (!running.isRelease()) {
            printDevelopmentBuild();
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
            fmt::print("Run 'lyxbosa update' to install it, or fetch it from\n"
                       "https://github.com/LytraX/lyxbosa/releases\n");
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

    int runApply(const CliArgs& args) {
        ApplyOptions options;
        options.assumeYes = args.assumeYes;
        options.now = currentEpochSeconds;

        options.onStep = [this](std::string_view what) {
            terminal_.printErr(Terminal::muted(), "  {}...\n", what);
        };

        options.confirm = [this](const ApplyPlan& plan) { return confirm(plan); };

        const ApplyResult result = applyUpdate(*source_, *assets_, options);

        switch (result.outcome) {
            case ApplyOutcome::Replaced:
                terminal_.print(Terminal::success(), "Updated {} -> {}.\n",
                                toString(result.plan->from), toString(result.plan->to));
                fmt::print("{}\n", result.detail);
                // The trusted comment is printed only because it verified, and it is
                // worth printing because it is the line that names the release the
                // checksums belong to.
                if (!result.trustedComment.empty()) {
                    fmt::print("Signed: {}\n", result.trustedComment);
                }
                return 0;

            case ApplyOutcome::AlreadyCurrent:
                terminal_.print(Terminal::success(), "Up to date ({}).\n", result.detail);
                return 0;

            case ApplyOutcome::Declined:
                fmt::print(stderr, "Cancelled. {}\n", result.detail);
                return 1;

            case ApplyOutcome::DevelopmentBuild:
                printDevelopmentBuild();
                return 1;

            default:
                break;
        }

        terminal_.printErr(Terminal::error(), "Not updated: {}.\n",
                           describeOutcome(result.outcome));
        if (!result.detail.empty()) {
            fmt::print(stderr, "{}\n", result.detail);
        }

        // Every refusal ends the same way, because every refusal has the same answer:
        // the old binary is still there, and the release can be fetched and verified by
        // hand. docs/RELEASING.md's "After the release" section is that procedure, and
        // this is the short form of it.
        //
        // It names only things a person holding a downloaded release can reach. The
        // previous version of this text said to verify with "the key in
        // keys/minisign-trusted.txt", which is a path in a source checkout: a release
        // publishes six binaries, SHA256SUMS and SHA256SUMS.minisig, and no keyring.
        fmt::print(stderr,
                   "\nThe binary you are running has not been changed.\n"
                   "\n"
                   "To install a release by hand, take the binary for this platform from\n"
                   "https://github.com/LytraX/lyxbosa/releases together with SHA256SUMS\n"
                   "and SHA256SUMS.minisig, and check the signature before the checksums:\n"
                   "\n"
                   "    minisign -Vm SHA256SUMS -P <key>\n"
                   "    sha256sum -c SHA256SUMS\n"
                   "\n"
                   "The checksums are published beside the files they describe, so they\n"
                   "are worth reading only once the signature over them verifies. The key\n"
                   "is not published with the release for the same reason - take it from\n"
                   "the repository, which is somewhere else:\n"
                   "https://github.com/LytraX/lyxbosa/blob/master/keys/minisign-trusted.txt\n"
                   "\n"
                   "minisign prints the trusted comment, which is covered by the signature\n"
                   "and names the release. Read it: a SHA256SUMS and .minisig pair lifted\n"
                   "from an older release verifies perfectly well and describes different\n"
                   "binaries. docs/RELEASING.md, \"After the release\", is the long form.\n");
        return 1;
    }

    bool confirm(const ApplyPlan& plan) {
        // Without a terminal there is nobody to answer, and treating that as consent
        // would let a cron job replace the binary it is running.
        if (!caps_.stdinIsTty()) {
            terminal_.printErr(Terminal::error(),
                "Refusing to replace {} unconfirmed because stdin is not a terminal.\n"
                "Re-run with --yes to update non-interactively.\n", plan.target.string());
            return false;
        }

        fmt::print(stderr, "\n  {} -> {}\n  {}\n  from release {}, asset {}\n\n",
                   toString(plan.from), toString(plan.to), plan.target.string(), plan.tag,
                   plan.assetName);
        fmt::print(stderr, "Replace it? [y/N] ");
        std::fflush(stderr);

        std::string input;
        if (!std::getline(std::cin, input)) {
            // EOF or a read error is not consent.
            fmt::print(stderr, "\n");
            return false;
        }
        // Default no, unlike the scan prompt: this one rewrites the program asking.
        return !input.empty() && (input[0] == 'y' || input[0] == 'Y');
    }

    void printDevelopmentBuild() {
        terminal_.printErr(Terminal::warning(),
            "This is a development build ({}), not a release build.\n", LYXBOSA_VERSION);
        fmt::print(stderr,
            "There is no released version to compare it against. Release builds\n"
            "carry the tag they were built from; see docs/RELEASING.md.\n");
    }

    const Terminal& terminal_;
    const TerminalCaps& caps_;
    std::shared_ptr<VersionSource> source_;
    std::shared_ptr<AssetSource> assets_;
};

}  // namespace lyxbosa
