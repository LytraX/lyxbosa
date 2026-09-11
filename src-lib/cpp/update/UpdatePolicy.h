#pragma once

// UpdatePolicy.h - whether this invocation may ask whether a newer release exists.
//
// This is a pure function of facts already known at startup, separated from
// everything that touches a socket or the filesystem so that every branch can be
// tested without either. It is the whole of the narrowing in
// docs/tasks/UPDATE_PLAN.md 5, and the reasons matter more than the code:
//
//   `check` is called programmatically. corpus/verify.py runs `lyxbosa check` once
//   per sample, 167 times in one suite run. A network call per invocation breaks the
//   tool's own harness and the scripted use the command exists for. This is the
//   constraint that is not negotiable, and it is why the command is a field here
//   rather than an inferred property of the flags.
//
//   It runs in cron, fanned out. A hundred hosts behind one egress address is a
//   hundred requests to one rate-limited API, and a refused check is a check that
//   never says anything.
//
//   It runs during incident response. An outbound request tells whoever is watching
//   the network that a scan is starting, and when.
//
//   It runs in containers and egress-filtered networks, where the request hangs.
//
// Returning a reason rather than a bool is not decoration: it is what lets a test
// assert *why* a check did not happen, so that a case which passes for the wrong
// reason - the failure mode this repository keeps finding - shows up as the wrong
// enumerator rather than as a green bool.

#include "config/Rules.h"
#include "update/BuildIdentity.h"
#include "update/Version.h"

#include <cstdint>
#include <optional>
#include <string_view>

namespace lyxbosa {

// Which command is running. Only a scan may ever check implicitly.
enum class UpdateCallSite {
    Scan,
    OtherCommand,     // check, validate-config, init-config: never
    ExplicitRequest   // `lyxbosa update --check` was typed
};

enum class UpdateDecision {
    Check,
    SkipNotAScan,          // any command but scan, `check` above all
    SkipDisabled,          // updates.check is off or on-demand
    SkipDevBuild,          // 0.0.0 has nothing to compare against
    SkipUnattended,        // --quiet, --silent or --force
    SkipNotATerminal,      // stdout is redirected, piped or absent
    SkipCI,                // nobody is reading, and the egress is shared
    SkipNoWritableState,   // cannot record that we checked, so do not check
    SkipWithinInterval     // already asked, recently enough
};

struct UpdateCheckContext {
    UpdateCallSite callSite = UpdateCallSite::OtherCommand;
    UpdateCheckMode mode = UpdateCheckMode::Off;
    uint64_t intervalSeconds = 0;

    Version running;              // 0.0.0 for a build that is not from a tag
    bool stdoutIsTty = false;
    bool isCI = false;
    bool quiet = false;
    bool silent = false;
    bool force = false;

    bool stateWritable = false;   // proven by writing, not by looking
    std::optional<uint64_t> lastCheckEpoch;
    uint64_t nowEpoch = 0;
};

// The order of these tests is the order of the argument, cheapest and most decisive
// first. Every one of them is a reason a check must not happen; none of them is a
// reason a scan may behave differently.
inline UpdateDecision decideUpdateCheck(const UpdateCheckContext& ctx) {
    // Typed by a person, so it happens: not gated by mode, interval, terminal or
    // cache. `off` means the binary never reaches the network *unless asked*, and
    // this is the asking.
    if (ctx.callSite == UpdateCallSite::ExplicitRequest) {
        return UpdateDecision::Check;
    }

    if (ctx.callSite != UpdateCallSite::Scan) {
        return UpdateDecision::SkipNotAScan;
    }
    if (ctx.mode != UpdateCheckMode::Periodic) {
        return UpdateDecision::SkipDisabled;
    }
    // A development build is newer than nothing and older than everything. Checking
    // would tell every developer, on every scan, that 0.0.0 is out of date.
    if (!ctx.running.isRelease()) {
        return UpdateDecision::SkipDevBuild;
    }
    if (ctx.quiet || ctx.silent || ctx.force) {
        return UpdateDecision::SkipUnattended;
    }
    if (!ctx.stdoutIsTty) {
        return UpdateDecision::SkipNotATerminal;
    }
    if (ctx.isCI) {
        return UpdateDecision::SkipCI;
    }

    if (ctx.lastCheckEpoch) {
        const uint64_t last = *ctx.lastCheckEpoch;
        // A timestamp in the future is a clock that moved, not permission to check.
        // Subtracting unsigned in the other order would wrap to something enormous
        // and read as "long overdue".
        if (last > ctx.nowEpoch) {
            return UpdateDecision::SkipWithinInterval;
        }
        if (ctx.nowEpoch - last < ctx.intervalSeconds) {
            return UpdateDecision::SkipWithinInterval;
        }
    }

    // Last, because it is the only test that costs a write. Without somewhere to
    // record the timestamp there is no interval, and a check that cannot remember it
    // happened is a check on every single run - which is what this whole file exists
    // to prevent. startUpdateCheck() proves this by writing rather than by looking,
    // and only for a run that has already passed everything above.
    if (!ctx.stateWritable) {
        return UpdateDecision::SkipNoWritableState;
    }

    return UpdateDecision::Check;
}

// ---------------------------------------------------------------------------------------
// The other thing a scan may say, and the same argument one step further.
//
// A portable build running on a host that could have had the faster one is worth one
// line, because the reader can act on it: their installer fell back further than it
// needed to, or they fetched the wrong asset by hand. On a host that CANNOT run the
// standard build the same line is noise about a choice they do not have, and a tool that
// prints that on every scan is a tool people redirect to /dev/null.
//
// So the gates below are the update notice's gates, deliberately: interactive, a
// terminal, not CI, none of --quiet, --silent or --force, and recorded so it does not
// repeat. Two are its own. The build has to be the portable one, and the host has to be
// PROVEN able to run the other - BuildIdentity.h's Unknown is treated exactly like No,
// which is what keeps a host this cannot read quiet rather than nagged.
//
// It is deliberately not gated on updates.check or on being a release build. Neither is
// about this: the notice reaches no network, and a development portable build is as
// portable as a released one.
enum class PortableNoticeDecision {
    Show,
    SkipNotPortableBuild,   // the standard build never says anything about itself
    SkipNotAScan,
    SkipUnattended,         // --quiet, --silent or --force
    SkipNotATerminal,
    SkipCI,
    SkipAlreadyShown,       // said once, which is the whole contract
    SkipNoWritableState,    // cannot record it, so would repeat every run: do not start
    SkipNoAlternative       // this host cannot run the standard build, or cannot be read
};

struct PortableNoticeContext {
    UpdateCallSite callSite = UpdateCallSite::OtherCommand;
    bool portableBuild = false;
    bool stdoutIsTty = false;
    bool isCI = false;
    bool quiet = false;
    bool silent = false;
    bool force = false;

    bool stateWritable = false;   // proven by writing, not by looking
    bool alreadyShown = false;

    // Only consulted once everything above has passed, so a run that was never going to
    // say anything does not read a single file off the host.
    StandardBuildHere standardBuild = StandardBuildHere::Unknown;
};

inline PortableNoticeDecision decidePortableNotice(const PortableNoticeContext& ctx) {
    // First because it is the most decisive: on the standard build and on every platform
    // that is not Linux, there is nothing this could be about.
    if (!ctx.portableBuild) {
        return PortableNoticeDecision::SkipNotPortableBuild;
    }
    if (ctx.callSite != UpdateCallSite::Scan) {
        return PortableNoticeDecision::SkipNotAScan;
    }
    if (ctx.quiet || ctx.silent || ctx.force) {
        return PortableNoticeDecision::SkipUnattended;
    }
    if (!ctx.stdoutIsTty) {
        return PortableNoticeDecision::SkipNotATerminal;
    }
    if (ctx.isCI) {
        return PortableNoticeDecision::SkipCI;
    }
    if (ctx.alreadyShown) {
        return PortableNoticeDecision::SkipAlreadyShown;
    }
    // Before the host is looked at, for the same reason the update check tests it last
    // and for the opposite ordering reason: a notice that cannot be recorded is a notice
    // on every single run, which is the thing being avoided.
    if (!ctx.stateWritable) {
        return PortableNoticeDecision::SkipNoWritableState;
    }
    // Last, because it is the only test that reads the host's own files - and the only
    // one where not knowing has to mean no. Unknown is not a maybe here.
    if (ctx.standardBuild != StandardBuildHere::Yes) {
        return PortableNoticeDecision::SkipNoAlternative;
    }
    return PortableNoticeDecision::Show;
}

constexpr std::string_view portableNoticeReason(PortableNoticeDecision d) {
    switch (d) {
        case PortableNoticeDecision::Show:                 return "saying it once";
        case PortableNoticeDecision::SkipNotPortableBuild: return "not the portable build";
        case PortableNoticeDecision::SkipNotAScan:         return "not a scan";
        case PortableNoticeDecision::SkipUnattended:       return "unattended run";
        case PortableNoticeDecision::SkipNotATerminal:     return "stdout is not a terminal";
        case PortableNoticeDecision::SkipCI:               return "running in CI";
        case PortableNoticeDecision::SkipAlreadyShown:     return "already said once";
        case PortableNoticeDecision::SkipNoWritableState:  return "no writable state file";
        case PortableNoticeDecision::SkipNoAlternative:
            return "this host has no faster build to move to";
    }
    return "unknown";
}

// For --verbose and for test failure messages: a decision that reads as a sentence.
constexpr std::string_view updateDecisionReason(UpdateDecision d) {
    switch (d) {
        case UpdateDecision::Check:              return "checking";
        case UpdateDecision::SkipNotAScan:       return "not a scan";
        case UpdateDecision::SkipDisabled:       return "updates.check is not periodic";
        case UpdateDecision::SkipDevBuild:       return "not a release build";
        case UpdateDecision::SkipUnattended:     return "unattended run";
        case UpdateDecision::SkipNotATerminal:   return "stdout is not a terminal";
        case UpdateDecision::SkipCI:             return "running in CI";
        case UpdateDecision::SkipNoWritableState:return "no writable state file";
        case UpdateDecision::SkipWithinInterval: return "checked recently";
    }
    return "unknown";
}

}  // namespace lyxbosa
