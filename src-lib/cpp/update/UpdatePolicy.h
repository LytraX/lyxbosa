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
// terminal, not CI, none of --quiet, --silent or --force, and recorded so it is not on
// every run. Two are its own. The build has to be the portable one, and the host has to
// be PROVEN able to run the other - BuildIdentity.h's Unknown is treated exactly like
// No, which is what keeps a host this cannot read quiet rather than nagged.
//
// It is deliberately not gated on updates.check or on being a release build. Neither is
// about this: the notice reaches no network, and a development portable build is as
// portable as a released one.
//
// WHY IT REPEATS, AND WHY IT HAS ITS OWN INTERVAL. It repeats rather than being said
// once, because once-ever is not quiet - it is unobservable. A server scan's output
// scrolls; the state file belongs to whichever user ran the scan; the person reading the
// output is routinely not the person who installed the binary; and from outside the
// process "said once, months ago" and "never said" are the same thing, which is what they
// turned out to be while the once-ever version was being tested.
//
// The interval is this file's own constant and NOT updates.intervalSeconds, for the same
// reason the notice is not gated on updates.check one line up. An operator who lengthens
// the update interval is buying less traffic to a rate-limited API; letting that also
// silence a line that opens no socket is the coupling this design already refuses, one
// level down. The two numbers are also priced in different currencies: there, the cost
// is a request; here, it is a person's attention, so the reasoning that made the update
// check daily does not transfer and neither does its number.
// ---------------------------------------------------------------------------------------

// Thirty days.
//
// The line asks for one deliberate manual install, on a host somebody schedules work on,
// and it never changes. A week would put an unchanging fact in front of a weekly cron
// operator fifty-two times a year, which is how a notice becomes something people learn
// not to read. A quarter is near enough to once-ever to bring the original defect back:
// a contractor on a two-month engagement could scan throughout it and never be told.
// A month is the period over which "I keep meaning to install that" stays true, and it
// puts the line in front of anybody newly running scans on the host within one.
constexpr uint64_t kPortableNoticeIntervalSeconds = 30ull * 24 * 60 * 60;

enum class PortableNoticeDecision {
    Show,
    AdoptLegacyFlag,        // a pre-timestamp state file: stamp it, print nothing
    SkipNotPortableBuild,   // the standard build never says anything about itself
    SkipNotAScan,
    SkipUnattended,         // --quiet, --silent or --force
    SkipNotATerminal,
    SkipCI,
    SkipSaidRecently,       // inside the interval above
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

    // When the line was last said, and what "now" is. Both parameters rather than a
    // clock read in here, so that a test drives the interval without sleeping and
    // without a time source to fake.
    std::optional<uint64_t> lastShownEpoch;
    uint64_t nowEpoch = 0;

    // A state file written before the timestamp existed says the line was said and not
    // when. Neither answer available from that alone is right: treating it as never said
    // repeats, on upgrade, a line the operator already dismissed, and treating it as
    // said forever leaves the host silent for good on the strength of a flag whose
    // meaning changed. So it is neither - see AdoptLegacyFlag below.
    bool shownBeforeTimestamps = false;

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
    if (ctx.lastShownEpoch) {
        const uint64_t last = *ctx.lastShownEpoch;
        // A timestamp in the future is a broken timestamp, and here that is a reason to
        // say the line rather than to withhold it - the opposite of decideUpdateCheck()
        // above, deliberately. There, one extra request to a rate-limited API is the
        // whole cost being avoided, so a clock that moved buys silence. Here the cost is
        // one line, and the run that prints it also rewrites the timestamp, so treating
        // it as due repairs the file after a single line; treating it as silence would
        // leave a host whose clock was briefly wrong in the once-ever state this exists
        // to get out of. Falling through is what makes it due, and the subtraction below
        // is never reached with `last` above `nowEpoch`, so it cannot wrap.
        if (last <= ctx.nowEpoch &&
            ctx.nowEpoch - last < kPortableNoticeIntervalSeconds) {
            return PortableNoticeDecision::SkipSaidRecently;
        }
    }
    // Before the host is looked at, for the same reason the update check tests it last
    // and for the opposite ordering reason: a notice that cannot be recorded is a notice
    // on every single run, which is the thing being avoided.
    if (!ctx.stateWritable) {
        return PortableNoticeDecision::SkipNoWritableState;
    }
    // Last of the gates, because it is the only test that reads the host's own files -
    // and the only one where not knowing has to mean no. Unknown is not a maybe here.
    if (ctx.standardBuild != StandardBuildHere::Yes) {
        return PortableNoticeDecision::SkipNoAlternative;
    }
    // The flag only speaks when there is no timestamp: a file carrying both - which is
    // what this version writes - is governed entirely by the timestamp, so the migration
    // happens on one run and not on every run past the interval for ever. Being below
    // the interval test is not enough on its own for that, because the interval test
    // returns only when it is INSIDE the interval and falls through when it is not.
    //
    // Below the host test as well, so the stamp written here means what every other stamp
    // in this file means: a run on which the line was said or would have been.
    if (ctx.shownBeforeTimestamps && !ctx.lastShownEpoch) {
        return PortableNoticeDecision::AdoptLegacyFlag;
    }
    return PortableNoticeDecision::Show;
}

// Whether a decision still requires the state file to be written. Both outcomes that are
// not a silent return write; only one of them also prints. The caller branches on this
// rather than on `== Show`, so that adding a third writing outcome cannot silently turn
// into a run that prints without recording.
constexpr bool portableNoticeWrites(PortableNoticeDecision d) {
    return d == PortableNoticeDecision::Show ||
           d == PortableNoticeDecision::AdoptLegacyFlag;
}

constexpr std::string_view portableNoticeReason(PortableNoticeDecision d) {
    switch (d) {
        case PortableNoticeDecision::Show:                 return "saying it";
        case PortableNoticeDecision::AdoptLegacyFlag:
            return "said once by an older version; starting the clock from now";
        case PortableNoticeDecision::SkipNotPortableBuild: return "not the portable build";
        case PortableNoticeDecision::SkipNotAScan:         return "not a scan";
        case PortableNoticeDecision::SkipUnattended:       return "unattended run";
        case PortableNoticeDecision::SkipNotATerminal:     return "stdout is not a terminal";
        case PortableNoticeDecision::SkipCI:               return "running in CI";
        case PortableNoticeDecision::SkipSaidRecently:     return "said recently enough";
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
