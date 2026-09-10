// Tests for the update check. Nothing here touches a network.
//
// The standing requirement for this round is that every check ships its control in
// both directions, and for an update check that means proving it does NOT fire as
// hard as proving it does. The controls that matter are the ones asserting a
// *counted* source was never called: a predicate that returns "skip" is only
// evidence if the thing it guards can be observed not to have run.

#include <gtest/gtest.h>

#include "config/Config.h"
#include "update/UpdateCheck.h"
#include "update/UpdatePolicy.h"
#include "update/UpdateState.h"
#include "update/Version.h"
#include "update/VersionSource.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>

using namespace lyxbosa;
using namespace std::chrono_literals;

namespace {

namespace fs = std::filesystem;

// A source that records every call and never opens anything.
class CountingSource : public VersionSource {
public:
    explicit CountingSource(std::string version = "v9.9.9") : version_(std::move(version)) {}

    FetchOutcome fetchLatest(std::chrono::milliseconds,
                             const std::atomic<bool>&) override {
        calls.fetch_add(1, std::memory_order_relaxed);
        FetchOutcome out;
        out.status = FetchOutcome::Status::Ok;
        out.version = version_;
        return out;
    }

    std::atomic<int> calls{0};

private:
    std::string version_;
};

// Fails the way an egress-filtered host does.
class FailingSource : public VersionSource {
public:
    FetchOutcome fetchLatest(std::chrono::milliseconds,
                             const std::atomic<bool>&) override {
        calls.fetch_add(1, std::memory_order_relaxed);
        FetchOutcome out;
        out.status = FetchOutcome::Status::RequestFailed;
        out.detail = "no route to host";
        return out;
    }
    std::atomic<int> calls{0};
};

class ThrowingSource : public VersionSource {
public:
    FetchOutcome fetchLatest(std::chrono::milliseconds,
                             const std::atomic<bool>&) override {
        throw std::runtime_error("the version check has opinions");
    }
};

// Answers, but not instantly. Every other source here returns before the caller can
// look away, which is why none of them could observe what happens to an answer that
// arrives after the scan has finished - a real request was measured at about a
// quarter of a second against a scan of a hundredth.
class SlowSource : public VersionSource {
public:
    explicit SlowSource(std::chrono::milliseconds delay, std::string version = "v9.9.9")
        : delay_(delay), version_(std::move(version)) {}

    FetchOutcome fetchLatest(std::chrono::milliseconds,
                             const std::atomic<bool>& cancelled) override {
        calls.fetch_add(1, std::memory_order_relaxed);
        const auto deadline = std::chrono::steady_clock::now() + delay_;
        while (std::chrono::steady_clock::now() < deadline) {
            if (cancelled.load(std::memory_order_relaxed)) {
                FetchOutcome cancelledOut;
                cancelledOut.status = FetchOutcome::Status::Cancelled;
                return cancelledOut;
            }
            std::this_thread::sleep_for(1ms);
        }
        FetchOutcome out;
        out.status = FetchOutcome::Status::Ok;
        out.version = version_;
        return out;
    }

    std::atomic<int> calls{0};

private:
    std::chrono::milliseconds delay_;
    std::string version_;
};

// Blocks until cancelled, like a connection to a host that never answers.
class HangingSource : public VersionSource {
public:
    FetchOutcome fetchLatest(std::chrono::milliseconds,
                             const std::atomic<bool>& cancelled) override {
        started.store(true, std::memory_order_release);
        while (!cancelled.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(1ms);
        }
        FetchOutcome out;
        out.status = FetchOutcome::Status::Cancelled;
        return out;
    }
    std::atomic<bool> started{false};
};

// A temporary directory that removes itself, so the cache tests never write into
// the developer's real one.
class TempDir {
public:
    TempDir() {
        const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = fs::temp_directory_path() /
                ("lyxbosa-update-test-" + std::to_string(tick) + "-" +
                 std::to_string(counter_++));
        fs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    const fs::path& path() const { return path_; }
    fs::path file(const std::string& name) const { return path_ / name; }

private:
    fs::path path_;
    static inline int counter_ = 0;
};

// A context that would check, so each test can spoil exactly one thing.
UpdateCheckContext checkableContext() {
    UpdateCheckContext ctx;
    ctx.callSite = UpdateCallSite::Scan;
    ctx.mode = UpdateCheckMode::Periodic;
    ctx.intervalSeconds = 24 * 3600;
    ctx.running = Version{2, 2, 1};
    ctx.stdoutIsTty = true;
    ctx.isCI = false;
    ctx.quiet = false;
    ctx.silent = false;
    ctx.force = false;
    ctx.stateWritable = true;
    ctx.nowEpoch = 1'757'000'000;
    return ctx;
}

}  // namespace

// ---------------------------------------------------------------------------
// Version parsing and ordering
// ---------------------------------------------------------------------------

TEST(VersionTest, ParsesPlainAndPrefixedVersions) {
    EXPECT_EQ(parseVersion("2.2.1"), std::optional<Version>(Version{2, 2, 1}));
    EXPECT_EQ(parseVersion("v2.2.1"), std::optional<Version>(Version{2, 2, 1}));
    EXPECT_EQ(parseVersion("V2.2.1"), std::optional<Version>(Version{2, 2, 1}));
    EXPECT_EQ(parseVersion("0.0.0"), std::optional<Version>(Version{0, 0, 0}));
}

// The one that a string comparison gets backwards, and the reason this is a
// function rather than an operator< on std::string.
TEST(VersionTest, TenIsNewerThanNine) {
    const auto ten = *parseVersion("2.10.0");
    const auto nine = *parseVersion("2.9.0");
    EXPECT_TRUE(nine < ten);
    EXPECT_FALSE(ten < nine);
    EXPECT_TRUE(std::string("2.10.0") < std::string("2.9.0"))
        << "the mistake this test exists to catch is a string comparison";

    EXPECT_TRUE(*parseVersion("2.2.9") < *parseVersion("2.2.10"));
    EXPECT_TRUE(*parseVersion("9.0.0") < *parseVersion("10.0.0"));
}

TEST(VersionTest, OrdersByMajorThenMinorThenPatch) {
    EXPECT_TRUE(*parseVersion("1.9.9") < *parseVersion("2.0.0"));
    EXPECT_TRUE(*parseVersion("2.1.9") < *parseVersion("2.2.0"));
    EXPECT_TRUE(*parseVersion("2.2.0") < *parseVersion("2.2.1"));
    EXPECT_EQ(*parseVersion("2.2.1"), *parseVersion("v2.2.1"));
}

TEST(VersionTest, RefusesEverythingThatIsNotThreeNumbers) {
    EXPECT_FALSE(parseVersion(""));
    EXPECT_FALSE(parseVersion("v"));
    EXPECT_FALSE(parseVersion("2.2"));
    EXPECT_FALSE(parseVersion("2.2.1.4"));
    EXPECT_FALSE(parseVersion("2.2.x"));
    EXPECT_FALSE(parseVersion("2..1"));
    EXPECT_FALSE(parseVersion("2.2.1-rc1"));   // not a tag this project publishes
    EXPECT_FALSE(parseVersion(" 2.2.1"));
    EXPECT_FALSE(parseVersion("2.2.1 "));
    EXPECT_FALSE(parseVersion("latest"));
    EXPECT_FALSE(parseVersion("9999999.0.0"));  // seven digits: past the cap
}

// docs/RELEASING.md: a build that is not from a tag reports 0.0.0. Every release is
// numerically newer than that, so the answer has to be "not a release build".
TEST(VersionTest, DevBuildIsNotARelease) {
    EXPECT_FALSE((Version{0, 0, 0}.isRelease()));
    EXPECT_TRUE((Version{0, 0, 1}.isRelease()));
    EXPECT_TRUE((Version{0, 1, 0}.isRelease()));
    EXPECT_TRUE((Version{2, 2, 1}.isRelease()));
    EXPECT_TRUE((Version{0, 0, 0} < *parseVersion("2.2.1")))
        << "which is exactly why a dev build must never reach the comparison";
}

// ---------------------------------------------------------------------------
// The predicate: when a check may happen
// ---------------------------------------------------------------------------

TEST(UpdatePolicyTest, InteractiveScanChecks) {
    EXPECT_EQ(decideUpdateCheck(checkableContext()), UpdateDecision::Check);
}

// The constraint that is not negotiable: corpus/verify.py runs `lyxbosa check` 167
// times in one suite run.
TEST(UpdatePolicyTest, CheckSubcommandNeverChecks) {
    auto ctx = checkableContext();
    ctx.callSite = UpdateCallSite::OtherCommand;
    EXPECT_EQ(decideUpdateCheck(ctx), UpdateDecision::SkipNotAScan);
}

TEST(UpdatePolicyTest, QuietSilentAndForceNeverCheck) {
    for (const char* which : {"quiet", "silent", "force"}) {
        auto ctx = checkableContext();
        if (std::string(which) == "quiet")  ctx.quiet = true;
        if (std::string(which) == "silent") ctx.silent = true;
        if (std::string(which) == "force")  ctx.force = true;
        EXPECT_EQ(decideUpdateCheck(ctx), UpdateDecision::SkipUnattended) << which;
    }
}

TEST(UpdatePolicyTest, RedirectedStdoutNeverChecks) {
    auto ctx = checkableContext();
    ctx.stdoutIsTty = false;
    EXPECT_EQ(decideUpdateCheck(ctx), UpdateDecision::SkipNotATerminal);
}

TEST(UpdatePolicyTest, CiNeverChecks) {
    auto ctx = checkableContext();
    ctx.isCI = true;
    EXPECT_EQ(decideUpdateCheck(ctx), UpdateDecision::SkipCI);
}

TEST(UpdatePolicyTest, OffAndOnDemandNeverCheckByThemselves) {
    for (const auto mode : {UpdateCheckMode::Off, UpdateCheckMode::OnDemand}) {
        auto ctx = checkableContext();
        ctx.mode = mode;
        EXPECT_EQ(decideUpdateCheck(ctx), UpdateDecision::SkipDisabled)
            << updateCheckModeToString(mode);
    }
}

TEST(UpdatePolicyTest, DevBuildNeverChecks) {
    auto ctx = checkableContext();
    ctx.running = Version{0, 0, 0};
    EXPECT_EQ(decideUpdateCheck(ctx), UpdateDecision::SkipDevBuild);
}

TEST(UpdatePolicyTest, UnwritableStateNeverChecks) {
    auto ctx = checkableContext();
    ctx.stateWritable = false;
    EXPECT_EQ(decideUpdateCheck(ctx), UpdateDecision::SkipNoWritableState);
}

// `off` has to mean it, and the one exception is a person typing the command.
TEST(UpdatePolicyTest, ExplicitRequestChecksWhateverElseIsTrue) {
    auto ctx = checkableContext();
    ctx.callSite = UpdateCallSite::ExplicitRequest;
    ctx.mode = UpdateCheckMode::Off;
    ctx.stdoutIsTty = false;
    ctx.isCI = true;
    ctx.quiet = true;
    ctx.silent = true;
    ctx.force = true;
    ctx.stateWritable = false;
    ctx.lastCheckEpoch = ctx.nowEpoch;  // checked one second ago
    EXPECT_EQ(decideUpdateCheck(ctx), UpdateDecision::Check);
}

// ---------------------------------------------------------------------------
// Interval arithmetic
// ---------------------------------------------------------------------------

TEST(UpdatePolicyTest, InsideTheIntervalDoesNotCheck) {
    auto ctx = checkableContext();
    ctx.lastCheckEpoch = ctx.nowEpoch - (23 * 3600);
    EXPECT_EQ(decideUpdateCheck(ctx), UpdateDecision::SkipWithinInterval);
}

TEST(UpdatePolicyTest, PastTheIntervalChecks) {
    auto ctx = checkableContext();
    ctx.lastCheckEpoch = ctx.nowEpoch - (24 * 3600);
    EXPECT_EQ(decideUpdateCheck(ctx), UpdateDecision::Check);

    ctx.lastCheckEpoch = ctx.nowEpoch - (25 * 3600);
    EXPECT_EQ(decideUpdateCheck(ctx), UpdateDecision::Check);
}

TEST(UpdatePolicyTest, BoundaryIsExclusiveOnTheLowSide) {
    auto ctx = checkableContext();
    ctx.lastCheckEpoch = ctx.nowEpoch - (24 * 3600 - 1);
    EXPECT_EQ(decideUpdateCheck(ctx), UpdateDecision::SkipWithinInterval);
}

// A clock that moved backwards must not wrap the unsigned subtraction into
// "enormously overdue", which is what `now - last` does when last is in the future.
TEST(UpdatePolicyTest, AFutureTimestampDoesNotBecomeOverdue) {
    auto ctx = checkableContext();
    ctx.lastCheckEpoch = ctx.nowEpoch + (365 * 24 * 3600);
    EXPECT_EQ(decideUpdateCheck(ctx), UpdateDecision::SkipWithinInterval);
}

TEST(UpdatePolicyTest, NeverCheckedBeforeChecks) {
    auto ctx = checkableContext();
    ctx.lastCheckEpoch = std::nullopt;
    EXPECT_EQ(decideUpdateCheck(ctx), UpdateDecision::Check);
}

// ---------------------------------------------------------------------------
// The state file
// ---------------------------------------------------------------------------

TEST(UpdateStateTest, WritesAndReadsBack) {
    TempDir dir;
    const auto path = dir.file("update-check");

    UpdateState state;
    state.lastCheckEpoch = 1'757'000'000;
    state.latestVersion = "2.3.0";
    ASSERT_TRUE(writeUpdateState(path, state));

    const auto read = readUpdateState(path);
    ASSERT_TRUE(read);
    EXPECT_EQ(read->lastCheckEpoch, 1'757'000'000u);
    EXPECT_EQ(read->latestVersion, "2.3.0");
}

TEST(UpdateStateTest, CreatesTheParentDirectory) {
    TempDir dir;
    const auto path = dir.path() / "a" / "b" / "update-check";
    UpdateState state;
    state.lastCheckEpoch = 1;
    EXPECT_TRUE(writeUpdateState(path, state));
    EXPECT_TRUE(fs::exists(path));
}

TEST(UpdateStateTest, LeavesNoTempFileBehind) {
    TempDir dir;
    const auto path = dir.file("update-check");
    UpdateState state;
    state.lastCheckEpoch = 1;
    ASSERT_TRUE(writeUpdateState(path, state));
    EXPECT_FALSE(fs::exists(dir.file("update-check.tmp")))
        << "a .tmp left beside the state file is the half-written read on the next run";
}

// Every unreadable shape has to mean "never checked" rather than throwing into a
// scan - and "never checked" is the answer that errs towards checking, not towards
// silence, so these are the cases where being total actually matters.
TEST(UpdateStateTest, UnreadableShapesAreNulloptRatherThanAThrow) {
    TempDir dir;

    EXPECT_FALSE(readUpdateState(dir.file("does-not-exist")));
    EXPECT_FALSE(readUpdateState(fs::path{}));
    EXPECT_FALSE(readUpdateState(dir.path()));  // a directory, not a file

    const auto write = [&](const std::string& name, const std::string& body) {
        const auto p = dir.file(name);
        std::ofstream(p, std::ios::binary) << body;
        return p;
    };

    EXPECT_FALSE(readUpdateState(write("empty", "")));
    EXPECT_FALSE(readUpdateState(write("junk", "\x01\x02\x03 not a state file")));
    EXPECT_FALSE(readUpdateState(write("no-keys", "# only a comment\n")));
    EXPECT_FALSE(readUpdateState(write("bad-epoch", "last_check=yesterday\n")));
    EXPECT_FALSE(readUpdateState(write("overflow",
                                       "last_check=999999999999999999999999\n")));
    EXPECT_FALSE(readUpdateState(write("truncated", "last_ch")));

    // A file larger than any state file is not one.
    EXPECT_FALSE(readUpdateState(write("huge", std::string(5000, 'x'))));
}

TEST(UpdateStateTest, IgnoresKeysFromALaterVersionOfTheFile) {
    TempDir dir;
    const auto path = dir.file("update-check");
    std::ofstream(path, std::ios::binary)
        << "# lyxbosa update check state\n"
        << "last_check=1757000000\n"
        << "latest_version=2.3.0\n"
        << "something_added_later=whatever\n";

    const auto read = readUpdateState(path);
    ASSERT_TRUE(read);
    EXPECT_EQ(read->lastCheckEpoch, 1'757'000'000u);
    EXPECT_EQ(read->latestVersion, "2.3.0");
}

TEST(UpdateStateTest, ReservationKeepsTheVersionItAlreadyKnew) {
    TempDir dir;
    const auto path = dir.file("update-check");

    UpdateState state;
    state.lastCheckEpoch = 100;
    state.latestVersion = "2.3.0";
    ASSERT_TRUE(writeUpdateState(path, state));

    ASSERT_TRUE(reserveUpdateCheck(path, 200));
    const auto read = readUpdateState(path);
    ASSERT_TRUE(read);
    EXPECT_EQ(read->lastCheckEpoch, 200u);
    EXPECT_EQ(read->latestVersion, "2.3.0");
}

TEST(UpdateStateTest, RefusesAPathItCannotWrite) {
    // A parent that is a regular file cannot become a directory.
    TempDir dir;
    const auto blocker = dir.file("blocker");
    std::ofstream(blocker, std::ios::binary) << "not a directory";

    UpdateState state;
    state.lastCheckEpoch = 1;
    EXPECT_FALSE(writeUpdateState(blocker / "update-check", state));
    EXPECT_FALSE(writeUpdateState(fs::path{}, state));
    EXPECT_FALSE(reserveUpdateCheck(blocker / "update-check", 1));
}

// ---------------------------------------------------------------------------
// startUpdateCheck: the controls, on the production path
// ---------------------------------------------------------------------------
//
// The predicate tests above assert a decision. These assert that the decision is
// what actually governs the socket, by counting calls on a source that would have
// been used. A skip that still fetched would pass every test in the section above.

TEST(StartUpdateCheckTest, InteractiveScanStartsExactlyOneFetch) {
    TempDir dir;
    auto source = std::make_shared<CountingSource>();
    {
        auto handle = startUpdateCheck(checkableContext(), source,
                                       dir.file("update-check"));
        ASSERT_NE(handle.live, nullptr);
        EXPECT_EQ(handle.decision, UpdateDecision::Check);
        EXPECT_TRUE(handle.mayNotify);
    }
    EXPECT_EQ(source->calls.load(), 1);
}

TEST(StartUpdateCheckTest, NoNetworkCallFromTheCheckSubcommand) {
    TempDir dir;
    auto source = std::make_shared<CountingSource>();
    auto ctx = checkableContext();
    ctx.callSite = UpdateCallSite::OtherCommand;

    auto handle = startUpdateCheck(ctx, source, dir.file("update-check"));

    EXPECT_EQ(handle.live, nullptr);
    EXPECT_EQ(handle.decision, UpdateDecision::SkipNotAScan);
    EXPECT_FALSE(handle.mayNotify) << "and it must not speak from the cache either";
    EXPECT_EQ(source->calls.load(), 0);
    EXPECT_FALSE(fs::exists(dir.file("update-check")))
        << "a command that must not check must not write either";
}

TEST(StartUpdateCheckTest, NoNetworkCallUnderQuiet) {
    TempDir dir;
    auto source = std::make_shared<CountingSource>();
    auto ctx = checkableContext();
    ctx.quiet = true;

    auto handle = startUpdateCheck(ctx, source, dir.file("update-check"));

    EXPECT_EQ(handle.live, nullptr);
    EXPECT_EQ(handle.decision, UpdateDecision::SkipUnattended);
    EXPECT_FALSE(handle.mayNotify);
    EXPECT_EQ(source->calls.load(), 0);
    EXPECT_FALSE(fs::exists(dir.file("update-check")));
}

TEST(StartUpdateCheckTest, NoNetworkCallInsideTheInterval) {
    TempDir dir;
    const auto path = dir.file("update-check");
    auto source = std::make_shared<CountingSource>();
    auto ctx = checkableContext();

    // The first run checks and leaves a timestamp behind.
    {
        auto handle = startUpdateCheck(ctx, source, path);
        ASSERT_NE(handle.live, nullptr);
        EXPECT_EQ(handle.decision, UpdateDecision::Check);
    }
    ASSERT_EQ(source->calls.load(), 1);
    ASSERT_TRUE(fs::exists(path));

    // An hour later, the same context reads that timestamp and does not.
    ctx.nowEpoch += 3600;
    auto again = startUpdateCheck(ctx, source, path);

    EXPECT_EQ(again.live, nullptr);
    EXPECT_EQ(again.decision, UpdateDecision::SkipWithinInterval);
    EXPECT_EQ(source->calls.load(), 1) << "the second run asked anyway";

    // ...and it still knows what the first run learned, without having asked.
    EXPECT_TRUE(again.mayNotify);
    ASSERT_TRUE(again.known);
    EXPECT_EQ(toString(*again.known), "9.9.9");
}

TEST(StartUpdateCheckTest, NoNetworkCallWhenTheStateCannotBeWritten) {
    TempDir dir;
    const auto blocker = dir.file("blocker");
    std::ofstream(blocker, std::ios::binary) << "not a directory";

    auto source = std::make_shared<CountingSource>();
    auto handle = startUpdateCheck(checkableContext(), source,
                                   blocker / "update-check");

    EXPECT_EQ(handle.live, nullptr);
    EXPECT_EQ(handle.decision, UpdateDecision::SkipNoWritableState);
    EXPECT_EQ(source->calls.load(), 0);
}

// The reservation is what stops an unreachable network from becoming a request on
// every single run - the state file has to carry the attempt, not only the success.
TEST(StartUpdateCheckTest, AFailedCheckStillMovesTheTimestamp) {
    TempDir dir;
    const auto path = dir.file("update-check");
    auto source = std::make_shared<FailingSource>();
    auto ctx = checkableContext();

    {
        auto handle = startUpdateCheck(ctx, source, path);
        ASSERT_NE(handle.live, nullptr);
    }
    ASSERT_EQ(source->calls.load(), 1);

    const auto state = readUpdateState(path);
    ASSERT_TRUE(state) << "a failed check left nothing behind, so the next run repeats it";
    EXPECT_EQ(state->lastCheckEpoch, ctx.nowEpoch);
    EXPECT_TRUE(state->latestVersion.empty());

    // And the next run, an hour later, does not ask again.
    ctx.nowEpoch += 3600;
    auto second = startUpdateCheck(ctx, source, path);
    EXPECT_EQ(second.live, nullptr);
    EXPECT_EQ(second.decision, UpdateDecision::SkipWithinInterval);
    EXPECT_EQ(source->calls.load(), 1);
    EXPECT_FALSE(second.known) << "a failed check has nothing to repeat";
}

TEST(StartUpdateCheckTest, ASuccessfulCheckRecordsWhatItLearned) {
    TempDir dir;
    const auto path = dir.file("update-check");
    auto source = std::make_shared<CountingSource>("v2.10.0");

    {
        auto handle = startUpdateCheck(checkableContext(), source, path);
        ASSERT_NE(handle.live, nullptr);
    }

    const auto state = readUpdateState(path);
    ASSERT_TRUE(state);
    EXPECT_EQ(state->latestVersion, "2.10.0");
}

// ---------------------------------------------------------------------------
// Failure and timeout paths: none of them may produce a notice or a delay
// ---------------------------------------------------------------------------

TEST(UpdateNoticeTest, SaysNothingWhenThereIsNothingToSay) {
    const Version running{2, 2, 1};

    EXPECT_EQ(updateNotice(std::nullopt, std::nullopt, running), "")
        << "a check that never finished must be silent";

    UpdateCheckResult failed;
    failed.outcome.status = FetchOutcome::Status::RequestFailed;
    EXPECT_EQ(updateNotice(failed, std::nullopt, running), "");

    UpdateCheckResult noTransport;
    noTransport.outcome.status = FetchOutcome::Status::NoTransport;
    EXPECT_EQ(updateNotice(noTransport, std::nullopt, running), "");

    UpdateCheckResult bad;
    bad.outcome.status = FetchOutcome::Status::BadResponse;
    EXPECT_EQ(updateNotice(bad, std::nullopt, running), "");

    UpdateCheckResult sameVersion;
    sameVersion.outcome.status = FetchOutcome::Status::Ok;
    sameVersion.latest = running;
    sameVersion.newerAvailable = false;
    EXPECT_EQ(updateNotice(sameVersion, std::nullopt, running), "");

    UpdateCheckResult older;
    older.outcome.status = FetchOutcome::Status::Ok;
    older.latest = Version{2, 1, 0};
    older.newerAvailable = false;
    EXPECT_EQ(updateNotice(older, std::nullopt, running), "");
}

TEST(UpdateNoticeTest, NamesBothVersionsWhenThereIsOne) {
    const Version running{2, 9, 0};
    UpdateCheckResult newer;
    newer.outcome.status = FetchOutcome::Status::Ok;
    newer.latest = Version{2, 10, 0};
    newer.newerAvailable = true;

    const auto notice = updateNotice(newer, std::nullopt, running);
    EXPECT_NE(notice.find("2.10.0"), std::string::npos);
    EXPECT_NE(notice.find("2.9.0"), std::string::npos);
}

// The cache is what makes a scan that outran its own request survivable, and what
// lets the other twenty-three hours of scans say something without asking again.
TEST(UpdateNoticeTest, FallsBackToWhatAPreviousRunLearned) {
    const Version running{2, 2, 1};
    const std::optional<Version> known{Version{2, 3, 0}};

    // No fresh answer at all: the scan finished before the request did.
    const auto notice = updateNotice(std::nullopt, known, running);
    EXPECT_NE(notice.find("2.3.0"), std::string::npos);

    // A fresh answer that failed falls back the same way.
    UpdateCheckResult failed;
    failed.outcome.status = FetchOutcome::Status::RequestFailed;
    EXPECT_NE(updateNotice(failed, known, running).find("2.3.0"), std::string::npos);

    // A cache that is not newer says nothing, which is what an upgraded binary
    // reading yesterday's cache has to do.
    EXPECT_EQ(updateNotice(std::nullopt, std::optional<Version>(Version{2, 2, 1}),
                           running), "");
    EXPECT_EQ(updateNotice(std::nullopt, std::optional<Version>(Version{2, 1, 0}),
                           running), "");

    // A fresh answer beats the cache when both have something to say.
    UpdateCheckResult fresh;
    fresh.outcome.status = FetchOutcome::Status::Ok;
    fresh.latest = Version{2, 4, 0};
    fresh.newerAvailable = true;
    const auto both = updateNotice(fresh, known, running);
    EXPECT_NE(both.find("2.4.0"), std::string::npos);
    EXPECT_EQ(both.find("2.3.0"), std::string::npos);
}

// A cached version must not turn into a notice on a run that is meant to be silent.
TEST(StartUpdateCheckTest, ASilentRunDoesNotSpeakFromTheCache) {
    TempDir dir;
    const auto path = dir.file("update-check");

    UpdateState state;
    state.lastCheckEpoch = 1'757'000'000;
    state.latestVersion = "9.9.9";
    ASSERT_TRUE(writeUpdateState(path, state));

    auto source = std::make_shared<CountingSource>();
    for (const auto spoil : {"check", "quiet", "tty", "ci", "off", "dev"}) {
        auto ctx = checkableContext();
        const std::string which(spoil);
        if (which == "check") ctx.callSite = UpdateCallSite::OtherCommand;
        if (which == "quiet") ctx.quiet = true;
        if (which == "tty")   ctx.stdoutIsTty = false;
        if (which == "ci")    ctx.isCI = true;
        if (which == "off")   ctx.mode = UpdateCheckMode::Off;
        if (which == "dev")   ctx.running = Version{0, 0, 0};

        const auto handle = startUpdateCheck(ctx, source, path);
        EXPECT_FALSE(handle.mayNotify) << which;
        EXPECT_EQ(handle.live, nullptr) << which;
    }
    EXPECT_EQ(source->calls.load(), 0);
}

TEST(FetchAndCompareTest, ASourceThatThrowsIsAFailedRequest) {
    ThrowingSource source;
    const auto result = fetchAndCompare(source, Version{2, 2, 1}, 10ms);
    EXPECT_EQ(result.outcome.status, FetchOutcome::Status::RequestFailed);
    EXPECT_FALSE(result.newerAvailable);
    EXPECT_FALSE(result.latest);
    EXPECT_EQ(updateNotice(result, std::nullopt, Version{2, 2, 1}), "");
}

TEST(FetchAndCompareTest, AnAnswerThatIsNotAVersionIsABadResponse) {
    class JunkSource : public VersionSource {
    public:
        FetchOutcome fetchLatest(std::chrono::milliseconds,
                                 const std::atomic<bool>&) override {
            FetchOutcome out;
            out.status = FetchOutcome::Status::Ok;
            out.version = "latest";
            return out;
        }
    } source;

    const auto result = fetchAndCompare(source, Version{2, 2, 1}, 10ms);
    EXPECT_EQ(result.outcome.status, FetchOutcome::Status::BadResponse);
    EXPECT_EQ(updateNotice(result, std::nullopt, Version{2, 2, 1}), "");
}

// The property the whole design turns on: a check still in flight is polled, not
// waited for, and tearing it down does not block on the network either.
TEST(BackgroundUpdateCheckTest, AHangingCheckIsBoundedByTheGraceAndNotTheTimeout) {
    TempDir dir;
    auto source = std::make_shared<HangingSource>();

    const auto begun = std::chrono::steady_clock::now();
    {
        auto check = std::make_unique<BackgroundUpdateCheck>(
            source, Version{2, 2, 1}, dir.file("update-check"), 1'757'000'000,
            std::chrono::hours(1),  // a deadline nobody would wait out
            50ms);                  // and a grace that is not one either

        while (!source->started.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(1ms);
        }

        EXPECT_FALSE(check->resultIfReady())
            << "polling a check in flight must not block until it finishes";
        EXPECT_EQ(updateNotice(check->resultIfReady(), std::nullopt, Version{2, 2, 1}), "");
    }  // destructor waits out the grace, then cancels and joins

    const auto elapsed = std::chrono::steady_clock::now() - begun;
    // The assertion that matters is the bound, not "no wait at all": teardown now
    // waits, and what stops a hung network from being felt is that the grace ends it
    // and the source watches the cancel flag. An hour was available and was not taken.
    EXPECT_LT(elapsed, 2s) << "teardown waited for the network rather than the grace";
}

// ---------------------------------------------------------------------------
// An answer that arrives after the scan has finished
//
// The reservation writes the timestamp before the request, so the interval is spent
// whether or not an answer comes back. Teardown used to cancel the moment the scan
// ended, so a scan quicker than its request learned nothing and the state file
// recorded only that a check had happened - and every later scan inside the interval
// read that empty cache and said nothing. Each case below is paired with one asserting
// the other answer, because a destructor that simply always waited would pass the
// first of each pair.
// ---------------------------------------------------------------------------

TEST(AnswerGraceTest, AnAnswerThatArrivesAfterTheScanIsStillRecorded) {
    TempDir dir;
    const auto path = dir.file("update-check");
    auto source = std::make_shared<SlowSource>(120ms, "v2.10.0");

    // The reservation, written before the request exactly as startUpdateCheck writes
    // it. It is what spends the interval, and it records no version.
    ASSERT_TRUE(reserveUpdateCheck(path, 1'757'000'000));

    {
        // A scan that is over before the request is: the handle is destroyed at once.
        BackgroundUpdateCheck check(source, Version{2, 2, 1}, path, 1'757'000'000,
                                    kUpdateCheckTimeout, 2s);
        EXPECT_FALSE(check.resultIfReady())
            << "the answer must not be here yet, or this case proves nothing";
    }

    const auto state = readUpdateState(path);
    ASSERT_TRUE(state);
    EXPECT_EQ(state->latestVersion, "2.10.0")
        << "the interval was spent on this answer; discarding it spends it for nothing";
}

// The companion. Without it the case above would pass against a destructor that waited
// for however long the network took, which is the thing the contract forbids.
TEST(AnswerGraceTest, AnAnswerThatMissesTheGraceIsAbandoned) {
    TempDir dir;
    const auto path = dir.file("update-check");
    auto source = std::make_shared<SlowSource>(30s, "v2.10.0");

    ASSERT_TRUE(reserveUpdateCheck(path, 1'757'000'000));

    const auto begun = std::chrono::steady_clock::now();
    {
        BackgroundUpdateCheck check(source, Version{2, 2, 1}, path, 1'757'000'000,
                                    kUpdateCheckTimeout, 40ms);
    }
    const auto elapsed = std::chrono::steady_clock::now() - begun;

    EXPECT_LT(elapsed, 2s) << "the grace is a bound, not a suggestion";

    const auto state = readUpdateState(path);
    ASSERT_TRUE(state) << "the reservation is still there - the interval was spent";
    EXPECT_TRUE(state->latestVersion.empty())
        << "and it learned nothing, which is what the next scan must be able to see";
}

// And the third answer: an answer already in hand costs nothing, which is every scan
// that runs longer than one request - the case where this was never broken.
TEST(AnswerGraceTest, ACheckAlreadyFinishedIsNotWaitedForAtAll) {
    TempDir dir;
    auto source = std::make_shared<CountingSource>("v2.10.0");

    auto check = std::make_unique<BackgroundUpdateCheck>(
        source, Version{2, 2, 1}, dir.file("update-check"), 1'757'000'000,
        kUpdateCheckTimeout, 30s);  // a grace nobody would wait out

    while (!check->resultIfReady()) {
        std::this_thread::sleep_for(1ms);
    }

    const auto begun = std::chrono::steady_clock::now();
    check.reset();
    EXPECT_LT(std::chrono::steady_clock::now() - begun, 2s)
        << "the wait must be for an answer, not unconditional";
}

// The defect as a user meets it, one level up: two scans inside one interval, the
// first quicker than its request. The second is entitled to repeat what the first
// learned without asking again, and before this change there was nothing to repeat.
TEST(AnswerGraceTest, AScanThatOutranItsRequestLeavesTheNextScanAbleToSpeak) {
    TempDir dir;
    const auto path = dir.file("update-check");
    auto source = std::make_shared<SlowSource>(120ms, "v2.10.0");

    UpdateCheckContext first = checkableContext();
    {
        auto handle = startUpdateCheck(first, source, path, kUpdateCheckTimeout, 2s);
        ASSERT_NE(handle.live, nullptr);
        EXPECT_EQ(handle.decision, UpdateDecision::Check);
        // This scan says nothing: its request had not answered when the report ended.
        EXPECT_EQ(updateNotice(handle.live->resultIfReady(), handle.known, first.running),
                  "");
    }

    // A second scan an hour later, well inside the one-day interval.
    UpdateCheckContext second = checkableContext();
    second.nowEpoch = first.nowEpoch + 3600;
    auto handle = startUpdateCheck(second, source, path, kUpdateCheckTimeout, 2s);

    EXPECT_EQ(handle.decision, UpdateDecision::SkipWithinInterval);
    EXPECT_EQ(handle.live, nullptr);
    EXPECT_EQ(source->calls.load(), 1) << "the interval still throttles the request";
    ASSERT_TRUE(handle.known.has_value());
    EXPECT_TRUE(handle.mayNotify);
    EXPECT_NE(updateNotice(std::nullopt, handle.known, second.running), "")
        << "the second scan inside the interval is what actually tells the user";
}

// The other direction of the same pair: when the answer really never arrived, the
// second scan inside the interval still says nothing AND still does not ask again.
// The interval must go on throttling requests whether or not one succeeded.
TEST(AnswerGraceTest, AnIntervalSpentLearningNothingStaysSilentAndStaysThrottled) {
    TempDir dir;
    const auto path = dir.file("update-check");
    auto source = std::make_shared<SlowSource>(30s, "v2.10.0");

    UpdateCheckContext first = checkableContext();
    {
        auto handle = startUpdateCheck(first, source, path, kUpdateCheckTimeout, 40ms);
        ASSERT_NE(handle.live, nullptr);
    }

    UpdateCheckContext second = checkableContext();
    second.nowEpoch = first.nowEpoch + 3600;
    auto handle = startUpdateCheck(second, source, path, kUpdateCheckTimeout, 40ms);

    EXPECT_EQ(handle.decision, UpdateDecision::SkipWithinInterval);
    EXPECT_EQ(source->calls.load(), 1) << "a check that failed must not become a retry";
    EXPECT_FALSE(handle.known.has_value());
    EXPECT_EQ(updateNotice(std::nullopt, handle.known, second.running), "");
}

// ---------------------------------------------------------------------------
// Reading the release response
// ---------------------------------------------------------------------------

TEST(ExtractTagNameTest, FindsTheTagInARealisticResponse) {
    const std::string body =
        R"({"url":"https://api.github.com/repos/x/y/releases/1","id":1,)"
        R"("tag_name":"v2.2.1","target_commitish":"master","name":"v2.2.1",)"
        R"("draft":false,"prerelease":false})";
    EXPECT_EQ(extractTagName(body), std::optional<std::string>("v2.2.1"));
}

TEST(ExtractTagNameTest, ToleratesWhitespaceAroundTheColon) {
    EXPECT_EQ(extractTagName("{ \"tag_name\" :  \"v1.2.3\" }"),
              std::optional<std::string>("v1.2.3"));
    EXPECT_EQ(extractTagName("{\n  \"tag_name\":\n    \"v1.2.3\"\n}"),
              std::optional<std::string>("v1.2.3"));
}

TEST(ExtractTagNameTest, RefusesAnythingItCannotBeSureOf) {
    EXPECT_FALSE(extractTagName(""));
    EXPECT_FALSE(extractTagName("{}"));
    EXPECT_FALSE(extractTagName(R"({"name":"v2.2.1"})"));       // wrong key
    EXPECT_FALSE(extractTagName(R"({"tag_name")"));             // truncated
    EXPECT_FALSE(extractTagName(R"({"tag_name":)"));
    EXPECT_FALSE(extractTagName(R"({"tag_name":")"));           // no closing quote
    EXPECT_FALSE(extractTagName(R"({"tag_name":"v2.2.1)"));
    EXPECT_FALSE(extractTagName(R"({"tag_name":""})"));         // empty
    EXPECT_FALSE(extractTagName(R"({"tag_name":123})"));        // not a string
    EXPECT_FALSE(extractTagName("{\"tag_name\":\"v2.\n2.1\"}"));  // control character
    EXPECT_FALSE(extractTagName("{\"tag_name\":\"v2\\.2.1\"}"));  // a backslash escape
    EXPECT_FALSE(extractTagName(
        "{\"tag_name\":\"" + std::string(200, 'a') + "\"}"));   // past the cap
}

// A refused body must reach the same silence as a refused request.
TEST(ExtractTagNameTest, ARateLimitBodyProducesNoVersion) {
    const std::string body =
        R"({"message":"API rate limit exceeded","documentation_url":"https://docs.github.com"})";
    EXPECT_FALSE(extractTagName(body));
}

// ---------------------------------------------------------------------------
// Finding the system trust store
// ---------------------------------------------------------------------------
//
// This is here because the real release artefact failed without it. curl bakes its
// CA bundle path in at configure time; the AlmaLinux 8 release build therefore
// carries /etc/pki/tls/certs/ca-bundle.crt, and on the Debian and Ubuntu hosts that
// binary ships to, no such file exists - "Problem with the SSL CA cert (path? access
// rights?)". The lists are driven explicitly so the test does not depend on whatever
// the machine running it happens to have in /etc.

TEST(CaLocationTest, PicksTheFirstCandidateThatExists) {
    TempDir dir;
    const auto present = dir.file("ca-bundle.crt");
    std::ofstream(present, std::ios::binary) << "-----BEGIN CERTIFICATE-----\n";
    const auto presentDir = dir.path() / "certs";
    fs::create_directories(presentDir);

    const auto found = resolveCaLocation(
        {(dir.path() / "absent-first.crt").string(), present.string(),
         (dir.path() / "never-reached.crt").string()},
        {(dir.path() / "absent-dir").string(), presentDir.string()});

    EXPECT_TRUE(found.found());
    EXPECT_EQ(found.file, present.string());
    EXPECT_EQ(found.dir, presentDir.string());
}

TEST(CaLocationTest, FindsNothingWhenNothingIsThere) {
    TempDir dir;
    const auto found = resolveCaLocation({(dir.path() / "nope.crt").string()},
                                         {(dir.path() / "nope").string()});
    EXPECT_FALSE(found.found());
    EXPECT_TRUE(found.file.empty());
    EXPECT_TRUE(found.dir.empty());
}

// A directory is not a bundle file and a file is not a bundle directory; picking one
// for the other would set CURLOPT_CAINFO to something curl cannot read.
TEST(CaLocationTest, DoesNotConfuseAFileForADirectory) {
    TempDir dir;
    const auto aFile = dir.file("plain-file");
    std::ofstream(aFile, std::ios::binary) << "x";
    const auto aDir = dir.path() / "plain-dir";
    fs::create_directories(aDir);

    // The file list is given the directory, and the directory list the file.
    const auto found = resolveCaLocation({aDir.string()}, {aFile.string()});
    EXPECT_FALSE(found.found());
}

// The lists that ship must name real, absolute, distribution-owned locations - never
// a path from the machine this was built on.
TEST(CaLocationTest, TheShippedCandidatesAreAbsoluteSystemPaths) {
    const auto all = {systemCaBundleFiles(), systemCaBundleDirs()};
    size_t count = 0;
    for (const auto& list : all) {
        for (const auto& candidate : list) {
            ++count;
            EXPECT_EQ(candidate.front(), '/') << candidate;
            EXPECT_EQ(candidate.find("vcpkg"), std::string::npos) << candidate;
            EXPECT_EQ(candidate.find("buildtrees"), std::string::npos) << candidate;
            EXPECT_EQ(candidate.find("/home/"), std::string::npos) << candidate;
        }
    }
    EXPECT_GE(count, 6u);
}

// A host with no certificates at all cannot verify anything. The answer is to say so
// and fail, never to carry on unverified: a version check is not worth teaching this
// tool to talk to whoever answers.
TEST(CaLocationTest, NoTrustStoreGetsAnAnswerSomebodyCanActOn) {
    const auto detail = certificateFailureDetail(/*trustStoreFound=*/false,
                                                 "Problem with the SSL CA cert");
    EXPECT_NE(detail.find("no certificate store"), std::string::npos);
    EXPECT_NE(detail.find("SSL_CERT_FILE"), std::string::npos);

    // With a store present, the underlying reason is the useful one and is kept.
    const auto passed = certificateFailureDetail(/*trustStoreFound=*/true,
                                                 "certificate has expired");
    EXPECT_EQ(passed, "certificate has expired");
    EXPECT_FALSE(certificateFailureDetail(true, "").empty());
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

TEST(UpdatesConfigTest, DefaultConfigParsesAndCarriesTheCompiledDefault) {
    const auto config = Config::loadFromString(Config::generateDefault());
    EXPECT_EQ(config.updates.check, kDefaultUpdateCheck);
    EXPECT_EQ(config.updates.intervalSeconds, kDefaultUpdateInterval);
}

// The default is one line in Rules.h, and the generated YAML prints it rather than
// repeating it. If those two ever disagree, flipping the default stops working
// silently for everyone who has no configuration file.
TEST(UpdatesConfigTest, GeneratedYamlQuotesTheDefaultRatherThanRepeatingIt) {
    const auto yaml = Config::generateDefault();
    const auto expected =
        std::string("check: ") + std::string(updateCheckModeToString(kDefaultUpdateCheck));
    EXPECT_NE(yaml.find(expected), std::string::npos) << expected << " not in the default config";
}

TEST(UpdatesConfigTest, ParsesEveryMode) {
    for (const auto* text : {"off", "on-demand", "periodic"}) {
        const auto yaml = std::string("builtin_rules:\n  enabled: true\nupdates:\n  check: ") + text + "\n";
        const auto config = Config::loadFromString(yaml);
        EXPECT_EQ(std::string(updateCheckModeToString(config.updates.check)), text);
    }
}

TEST(UpdatesConfigTest, ParsesTheInterval) {
    const auto config = Config::loadFromString(
        "builtin_rules:\n  enabled: true\nupdates:\n  check: periodic\n  interval: 6h\n");
    EXPECT_EQ(config.updates.intervalSeconds, 6u * 3600u);
}

// A typo away from `off` must not become the compiled-in default.
TEST(UpdatesConfigTest, RefusesAModeItDoesNotUnderstand) {
    EXPECT_THROW(Config::loadFromString(
        "builtin_rules:\n  enabled: true\nupdates:\n  check: of\n"), ConfigError);
    EXPECT_THROW(Config::loadFromString(
        "builtin_rules:\n  enabled: true\nupdates:\n  check: true\n"), ConfigError);
}

// An interval of zero means "every run", which is the thing the design exists to
// prevent - and it is what an unparseable duration silently becomes.
TEST(UpdatesConfigTest, RefusesAnIntervalItCannotRead) {
    EXPECT_THROW(Config::loadFromString(
        "builtin_rules:\n  enabled: true\nupdates:\n  interval: daily\n"), ConfigError);
    EXPECT_THROW(Config::loadFromString(
        "builtin_rules:\n  enabled: true\nupdates:\n  interval: 0\n"), ConfigError);
}

TEST(UpdatesConfigTest, WarnsAboutAnIntervalNobodyReadsTheAnswerTo) {
    auto config = Config::loadFromString(
        "builtin_rules:\n  enabled: true\nupdates:\n  check: periodic\n  interval: 5m\n");
    const auto warnings = Config::warnings(config);
    bool found = false;
    for (const auto& w : warnings) {
        if (w.find("updates.interval") != std::string::npos) found = true;
    }
    EXPECT_TRUE(found);

    // ...and does not warn about a sane one.
    config.updates.intervalSeconds = 24 * 3600;
    for (const auto& w : Config::warnings(config)) {
        EXPECT_EQ(w.find("updates.interval"), std::string::npos) << w;
    }
}

// "7d" was seven seconds before the day unit existed, which for an interval is the
// failure that looks like it worked.
TEST(DurationTest, ParsesTheDayUnit) {
    EXPECT_EQ(parseDurationSeconds("7d"), 7u * 86400u);
    EXPECT_EQ(parseDurationSeconds("1D"), 86400u);
    EXPECT_EQ(parseDurationSeconds("24h"), 24u * 3600u);
    EXPECT_EQ(parseDurationSeconds("90m"), 90u * 60u);
    EXPECT_EQ(parseDurationSeconds("30s"), 30u);
    EXPECT_EQ(parseDurationSeconds("30"), 30u);
    EXPECT_EQ(parseDurationSeconds(""), 0u);
    EXPECT_EQ(parseDurationSeconds("daily"), 0u);
}


// ---------------------------------------------------------------------------
// A trust store the operator named. Added with phase 3, because the download
// depends on the same configuration the check does.
// ---------------------------------------------------------------------------

TEST(CaLocationTest, AnOperatorsOwnBundleIsUsedRatherThanStoodAsideFor) {
    // The three names had to become something this code acts on. libcurl reads none of
    // them - CURL_CA_BUNDLE is a compile-time macro in libcurl and an environment
    // variable only for the curl command-line tool - so skipping the probe when one was
    // set left libcurl using the path from the machine it was BUILT on, which is the
    // failure the probe exists to prevent.
    const auto named = caLocationFromEnvironment(
        TrustStoreEnvironment{"/tmp/mine.pem", "", ""});
    EXPECT_EQ(named.file, "/tmp/mine.pem");
    EXPECT_TRUE(named.dir.empty());

    // SSL_CERT_FILE wins over CURL_CA_BUNDLE when both are set.
    EXPECT_EQ(caLocationFromEnvironment(
                  TrustStoreEnvironment{"/tmp/a.pem", "/tmp/b.pem", ""}).file,
              "/tmp/a.pem");
    EXPECT_EQ(caLocationFromEnvironment(TrustStoreEnvironment{"", "/tmp/b.pem", ""}).file,
              "/tmp/b.pem");
    EXPECT_EQ(caLocationFromEnvironment(TrustStoreEnvironment{"", "", "/tmp/certs"}).dir,
              "/tmp/certs");
}

TEST(CaLocationTest, NothingNamedLeavesTheProbeInCharge) {
    const auto named = caLocationFromEnvironment(TrustStoreEnvironment{});
    EXPECT_FALSE(named.found());

    CaLocation probed;
    probed.file = "/etc/ssl/certs/ca-certificates.crt";
    probed.dir = "/etc/ssl/certs";
    const auto chosen = chooseCaLocation(named, probed);
    EXPECT_EQ(chosen.file, probed.file);
    EXPECT_EQ(chosen.dir, probed.dir);
}

TEST(CaLocationTest, NamingOneKindDoesNotThrowAwayTheOther) {
    // Naming a bundle must not lose a probed directory, and the reverse. Collapsing the
    // two into one "is anything set" question is what the previous shape did, and it
    // took away both.
    CaLocation probed;
    probed.file = "/etc/ssl/certs/ca-certificates.crt";
    probed.dir = "/etc/ssl/certs";

    const auto fileOnly = chooseCaLocation(
        caLocationFromEnvironment(TrustStoreEnvironment{"/tmp/mine.pem", "", ""}), probed);
    EXPECT_EQ(fileOnly.file, "/tmp/mine.pem");
    EXPECT_EQ(fileOnly.dir, "/etc/ssl/certs");

    const auto dirOnly = chooseCaLocation(
        caLocationFromEnvironment(TrustStoreEnvironment{"", "", "/tmp/certs"}), probed);
    EXPECT_EQ(dirOnly.file, "/etc/ssl/certs/ca-certificates.crt");
    EXPECT_EQ(dirOnly.dir, "/tmp/certs");
}
