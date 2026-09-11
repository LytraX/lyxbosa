#pragma once

// UpdateApply.h - download, verify, replace. The dangerous phase, and the reason the
// three before it exist.
//
//
// THE VERIFICATION CHAIN, AND WHY IT IS IN THIS ORDER
// ----------------------------------------------------
//   1. fetch SHA256SUMS and SHA256SUMS.minisig
//   2. verify the signature over the LIST against the keyring compiled into this binary
//   3. verify the global signature, which is what binds the trusted comment
//   4. check the trusted comment names the tag being installed
//   5. only then hash the downloaded asset and compare it to its line in that list
//
// Step 5 is worth nothing without steps 2 and 3. A hash checked against an unverified
// list defends against a corrupted transfer and nothing else, because whoever can
// rewrite the asset can rewrite the list published beside it. Step 4 is the one that is
// easy to leave out and it is not decoration: docs/RELEASING.md records that a
// SHA256SUMS and SHA256SUMS.minisig pair lifted wholesale from an older release
// verifies perfectly and describes the wrong binaries.
//
//
// ROLLING BACKWARDS IS AN ATTACK, SO IT IS REFUSED
// -------------------------------------------------
// A signed old release is still signed. An attacker who can decide which release you
// fetch - a hostile mirror, a DNS answer, an intercepted redirect - can move you onto a
// version with a known defect without forging anything. So `update` refuses to move to
// a version that is not strictly newer than the running one, and that refusal is not
// conditional on anything.
//
// `--to VER` IS DELIBERATELY NOT IN THIS ROUND. It is the one feature that would put a
// hole in the rule above by construction, it needs a second API endpoint
// (/releases/tags/<tag>) that nothing else uses, and it would ship in the same round
// that first taught this program to replace itself. It is worth having later, with its
// own output saying in plain words that it is going backwards and what that means; it
// is not worth having in the round where the replace itself is new.
//
//
// EVERY SEAM IS INJECTED
// -----------------------
// The network (VersionSource, AssetSource), the filesystem (the target path is a
// parameter) and the clock are all handed in, so that no test touches GitHub and no
// test writes outside a temporary directory. The controls that matter are the
// refusals - a bad signature, a good signature by an untrusted key, a good signature
// over a mutated list, a list that does not name the asset, a hash mismatch, a
// truncated download, a download that never completes, an unwritable target, and a
// downgrade - and each asserts afterwards that the old binary is still there and still
// runs. A refusal that leaves a half-written file is not a refusal.

#include "update/Minisign.h"
#include "update/ReleaseAssets.h"
#include "update/UpdateCheck.h"
#include "update/UpdateState.h"
#include "update/Version.h"
#include "update/VersionSource.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace lyxbosa {

// What an update would do, decided before anything is downloaded so it can be shown to
// a person and agreed to.
struct ApplyPlan {
    Version from;
    Version to;
    std::string tag;        // the release tag, exactly as published
    std::string assetName;  // the asset this platform installs
    std::filesystem::path target;
};

enum class ApplyOutcome {
    Replaced,               // the only outcome in which the binary changed
    AlreadyCurrent,
    Declined,               // the person said no

    // Guards that fire before anything is fetched.
    PlatformCannotReplace,  // no replace is implemented for this platform at all
    NoVerifier,             // built without Ed25519, so nothing could be checked
    NoAssetForPlatform,     // no release asset exists for this platform at all
    DevelopmentBuild,       // 0.0.0 is not a release and has nothing to compare against
    InstallPathUnknown,
    PackageManaged,
    NotWritable,

    // What the releases API said.
    VersionUnavailable,
    TagUnusable,            // an answer this updater will not build a URL from
    Downgrade,              // the newest published release is older than this one

    // The chain.
    ListUnavailable,        // SHA256SUMS or its signature could not be fetched
    KeyringMalformed,       // the keys compiled into this binary did not parse
    SignatureMalformed,
    UnknownKey,             // signed by a key this build does not carry
    SignatureBad,
    TrustedCommentBad,      // the comment is not the one that was signed
    WrongRelease,           // signed, genuine, and for a different release
    ListMalformed,
    AssetNotListed,         // the verified list does not mention this platform's asset

    // The download and the replace.
    DownloadFailed,         // refused, truncated, stalled, or unreadable afterwards
    HashMismatch,
    StagedBinaryUnusable,   // it verified and it will not run on this host
    ReplaceFailed,
};

struct ApplyResult {
    ApplyOutcome outcome = ApplyOutcome::VersionUnavailable;
    std::string detail;               // one sentence, for someone who typed a command

    std::optional<ApplyPlan> plan;    // set once a target version is known
    std::optional<Version> latest;    // what the releases API said, when it answered

    // The trusted comment, and only when it VERIFIED. An unverified comment is
    // attacker-supplied text; carrying it beside a failure is how it ends up printed as
    // if it were a fact.
    std::string trustedComment;

    bool replaced() const { return outcome == ApplyOutcome::Replaced; }
    bool ok() const {
        return outcome == ApplyOutcome::Replaced || outcome == ApplyOutcome::AlreadyCurrent;
    }
};

struct ApplyOptions {
    // Empty means the file this process is running from. Tests point it at a copy in a
    // temporary directory, which is also what makes "the old binary is still there and
    // still runs" an assertion rather than a hope.
    std::filesystem::path target;

    // Empty means runningVersion(). Set explicitly by tests so the comparison, the
    // downgrade refusal and the development-build refusal do not depend on how the test
    // binary was built.
    std::optional<Version> running;

    std::chrono::milliseconds versionTimeout = kUpdateCheckTimeout;

    // No default yes. A caller that provides nothing gets a refusal rather than an
    // update, so a missing prompt can never become a silent replacement.
    std::function<bool(const ApplyPlan&)> confirm;
    bool assumeYes = false;

    // Progress, one line per step. Optional.
    std::function<void(std::string_view)> onStep;

    // Whether the verified, staged binary actually runs here. Injected so a test can
    // make it fail without needing a binary that will not run on the test machine.
    std::function<bool(const std::filesystem::path&)> smokeTest;

    // Seconds since the epoch, for the state file. Injected so no test depends on a
    // wall clock.
    std::function<uint64_t()> now;

    // Where the "we asked, and this is what we heard" cache lives. Empty means the
    // default location; a test points it inside its own temporary directory.
    std::filesystem::path statePath;

    // Null means the keys compiled into this binary, which is what the CLI always uses
    // and what a release always uses. It exists so that tests can drive the whole chain
    // - a good signature, a bad one, one by an untrusted key, one over a mutated list -
    // against keys they generate, which is impossible with the shipped keyring because
    // nobody holds its private half. It is an in-process parameter with no flag, no
    // environment variable and no configuration key behind it; there is a test asserting
    // that the DEFAULT really is the embedded keyring and not something permissive.
    const minisign::Keyring* keyring = nullptr;
};

// Run the whole thing. Never throws.
ApplyResult applyUpdate(VersionSource& versions, AssetSource& assets,
                        const ApplyOptions& options);

// The sentence for an outcome, without the detail. Split out so the CLI and the tests
// agree on the wording and neither has to spell it twice.
std::string_view describeOutcome(ApplyOutcome outcome);

}  // namespace lyxbosa
