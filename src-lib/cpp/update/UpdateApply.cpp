// See UpdateApply.h for the chain and why it is in this order. This file is the order.

#include "update/UpdateApply.h"

#include "update/Checksums.h"
#include "update/InstallPath.h"
#include "update/Minisign.h"

#include <fmt/format.h>

#include <cstdio>
#include <system_error>
#include <vector>

namespace lyxbosa {

namespace {

// Removes whatever staging files still exist, however the function leaves. Every
// refusal below returns through this, which is what makes "a refusal leaves nothing
// behind" a property of the code rather than of remembering to write the cleanup at
// twenty return sites.
class Staging {
public:
    ~Staging() { clear(); }

    void track(std::filesystem::path path) { paths_.push_back(std::move(path)); }

    void clear() {
        std::error_code ec;
        for (const auto& path : paths_) {
            std::filesystem::remove(path, ec);
        }
        paths_.clear();
    }

    // Called when a file has been renamed away and is no longer ours to delete.
    void forget(const std::filesystem::path& path) {
        for (auto it = paths_.begin(); it != paths_.end(); ++it) {
            if (*it == path) {
                paths_.erase(it);
                return;
            }
        }
    }

private:
    std::vector<std::filesystem::path> paths_;
};

std::optional<std::string> readFile(const std::filesystem::path& path, uint64_t maxBytes) {
    std::FILE* file = std::fopen(path.string().c_str(), "rb");
    if (file == nullptr) return std::nullopt;

    std::string out;
    char buffer[16 * 1024];
    for (;;) {
        const size_t read = std::fread(buffer, 1, sizeof(buffer), file);
        if (read > 0) {
            if (out.size() + read > maxBytes) {
                std::fclose(file);
                return std::nullopt;
            }
            out.append(buffer, read);
        }
        if (read < sizeof(buffer)) {
            const bool bad = std::ferror(file) != 0;
            std::fclose(file);
            if (bad) return std::nullopt;
            return out;
        }
    }
}

ApplyResult refuse(ApplyOutcome outcome, std::string detail) {
    ApplyResult out;
    out.outcome = outcome;
    out.detail = std::move(detail);
    return out;
}

void step(const ApplyOptions& options, std::string_view what) {
    if (options.onStep) options.onStep(what);
}

// The tag, as a string this updater is willing to put in a URL.
//
// The tag arrives over the network, and it is the only network-supplied value that
// reaches a URL path. Rather than escaping it, it is REBUILT: the version is parsed
// first, and the tag is accepted only if it is exactly that version, optionally with a
// leading `v`. docs/RELEASING.md's tags are `v1.2.0` and nothing else - it records that
// a non-numeric tag such as v0.0.1-rc1 breaks the Windows build outright - so this
// refuses nothing this project publishes, and it refuses everything else without
// anybody having to reason about escaping.
bool tagIsUsable(std::string_view tag, const Version& version) {
    const std::string plain = toString(version);
    return tag == plain || (tag.size() == plain.size() + 1 && tag.front() == 'v' &&
                            tag.substr(1) == plain);
}

}  // namespace

std::string_view describeOutcome(ApplyOutcome outcome) {
    switch (outcome) {
        case ApplyOutcome::Replaced:              return "the binary was replaced";
        case ApplyOutcome::AlreadyCurrent:        return "already up to date";
        case ApplyOutcome::Declined:              return "nothing was changed";
        case ApplyOutcome::PlatformCannotReplace: return "this platform cannot replace a running binary yet";
        case ApplyOutcome::NoVerifier:            return "this build cannot verify a download";
        case ApplyOutcome::NoAssetForPlatform:    return "a release publishes no binary for this platform";
        case ApplyOutcome::DevelopmentBuild:      return "this is a development build";
        case ApplyOutcome::InstallPathUnknown:    return "the installed binary could not be located";
        case ApplyOutcome::PackageManaged:        return "a package manager owns this install";
        case ApplyOutcome::NotWritable:           return "the installed binary cannot be replaced by this user";
        case ApplyOutcome::VersionUnavailable:    return "the newest release could not be found out";
        case ApplyOutcome::TagUnusable:           return "the newest release is tagged in a way this updater will not follow";
        case ApplyOutcome::Downgrade:             return "that would be a downgrade";
        case ApplyOutcome::ListUnavailable:       return "the signed checksum list could not be fetched";
        case ApplyOutcome::KeyringMalformed:      return "the keys built into this binary did not parse";
        case ApplyOutcome::SignatureMalformed:    return "the signature file could not be read";
        case ApplyOutcome::UnknownKey:            return "the release is signed by a key this build does not carry";
        case ApplyOutcome::SignatureBad:          return "the signature does not verify";
        case ApplyOutcome::TrustedCommentBad:     return "the signature's trusted comment does not verify";
        case ApplyOutcome::WrongRelease:          return "the signed list is for a different release";
        case ApplyOutcome::ListMalformed:         return "the checksum list could not be read";
        case ApplyOutcome::AssetNotListed:        return "the signed list does not mention this platform's binary";
        case ApplyOutcome::DownloadFailed:        return "the download did not complete";
        case ApplyOutcome::HashMismatch:          return "the download does not match the signed checksum";
        case ApplyOutcome::StagedBinaryUnusable:  return "the downloaded binary does not run on this host";
        case ApplyOutcome::ReplaceFailed:         return "the binary could not be put in place";
    }
    return "the update did not happen";
}

ApplyResult applyUpdate(VersionSource& versions, AssetSource& assets,
                        const ApplyOptions& options) {
    // ---------------------------------------------------------------------------
    // Guards that fire before a single byte is fetched. Cheap first, and ordered so
    // that the reason a user is told is the one they can act on: a Windows user needs
    // to hear about Windows, not about a verifier that is absent because of it.
    // ---------------------------------------------------------------------------
    if (!platformCanReplaceRunningBinary()) {
        return refuse(ApplyOutcome::PlatformCannotReplace,
                      "a running executable is locked on Windows, so it has to be "
                      "replaced on the next start - that is not built yet");
    }
    if (!minisign::verifierAvailable()) {
        // Never degrade to "download it anyway". A program that runs as root on
        // compromised hosts does not install bytes it cannot check.
        return refuse(ApplyOutcome::NoVerifier,
                      "there is no signature verifier compiled into it, so it cannot "
                      "check what it would be about to run");
    }

    const std::string_view assetName = platformAssetName();
    if (assetName.empty()) {
        return refuse(ApplyOutcome::NoAssetForPlatform,
                      "a release publishes Linux and Windows binaries only");
    }

    const Version running = options.running.value_or(runningVersion());
    if (!running.isRelease()) {
        // 0.0.0 is what a build that did not come from a tag reports. Every published
        // release is numerically newer than it, so an updater that compared would
        // replace every developer's build with the last release.
        return refuse(ApplyOutcome::DevelopmentBuild,
                      fmt::format("this binary reports {}, which is not a released "
                                  "version, so there is nothing to update from",
                                  LYXBOSA_VERSION));
    }

    std::filesystem::path target = options.target;
    if (target.empty()) target = runningExecutablePath();
    if (target.empty()) {
        return refuse(ApplyOutcome::InstallPathUnknown,
                      "this platform does not tell a process where its own binary is");
    }

    if (const std::string_view owner = packageManagerOwning(target); !owner.empty()) {
        return refuse(ApplyOutcome::PackageManaged,
                      fmt::format("{} is owned by {}; updating it behind the package "
                                  "manager's back leaves its database describing a file "
                                  "that is no longer there",
                                  target.string(), owner));
    }

    // Asked before the download rather than after it, so a user who cannot install the
    // update is not made to fetch it first. It is asked again, implicitly, by the write
    // itself - a filesystem can go read-only between the two.
    if (const ReplaceAccess access = canReplace(target); !access.ok) {
        return refuse(ApplyOutcome::NotWritable,
                      fmt::format("{}. Download the release and install it yourself "
                                  "rather than re-running this under sudo: a scanner "
                                  "that rewrites a system binary because a version "
                                  "check said so is a footgun",
                                  access.reason));
    }

    // ---------------------------------------------------------------------------
    // What is newest, and whether it is newer.
    // ---------------------------------------------------------------------------
    step(options, "Asking which release is newest");
    const UpdateCheckResult check = fetchAndCompare(versions, running, options.versionTimeout);

    if (!check.outcome.ok() || !check.latest) {
        return refuse(ApplyOutcome::VersionUnavailable,
                      check.outcome.detail.empty() ? "the request did not succeed"
                                                   : check.outcome.detail);
    }

    ApplyResult result;
    result.latest = check.latest;

    // Best effort, and deliberately before the decision below: a run that goes on to
    // refuse still learned what the newest release is, and a scan later today should
    // not have to ask again.
    if (options.now) {
        UpdateState state;
        state.lastCheckEpoch = options.now();
        state.latestVersion = toString(*check.latest);
        writeUpdateState(
            options.statePath.empty() ? defaultUpdateStatePath() : options.statePath, state);
    }

    const std::string tag = check.outcome.version;
    if (!tagIsUsable(tag, *check.latest)) {
        result.outcome = ApplyOutcome::TagUnusable;
        result.detail = fmt::format(
            "the newest release parses as {} and is tagged something else; this updater "
            "builds its download URL from the tag and will not guess at one",
            toString(*check.latest));
        return result;
    }

    if (*check.latest == running) {
        result.outcome = ApplyOutcome::AlreadyCurrent;
        result.detail = fmt::format("{} is the newest release", toString(running));
        return result;
    }
    if (*check.latest < running) {
        // A signed old release is still signed. Refusing to move backwards is the only
        // thing standing between "an attacker chose which release you fetch" and "you
        // are now running a version with a known defect".
        result.outcome = ApplyOutcome::Downgrade;
        result.detail = fmt::format(
            "the newest published release is {} and this is {}; moving to an older "
            "version is refused, because a signed old release is still signed and "
            "rolling somebody backwards into a known defect needs no forgery",
            toString(*check.latest), toString(running));
        return result;
    }

    ApplyPlan plan;
    plan.from = running;
    plan.to = *check.latest;
    plan.tag = tag;
    plan.assetName = std::string(assetName);
    plan.target = target;
    result.plan = plan;

    if (!options.assumeYes) {
        // No default yes. A caller that supplied no way to ask gets a refusal.
        const bool agreed = options.confirm && options.confirm(plan);
        if (!agreed) {
            result.outcome = ApplyOutcome::Declined;
            result.detail = fmt::format("{} is still in place", target.string());
            return result;
        }
    }

    // ---------------------------------------------------------------------------
    // The chain. Everything from here writes into the install directory and is
    // removed again by `staging` on every path out of this function.
    // ---------------------------------------------------------------------------
    Staging staging;

    const std::filesystem::path stagedAsset = stagingPathFor(target);
    // Derived from the same pid-unique name, so two updates running at once do not
    // write over each other's list while verifying it.
    const std::filesystem::path stagedList = stagedAsset.string() + ".sums";
    const std::filesystem::path stagedSignature = stagedAsset.string() + ".sums.minisig";
    staging.track(stagedAsset);
    staging.track(stagedList);
    staging.track(stagedSignature);

    step(options, "Fetching the checksum list and its signature");
    if (const http::Outcome fetched = assets.fetch(tag, kChecksumListName, stagedList,
                                                   kMaxChecksumListBytes);
        !fetched.ok()) {
        result.outcome = ApplyOutcome::ListUnavailable;
        result.detail = fmt::format("{}: {}", kChecksumListName, fetched.detail);
        return result;
    }
    if (const http::Outcome fetched = assets.fetch(tag, kChecksumSignatureName,
                                                   stagedSignature, kMaxChecksumListBytes);
        !fetched.ok()) {
        result.outcome = ApplyOutcome::ListUnavailable;
        result.detail = fmt::format("{}: {}", kChecksumSignatureName, fetched.detail);
        return result;
    }

    const auto listText = readFile(stagedList, kMaxChecksumListBytes);
    const auto signatureText = readFile(stagedSignature, kMaxChecksumListBytes);
    if (!listText || !signatureText) {
        result.outcome = ApplyOutcome::ListUnavailable;
        result.detail = "the downloaded checksum list could not be read back";
        return result;
    }

    // ---------------------------------------------------------------------------
    // The signature, over the LIST, before the list is read as anything but bytes.
    // ---------------------------------------------------------------------------
    step(options, "Verifying the signature over the checksum list");
    const minisign::SignatureParse parsed = minisign::parseSignature(*signatureText);
    if (!parsed.ok()) {
        result.outcome = ApplyOutcome::SignatureMalformed;
        result.detail = parsed.error;
        return result;
    }

    const minisign::Keyring& keyring =
        options.keyring != nullptr ? *options.keyring : minisign::embeddedKeyring();
    const minisign::VerifyResult verified =
        minisign::verifyDetached(*listText, parsed.signature, keyring);
    switch (verified.status) {
        case minisign::VerifyStatus::Ok:
            break;
        case minisign::VerifyStatus::MalformedKeyring:
            result.outcome = ApplyOutcome::KeyringMalformed;
            result.detail = verified.detail;
            return result;
        case minisign::VerifyStatus::UnknownKey:
            // The frozen-keyring case, designed for rather than discovered: a binary
            // built before a key was introduced has never seen it and cannot verify a
            // release signed by it. Refusing and sending the user to a manual download
            // is the correct outcome; proceeding unverified is not an option that
            // exists in this program.
            result.outcome = ApplyOutcome::UnknownKey;
            result.detail =
                "the keys a binary trusts are compiled into it, so a release signed by "
                "a key introduced after this build cannot be checked here - download "
                "the release and verify it by hand instead";
            return result;
        case minisign::VerifyStatus::BadGlobalSignature:
            result.outcome = ApplyOutcome::TrustedCommentBad;
            result.detail = verified.detail;
            return result;
        case minisign::VerifyStatus::NoVerifier:
        case minisign::VerifyStatus::BadSignature:
            result.outcome = ApplyOutcome::SignatureBad;
            result.detail = verified.detail;
            return result;
    }
    result.trustedComment = verified.trustedComment;

    // Signed, genuine, and possibly for another release. The tag inside the trusted
    // comment is the only thing that says which one, and the global signature checked
    // above is what makes it worth reading.
    if (!minisign::trustedCommentNamesTag(verified.trustedComment, tag)) {
        result.outcome = ApplyOutcome::WrongRelease;
        result.detail = fmt::format(
            "its signature is genuine and its trusted comment does not name {} - an "
            "older release's list and signature verify perfectly well and describe the "
            "wrong binaries", tag);
        return result;
    }

    const ChecksumList list = parseChecksumList(*listText);
    if (!list.ok()) {
        result.outcome = ApplyOutcome::ListMalformed;
        result.detail = list.error;
        return result;
    }

    const ChecksumEntry* expected = list.find(assetName);
    if (expected == nullptr) {
        result.outcome = ApplyOutcome::AssetNotListed;
        result.detail = fmt::format(
            "{} names {} file(s) and none of them is {}", kChecksumListName,
            list.entries.size(), assetName);
        return result;
    }

    // ---------------------------------------------------------------------------
    // Only now the binary itself.
    // ---------------------------------------------------------------------------
    step(options, fmt::format("Downloading {}", assetName));
    if (const http::Outcome fetched =
            assets.fetch(tag, assetName, stagedAsset, kMaxAssetBytes);
        !fetched.ok()) {
        result.outcome = ApplyOutcome::DownloadFailed;
        result.detail = fetched.detail;
        return result;
    }

    step(options, "Checking it against the signed checksum");
    const auto actual = sha256File(stagedAsset);
    if (!actual) {
        result.outcome = ApplyOutcome::DownloadFailed;
        result.detail = "the download could not be read back to hash it";
        return result;
    }
    if (!hashesEqual(*actual, expected->hash)) {
        result.outcome = ApplyOutcome::HashMismatch;
        result.detail = fmt::format(
            "the signed list says {} and what arrived hashes to {}", expected->hash, *actual);
        return result;
    }

    // The old binary's permission bits, before the file is executed rather than after.
    // A download arrives without an execute bit, and exec on it would fail in a way
    // indistinguishable from a binary that cannot run on this host.
    if (const std::string failure = adoptTargetOwnership(stagedAsset, target);
        !failure.empty()) {
        result.outcome = ApplyOutcome::ReplaceFailed;
        result.detail = failure;
        return result;
    }

    // Verified bytes, and they are about to be installed and run as root. Finding out
    // now that they will not run here - a glibc newer than this host's is the realistic
    // way - costs a download; finding out afterwards costs the user their scanner.
    step(options, "Checking it runs on this host");
    const bool runs = options.smokeTest ? options.smokeTest(stagedAsset)
                                        : stagedBinaryRuns(stagedAsset);
    if (!runs) {
        result.outcome = ApplyOutcome::StagedBinaryUnusable;
        result.detail =
            "it did not start when asked for its version, so it has not been installed - "
            "the most likely cause is a C library older here than on the build host";
        return result;
    }

    step(options, fmt::format("Replacing {}", target.string()));
    if (const std::string failure = replaceAtomically(stagedAsset, target); !failure.empty()) {
        result.outcome = ApplyOutcome::ReplaceFailed;
        result.detail = failure;
        return result;
    }
    staging.forget(stagedAsset);  // renamed away; it is the installed binary now

    result.outcome = ApplyOutcome::Replaced;
    result.detail = fmt::format("{} is now {}", target.string(), toString(plan.to));
    return result;
}

}  // namespace lyxbosa
