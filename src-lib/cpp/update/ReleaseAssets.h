#pragma once

// ReleaseAssets.h - which file a release publishes for this platform, where it lives,
// and the seam that fetches it.
//
// The seam is the reason this is a class rather than a function: no test in this
// repository touches GitHub, and every refusal in UpdateApply - a bad signature, a
// mutated list, a truncated download, a download that never completes - is driven by
// handing it an AssetSource that produces exactly that.

#include "update/HttpTransport.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace lyxbosa {

// The two files that make a release verifiable, named once.
inline constexpr std::string_view kChecksumListName = "SHA256SUMS";
inline constexpr std::string_view kChecksumSignatureName = "SHA256SUMS.minisig";

// A release binary is about 3 MB. 64 MB is twenty times that and still small enough
// that a redirect onto something enormous is refused rather than written to the disk
// of a host somebody is in the middle of an incident on.
inline constexpr uint64_t kMaxAssetBytes = 64ull * 1024 * 1024;

// The list and its signature are a few hundred bytes each.
inline constexpr uint64_t kMaxChecksumListBytes = 256ull * 1024;

// The asset name a release publishes for the platform this binary was built for.
//
// Empty means a release publishes nothing this binary could install, and that is not
// hypothetical: .github/workflows/build.yml builds Linux amd64/arm64 and Windows
// amd64/arm64, four assets, which `release-checksums.sh --expect 4` exists to hold it
// to. There is no macOS asset, so an updater running there has nothing to fetch and
// says so rather than guessing at a name.
std::string_view platformAssetName();

// Whether a running executable can be replaced on this platform. True everywhere a
// release publishes a binary: by an atomic rename on Linux, and on Windows by moving
// the running image aside and the verified download into its place - InstallPath.h
// describes both. It stays a function rather than a constant because it is the seam
// `update` refuses through: a platform added without a replace of its own returns
// false here and is told so, rather than failing inside the replace.
bool platformCanReplaceRunningBinary();

// Where the releases API and the release downloads live.
//
// These are functions rather than constants because of LYXBOSA_UPDATE_TEST_ORIGIN
// below. In a shipped build they return the constants and nothing else can happen.
std::string releasesLatestUrl();
std::string releaseAssetUrl(std::string_view tag, std::string_view assetName);

// True when this build was compiled with the origin override AND the environment is
// using it. Always false in a shipped binary.
//
// LYXBOSA_UPDATE_TEST_ORIGIN is a CMake option, OFF by default, that lets a local build
// point both origins at a server on this machine so that docs/local/demo-update.sh can
// show a real download, a real verification and a real replacement without a release
// being cut. It is compiled out of every release build, so a shipped binary has no code
// path that reads the variable at all.
//
// Note what it does NOT do even when it is on: it cannot make an unverified binary
// install. The keyring is compiled in, so bytes served from anywhere still have to
// carry a signature from a key this build already trusts. Moving the origin buys an
// attacker a denial of updates, which anybody on the network already has.
bool usingTestOrigin();

// Where the release files come from. One method, because everything is fetched the same
// way: to a file, completely, or not at all. Nothing downstream is ever handed a
// partial file and asked to notice.
class AssetSource {
public:
    virtual ~AssetSource() = default;

    // Fetch <tag>/<assetName> into `destination`. On any failure the destination must
    // not exist afterwards: a half-written file that a later step is trusted to notice
    // is the shape this whole round is written to avoid.
    virtual http::Outcome fetch(std::string_view tag, std::string_view assetName,
                                const std::filesystem::path& destination,
                                uint64_t maxBytes) = 0;
};

// The real one.
class HttpAssetSource : public AssetSource {
public:
    explicit HttpAssetSource(std::chrono::seconds stallAfter = std::chrono::seconds{30})
        : stallAfter_(stallAfter) {}

    http::Outcome fetch(std::string_view tag, std::string_view assetName,
                        const std::filesystem::path& destination,
                        uint64_t maxBytes) override;

private:
    std::chrono::seconds stallAfter_;
    std::atomic<bool> neverCancelled_{false};
};

}  // namespace lyxbosa
