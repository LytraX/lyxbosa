#include "update/ReleaseAssets.h"

#include <fmt/format.h>

#include <cstdio>
#include <cstdlib>
#include <system_error>

namespace lyxbosa {

namespace {

constexpr std::string_view kApiOrigin = "https://api.github.com";
constexpr std::string_view kDownloadOrigin = "https://github.com";
constexpr std::string_view kRepository = "LytraX/lyxbosa";

#ifdef LYXBOSA_UPDATE_TEST_ORIGIN
// Compiled in only by an explicit -DLYXBOSA_UPDATE_TEST_ORIGIN=ON, which no release
// preset sets. See the note in ReleaseAssets.h for why moving the origin cannot make an
// unverified binary install: the keyring is compiled in, and bytes from anywhere still
// have to carry a signature from a key this build already trusts.
const char* testOrigin() {
    const char* value = std::getenv("LYXBOSA_UPDATE_ORIGIN");
    return (value != nullptr && value[0] != '\0') ? value : nullptr;
}
#endif

std::string apiOrigin() {
#ifdef LYXBOSA_UPDATE_TEST_ORIGIN
    if (const char* origin = testOrigin()) return origin;
#endif
    return std::string(kApiOrigin);
}

std::string downloadOrigin() {
#ifdef LYXBOSA_UPDATE_TEST_ORIGIN
    if (const char* origin = testOrigin()) return origin;
#endif
    return std::string(kDownloadOrigin);
}

}  // namespace

bool usingTestOrigin() {
#ifdef LYXBOSA_UPDATE_TEST_ORIGIN
    return testOrigin() != nullptr;
#else
    return false;
#endif
}

std::string_view platformAssetName() {
    // The four names .github/workflows/build.yml publishes, and nothing else. A
    // platform not listed here gets an empty string and `update` refuses, which is the
    // honest answer when there is no asset to fetch.
#if defined(_WIN32)
#if defined(_M_ARM64) || defined(__aarch64__)
    return "lyxbosa-windows-arm64.exe";
#elif defined(_M_X64) || defined(__x86_64__)
    return "lyxbosa-windows-amd64.exe";
#else
    return "";
#endif
#elif defined(__linux__)
#if defined(__aarch64__)
    return "lyxbosa-linux-arm64";
#elif defined(__x86_64__)
    return "lyxbosa-linux-amd64";
#else
    return "";
#endif
#else
    // macOS, the BSDs, anything else. A release publishes no binary for them, so there
    // is nothing an updater could install even though the replace itself would work.
    return "";
#endif
}

bool platformCanReplaceRunningBinary() {
    // Linux renames over the running inode; Windows moves the running image aside
    // first. Both are implemented in InstallPath.cpp, and there is no platform this is
    // built for that has neither.
    return true;
}

std::string releasesLatestUrl() {
    return fmt::format("{}/repos/{}/releases/latest", apiOrigin(), kRepository);
}

std::string releaseAssetUrl(std::string_view tag, std::string_view assetName) {
    return fmt::format("{}/{}/releases/download/{}/{}", downloadOrigin(), kRepository, tag,
                       assetName);
}

http::Outcome HttpAssetSource::fetch(std::string_view tag, std::string_view assetName,
                                     const std::filesystem::path& destination,
                                     uint64_t maxBytes) {
    std::error_code ec;
    std::filesystem::remove(destination, ec);

    // "wb" and not std::ofstream, because the bytes have to reach the filesystem and
    // the fsync that follows in InstallPath needs a descriptor rather than a stream.
    std::FILE* out = std::fopen(destination.string().c_str(), "wb");
    if (out == nullptr) {
        http::Outcome failed;
        failed.status = http::Outcome::Status::Failed;
        failed.detail = fmt::format("{} could not be opened for writing",
                                    destination.string());
        return failed;
    }

    http::Request request;
    request.url = releaseAssetUrl(tag, assetName);
    request.maxBytes = maxBytes;
    request.connectTimeout = std::chrono::seconds{10};
    // No wall-clock cap. A 3 MB download over a slow link legitimately takes minutes,
    // and cutting it off at an arbitrary number would refuse a download that was
    // working. What is NOT legitimate is a transfer that stops moving, and that is what
    // the low-speed guard below is for - it is the honest shape of "this will never
    // finish" for something whose duration varies.
    request.totalTimeout = std::chrono::milliseconds{0};
    request.lowSpeedBytesPerSecond = 512;
    request.lowSpeedFor = stallAfter_;

    bool writeFailed = false;
    http::Outcome outcome = http::perform(
        request,
        [out, &writeFailed](const char* data, size_t bytes) {
            if (bytes == 0) return true;
            if (std::fwrite(data, 1, bytes, out) != bytes) {
                writeFailed = true;
                return false;
            }
            return true;
        },
        neverCancelled_);

    const bool flushed = std::fflush(out) == 0;
    std::fclose(out);

    if (outcome.ok() && (writeFailed || !flushed)) {
        outcome.status = http::Outcome::Status::Failed;
        outcome.detail = fmt::format("{} could not be written in full", destination.string());
    }

    // Nothing downstream is handed a partial file. This is the rule the round is built
    // on: a failed step leaves no artefact for a later step to be trusted to notice.
    if (!outcome.ok()) {
        std::error_code removeEc;
        std::filesystem::remove(destination, removeEc);
    }
    return outcome;
}

}  // namespace lyxbosa
