#pragma once

// VersionSource.h - where "what is the newest release" comes from, behind a seam.
//
// The seam exists so that no test ever touches GitHub. Everything that decides
// behaviour - the predicate, the interval arithmetic, the cache, the comparison, the
// timeout and every failure path - is exercised against a fake, and the one piece
// that cannot be is the HTTP request itself.
//
//
// WHY THE RELEASES API AND NOT A PUBLISHED MANIFEST
// -------------------------------------------------
// docs/tasks/UPDATE_PLAN.md 10 left this open: the GitHub releases API, or a small
// static JSON published as a release asset. The asset is genuinely the nicer shape -
// bytes we define, served by the release CDN, no API rate limit - and it still loses
// here, for three reasons that are specific to this repository:
//
//   The release job cannot be rehearsed. `.github/scripts/release-checksums.sh` says
//   so at length, and it is gated on a `v*` tag, so any change to it is code that
//   ships without ever having run. Publishing a manifest means changing that job and
//   changing `--expect 4`, whose entire design is to STOP when the asset set changes.
//   The API needs no release change at all.
//
//   A manifest does not exist for any release already published. Shipping one would
//   leave the check inert until the release after next, which is a feature that looks
//   like it works and does nothing.
//
//   Both of the API's real drawbacks fail in the safe direction. The unauthenticated
//   rate limit is 60 requests an hour per address, and being refused means no notice
//   today - not a failed scan. A change in the response shape means the field is not
//   found, which is also no notice today. Every other failure path in this design
//   already degrades to silence, so these two are not new behaviour.
//
// What is NOT done is parse the response as JSON. One field is extracted, bounded,
// from a bounded body, and then validated against a strict version grammar. A general
// parser over 20 KB of network-supplied text is a larger thing to have in a scanner
// that runs as root than the problem justifies.
//
// If a rate-limit refusal is ever actually observed, the manifest is the answer, and
// it is then a release-job change with its own --selftest rather than a guess.
//
//
// THE TRANSPORT IS libcurl, LINKED
// ---------------------------------
// vcpkg.json asks for `curl` with `default-features: false` and the one feature
// `ssl`. The reasoning, and what it actually costs, is in HttpVersionSource.cpp
// beside the code it governs. The short version:
//
//   Dropping `non-http` drops FTP, LDAP, SMTP, telnet, dict, gopher and the rest out
//   of the build. This speaks HTTPS to one host; the rest is surface with no user.
//
//   `ssl` is Schannel on Windows - the OS stack and the OS certificate store, so no
//   dependency at all there - and OpenSSL on Linux and macOS, reading the system
//   trust store at the standard paths. No certificate bundle is shipped or embedded.
//
//   Measured cost of adding it, cold: OpenSSL 59s, curl 38s, once, then cached.
//
// Two alternatives were built and measured rather than argued about.
//
//   Spawning the `curl` BINARY. Avoids the dependency, and was the wrong trade: the
//   feature then silently does nothing on a host without curl and nothing says which
//   - the failure this repository has the least patience for - and it needs a
//   hand-written CreateProcess path on Windows that no CI here compiles.
//
//   `cpr`, which is the obvious clean-API answer. Its own manifest calls it "a simple
//   wrapper around libcurl" and it depends on curl[ssl] and openssl, so it changes
//   nothing about the dependency, the TLS stack, the CA problem below, or the Perl
//   that OpenSSL builds with. What it changes is cancellation: cpr can only cancel
//   through libcurl's progress callback, which is not called at all while a connect
//   is stalled. Measured, on an api.github.com pointed at a blackhole: a scan takes
//   2.04s with cpr and 0.29s here, because curl_multi_poll notices the cancel flag in
//   50 ms and an easy-handle perform cannot be interrupted. The clean version was
//   also only 19 lines shorter over the whole file - the CA probe, the version
//   extraction and the error mapping are most of it, and cpr replaces none of them.
//
// If "cannot delay output" is ever relaxed, cpr is the better code and the swap is
// this one function.

#include <atomic>
#include <chrono>
#include <vector>
#include <optional>
#include <string>
#include <string_view>

namespace lyxbosa {

struct FetchOutcome {
    enum class Status {
        Ok,             // version holds the tag as published
        NoTransport,    // no curl on this host
        RequestFailed,  // curl ran and did not come back with a body
        BadResponse,    // a body arrived and did not contain a version
        Cancelled       // the caller stopped waiting
    };

    Status status = Status::RequestFailed;
    std::string version;  // the raw tag, e.g. "v2.2.1"; only set when Ok
    std::string detail;   // one line, for a command a person typed

    bool ok() const { return status == Status::Ok; }
};

class VersionSource {
public:
    virtual ~VersionSource() = default;

    // Must return within `timeout`, and must return promptly once `cancelled` is
    // set. Both are requirements rather than hints: the caller is a scan that has
    // already printed its report and is not allowed to wait for this.
    virtual FetchOutcome fetchLatest(std::chrono::milliseconds timeout,
                                     const std::atomic<bool>& cancelled) = 0;
};

// The releases API for this repository.
inline constexpr std::string_view kReleasesApiUrl =
    "https://api.github.com/repos/LytraX/lyxbosa/releases/latest";

// Where the system's certificate authorities live on this host.
//
// This exists because a released binary is built on one distribution and run on
// another. curl bakes its CA bundle path in at configure time, so the AlmaLinux 8
// release build carries /etc/pki/tls/certs/ca-bundle.crt and every Debian or Ubuntu
// host it then runs on has no such file - measured, on the real release artefact:
// "Problem with the SSL CA cert (path? access rights?)". Probing at run time is the
// fix, and it is still the host's own trust store; nothing is shipped or embedded.
//
// Split out from the caller so it can be tested against directories that exist rather
// than against whatever the machine running the tests happens to have in /etc.
struct CaLocation {
    std::string file;  // a bundle, for CURLOPT_CAINFO
    std::string dir;   // a hashed directory, for CURLOPT_CAPATH
    bool found() const { return !file.empty() || !dir.empty(); }
};

// The first candidate of each kind that exists, file preferred. Returns empty when
// none does, which leaves the TLS backend's own default in place.
CaLocation resolveCaLocation(const std::vector<std::string>& bundleFiles,
                             const std::vector<std::string>& bundleDirs);

// The candidates for this platform, in order.
const std::vector<std::string>& systemCaBundleFiles();
const std::vector<std::string>& systemCaBundleDirs();

// What to tell someone whose request failed on certificates. Separated from the
// request so the case an operator can actually act on - no trust store at all - has a
// test rather than a socket behind it. Verification is never disabled to get past it:
// a version check is not worth teaching anyone that this tool will talk to anybody.
std::string certificateFailureDetail(bool trustStoreFound,
                                     const std::string& underlying);

// Pull `"tag_name": "v2.2.1"` out of a releases API response.
//
// Not a JSON parser and not trying to be: it finds the key, requires a colon and a
// quoted value, and refuses a value containing an escape, a control character or more
// than 64 characters. Everything it refuses becomes "no notice today".
std::optional<std::string> extractTagName(std::string_view body);

// The real one. Uses libcurl; see the header comment.
class HttpVersionSource : public VersionSource {
public:
    explicit HttpVersionSource(std::string url = std::string(kReleasesApiUrl))
        : url_(std::move(url)) {}

    FetchOutcome fetchLatest(std::chrono::milliseconds timeout,
                             const std::atomic<bool>& cancelled) override;

private:
    std::string url_;
};

}  // namespace lyxbosa
