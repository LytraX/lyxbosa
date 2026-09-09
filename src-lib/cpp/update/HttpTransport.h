#pragma once

// HttpTransport.h - one place that knows how to make an HTTPS request safely.
//
// It exists because there are now two callers - the version check and the download
// that replaces the binary - and the options below are the ones that must not differ
// between them. HTTPS only, on the first request and on every redirect. Peer and host
// verification on. A certificate store probed on this host rather than the one curl was
// configured on. A hard cap on how many bytes may arrive. Duplicated, those are four
// lines that one of the two copies eventually loses, and losing any of them is not a
// bug anybody sees until it matters.
//
// Verification is never disabled to get past a failure, and there is no option here to
// disable it. A version check is not worth teaching this tool to talk to anybody, and a
// download that replaces the running binary certainly is not.
//
// The multi interface rather than curl_easy_perform, for one reason: the caller has to
// be able to stop it. A scan that has already printed its report may not wait for a
// connect to a host that is not answering, and CURLOPT_XFERINFOFUNCTION is not good
// enough because libcurl calls it about once a second while nothing is moving - which
// is exactly the case that matters. curl_multi_poll with a 50 ms cap is deterministic.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace lyxbosa::http {

struct Outcome {
    enum class Status {
        Ok,
        Cancelled,      // the caller stopped waiting
        TimedOut,       // no answer, or the transfer stalled
        Truncated,      // the body ended short of the length the server promised
        TooLarge,       // more bytes than the caller is prepared to accept
        HttpError,      // 4xx or 5xx
        TlsError,       // the connection could not be verified
        Failed          // anything else
    };

    Status status = Status::Failed;
    long httpStatus = 0;
    uint64_t bytes = 0;
    std::string detail;   // one sentence, for someone who typed a command

    bool ok() const { return status == Status::Ok; }
};

// Where the body goes. Returning false aborts the transfer, which is how the byte cap
// is enforced on a server that lies about Content-Length or sends none at all.
using Sink = std::function<bool(const char* data, size_t bytes)>;

struct Request {
    std::string url;

    // A hard cap on the body. Enforced twice: once against the length the server
    // declares, before anything is read, and once against the bytes that actually
    // arrive. The second is the one that counts - the first is only a courtesy that
    // stops a large transfer starting.
    uint64_t maxBytes = 0;

    std::chrono::milliseconds connectTimeout{2000};

    // A wall-clock cap on the whole transfer. Zero means none, which is what a
    // multi-megabyte download on a slow link needs; a stalled one is caught by the
    // low-speed guard below instead, which is the honest shape of "this is not
    // progressing" for a transfer whose duration legitimately varies.
    std::chrono::milliseconds totalTimeout{0};

    // Abort when fewer than this many bytes per second arrive for this long. Zero
    // disables it. This is what catches a download that never completes: a server that
    // accepts the connection, sends a header and then nothing at all would otherwise
    // hold the transfer open indefinitely.
    long lowSpeedBytesPerSecond = 0;
    std::chrono::seconds lowSpeedFor{0};

    std::string accept;  // an Accept header, when the caller wants one
};

Outcome perform(const Request& request, const Sink& sink, const std::atomic<bool>& cancelled);

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

// A trust store the operator named, taken from the environment.
//
// These three names had to become something this code ACTS ON rather than something it
// stands aside for, and the difference is not cosmetic. libcurl does not read any of
// them: `CURL_CA_BUNDLE` is a compile-time macro inside libcurl and an environment
// variable only for the curl COMMAND-LINE tool, and `SSL_CERT_FILE` reaches OpenSSL
// only through the default-paths fallback that curl skips once it has a CAINFO of its
// own - which it always has, because it bakes one in at configure time.
//
// So standing aside when one was set did the opposite of what it looked like: it turned
// OFF the probe and left libcurl using a path from the machine it was BUILT on. An
// operator pointing this at their own bundle got worse behaviour than one who set
// nothing at all. Now the value is read here and passed to CURLOPT_CAINFO/CAPATH, so
// the documented knob is the one that works.
//
// The values are parameters rather than getenv calls so this is testable without
// mutating the environment of the process running the tests.
struct TrustStoreEnvironment {
    std::string sslCertFile;   // SSL_CERT_FILE
    std::string curlCaBundle;  // CURL_CA_BUNDLE
    std::string sslCertDir;    // SSL_CERT_DIR
};
CaLocation caLocationFromEnvironment(const TrustStoreEnvironment& environment);

// An operator's own choice wins over anything probed, kind by kind: naming a bundle
// does not throw away a probed directory, and naming a directory does not throw away a
// probed bundle.
CaLocation chooseCaLocation(const CaLocation& named, const CaLocation& probed);

// The candidates for this platform, in order.
const std::vector<std::string>& systemCaBundleFiles();
const std::vector<std::string>& systemCaBundleDirs();

// What to tell someone whose request failed on certificates. Separated from the
// request so the case an operator can actually act on - no trust store at all - has a
// test rather than a socket behind it.
std::string certificateFailureDetail(bool trustStoreFound, const std::string& underlying);

}  // namespace lyxbosa::http
