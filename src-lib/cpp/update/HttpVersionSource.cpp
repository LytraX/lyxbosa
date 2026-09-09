// The one part of the update check that cannot be tested without a network, kept as
// small as possible for exactly that reason. Everything above it - the predicate, the
// cache, the comparison, the timeout and the failure paths - is exercised against a
// fake VersionSource in tests/update_test.cpp.
//
//
// WHY libcurl, AND WHY THE FEATURE SET IS THIS SMALL
// ---------------------------------------------------
// vcpkg.json asks for `curl` with `default-features: false` and the single feature
// `ssl`. That is deliberate and it is what the dependency costs:
//
//   Dropping the default `non-http` feature drops FTP, FTPS, LDAP, LDAPS, SMTP, IMAP,
//   POP3, telnet, dict, gopher, TFTP, RTSP and SMB out of the build entirely. This
//   binary speaks HTTPS to one host and nothing else, so the rest is attack surface
//   with no user. CURLOPT_PROTOCOLS_STR below says the same thing a second time, so
//   the guarantee does not depend on the port's feature resolution staying as it is.
//
//   `ssl` resolves to Schannel on Windows and OpenSSL everywhere else. On Windows that
//   is the operating system's own TLS stack and its own certificate store, so the
//   dependency there is nothing at all. On Linux and macOS it is OpenSSL, built by
//   vcpkg, which reads the SYSTEM certificate store - measured on the port as built
//   here, OPENSSLDIR is /etc/ssl, giving /etc/ssl/certs and /etc/ssl/cert.pem. Those
//   are the standard locations on Debian and Ubuntu, on RHEL and AlmaLinux (where
//   /etc/ssl/certs is a symlink into /etc/pki), and on macOS.
//
//   So: no certificate bundle is shipped, embedded or vendored. caBundleOverride()
//   below is a fallback for a host that has none of those paths, and on a normal one
//   it does nothing.
//
// Measured cost of adding it, on this machine, cold: OpenSSL 3.6.4 59s, curl 8.21.0
// 38s. CI triplets set VCPKG_BUILD_TYPE release, so they build one half of that, once,
// and the binary cache keyed on vcpkg.json carries it afterwards.
//
//
// WHY THE MULTI INTERFACE FOR ONE REQUEST
// ----------------------------------------
// VersionSource requires an implementation to return promptly once `cancelled` is set,
// because the caller is a scan that has already printed its report and is not allowed
// to wait. CURLOPT_XFERINFOFUNCTION would be the easy way and it is not good enough:
// libcurl calls it about once a second while nothing is moving, which is exactly the
// case that matters - a connect to a host that is not answering. curl_multi_poll with
// a 50 ms cap gives a deterministic 50 ms.

#include "update/VersionSource.h"

#include <curl/curl.h>
#include <fmt/format.h>
#include <re2/re2.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

namespace lyxbosa {

namespace {

// A releases API response is about 20 KB. Well past that is not one, and reading it
// would be reading whatever a redirect landed on.
constexpr size_t kMaxBodyBytes = 256 * 1024;

// How often the poll loop looks at the cancel flag.
constexpr int kPollSliceMs = 50;

// curl_global_init is not thread-safe and the fetch runs on a worker thread, so it is
// done here rather than left to curl_easy_init to do implicitly. There is no matching
// curl_global_cleanup: it would have to run after every handle is gone, and the only
// moment that is true is process exit, where the allocation is reclaimed anyway.
bool ensureGlobalInit() {
    static bool ok = false;
    static std::once_flag once;
    std::call_once(once, [] { ok = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK; });
    return ok;
}

// An operator pointing at their own store wins over anything probed. These are the
// names OpenSSL and curl already honour, so setting CAINFO without checking them
// would take away a knob that works today.
bool trustStoreSetByEnvironment() {
    for (const char* name : {"SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"}) {
        const char* value = std::getenv(name);
        if (value != nullptr && value[0] != '\0') {
            return true;
        }
    }
    return false;
}

size_t appendBody(char* data, size_t size, size_t count, void* userdata) {
    auto* body = static_cast<std::string*>(userdata);
    const size_t bytes = size * count;
    // Returning anything but `bytes` aborts the transfer, which is what a response
    // past the cap should do: it is not a release listing.
    if (body->size() + bytes > kMaxBodyBytes) {
        return 0;
    }
    body->append(data, bytes);
    return bytes;
}

FetchOutcome failed(std::string detail) {
    FetchOutcome out;
    out.status = FetchOutcome::Status::RequestFailed;
    out.detail = std::move(detail);
    return out;
}

FetchOutcome cancelledOutcome() {
    FetchOutcome out;
    out.status = FetchOutcome::Status::Cancelled;
    out.detail = "the check was still running when it was no longer wanted";
    return out;
}

// curl_easy_setopt is variadic, so the compiler checks nothing: a plain `1` where
// libcurl wants a `long` is undefined behaviour that builds without a word, and a
// std::string passed where it wants a `const char*` is worse. These overloads make
// the compiler pick, and shorten the option list to what each line actually says.
struct Setopt {
    CURL* handle;

    void operator()(CURLoption option, long value) const {
        curl_easy_setopt(handle, option, value);
    }
    void operator()(CURLoption option, const std::string& value) const {
        curl_easy_setopt(handle, option, value.c_str());
    }
    void operator()(CURLoption option, const char* value) const {
        curl_easy_setopt(handle, option, value);
    }
    void operator()(CURLoption option, void* value) const {
        curl_easy_setopt(handle, option, value);
    }
    template <typename Result, typename... Args>
    void operator()(CURLoption option, Result (*value)(Args...)) const {
        curl_easy_setopt(handle, option, value);
    }
};

// Closes the handles however the function leaves.
struct MultiHandles {
    CURLM* multi = nullptr;
    CURL* easy = nullptr;
    curl_slist* headers = nullptr;

    ~MultiHandles() {
        if (multi != nullptr && easy != nullptr) curl_multi_remove_handle(multi, easy);
        if (easy != nullptr) curl_easy_cleanup(easy);
        if (multi != nullptr) curl_multi_cleanup(multi);
        if (headers != nullptr) curl_slist_free_all(headers);
    }
};

}  // namespace

CaLocation resolveCaLocation(const std::vector<std::string>& bundleFiles,
                             const std::vector<std::string>& bundleDirs) {
    CaLocation out;
    std::error_code ec;
    for (const auto& candidate : bundleFiles) {
        if (std::filesystem::is_regular_file(candidate, ec)) {
            out.file = candidate;
            break;
        }
    }
    for (const auto& candidate : bundleDirs) {
        if (std::filesystem::is_directory(candidate, ec)) {
            out.dir = candidate;
            break;
        }
    }
    return out;
}

const std::vector<std::string>& systemCaBundleFiles() {
    // Every entry is a location the host distribution puts its own trust store in.
    // Order is by how specific the path is, not by preference between distributions.
    static const std::vector<std::string> files = {
        "/etc/ssl/certs/ca-certificates.crt",                  // Debian, Ubuntu, Arch
        "/etc/pki/tls/certs/ca-bundle.crt",                    // RHEL, AlmaLinux, Fedora
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",   // RHEL, newer layout
        "/etc/ssl/ca-bundle.pem",                              // SUSE
        "/etc/ssl/cert.pem",                                   // Alpine, macOS, BSD
        "/usr/local/share/certs/ca-root-nss.crt",              // FreeBSD
    };
    return files;
}

const std::vector<std::string>& systemCaBundleDirs() {
    static const std::vector<std::string> dirs = {
        "/etc/ssl/certs",
        "/etc/pki/tls/certs",
    };
    return dirs;
}

namespace {
// Probed once. A host does not grow a certificate store while a scan is running.
const CaLocation& systemCa() {
    static const CaLocation resolved =
        resolveCaLocation(systemCaBundleFiles(), systemCaBundleDirs());
    return resolved;
}
}  // namespace

std::string certificateFailureDetail(bool trustStoreFound,
                                     const std::string& underlying) {
    // A host with no certificates at all cannot verify anything, and the honest
    // answer is to say which of the two problems this is. libcurl's own wording -
    // "Problem with the SSL CA cert (path? access rights?)" - reads like a
    // misconfiguration in this tool, which sends people looking in the wrong place.
    if (!trustStoreFound) {
        return "no certificate store was found on this host, so the connection could "
               "not be verified - install your distribution's CA certificates, or "
               "point SSL_CERT_FILE at a bundle";
    }
    return underlying.empty() ? "the connection could not be verified" : underlying;
}

std::optional<std::string> extractTagName(std::string_view body) {
    // The whole of the rule, in one place: the key, a colon, a quoted value, and a
    // value that may not contain a quote, a backslash or a control character and may
    // not be longer than 64 bytes. Everything it refuses becomes "no notice today".
    //
    // RE2 rather than a hand-rolled scan because RE2 is already linked and this is
    // what it is for. It is also the safe engine to point at network-supplied text:
    // it has no backtracking, so the bound below is a bound on the work as well as on
    // the answer, which is not true of a std::regex written the same way.
    //
    // Latin-1 so the classes are bytes. In UTF-8 mode a body that is not valid UTF-8
    // would fail to match for a reason that has nothing to do with the version in it,
    // and this needs to read the same bytes a scan would.
    static const RE2::Options options = [] {
        RE2::Options opts;
        opts.set_encoding(RE2::Options::EncodingLatin1);
        opts.set_log_errors(false);
        return opts;
    }();
    // R"rx(...)rx" rather than R"(...)": the pattern itself ends in `")`, which closes
    // a default-delimited raw string in the middle of the regex.
    static const RE2 kTagName(
        R"rx("tag_name"\s*:\s*"([^"\\\x00-\x1f]{1,64})")rx", options);

    std::string tag;
    if (!RE2::PartialMatch(re2::StringPiece(body.data(), body.size()), kTagName, &tag)) {
        return std::nullopt;
    }
    return tag;
}

FetchOutcome HttpVersionSource::fetchLatest(std::chrono::milliseconds timeout,
                                            const std::atomic<bool>& cancelled) {
    if (!ensureGlobalInit()) {
        return failed("the HTTP client could not be initialised");
    }
    if (cancelled.load(std::memory_order_relaxed)) {
        return cancelledOutcome();
    }

    MultiHandles h;
    h.easy = curl_easy_init();
    h.multi = curl_multi_init();
    if (h.easy == nullptr || h.multi == nullptr) {
        return failed("the HTTP client could not be initialised");
    }

    const std::string agent = std::string("lyxbosa/") + LYXBOSA_VERSION;
    h.headers = curl_slist_append(nullptr, "Accept: application/vnd.github+json");
    std::string body;

    const Setopt set{h.easy};

    set(CURLOPT_URL, url_);
    set(CURLOPT_HTTPGET, 1L);
    set(CURLOPT_USERAGENT, agent);
    set(CURLOPT_HTTPHEADER, h.headers);
    set(CURLOPT_WRITEFUNCTION, appendBody);
    set(CURLOPT_WRITEDATA, &body);

    // An HTTP error is a failure rather than an error page parsed as a release.
    set(CURLOPT_FAILONERROR, 1L);
    set(CURLOPT_FOLLOWLOCATION, 1L);
    set(CURLOPT_MAXREDIRS, 3L);

    // HTTPS only, on the first request and on anything it redirects to. The port is
    // built without the other protocols; this is the second lock on the same door.
    set(CURLOPT_PROTOCOLS_STR, "https");
    set(CURLOPT_REDIR_PROTOCOLS_STR, "https");
    set(CURLOPT_SSL_VERIFYPEER, 1L);
    set(CURLOPT_SSL_VERIFYHOST, 2L);
#ifndef _WIN32
    // Not Windows: Schannel uses the certificate store the OS maintains, and there is
    // nothing to point at. Everywhere else the path curl was configured with belongs
    // to the machine it was BUILT on, so it is replaced with one that exists here.
    if (!trustStoreSetByEnvironment()) {
        if (!systemCa().file.empty()) set(CURLOPT_CAINFO, systemCa().file);
        if (!systemCa().dir.empty())  set(CURLOPT_CAPATH, systemCa().dir);
    }
#endif

    // libcurl uses signals for the synchronous resolver's timeout, which is not safe
    // in a process with other threads - and this always runs on one.
    set(CURLOPT_NOSIGNAL, 1L);

    const auto timeoutMs = static_cast<long>(timeout.count());
    set(CURLOPT_TIMEOUT_MS, timeoutMs);
    set(CURLOPT_CONNECTTIMEOUT_MS, timeoutMs);

    if (curl_multi_add_handle(h.multi, h.easy) != CURLM_OK) {
        return failed("the request could not be started");
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    int running = 0;
    bool wasCancelled = false;
    bool ranOut = false;

    for (;;) {
        if (curl_multi_perform(h.multi, &running) != CURLM_OK) {
            break;
        }
        if (running == 0) {
            break;  // finished, successfully or not
        }
        if (cancelled.load(std::memory_order_relaxed)) {
            wasCancelled = true;
            break;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            ranOut = true;
            break;
        }

        // Capped so the cancel flag is noticed promptly even while nothing is moving,
        // which is the case a progress callback is too slow for.
        int ready = 0;
        if (curl_multi_poll(h.multi, nullptr, 0, kPollSliceMs, &ready) != CURLM_OK) {
            break;
        }
    }

    if (wasCancelled) return cancelledOutcome();

    CURLcode result = CURLE_OK;
    bool sawResult = false;
    int queued = 0;
    while (CURLMsg* message = curl_multi_info_read(h.multi, &queued)) {
        if (message->msg == CURLMSG_DONE) {
            result = message->data.result;
            sawResult = true;
        }
    }

    if (ranOut && !sawResult) {
        return failed("no answer within the timeout");
    }
    if (!sawResult) {
        return failed("the request ended without a result");
    }
    if (result != CURLE_OK) {
        long status = 0;
        curl_easy_getinfo(h.easy, CURLINFO_RESPONSE_CODE, &status);
        if (status >= 400) {
            return failed(fmt::format(
                "the releases API answered HTTP {}{}", status,
                status == 403 || status == 429
                    ? " (very often the unauthenticated rate limit)" : ""));
        }
        if (result == CURLE_SSL_CACERT_BADFILE ||
            result == CURLE_PEER_FAILED_VERIFICATION ||
            result == CURLE_SSL_CERTPROBLEM ||
            result == CURLE_SSL_CONNECT_ERROR) {
            return failed(certificateFailureDetail(systemCa().found(),
                                                   curl_easy_strerror(result)));
        }
        return failed(curl_easy_strerror(result));
    }

    if (const auto tag = extractTagName(body)) {
        FetchOutcome out;
        out.status = FetchOutcome::Status::Ok;
        out.version = *tag;
        return out;
    }

    FetchOutcome out;
    out.status = FetchOutcome::Status::BadResponse;
    out.detail = "the releases API answered with something that has no version in it";
    return out;
}

}  // namespace lyxbosa
