// The one part of the updater that cannot be tested without a network, kept as small
// as possible for exactly that reason. Everything above it - the predicate, the cache,
// the comparison, the signature check, the hash check, the guards and the replace -
// runs against fakes in tests/update_test.cpp and tests/update_apply_test.cpp.
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
//   So: no certificate bundle is shipped, embedded or vendored. The probe below is a
//   fallback for a host whose paths differ from the build machine's, and on a host that
//   matches it changes nothing.
//
// Measured cost of adding it, cold: OpenSSL 3.6.4 59s, curl 8.21.0 38s. CI triplets set
// VCPKG_BUILD_TYPE release, so they build one half of that, once, and the binary cache
// keyed on vcpkg.json carries it afterwards.

#include "update/HttpTransport.h"

#include <curl/curl.h>
#include <fmt/format.h>

#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <system_error>

namespace lyxbosa::http {

namespace {

// How often the poll loop looks at the cancel flag.
constexpr int kPollSliceMs = 50;

// curl_global_init is not thread-safe and a fetch may run on a worker thread, so it is
// done here rather than left to curl_easy_init to do implicitly. There is no matching
// curl_global_cleanup: it would have to run after every handle is gone, and the only
// moment that is true is process exit, where the allocation is reclaimed anyway.
bool ensureGlobalInit() {
    static bool ok = false;
    static std::once_flag once;
    std::call_once(once, [] { ok = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK; });
    return ok;
}

std::string fromEnvironment(const char* name) {
    const char* value = std::getenv(name);
    return (value != nullptr && value[0] != '\0') ? std::string(value) : std::string();
}

// Resolved once. A host does not grow a certificate store while a scan is running, and
// nothing here changes its own environment.
const CaLocation& systemCa() {
    static const CaLocation resolved = chooseCaLocation(
        caLocationFromEnvironment(TrustStoreEnvironment{fromEnvironment("SSL_CERT_FILE"),
                                                       fromEnvironment("CURL_CA_BUNDLE"),
                                                       fromEnvironment("SSL_CERT_DIR")}),
        resolveCaLocation(systemCaBundleFiles(), systemCaBundleDirs()));
    return resolved;
}

// curl_easy_setopt is variadic, so the compiler checks nothing: a plain `1` where
// libcurl wants a `long` is undefined behaviour that builds without a word, and a
// std::string passed where it wants a `const char*` is worse. These overloads make the
// compiler pick, and shorten the option list to what each line actually says.
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

    // A named method rather than another overload: curl_off_t is `long` on this
    // platform and `long long` on others, so an overload for it either collides with
    // the `long` one or does not exist, depending on where it is compiled.
    void large(CURLoption option, curl_off_t value) const {
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

// What the write callback carries. `overflowed` is separate from a short return
// because libcurl reports an aborted write as CURLE_WRITE_ERROR, which is
// indistinguishable from a sink that failed for its own reason - and those two need
// different sentences.
struct WriteState {
    const Sink* sink = nullptr;
    uint64_t written = 0;
    uint64_t maxBytes = 0;
    bool overflowed = false;
    bool sinkFailed = false;
};

size_t writeBody(char* data, size_t size, size_t count, void* userdata) {
    auto* state = static_cast<WriteState*>(userdata);
    const size_t bytes = size * count;

    if (state->maxBytes != 0 && state->written + bytes > state->maxBytes) {
        state->overflowed = true;
        return 0;  // anything but `bytes` aborts the transfer
    }
    if (!(*state->sink)(data, bytes)) {
        state->sinkFailed = true;
        return 0;
    }
    state->written += bytes;
    return bytes;
}

Outcome make(Outcome::Status status, std::string detail) {
    Outcome out;
    out.status = status;
    out.detail = std::move(detail);
    return out;
}

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

CaLocation caLocationFromEnvironment(const TrustStoreEnvironment& environment) {
    CaLocation out;
    // SSL_CERT_FILE first: it is OpenSSL's own name and the one most people reach for.
    // Neither is checked for existence - an operator who names a path that is not there
    // gets a TLS failure naming it, which is a better answer than being silently given
    // a different store than the one they asked for.
    out.file = !environment.sslCertFile.empty() ? environment.sslCertFile
                                                : environment.curlCaBundle;
    out.dir = environment.sslCertDir;
    return out;
}

CaLocation chooseCaLocation(const CaLocation& named, const CaLocation& probed) {
    CaLocation out;
    out.file = named.file.empty() ? probed.file : named.file;
    out.dir = named.dir.empty() ? probed.dir : named.dir;
    return out;
}

const std::vector<std::string>& systemCaBundleDirs() {
    static const std::vector<std::string> dirs = {
        "/etc/ssl/certs",
        "/etc/pki/tls/certs",
    };
    return dirs;
}

std::string certificateFailureDetail(bool trustStoreFound, const std::string& underlying) {
    // A host with no certificates at all cannot verify anything, and the honest answer
    // is to say which of the two problems this is. libcurl's own wording - "Problem
    // with the SSL CA cert (path? access rights?)" - reads like a misconfiguration in
    // this tool, which sends people looking in the wrong place.
    if (!trustStoreFound) {
        return "no certificate store was found on this host, so the connection could "
               "not be verified - install your distribution's CA certificates, or "
               "point SSL_CERT_FILE at a bundle";
    }
    return underlying.empty() ? "the connection could not be verified" : underlying;
}

Outcome perform(const Request& request, const Sink& sink,
                const std::atomic<bool>& cancelled) {
    if (!ensureGlobalInit()) {
        return make(Outcome::Status::Failed, "the HTTP client could not be initialised");
    }
    if (cancelled.load(std::memory_order_relaxed)) {
        return make(Outcome::Status::Cancelled,
                    "the request was still running when it was no longer wanted");
    }

    MultiHandles h;
    h.easy = curl_easy_init();
    h.multi = curl_multi_init();
    if (h.easy == nullptr || h.multi == nullptr) {
        return make(Outcome::Status::Failed, "the HTTP client could not be initialised");
    }

    const std::string agent = std::string("lyxbosa/") + LYXBOSA_VERSION;
    if (!request.accept.empty()) {
        h.headers = curl_slist_append(nullptr, ("Accept: " + request.accept).c_str());
    }

    WriteState state;
    state.sink = &sink;
    state.maxBytes = request.maxBytes;

    const Setopt set{h.easy};

    set(CURLOPT_URL, request.url);
    set(CURLOPT_HTTPGET, 1L);
    set(CURLOPT_USERAGENT, agent);
    if (h.headers != nullptr) set(CURLOPT_HTTPHEADER, h.headers);
    set(CURLOPT_WRITEFUNCTION, writeBody);
    set(CURLOPT_WRITEDATA, &state);

    // An HTTP error is a failure rather than an error page parsed as content - or, for
    // the download, written to disk and hashed.
    set(CURLOPT_FAILONERROR, 1L);
    set(CURLOPT_FOLLOWLOCATION, 1L);
    // Release assets are served by a redirect to the CDN, so redirects are not
    // optional here. Three is enough for that and short enough to bound a loop.
    set(CURLOPT_MAXREDIRS, 3L);

    // HTTPS only, on the first request and on anything it redirects to. The port is
    // built without the other protocols; this is the second lock on the same door, and
    // it is the one that stops a redirect walking the download onto a file:// path.
    set(CURLOPT_PROTOCOLS_STR, "https");
    set(CURLOPT_REDIR_PROTOCOLS_STR, "https");
    set(CURLOPT_SSL_VERIFYPEER, 1L);
    set(CURLOPT_SSL_VERIFYHOST, 2L);
#ifndef _WIN32
    // Not Windows: Schannel uses the certificate store the OS maintains, and there is
    // nothing to point at. Everywhere else the path curl was configured with belongs to
    // the machine it was BUILT on, so it is replaced with the operator's choice or with
    // one that exists here.
    if (!systemCa().file.empty()) set(CURLOPT_CAINFO, systemCa().file);
    if (!systemCa().dir.empty()) set(CURLOPT_CAPATH, systemCa().dir);
#endif

    // libcurl uses signals for the synchronous resolver's timeout, which is not safe in
    // a process with other threads - and the version check always runs on one.
    set(CURLOPT_NOSIGNAL, 1L);

    set(CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(request.connectTimeout.count()));
    if (request.totalTimeout.count() > 0) {
        set(CURLOPT_TIMEOUT_MS, static_cast<long>(request.totalTimeout.count()));
    }
    if (request.lowSpeedBytesPerSecond > 0 && request.lowSpeedFor.count() > 0) {
        set(CURLOPT_LOW_SPEED_LIMIT, request.lowSpeedBytesPerSecond);
        set(CURLOPT_LOW_SPEED_TIME, static_cast<long>(request.lowSpeedFor.count()));
    }
    if (request.maxBytes != 0) {
        // The declared length, refused before a byte is read. The write callback is
        // what actually enforces the cap; this only avoids starting a large transfer.
        set.large(CURLOPT_MAXFILESIZE_LARGE, static_cast<curl_off_t>(request.maxBytes));
    }

    if (curl_multi_add_handle(h.multi, h.easy) != CURLM_OK) {
        return make(Outcome::Status::Failed, "the request could not be started");
    }

    const bool bounded = request.totalTimeout.count() > 0;
    const auto deadline = std::chrono::steady_clock::now() + request.totalTimeout;
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
        if (bounded && std::chrono::steady_clock::now() >= deadline) {
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

    if (wasCancelled) {
        return make(Outcome::Status::Cancelled,
                    "the request was still running when it was no longer wanted");
    }

    CURLcode result = CURLE_OK;
    bool sawResult = false;
    int queued = 0;
    while (CURLMsg* message = curl_multi_info_read(h.multi, &queued)) {
        if (message->msg == CURLMSG_DONE) {
            result = message->data.result;
            sawResult = true;
        }
    }

    long status = 0;
    curl_easy_getinfo(h.easy, CURLINFO_RESPONSE_CODE, &status);

    Outcome out;
    out.httpStatus = status;
    out.bytes = state.written;

    if (ranOut && !sawResult) {
        out.status = Outcome::Status::TimedOut;
        out.detail = "no answer within the timeout";
        return out;
    }
    if (!sawResult) {
        out.status = Outcome::Status::Failed;
        out.detail = "the request ended without a result";
        return out;
    }

    if (result == CURLE_OK) {
        out.status = Outcome::Status::Ok;
        return out;
    }

    // The cap, reported as itself. Both routes to it - a declared length over the cap,
    // and bytes over the cap arriving anyway - say the same thing, because to a caller
    // they are the same refusal.
    if (state.overflowed || result == CURLE_FILESIZE_EXCEEDED) {
        out.status = Outcome::Status::TooLarge;
        out.detail = fmt::format("it is larger than the {} bytes this is willing to read",
                                 request.maxBytes);
        return out;
    }
    if (state.sinkFailed) {
        out.status = Outcome::Status::Failed;
        out.detail = "the bytes could not be written";
        return out;
    }
    if (result == CURLE_PARTIAL_FILE) {
        out.status = Outcome::Status::Truncated;
        out.detail = fmt::format(
            "the transfer ended early - {} bytes arrived and the server said there "
            "would be more", state.written);
        return out;
    }
    if (result == CURLE_OPERATION_TIMEDOUT) {
        out.status = Outcome::Status::TimedOut;
        out.detail = state.written == 0
            ? "no answer within the timeout"
            : fmt::format("the transfer stopped making progress after {} bytes",
                          state.written);
        return out;
    }
    if (status >= 400) {
        out.status = Outcome::Status::HttpError;
        out.detail = fmt::format(
            "the server answered HTTP {}{}", status,
            status == 403 || status == 429 ? " (very often the unauthenticated rate limit)"
                                           : "");
        return out;
    }
    if (result == CURLE_SSL_CACERT_BADFILE || result == CURLE_PEER_FAILED_VERIFICATION ||
        result == CURLE_SSL_CERTPROBLEM || result == CURLE_SSL_CONNECT_ERROR) {
        out.status = Outcome::Status::TlsError;
        out.detail = certificateFailureDetail(systemCa().found(), curl_easy_strerror(result));
        return out;
    }

    out.status = Outcome::Status::Failed;
    out.detail = curl_easy_strerror(result);
    return out;
}

}  // namespace lyxbosa::http
