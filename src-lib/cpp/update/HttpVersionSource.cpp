// Asking the releases API what the newest version is. The request itself is
// HttpTransport.cpp; what is left here is the one field this extracts from the answer
// and the mapping from a transport failure to the sentence a person reads.
//
// Everything above it - the predicate, the cache, the comparison, the timeout and the
// failure paths - is exercised against a fake VersionSource in tests/update_test.cpp.

#include "update/VersionSource.h"

#include "update/HttpTransport.h"

#include <re2/re2.h>

namespace lyxbosa {

namespace {

// A releases API response is about 20 KB. Well past that is not one, and reading it
// would be reading whatever a redirect landed on.
constexpr uint64_t kMaxBodyBytes = 256 * 1024;

FetchOutcome failed(std::string detail) {
    FetchOutcome out;
    out.status = FetchOutcome::Status::RequestFailed;
    out.detail = std::move(detail);
    return out;
}

}  // namespace

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
    std::string body;

    http::Request request;
    request.url = url_;
    request.maxBytes = kMaxBodyBytes;
    request.connectTimeout = timeout;
    request.totalTimeout = timeout;
    request.accept = "application/vnd.github+json";

    const http::Outcome outcome = http::perform(
        request,
        [&body](const char* data, size_t bytes) {
            body.append(data, bytes);
            return true;
        },
        cancelled);

    if (outcome.status == http::Outcome::Status::Cancelled) {
        FetchOutcome out;
        out.status = FetchOutcome::Status::Cancelled;
        out.detail = "the check was still running when it was no longer wanted";
        return out;
    }
    if (!outcome.ok()) {
        // Every transport failure is one thing to a caller who only wanted a version
        // number: no notice today. The detail is what separates them for a person who
        // typed `update --check` and is owed a reason.
        return failed(outcome.detail);
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
