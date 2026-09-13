// Asking the releases API what the newest version is. The request itself is
// HttpTransport.cpp; what is left here is the one field this extracts from the answer
// and the mapping from a transport failure to the sentence a person reads.
//
// Everything above it - the predicate, the cache, the comparison, the timeout and the
// failure paths - is exercised against a fake VersionSource in tests/update_test.cpp.

#include "update/VersionSource.h"

#include "update/HttpTransport.h"

#include <nlohmann/json.hpp>

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
    // A real parse, in the library's non-throwing mode: a body that is not one well-formed
    // JSON document - truncated, followed by anything, not valid UTF-8 - comes back
    // discarded, and that is a refusal like every other one here.
    //
    // nlohmann::json rather than ordered_json, which is what the report writer uses. The
    // order of keys is irrelevant to one lookup, and ordered_json finds a key by walking
    // every key before it: a 256 KiB object of tens of thousands of short keys would cost
    // a quadratic number of comparisons to build, where the sorted map costs n log n.
    //
    // NOTHING BELOW MAY COPY, DUMP OR COMPARE `doc`, and that is the whole of the nesting
    // defence. The 256 KiB cap admits 131,072 levels of `[`, and in nlohmann/json 3.12
    // parsing and destroying are both iterative: measured on a 32 KiB thread stack, a body
    // nested to the cap parses and is destroyed. The copy constructor, dump() and operator==
    // recurse once per level, and each of the three exhausts a 128 KiB stack - musl's
    // default for the thread this runs on in the portable build - on that same body.
    // tests/update_test.cpp runs this function over such bodies on a 128 KiB stack, so an
    // edit that starts doing any of the three crashes the suite rather than a scan.
    const nlohmann::json doc = nlohmann::json::parse(
        body.data(), body.data() + body.size(), /*cb=*/nullptr, /*allow_exceptions=*/false);

    // Only the top-level object's own key. A `tag_name` inside an asset, or anywhere else
    // in the document, is not the release's.
    if (!doc.is_object()) {
        return std::nullopt;
    }
    const auto it = doc.find("tag_name");
    if (it == doc.end() || !it->is_string()) {
        return std::nullopt;
    }

    // The rule, applied to the value as decoded: 1 to 64 bytes, and no quote, backslash or
    // control character. An escape in the response is decoded first, so `\u002e` is a dot
    // and accepted, and `\"` is a quote and refused. Everything refused becomes "no notice
    // today".
    const std::string& tag = it->get_ref<const std::string&>();
    if (tag.empty() || tag.size() > 64) {
        return std::nullopt;
    }
    for (const char raw : tag) {
        const auto c = static_cast<unsigned char>(raw);
        if (c == '"' || c == '\\' || c < 0x20) {
            return std::nullopt;
        }
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
