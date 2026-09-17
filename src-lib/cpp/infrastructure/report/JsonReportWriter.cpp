#include "infrastructure/report/JsonReportWriter.h"

#include "infrastructure/PathUtils.h"
#include "utils/SafeText.h"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

namespace lyxbosa {

namespace {

using Json = nlohmann::ordered_json;

// THE FRAME. The outermost object and the `files` array are the only structure the library
// cannot render, because the array stays open for the whole scan. These five functions are
// all of the punctuation written by hand, and each piece of it is written in one place.
// Every key and value is the library's compact rendering.
//
// The layout is compact, with each file's record on a line of its own: a report of hundreds
// of thousands of files can then be read, searched and cut record by record, and nothing in
// it is indentation. A newline placed here is the only raw newline in the document, because
// the library escapes every newline inside a string - which is what lets a test remove them
// and compare what remains with the library's rendering of the whole document.
//
// dump() throws a type_error for a string that is not valid UTF-8.

// `{` and the key of the array that stays open.
std::string openDocument() {
    return "{" + Json("files").dump() + ":[";
}

// One element of the open array: the comma that separates it from the one before, if there
// was one, and the record on a line of its own.
std::string arrayElement(bool first, const Json& value) {
    return (first ? "\n" : ",\n") + value.dump();
}

// `]`, on a line of its own when the array holds anything - `[]` otherwise, which is how
// the library writes an empty array.
std::string closeArray(bool empty) {
    return empty ? "]" : "\n]";
}

// A member after the array: the comma, the key and the value.
std::string member(std::string_view key, const Json& value) {
    return "," + Json(key).dump() + ":" + value.dump();
}

std::string closeDocument() {
    return "}\n";
}

Json fileRecord(const FileResult& result) {
    Json record = Json::object();
    record["path"] = pathForDisplay(result.path);

    // The same path as bytes, when the rendering above could not carry them.
    //
    // `path` is escaped so that the document stays valid UTF-8 and a parser accepts it - a
    // file name on a Linux host may be any bytes at all, and one that is not valid UTF-8
    // has no JSON string that spells it. That escape is one-way, which is fine for a person
    // and useless to a program: an external tool reading this report has to be able to
    // open, match or delete the exact file, and it cannot do that from a rendering. So it
    // gets the bytes here, in hex, and keeps a document that every JSON parser still reads.
    //
    // Absent - not empty - whenever `path` is already exact, which is every file in an
    // ordinary tree. A consumer reads this key only when it is there, and its presence is
    // itself the statement that `path` is a rendering rather than a name.
    if (pathDisplayIsLossy(result.path)) {
        record["pathBytesHex"] = pathBytesHex(result.path);
    }

    // `skipped` keeps meaning exactly what it always did, so every existing consumer reads
    // this report unchanged; `skipReason` is additive and present only when there is one.
    record["skipped"] = result.skipped();
    if (result.skipReason) {
        record["skipReason"] = std::string(skipReasonToString(*result.skipReason));
    }

    record["quarantined"] = result.quarantined;
    // Present only when it happened, like `skipReason` and `suppressed`, so a report from a
    // run where every move succeeded is byte-identical to before. `quarantined: false` is
    // the answer for an exposure finding and for a run with quarantine off as well; this
    // key is the one that says the file is still there.
    if (result.quarantineFailed) {
        record["quarantineFailed"] = true;
    }

    // Where the bytes are now. The scanner has always known this and exactly one consumer
    // ever read it - the `moved:` line of the verbose text view - so a pipeline was told a
    // file had been quarantined and never told where to, which is the half of the answer a
    // machine needs and a human can go and look for.
    if (!result.quarantinePath.empty()) {
        record["quarantinePath"] = pathForDisplay(result.quarantinePath);
        // Same rule as `pathBytesHex`, and needed for the same reason one level on: under
        // `preserve_structure` the destination mirrors the source's whole path, so a name
        // that could not be rendered exactly arrives here too - and this is the path a tool
        // has to open to find where the bytes went.
        if (pathDisplayIsLossy(result.quarantinePath)) {
            record["quarantinePathBytesHex"] = pathBytesHex(result.quarantinePath);
        }
    }

    // What happened to the container this file was found inside. Absent for a loose file
    // and for a member no decision was taken about, which is why it is a string rather than
    // a bool: `false` would be the answer for a member that went into quarantine inside its
    // container AND for one still sitting under the web root, and those are the two answers
    // an operator acts on differently.
    if (result.containerQuarantine) {
        record["containerQuarantine"] =
            std::string(containerQuarantineToString(*result.containerQuarantine));
    }

    // Always present, and an empty array for a file with no match of its own.
    Json matches = Json::array();
    for (const auto& match : result.matches) {
        Json m = Json::object();
        m["rule"] = match.ruleName;
        m["severity"] = std::string(severityToString(match.severity));
        // Both present only for a suppressed finding, and `suppressed` only ever true.
        if (match.suppressed) {
            m["originalSeverity"] = std::string(severityToString(match.originalSeverity));
            m["suppressed"] = true;
        }
        m["category"] = match.category;
        m["line"] = match.line;
        m["column"] = match.column;
        matches.push_back(std::move(m));
    }
    record["matches"] = std::move(matches);
    return record;
}

// Every key after `files`, in the order it is written. All of them are present in every
// report except `archives`, and the comments say why each one is.
Json summary(const ScanResult& result, bool interrupted) {
    Json s = Json::object();
    s["interrupted"] = interrupted;
    s["totalFilesScanned"] = result.totalFilesScanned;
    s["totalDirectoriesScanned"] = result.totalDirectoriesScanned;
    s["filesWithMatches"] = result.filesWithMatches;
    // Beside the count it is a subset of, and emitted unconditionally like it: a consumer
    // that has to test for a key's presence to learn a count was zero reads an old report
    // and a clean tree as the same thing. This is the volume answer - a caller can tell
    // 4,102 findings about names from 16 about content without walking the file list to
    // work it out.
    s["filesWithHostileNames"] = result.filesWithHostileNames;
    s["filesSkippedSize"] = result.filesSkippedSize();

    // Files not scanned, by reason - shaped exactly like archives.membersSkipped so the two
    // levels read the same way. Emitted unconditionally, because filesSkippedSize already
    // is, and that key stays above it for compatibility.
    Json skipped = Json::object();
    skipped["total"] = result.skips.total();
    skipped["size"] = result.skips.count(SkipReason::Size);
    skipped["excluded"] = result.skips.count(SkipReason::Excluded);
    skipped["unreadable"] = result.skips.count(SkipReason::Unreadable);
    s["filesSkipped"] = std::move(skipped);

    s["directoriesUnreadable"] = result.directoriesUnreadable;
    // Beside the unreadable directories because it is the same kind of gap, and unconditional
    // for the reason every count here is: a consumer must not have to tell an old report from
    // a tree with none of these by whether the key is there.
    s["entriesUnreadable"] = result.entriesUnreadable;
    // Unconditional like the key above it. A consumer that has to test for a key's presence
    // to learn a count was zero is a consumer that reads an old report and a loop-free one
    // as the same thing.
    s["directoriesCycleSkipped"] = result.directoriesCycleSkipped;
    // Unconditional for the same reason, and beside the loop count because both are about
    // what the walk did at a link.
    s["linksNotFollowed"] = result.linksNotFollowed;
    s["filesQuarantined"] = result.filesQuarantined;
    s["filesQuarantineFailed"] = result.filesQuarantineFailed;

    // The roots that were named and were not there. Emitted unconditionally and as an array
    // rather than a count, because a consumer that reads only the counts above cannot
    // otherwise tell a clean scan of a whole tree from a successful scan of nothing at all -
    // which is the machine-readable form of the same lie.
    Json roots = Json::array();
    for (const auto& root : result.rootsMissing) {
        roots.push_back(pathForDisplay(root));
    }
    s["rootsMissing"] = std::move(roots);

    // Archive handling, including every member that was not scanned and why. Emitted only
    // when an archive was actually opened, so a report from a tree with none in it is
    // byte-identical to what this wrote before.
    const archive::Stats& stats = result.archives;
    if (stats.archivesOpened != 0) {
        Json a = Json::object();
        a["opened"] = stats.archivesOpened;
        a["unreadable"] = stats.archivesUnreadable;
        a["stoppedEarly"] = stats.archivesTruncated;
        a["membersScanned"] = stats.membersScanned;
        a["bytesExpanded"] = stats.bytesExpanded;
        // Every member-level reason, each under the spelling a member row's `skipReason` uses
        // for it. The priority policy's and the guards' six keep their places, and the
        // operator's patterns and the sidecars follow them.
        static constexpr SkipReason kMemberKeys[] = {
            SkipReason::Policy, SkipReason::Size, SkipReason::Budget, SkipReason::Ratio,
            SkipReason::Depth, SkipReason::Corrupt, SkipReason::Excluded, SkipReason::Sidecar,
        };
        Json members = Json::object();
        for (const SkipReason reason : kMemberKeys) {
            members[std::string(skipReasonToString(reason))] = stats.skips.count(reason);
        }
        a["membersSkipped"] = std::move(members);
        s["archives"] = std::move(a);
    }

    s["durationMs"] = result.duration().count();
    return s;
}

// The library's refusal, in a sentence that is safe to print. Its message names a byte
// offset and a byte value in hex and quotes nothing, but it is sanitized anyway: this line
// reaches a terminal, and what it is about is text that failed a validity check.
std::string libraryRefusal(const nlohmann::json::exception& e) {
    return safe_text::sanitize(e.what());
}

}  // namespace

void JsonReportWriter::write(const std::string& text) {
    if (failure_) {
        return;
    }
    out_ << text;
    out_.flush();
}

void JsonReportWriter::stop(std::string reason) {
    failure_ = std::move(reason);
    out_.setstate(std::ios::badbit);
}

void JsonReportWriter::begin() {
    write(openDocument());
}

void JsonReportWriter::onFile(const FileResult& result) {
    if (failure_ || !worthReporting(result)) {
        return;
    }
    // Asked first, and of all three writers, so that a finding this report refuses is one
    // the CSV and text reports refuse too, in the same words - see ReportWriter.h.
    if (const auto why = unwritableFinding(result)) {
        stop(unwritableRecord(result, "JSON", *why));
        return;
    }
    // Rendered in full before any of it is written, so a refusal leaves no half of a record
    // on the stream. The library's own refusal is the last line behind the question above:
    // every string this record holds is escaped or has been asked it, so nothing known
    // reaches this catch, and it stays for whatever the next key adds.
    std::string text;
    try {
        text = arrayElement(!anyFile_, fileRecord(result));
    } catch (const nlohmann::json::exception& e) {
        stop(unwritableRecord(result, "JSON", libraryRefusal(e)));
        return;
    }
    anyFile_ = true;
    write(text);
}

void JsonReportWriter::end(const ScanResult& result, bool interrupted) {
    if (failure_) {
        return;
    }
    std::string text = closeArray(!anyFile_);
    try {
        const Json s = summary(result, interrupted);
        for (auto it = s.begin(); it != s.end(); ++it) {
            text += member(it.key(), it.value());
        }
    } catch (const nlohmann::json::exception& e) {
        stop("the summary could not be written as JSON: " + libraryRefusal(e));
        return;
    }
    text += closeDocument();
    write(text);
}

}  // namespace lyxbosa
