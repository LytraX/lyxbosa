#pragma once

#include "ReportWriter.h"
#include "infrastructure/PathUtils.h"
#include <ostream>
#include <string_view>
#include <fmt/format.h>

namespace lyxbosa {

// Streaming JSON. Files are emitted as they are found, so the summary counters
// can only be written at the end - the key set is unchanged from the previous
// all-at-once implementation, only the order differs.
class JsonReportWriter : public ReportWriter {
public:
    explicit JsonReportWriter(std::ostream& out) : out_(out) {}

    void begin() override {
        out_ << "{\n";
        out_ << "  \"files\": [";
    }

    void onFile(const FileResult& result) override {
        if (!worthReporting(result)) {
            return;
        }

        out_ << (firstFile_ ? "\n" : ",\n");
        firstFile_ = false;

        out_ << "    {\n";
        out_ << "      \"path\": ";
        writeString(out_, pathForDisplay(result.path));
        out_ << ",\n";

        // The same path as bytes, when the rendering above could not carry them.
        //
        // `path` is escaped so that the document stays valid UTF-8 and a parser accepts
        // it - a file name on a Linux host may be any bytes at all, and one that is not
        // valid UTF-8 has no JSON string that spells it. That escape is one-way, which
        // is fine for a person and useless to a program: an external tool reading this
        // report has to be able to open, match or delete the exact file, and it cannot
        // do that from a rendering. So it gets the bytes here, in hex, and keeps a
        // document that every JSON parser still reads.
        //
        // Absent - not empty - whenever `path` is already exact, which is every file in
        // an ordinary tree. A consumer reads this key only when it is there, and its
        // presence is itself the statement that `path` is a rendering rather than a name.
        if (pathDisplayIsLossy(result.path)) {
            out_ << "      \"pathBytesHex\": ";
            writeString(out_, pathBytesHex(result.path));
            out_ << ",\n";
        }
        // `skipped` keeps meaning exactly what it always did, so every existing
        // consumer reads this report unchanged; `skipReason` is additive and
        // present only when there is one.
        out_ << "      \"skipped\": " << (result.skipped() ? "true" : "false") << ",\n";
        if (result.skipReason) {
            out_ << "      \"skipReason\": \"" << skipReasonToString(*result.skipReason)
                 << "\",\n";
        }
        out_ << "      \"quarantined\": " << (result.quarantined ? "true" : "false") << ",\n";
        // Present only when it happened, like `skipReason` and `suppressed` above, so a
        // report from a run where every move succeeded is byte-identical to before.
        // `quarantined: false` is the answer for an exposure finding and for a run with
        // quarantine off as well; this key is the one that says the file is still there.
        if (result.quarantineFailed) {
            out_ << "      \"quarantineFailed\": true,\n";
        }

        // Where the bytes are now. The scanner has always known this and exactly one
        // consumer ever read it - the `moved:` line of the verbose text view - so a
        // pipeline was told a file had been quarantined and never told where to, which
        // is the half of the answer a machine needs and a human can go and look for.
        if (!result.quarantinePath.empty()) {
            out_ << "      \"quarantinePath\": ";
            writeString(out_, pathForDisplay(result.quarantinePath));
            out_ << ",\n";
            // Same rule as `pathBytesHex`, and needed for the same reason one level on:
            // under `preserve_structure` the destination mirrors the source's whole
            // path, so a name that could not be rendered exactly arrives here too - and
            // this is the path a tool has to open to find where the bytes went.
            if (pathDisplayIsLossy(result.quarantinePath)) {
                out_ << "      \"quarantinePathBytesHex\": ";
                writeString(out_, pathBytesHex(result.quarantinePath));
                out_ << ",\n";
            }
        }

        // What happened to the container this file was found inside. Absent for a loose
        // file and for a member no decision was taken about, which is why it is a
        // string rather than a bool: `false` would be the answer for a member that went
        // into quarantine inside its container AND for one still sitting under the web
        // root, and those are the two answers an operator acts on differently.
        if (result.containerQuarantine) {
            out_ << "      \"containerQuarantine\": \""
                 << containerQuarantineToString(*result.containerQuarantine) << "\",\n";
        }
        out_ << "      \"matches\": [";

        bool firstMatch = true;
        for (const auto& match : result.matches) {
            out_ << (firstMatch ? "\n" : ",\n");
            firstMatch = false;

            out_ << "        {\n";
            out_ << "          \"rule\": ";
            writeString(out_, match.ruleName);
            out_ << ",\n";
            out_ << "          \"severity\": ";
            writeString(out_, severityToString(match.severity));
            out_ << ",\n";
            if (match.suppressed) {
                out_ << "          \"originalSeverity\": ";
                writeString(out_, severityToString(match.originalSeverity));
                out_ << ",\n";
                out_ << "          \"suppressed\": true,\n";
            }
            out_ << "          \"category\": ";
            writeString(out_, match.category);
            out_ << ",\n";
            out_ << "          \"line\": " << match.line << ",\n";
            out_ << "          \"column\": " << match.column << "\n";
            out_ << "        }";
        }

        out_ << (firstMatch ? "]\n" : "\n      ]\n");
        out_ << "    }";
        out_.flush();
    }

    void end(const ScanResult& result, bool interrupted) override {
        out_ << (firstFile_ ? "],\n" : "\n  ],\n");
        out_ << "  \"interrupted\": " << (interrupted ? "true" : "false") << ",\n";
        out_ << "  \"totalFilesScanned\": " << result.totalFilesScanned << ",\n";
        out_ << "  \"totalDirectoriesScanned\": " << result.totalDirectoriesScanned << ",\n";
        out_ << "  \"filesWithMatches\": " << result.filesWithMatches << ",\n";
        // Beside the count it is a subset of, and emitted unconditionally like it: a
        // consumer that has to test for a key's presence to learn a count was zero
        // reads an old report and a clean tree as the same thing. This is the volume
        // answer - a caller can tell 4,102 findings about names from 16 about content
        // without walking the file list to work it out.
        out_ << "  \"filesWithHostileNames\": " << result.filesWithHostileNames << ",\n";
        out_ << "  \"filesSkippedSize\": " << result.filesSkippedSize() << ",\n";
        writeFilesSkipped(result);
        out_ << "  \"filesQuarantined\": " << result.filesQuarantined << ",\n";
        out_ << "  \"filesQuarantineFailed\": " << result.filesQuarantineFailed << ",\n";
        writeRootsMissing(result);
        writeArchives(result.archives);
        out_ << "  \"durationMs\": " << result.duration().count() << "\n";
        out_ << "}\n";
        out_.flush();
    }

    // Files not scanned, by reason - shaped exactly like archives.membersSkipped so
    // the two levels read the same way. Emitted unconditionally, because
    // filesSkippedSize already is, and that key stays above it for compatibility.
    void writeFilesSkipped(const ScanResult& result) {
        out_ << "  \"filesSkipped\": {\n";
        out_ << "    \"total\": " << result.skips.total() << ",\n";
        out_ << "    \"size\": " << result.skips.count(SkipReason::Size) << ",\n";
        out_ << "    \"excluded\": " << result.skips.count(SkipReason::Excluded) << ",\n";
        out_ << "    \"unreadable\": " << result.skips.count(SkipReason::Unreadable) << "\n";
        out_ << "  },\n";
        out_ << "  \"directoriesUnreadable\": " << result.directoriesUnreadable << ",\n";
        // Unconditional like the key above it. A consumer that has to test for a key's
        // presence to learn a count was zero is a consumer that reads an old report and
        // a loop-free one as the same thing.
        out_ << "  \"directoriesCycleSkipped\": " << result.directoriesCycleSkipped << ",\n";
    }

    // The roots that were named and were not there. Emitted unconditionally and as an
    // array rather than a count, because a consumer that reads only the counts above
    // cannot otherwise tell a clean scan of a whole tree from a successful scan of
    // nothing at all - which is the machine-readable form of the same lie.
    void writeRootsMissing(const ScanResult& result) {
        out_ << "  \"rootsMissing\": [";
        bool first = true;
        for (const auto& root : result.rootsMissing) {
            out_ << (first ? "\n    " : ",\n    ");
            first = false;
            writeString(out_, pathForDisplay(root));
        }
        out_ << (first ? "],\n" : "\n  ],\n");
    }

    // Archive handling, including every member that was not scanned and why.
    // Emitted only when an archive was actually opened, so a report from a tree
    // with none in it is byte-identical to what this wrote before.
    void writeArchives(const archive::Stats& stats) {
        if (stats.archivesOpened == 0) {
            return;
        }
        out_ << "  \"archives\": {\n";
        out_ << "    \"opened\": " << stats.archivesOpened << ",\n";
        out_ << "    \"unreadable\": " << stats.archivesUnreadable << ",\n";
        out_ << "    \"stoppedEarly\": " << stats.archivesTruncated << ",\n";
        out_ << "    \"membersScanned\": " << stats.membersScanned << ",\n";
        out_ << "    \"bytesExpanded\": " << stats.bytesExpanded << ",\n";
        out_ << "    \"membersSkipped\": {\n";
        out_ << "      \"policy\": " << stats.skippedPolicy() << ",\n";
        out_ << "      \"size\": " << stats.skippedSize() << ",\n";
        out_ << "      \"budget\": " << stats.skippedBudget() << ",\n";
        out_ << "      \"ratio\": " << stats.skippedRatio() << ",\n";
        out_ << "      \"depth\": " << stats.skippedDepth() << ",\n";
        out_ << "      \"corrupt\": " << stats.skippedCorrupt() << "\n";
        out_ << "    }\n";
        out_ << "  },\n";
    }

    // Escape per RFC 8259. Bytes >= 0x80 pass through: paths reach us already
    // converted to UTF-8. The previous implementation emitted them raw, so a
    // path containing a quote or a backslash produced invalid JSON.
    static void writeString(std::ostream& os, std::string_view s) {
        os << '"';
        for (char raw : s) {
            const auto c = static_cast<unsigned char>(raw);
            switch (c) {
                case '"':  os << "\\\""; break;
                case '\\': os << "\\\\"; break;
                case '\b': os << "\\b";  break;
                case '\f': os << "\\f";  break;
                case '\n': os << "\\n";  break;
                case '\r': os << "\\r";  break;
                case '\t': os << "\\t";  break;
                default:
                    if (c < 0x20) {
                        os << fmt::format("\\u{:04x}", static_cast<unsigned>(c));
                    } else {
                        os << raw;
                    }
            }
        }
        os << '"';
    }

private:
    std::ostream& out_;
    bool firstFile_ = true;
};

}  // namespace lyxbosa
