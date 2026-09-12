#pragma once

#include "ReportWriter.h"
#include "infrastructure/PathUtils.h"
#include <ostream>
#include <string_view>

namespace lyxbosa {

// Streaming CSV, one row per match.
class CsvReportWriter : public ReportWriter {
public:
    explicit CsvReportWriter(std::ostream& out) : out_(out) {}

    // `quarantine_failed` is appended rather than placed beside `quarantined`, where it
    // reads better, because every column before it keeps its index that way and this
    // format is consumed by position. A file that could not be moved is still where it
    // was found, which `quarantined,false` alone cannot distinguish from a run with
    // quarantine switched off.
    void begin() override {
        out_ << "file,rule,severity,original_severity,suppressed,category,line,column,"
                "quarantined,skipped,skip_reason,quarantine_failed\n";
    }

    void onFile(const FileResult& result) override {
        // A file with no matches can still be worth a row: it was skipped, or it is a
        // container whose quarantine outcome belongs to it rather than to any match of
        // its own. The loop below never runs for one, and CSV listed none of them at
        // all - 487 skipped files invisible in the format an operator is most likely to
        // pivot through a spreadsheet, and every unmoved container beside them.
        if (result.matches.empty() && worthReporting(result)) {
            writeField(out_, pathForDisplay(result.path));
            // rule,severity,original_severity,suppressed,category,line,column
            out_ << ",,,,false,,,,";
            out_ << (result.quarantined ? "true" : "false") << ',';
            out_ << (result.skipped() ? "true" : "false") << ',';
            writeField(out_, result.skipReason ? skipReasonToString(*result.skipReason)
                                               : std::string_view{});
            out_ << ',' << (result.quarantineFailed ? "true" : "false");
            out_ << '\n';
            out_.flush();
            return;
        }

        for (const auto& match : result.matches) {
            writeField(out_, pathForDisplay(result.path));       out_ << ',';
            writeField(out_, match.ruleName);                out_ << ',';
            writeField(out_, severityToString(match.severity)); out_ << ',';
            writeField(out_, match.suppressed ? severityToString(match.originalSeverity)
                                              : std::string_view{});
            out_ << ',';
            out_ << (match.suppressed ? "true" : "false")    << ',';
            writeField(out_, match.category);                out_ << ',';
            out_ << match.line   << ',';
            out_ << match.column << ',';
            out_ << (result.quarantined ? "true" : "false")  << ',';
            out_ << (result.skipped() ? "true" : "false")     << ',';
            writeField(out_, result.skipReason ? skipReasonToString(*result.skipReason)
                                               : std::string_view{});
            out_ << ',' << (result.quarantineFailed ? "true" : "false");
            out_ << '\n';
        }
        out_.flush();
    }

    void end(const ScanResult&, bool) override { out_.flush(); }

    // RFC 4180 quoting. Rule names and categories are tame, but a path may
    // legitimately contain a comma or a quote, which the previous
    // implementation wrote raw and so produced a broken row.
    static void writeField(std::ostream& os, std::string_view s) {
        if (s.find_first_of(",\"\r\n") == std::string_view::npos) {
            os << s;
            return;
        }
        os << '"';
        for (char c : s) {
            if (c == '"') {
                os << "\"\"";
            } else {
                os << c;
            }
        }
        os << '"';
    }

private:
    std::ostream& out_;
};

}  // namespace lyxbosa
