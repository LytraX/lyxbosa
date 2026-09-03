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

    void begin() override {
        out_ << "file,rule,severity,original_severity,suppressed,category,line,column,"
                "quarantined,skipped,skip_reason\n";
    }

    void onFile(const FileResult& result) override {
        // A skipped file has no matches, so the loop below never ran for one and CSV
        // output listed none of them at all - 487 files invisible in the format an
        // operator is most likely to pivot through a spreadsheet.
        if (result.matches.empty() && result.skipReason) {
            writeField(out_, pathForDisplay(result.path));
            // rule,severity,original_severity,suppressed,category,line,column
            out_ << ",,,,false,,,,";
            out_ << (result.quarantined ? "true" : "false") << ",true,";
            writeField(out_, skipReasonToString(*result.skipReason));
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
