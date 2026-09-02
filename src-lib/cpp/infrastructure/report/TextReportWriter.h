#pragma once

#include "ReportWriter.h"
#include "infrastructure/ResultPrinter.h"
#include <ostream>

namespace lyxbosa {

// Human-readable report. Used for both the terminal (colour, terminal width)
// and a text --output-file (no colour, fixed width).
class TextReportWriter : public ReportWriter {
public:
    TextReportWriter(std::ostream& out, bool color, size_t width, bool verbose, bool summary)
        : out_(out), printer_(out, color, width), verbose_(verbose), summary_(summary) {}

    void onFile(const FileResult& result) override {
        if (verbose_) {
            printer_.printFileResult(result);
        } else {
            printer_.printFileResultCompact(result);
        }
        out_.flush();
    }

    void end(const ScanResult& result, bool interrupted) override {
        if (interrupted) {
            out_ << "\nScan interrupted - the results above are partial.\n";
        }
        if (summary_) {
            printer_.printSummary(result);
        }
        out_.flush();
    }

private:
    std::ostream& out_;
    ResultPrinter printer_;
    bool verbose_;
    bool summary_;
};

}  // namespace lyxbosa
