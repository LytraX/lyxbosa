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
        if (failure_) {
            return;
        }
        // Asked of the compact view as well, which does not print the rule name: the
        // question is whether this finding can be reported at all, and a report file
        // written in text must not answer it differently from one written in JSON or CSV.
        // See ReportWriter.h. On a terminal the name would not be text, it would be
        // commands, which is why this writer stops rather than printing it.
        if (const auto why = unwritableFinding(result)) {
            failure_ = unwritableRecord(result, "text", *why);
            out_.setstate(std::ios::badbit);
            return;
        }
        if (verbose_) {
            printer_.printFileResult(result);
        } else {
            printer_.printFileResultCompact(result);
        }
        out_.flush();
    }

    void end(const ScanResult& result, bool interrupted) override {
        if (failure_) {
            return;
        }
        if (interrupted) {
            out_ << "\nScan interrupted - the results above are partial.\n";
        }
        if (summary_) {
            printer_.printSummary(result);
        }
        out_.flush();
    }

    std::optional<std::string> failure() const override { return failure_; }

private:
    std::ostream& out_;
    ResultPrinter printer_;
    bool verbose_;
    bool summary_;
    std::optional<std::string> failure_;
};

}  // namespace lyxbosa
