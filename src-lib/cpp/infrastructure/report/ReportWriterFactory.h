#pragma once

#include "ReportWriter.h"
#include "TextReportWriter.h"
#include "JsonReportWriter.h"
#include "CsvReportWriter.h"
#include <memory>
#include <ostream>

namespace lyxbosa {

// color, width, verbose and summary only apply to the text format.
inline std::unique_ptr<ReportWriter> makeReportWriter(ReportFormat format,
                                                      std::ostream& out,
                                                      bool color,
                                                      size_t width,
                                                      bool verbose,
                                                      bool summary) {
    switch (format) {
        case ReportFormat::Json: return std::make_unique<JsonReportWriter>(out);
        case ReportFormat::Csv:  return std::make_unique<CsvReportWriter>(out);
        case ReportFormat::Text: break;
    }
    return std::make_unique<TextReportWriter>(out, color, width, verbose, summary);
}

}  // namespace lyxbosa
