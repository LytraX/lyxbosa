#pragma once

// ReportWriter.h - Report output as a stream of events rather than one dump.
//
// Writers are fed each interesting file as the scan finds it, so a long scan
// writes its report incrementally and an interrupted one still leaves a
// well-formed file behind. It is also what lets the scanner stop retaining a
// FileResult for every clean file it walks past.

#include "core/ScanResult.h"
#include "config/Types.h"
#include <optional>
#include <ostream>
#include <string>

namespace lyxbosa {

class ReportWriter {
public:
    virtual ~ReportWriter() = default;

    // Called once before any file.
    virtual void begin() {}

    // Called for every file worth reporting: one with matches, or one skipped
    // because of the size limit.
    virtual void onFile(const FileResult& result) = 0;

    // Called once at the end, including when the scan was interrupted, so the
    // report is always closed off properly.
    virtual void end(const ScanResult& result, bool interrupted) = 0;

    // Why this writer stopped writing, when it did: the report it produced is incomplete
    // for a reason that is not the stream's. Empty for a report written in full.
    //
    // A writer that stops also sets badbit on its stream, so a caller holding only the
    // stream cannot read the incomplete document as a delivered one. This is for the
    // caller holding the writer, which is owed the reason as well as the fact - and for
    // standard output, whose stream state nothing else asks about.
    virtual std::optional<std::string> failure() const { return std::nullopt; }
};

}  // namespace lyxbosa
