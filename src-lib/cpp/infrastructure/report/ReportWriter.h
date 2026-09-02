#pragma once

// ReportWriter.h - Report output as a stream of events rather than one dump.
//
// Writers are fed each interesting file as the scan finds it, so a long scan
// writes its report incrementally and an interrupted one still leaves a
// well-formed file behind. It is also what lets the scanner stop retaining a
// FileResult for every clean file it walks past.

#include "core/ScanResult.h"
#include "config/Types.h"
#include <ostream>

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
};

}  // namespace lyxbosa
