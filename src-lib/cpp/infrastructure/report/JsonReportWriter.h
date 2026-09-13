#pragma once

#include "ReportWriter.h"
#include <optional>
#include <ostream>
#include <string>

namespace lyxbosa {

// Streaming JSON. Files are emitted as they are found, so the summary counters can only be
// written at the end.
//
// EVERY VALUE IS SERIALIZED BY nlohmann/json, AND NOTHING IS BUILT UP IN MEMORY. A scan can
// report on hundreds of thousands of files, so each file's record becomes an
// nlohmann::ordered_json when it arrives, is rendered, written and flushed, and is gone
// before the next one. The per-key rules - which keys are always present, which only when
// they have something to say - are in JsonReportWriter.cpp beside the code that applies
// them.
//
// ordered_json rather than json because nlohmann::json keeps object keys sorted, and the
// order of a record is part of what a reader of this report has always been given: `path`
// first, `matches` last, and the summary in the order its comments explain.
//
// THE FRAME IS THE ONLY TEXT WRITTEN BY HAND. What streaming cannot hand to the library is
// the outermost object and the `files` array inside it, because the array is open for the
// whole scan. So the writer holds exactly that much state - whether the array has an
// element yet - and five small functions in JsonReportWriter.cpp write the brackets, the
// braces and the commas, each piece in one place and nowhere else. Every key and every
// value, the summary included, is rendered by the library. The indentation is the library's
// too: each value is dumped at two spaces and moved to the depth it sits at, which is
// exact because a dumped value never contains a raw newline inside a string.
//
// The result is held to one statement, and tests/json_report_test.cpp asserts it: the
// streamed document is byte for byte what nlohmann itself renders for the document it
// parses to. A frame that dropped or doubled a comma, or misplaced a bracket, fails that
// comparison rather than producing a report no parser accepts.
//
// WHEN A VALUE CANNOT BE SERIALIZED. nlohmann refuses a string that is not valid UTF-8,
// and JSON has no way to spell one. Paths reach this writer through pathForDisplay(), which
// escapes such bytes and carries the real ones in the `...BytesHex` keys, but a rule's name
// and category come from a configuration file and are written as they were read. So the
// refusal is caught here, the record is not written, and the writer stops: it writes
// nothing further, not even the closing brackets, sets badbit on its stream and keeps the
// reason for failure(). The document is left unparseable deliberately. Closing it would
// hand a consumer that does not read the exit code a valid report that silently lacks a
// file; left open, no parser mistakes it for a complete answer. The scan itself carries on
// and the command exits 1 with the reason on stderr - see ScanUseCase::runScan.
class JsonReportWriter : public ReportWriter {
public:
    explicit JsonReportWriter(std::ostream& out) : out_(out) {}

    void begin() override;
    void onFile(const FileResult& result) override;
    void end(const ScanResult& result, bool interrupted) override;

    std::optional<std::string> failure() const override { return failure_; }

private:
    // Writes `text` if the writer has not stopped. The only call that reaches the stream.
    void write(const std::string& text);
    void stop(std::string reason);

    std::ostream& out_;
    bool anyFile_ = false;
    std::optional<std::string> failure_;
};

}  // namespace lyxbosa
