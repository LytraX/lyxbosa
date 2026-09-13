#pragma once

// ReportWriter.h - Report output as a stream of events rather than one dump.
//
// Writers are fed each interesting file as the scan finds it, so a long scan
// writes its report incrementally and an interrupted one still leaves a
// well-formed file behind. It is also what lets the scanner stop retaining a
// FileResult for every clean file it walks past.

#include "core/ScanResult.h"
#include "config/Types.h"
#include "infrastructure/PathUtils.h"
#include "utils/SafeText.h"
#include <fmt/format.h>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>

namespace lyxbosa {

// Why this file's findings cannot be written into any report, or empty when they can.
//
// A finding's rule name and category are the two strings every writer takes as they are
// instead of rendering them the way it renders a path, so each has to be plain text: valid
// UTF-8, which JSON can spell and CSV's encoding claims, with no control character, which
// the text report would hand to the terminal. Config::validate refuses a configuration
// whose custom rule breaks that, and rules_test holds every built-in rule to it, so through
// the CLI this is never true. It is here for a rule set assembled without the loader, and
// every writer asks it before writing a file's record, so that the three formats refuse the
// same finding in the same words - where they used to be one refusal, one raw write to a
// terminal and one CSV cell in no encoding at all.
inline std::optional<std::string> unwritableFinding(const FileResult& result) {
    for (const auto& match : result.matches) {
        if (auto why = safe_text::whyNotPlainText(match.ruleName)) {
            return fmt::format("the name of rule \"{}\" {}",
                               safe_text::sanitize(match.ruleName), *why);
        }
        if (auto why = safe_text::whyNotPlainText(match.category)) {
            return fmt::format("the category of rule \"{}\" {}",
                               safe_text::sanitize(match.ruleName), *why);
        }
    }
    return std::nullopt;
}

// The sentence a writer stops with: which file's record, in which format, and why. One
// function for all three writers, so a refusal reads the same whichever report it is.
inline std::string unwritableRecord(const FileResult& result, std::string_view format,
                                    std::string_view why) {
    return fmt::format("the record for {} could not be written as {}: {}",
                       pathForDisplay(result.path), format, why);
}

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
