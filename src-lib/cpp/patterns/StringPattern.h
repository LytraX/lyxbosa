#pragma once

#include "Pattern.h"
#include <string>

namespace lyxbosa {

// Exact string pattern matching
// Supports case-sensitive and case-insensitive matching
class StringPattern : public Pattern {
public:
    // Construct a string pattern
    // @param needle The string to search for
    // @param caseInsensitive If true, match regardless of case
    explicit StringPattern(std::string_view needle, bool caseInsensitive = false);

    std::vector<PatternMatch> match(std::string_view content) const override;
    std::string_view type() const override { return "string"; }
    std::string_view pattern() const override { return needle_; }

    bool isCaseInsensitive() const { return caseInsensitive_; }

private:
    std::string needle_;
    std::string needleLower_;  // lowercase version for case-insensitive matching
    bool caseInsensitive_;
};

}  // namespace lyxbosa
