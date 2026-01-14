#pragma once

#include "Pattern.h"
#include <re2/re2.h>
#include <memory>
#include <string>

namespace lyxbosa {

// Regular expression pattern matching using Google RE2
// RE2 guarantees linear time matching (no catastrophic backtracking)
class RegexPattern : public Pattern {
public:
    // Construct a regex pattern
    // @param pattern The regex pattern string
    // @param caseInsensitive If true, match regardless of case
    explicit RegexPattern(std::string_view pattern, bool caseInsensitive = false);

    // Check if the pattern compiled successfully
    bool isValid() const;
    std::string error() const;

    std::vector<PatternMatch> match(std::string_view content) const override;
    std::string_view type() const override { return "regex"; }
    std::string_view pattern() const override { return pattern_; }

    bool isCaseInsensitive() const { return caseInsensitive_; }

private:
    std::string pattern_;
    std::unique_ptr<RE2> regex_;
    bool caseInsensitive_;
};

}  // namespace lyxbosa
