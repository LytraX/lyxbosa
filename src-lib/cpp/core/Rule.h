#pragma once

#include "config/Types.h"
#include "config/Rules.h"
#include "patterns/Pattern.h"
#include "ScanResult.h"
#include <memory>
#include <vector>
#include <string>

namespace lyxbosa {

// A compiled rule ready for matching
// Holds multiple patterns and aggregates their matches
class Rule {
public:
    // Construct a rule from configuration
    explicit Rule(const RuleConfig& config);

    // Match content against all patterns in this rule
    // Returns matches with rule metadata attached
    std::vector<FileMatch> match(std::string_view content) const;

    // Accessors
    const std::string& name() const { return name_; }
    const std::string& description() const { return description_; }
    Severity severity() const { return severity_; }
    const std::string& category() const { return category_; }
    size_t patternCount() const { return patterns_.size(); }

    // Check if rule compiled successfully
    bool isValid() const { return !patterns_.empty(); }

private:
    std::string name_;
    std::string description_;
    Severity severity_;
    std::string category_;
    std::vector<std::unique_ptr<Pattern>> patterns_;
};

}  // namespace lyxbosa
