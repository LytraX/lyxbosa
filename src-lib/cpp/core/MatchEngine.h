#pragma once

#include "config/Rules.h"
#include "Rule.h"
#include "ScanResult.h"
#include <vector>
#include <memory>
#include <string_view>

namespace lyxbosa {

// Pattern matching engine
// Manages compiled rules and matches content against them
class MatchEngine {
public:
    MatchEngine() = default;

    // Load rules from configuration
    void loadRules(const std::vector<RuleConfig>& configs);

    // Add a single rule
    void addRule(std::unique_ptr<Rule> rule);

    // Match content against all rules
    // Returns all matches from all rules
    std::vector<FileMatch> match(std::string_view content) const;

    // Get the number of loaded rules
    size_t ruleCount() const { return rules_.size(); }

    // Get the total number of patterns across all rules
    size_t patternCount() const;

    // Clear all rules
    void clear();

private:
    std::vector<std::unique_ptr<Rule>> rules_;
};

}  // namespace lyxbosa
