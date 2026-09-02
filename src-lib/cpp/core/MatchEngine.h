#pragma once

#include "config/Rules.h"
#include "Rule.h"
#include "ScanResult.h"
#include "rules/Registry.hpp"
#include "LiteralPrefilter.h"

#include <re2/set.h>
#include <memory>
#include <vector>
#include <memory>
#include <string_view>
#include <unordered_set>
#include <functional>
#include <filesystem>

namespace lyxbosa {

// Context information passed to filters
struct MatchContext {
    std::string_view content;       // Full file content
    std::string_view filePath;      // File path (for extension checks)
    size_t matchOffset;             // Byte offset of match
    size_t matchLine;               // Line number (1-based)
    size_t matchColumn;             // Column number (1-based)
    std::string_view matchedText;   // The matched text
};

// Filter function: returns true if match should be kept, false to discard
using MatchFilter = std::function<bool(const MatchContext&)>;

// Pattern matching engine
// Manages compiled rules and matches content against them
class MatchEngine {
public:
    MatchEngine() = default;

    // Load rules from configuration (YAML custom rules)
    void loadRules(const std::vector<RuleConfig>& configs);

    // Load built-in rules by category
    void loadBuiltinCategory(rules::Category category);

    // Load all built-in rules
    void loadAllBuiltinRules();

    // Load specific built-in rules by code (e.g., "WS001", "RCE003")
    void loadBuiltinRule(std::string_view code);

    // Disable a built-in rule by code
    void disableBuiltinRule(std::string_view code);

    // Add a single custom rule
    void addRule(std::unique_ptr<Rule> rule);

    // Match content against all rules (built-in + custom)
    // Returns all matches from all rules
    std::vector<FileMatch> match(std::string_view content, std::string_view filePath = "") const;

    // Get the number of loaded custom rules
    size_t customRuleCount() const { return rules_.size(); }

    // Get the number of loaded built-in rules
    size_t builtinRuleCount() const { return builtinRules_.size(); }

    // Get total rule count
    size_t ruleCount() const { return rules_.size() + builtinRules_.size(); }

    // Get the total number of patterns across all custom rules
    size_t patternCount() const;

    // Clear all rules
    void clear();

    // Apply the context filter for a rule code: true keeps the match, false discards it.
    // Public so the rule tests can exercise a filter without building a whole scan -
    // several rules (OBF036, DEFC001) carry most of their precision here rather than
    // in the pattern, so the filter is the part worth testing directly.
    static bool applyContextFilter(const std::string& ruleCode, const MatchContext& ctx);

private:
    // Check if match has suppression comment nearby
    static bool hasSuppression(std::string_view content, size_t offset);

    // Get the line containing a specific offset
    static std::string_view getLineAtOffset(std::string_view content, size_t offset);

    // Check if position is inside a comment (PHP/JS style)
    static bool isInComment(std::string_view content, size_t offset);

    // Check if position is inside a SQL query (heuristic)
    static bool isInSqlQuery(std::string_view content, size_t offset);

    // Rebuilt whenever the builtin rule set changes. Handles are parallel to
    // builtinRules_: one vector of per-pattern handles per rule.
    void rebuildPrefilter();

    LiteralPrefilter prefilter_;
    std::vector<std::vector<size_t>> gateHandles_;

    // Patterns with no literal gate - structural things like `\$\w+\[\d+\]\s*\(`
    // that no substring is required for. Run individually they are the single
    // largest cost in a scan, because every one of them walks every file. Compiled
    // into one small RE2::Set they answer "which of these could match?" in a single
    // pass; only the ones it names are then run for their offsets and text.
    std::unique_ptr<RE2::Set> residualSet_;
    std::vector<size_t> residualRuleOf_;   // set id -> index into builtinRules_

    std::vector<std::unique_ptr<Rule>> rules_;  // Custom YAML rules
    std::vector<const rules::BuiltinRule*> builtinRules_;  // Built-in CTRE rules
    std::unordered_set<std::string> disabledRules_;  // Disabled rule codes
};

}  // namespace lyxbosa
