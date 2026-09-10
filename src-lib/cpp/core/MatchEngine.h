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

    // The file's path as the context filters see it. Every location test in
    // applyContextFilter goes through MatchEngine::underDirectoryNamed() or
    // underDirectoryContaining(), which read directory components only - never the
    // file name - and fold case. On Windows, where a backslash cannot be part of a name
    // and so is always a separator, MatchEngine::match() puts the path through
    // filterPath() ONCE, here, before any of them runs. On POSIX a backslash is a
    // character in a name and the path arrives byte for byte: rewriting it there would
    // let a file NAMED `tests\shell.php` claim a suppression meant for a directory. A
    // filter reads its path from this field and from nowhere else - that is what keeps
    // a fragment added later from having to know about Windows at all.
    std::string_view filePath;
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
    // in the pattern, so the filter is the part worth testing directly. A caller that
    // builds the MatchContext itself owes it a filePath in filterPath() spelling.
    static bool applyContextFilter(const std::string& ruleCode, const MatchContext& ctx);

    // The spelling of a Windows path the context filters see: every backslash turned
    // into a forward slash and nothing else touched, so a mixed path - a root the
    // operator typed one way joined to components the walk spelled the other - comes
    // out uniform. Pure, and public so the tests can drive every fragment through it
    // on any platform. match() applies it under _WIN32 only, for the reason given
    // there: it is exact where a backslash cannot be part of a name and a guess
    // everywhere else. Never applied to what a report prints.
    static std::string filterPath(std::string_view path);

    // The two ways a context filter may read a location, and the only two. Both look
    // at directory components - every `/`-separated piece of `path` except the last,
    // which is the file name - and compare case-insensitively. A name grants nothing:
    // that is the whole contract, and LocationPriorTest pins it for every prior.
    //
    // underDirectoryNamed: some directory component equals `name` (`vendor`, `tests`,
    // `.ssh`). underDirectoryContaining: some directory component contains `fragment`,
    // for a product whose directory name varies by distribution (`elementor`,
    // `elementor-pro`, `essential-addons-for-elementor-lite`).
    static bool underDirectoryNamed(std::string_view path, std::string_view name);
    static bool underDirectoryContaining(std::string_view path, std::string_view fragment);

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
