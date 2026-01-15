#include "MatchEngine.h"
#include <algorithm>

namespace lyxbosa {

// Suppression comment patterns to detect
static const std::vector<std::string> suppressionPatterns = {
    "phpcs:ignore",
    "phpcs:disable",
    "@codingStandardsIgnore",
    "// noqa",
    "# noqa",
    "/* noqa",
    "// nolint",
    "// NOSONAR",
    "@SuppressWarnings",
    "// @ts-ignore",
    "// eslint-disable",
    "/* eslint-disable",
};

// Check if a line contains a suppression comment
static bool lineContainsSuppression(std::string_view line) {
    for (const auto& pattern : suppressionPatterns) {
        if (line.find(pattern) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

// Get the line containing the given offset
static std::string_view getLineAt(std::string_view content, size_t offset) {
    // Find line start
    size_t lineStart = content.rfind('\n', offset > 0 ? offset - 1 : 0);
    lineStart = (lineStart == std::string_view::npos) ? 0 : lineStart + 1;

    // Find line end
    size_t lineEnd = content.find('\n', offset);
    if (lineEnd == std::string_view::npos) {
        lineEnd = content.size();
    }

    return content.substr(lineStart, lineEnd - lineStart);
}

// Get the previous line (before the line containing offset)
static std::string_view getPreviousLine(std::string_view content, size_t offset) {
    // Find current line start
    size_t lineStart = content.rfind('\n', offset > 0 ? offset - 1 : 0);
    if (lineStart == std::string_view::npos || lineStart == 0) {
        return {};  // No previous line
    }

    // Find previous line start
    size_t prevLineStart = content.rfind('\n', lineStart - 1);
    prevLineStart = (prevLineStart == std::string_view::npos) ? 0 : prevLineStart + 1;

    return content.substr(prevLineStart, lineStart - prevLineStart);
}

// Check if match has suppression comment nearby (same line or previous line)
bool MatchEngine::hasSuppression(std::string_view content, size_t offset) {
    std::string_view currentLine = getLineAt(content, offset);
    if (lineContainsSuppression(currentLine)) {
        return true;
    }

    std::string_view prevLine = getPreviousLine(content, offset);
    if (!prevLine.empty() && lineContainsSuppression(prevLine)) {
        return true;
    }

    return false;
}

// Calculate byte offset from line/column
static size_t lineColToOffset(std::string_view content, size_t line, size_t col) {
    size_t currentLine = 1;
    size_t lineStart = 0;

    for (size_t i = 0; i < content.size(); ++i) {
        if (currentLine == line) {
            return lineStart + col - 1;
        }
        if (content[i] == '\n') {
            ++currentLine;
            lineStart = i + 1;
        }
    }

    // If we're looking for the last line
    if (currentLine == line) {
        return lineStart + col - 1;
    }

    return 0;
}

// Get context (surrounding text) for a match
static std::string getContext(std::string_view content, size_t offset, size_t matchLen, size_t contextLen = 80) {
    // Get some context before and after
    size_t start = (offset > contextLen / 2) ? offset - contextLen / 2 : 0;
    size_t end = std::min(offset + matchLen + contextLen / 2, content.size());

    std::string ctx(content.substr(start, end - start));

    // Replace newlines with spaces for single-line display
    for (char& c : ctx) {
        if (c == '\n' || c == '\r') c = ' ';
    }

    return ctx;
}

void MatchEngine::loadRules(const std::vector<RuleConfig>& configs) {
    rules_.clear();
    rules_.reserve(configs.size());

    for (const auto& config : configs) {
        auto rule = std::make_unique<Rule>(config);
        if (rule->isValid()) {
            rules_.push_back(std::move(rule));
        }
    }
}

void MatchEngine::loadBuiltinCategory(rules::Category category) {
    const auto& registry = rules::Registry::instance();
    auto categoryRules = registry.getByCategory(category);

    for (const auto* rule : categoryRules) {
        std::string code = rule->code.toString();
        if (disabledRules_.find(code) == disabledRules_.end()) {
            // Check if already loaded
            bool alreadyLoaded = false;
            for (const auto* existing : builtinRules_) {
                if (existing == rule) {
                    alreadyLoaded = true;
                    break;
                }
            }
            if (!alreadyLoaded) {
                builtinRules_.push_back(rule);
            }
        }
    }
}

void MatchEngine::loadAllBuiltinRules() {
    const auto& registry = rules::Registry::instance();
    builtinRules_.clear();

    for (const auto* rule : registry.getAllRules()) {
        std::string code = rule->code.toString();
        if (disabledRules_.find(code) == disabledRules_.end()) {
            builtinRules_.push_back(rule);
        }
    }
}

void MatchEngine::loadBuiltinRule(std::string_view code) {
    const auto* rule = rules::getRuleByCode(code);
    if (rule) {
        std::string codeStr(code);
        if (disabledRules_.find(codeStr) == disabledRules_.end()) {
            // Check if already loaded
            bool alreadyLoaded = false;
            for (const auto* existing : builtinRules_) {
                if (existing == rule) {
                    alreadyLoaded = true;
                    break;
                }
            }
            if (!alreadyLoaded) {
                builtinRules_.push_back(rule);
            }
        }
    }
}

void MatchEngine::disableBuiltinRule(std::string_view code) {
    disabledRules_.insert(std::string(code));

    // Remove from loaded rules if present
    const auto* ruleToRemove = rules::getRuleByCode(code);
    if (ruleToRemove) {
        builtinRules_.erase(
            std::remove(builtinRules_.begin(), builtinRules_.end(), ruleToRemove),
            builtinRules_.end()
        );
    }
}

void MatchEngine::addRule(std::unique_ptr<Rule> rule) {
    if (rule && rule->isValid()) {
        rules_.push_back(std::move(rule));
    }
}

std::vector<FileMatch> MatchEngine::match(std::string_view content) const {
    std::vector<FileMatch> allMatches;

    // Match custom YAML rules
    for (const auto& rule : rules_) {
        auto ruleMatches = rule->match(content);

        // Check each match for suppression comments
        for (auto& match : ruleMatches) {
            if (hasSuppression(content, match.offset)) {
                match.suppressed = true;
                match.originalSeverity = match.severity;
                match.severity = Severity::Low;  // Downgrade to Low
            }
        }

        allMatches.insert(allMatches.end(),
                          std::make_move_iterator(ruleMatches.begin()),
                          std::make_move_iterator(ruleMatches.end()));
    }

    // Match built-in CTRE rules
    for (const auto* builtinRule : builtinRules_) {
        auto matches = builtinRule->findMatches(content);

        for (const auto& match : matches) {
            FileMatch fm;
            fm.ruleName = std::string(builtinRule->name);
            fm.severity = builtinRule->severity;
            fm.originalSeverity = builtinRule->severity;
            fm.category = builtinRule->code.toString();  // Use rule code as category (e.g., "WS001")
            fm.patternType = "builtin";
            fm.line = match.line;
            fm.column = match.column;
            fm.offset = lineColToOffset(content, match.line, match.column);
            fm.matchedText = std::string(match.matched);
            fm.context = getContext(content, fm.offset, match.matched.size());

            // Check for suppression
            if (hasSuppression(content, fm.offset)) {
                fm.suppressed = true;
                fm.originalSeverity = fm.severity;
                fm.severity = Severity::Low;
            }

            allMatches.push_back(std::move(fm));
        }
    }

    return allMatches;
}

size_t MatchEngine::patternCount() const {
    size_t total = 0;
    for (const auto& rule : rules_) {
        total += rule->patternCount();
    }
    // Add builtin patterns
    for (const auto* rule : builtinRules_) {
        total += rule->patterns.size();
    }
    return total;
}

void MatchEngine::clear() {
    rules_.clear();
    builtinRules_.clear();
    disabledRules_.clear();
}

}  // namespace lyxbosa
