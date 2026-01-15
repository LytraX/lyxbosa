#pragma once

#include "RuleCode.hpp"
#include <ctre.hpp>
#include <string_view>
#include <vector>
#include <functional>
#include <span>

namespace lyxbosa::rules {

// Match result from a pattern check
struct MatchResult {
    size_t line;
    size_t column;
    std::string_view matched;
};

// Pattern matcher function type
// Returns true if pattern matches, optionally fills results
using PatternMatcher = bool(*)(std::string_view content, std::vector<MatchResult>* results);

// A single pattern within a rule
struct Pattern {
    PatternMatcher matcher;
    std::string_view description;  // Optional description of what this pattern catches
    bool case_insensitive;
};

// Built-in rule definition
struct BuiltinRule {
    RuleCode code;
    std::string_view name;
    std::string_view description;
    Severity severity;
    std::span<const Pattern> patterns;

    // Check if any pattern matches
    bool matches(std::string_view content) const {
        for (const auto& pattern : patterns) {
            if (pattern.matcher(content, nullptr)) {
                return true;
            }
        }
        return false;
    }

    // Get all matches with positions
    std::vector<MatchResult> findMatches(std::string_view content) const {
        std::vector<MatchResult> results;
        for (const auto& pattern : patterns) {
            pattern.matcher(content, &results);
        }
        return results;
    }
};

// Helper to calculate line/column from position in content
inline std::pair<size_t, size_t> positionToLineCol(std::string_view content, size_t pos) {
    size_t line = 1;
    size_t lastNewline = 0;

    for (size_t i = 0; i < pos && i < content.size(); ++i) {
        if (content[i] == '\n') {
            ++line;
            lastNewline = i + 1;
        }
    }

    return {line, pos - lastNewline + 1};
}

// CTRE pattern wrapper - creates a PatternMatcher from a CTRE pattern
template<ctll::fixed_string Pattern>
constexpr PatternMatcher makePattern() {
    return [](std::string_view content, std::vector<MatchResult>* results) -> bool {
        if (results == nullptr) {
            // Just check if matches
            return static_cast<bool>(ctre::search<Pattern>(content));
        }

        // Find all matches
        bool found = false;
        auto remaining = content;
        size_t offset = 0;

        while (!remaining.empty()) {
            auto match = ctre::search<Pattern>(remaining);
            if (match) {
                found = true;

                // Get the matched view
                auto matchedView = match.template get<0>();

                // Calculate position in original content
                size_t matchPos = offset + static_cast<size_t>(matchedView.data() - remaining.data());
                auto [line, col] = positionToLineCol(content, matchPos);

                MatchResult res;
                res.line = line;
                res.column = col;
                res.matched = matchedView;
                results->push_back(res);

                // Move past this match
                size_t advance = static_cast<size_t>(matchedView.data() - remaining.data()) + matchedView.size();
                if (advance == 0) advance = 1;  // Prevent infinite loop on zero-width match
                offset += advance;
                remaining = remaining.substr(advance);
            } else {
                break;
            }
        }

        return found;
    };
}

// Case-insensitive pattern wrapper
// Note: CTRE doesn't support runtime case-insensitivity
// Use (?i) in pattern if supported, or [Aa][Bb] style
template<ctll::fixed_string Pattern>
constexpr PatternMatcher makePatternCI() {
    return makePattern<Pattern>();
}

} // namespace lyxbosa::rules
