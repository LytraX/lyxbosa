#pragma once

#include "RuleCode.hpp"
#include <re2/re2.h>
#include <string_view>
#include <vector>
#include <memory>
#include <span>
#include <mutex>
#include <unordered_map>

namespace lyxbosa::rules {

// Match result from a pattern check
struct MatchResult {
    size_t line;
    size_t column;
    std::string_view matched;
    std::string note;  // Analyzer rules only: what the analysis concluded
};

// A single pattern within a rule (stores regex string for RE2 compilation)
struct Pattern {
    std::string_view regex;          // The regex pattern string
    std::string_view description;    // Optional description of what this pattern catches
    bool case_insensitive;

    // Literal gate: substrings a match cannot occur without.
    //
    // Every non-empty entry must be present in the file (AND); alternatives inside
    // one entry are separated by '|' (OR). Comparison is case-insensitive, so write
    // them lowercase. An empty gate means the pattern always runs.
    //
    //   { R"((?i:eval)\s*\(\s*(?i:base64_decode)\s*\()", "...", false,
    //     {"eval", "base64_decode"} }
    //
    //   { R"(((?i:system)|(?i:exec))\s*\(\s*\$_(GET|POST))", "...", false,
    //     {"system|exec", "$_get|$_post"} }
    //
    // SOUNDNESS IS THE WHOLE CONTRACT. A gate entry may only name text that *every*
    // match must contain: not something inside an alternation the entry does not
    // enumerate, not inside a `?`/`*` group, not a character a quantifier could
    // consume zero times. Get this wrong and the pattern is silently skipped on
    // files it should have matched - a missed detection with no error anywhere.
    // LiteralGateTest checks each entry against the pattern it guards.
    std::string_view gate[3] = {};
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

// RE2 pattern cache - compiles patterns on first use
class PatternCache {
public:
    static PatternCache& instance() {
        static PatternCache cache;
        return cache;
    }

    // Get or compile a pattern
    // For findMatches, we need a version that wraps the pattern in a capture group
    const RE2* get(std::string_view pattern, bool case_insensitive = false, bool wrapCapture = false) {
        std::string key = makeKey(pattern, case_insensitive);
        if (wrapCapture) key += "\x02WC";

        std::lock_guard<std::mutex> lock(mutex_);

        auto it = cache_.find(key);
        if (it != cache_.end()) {
            return it->second.get();
        }

        // Compile the pattern
        RE2::Options opts;
        opts.set_log_errors(false);
        opts.set_case_sensitive(!case_insensitive);
        opts.set_dot_nl(true);  // Let . match newlines for multiline patterns
        opts.set_max_mem(64 << 20);  // 64MB DFA cache - prevents NFA fallback on large binary files

        // Wrap in capture group if requested (for findMatches to get matched text)
        std::string patternStr(pattern);
        if (wrapCapture) {
            patternStr = "(" + patternStr + ")";
        }

        auto re = std::make_unique<RE2>(patternStr, opts);
        if (!re->ok()) {
            // Pattern failed to compile - return nullptr
            return nullptr;
        }

        const RE2* ptr = re.get();
        cache_[key] = std::move(re);
        return ptr;
    }

    // Precompile all patterns (call during initialization)
    void precompile(std::span<const Pattern> patterns) {
        for (const auto& p : patterns) {
            get(p.regex, p.case_insensitive);
        }
    }

private:
    PatternCache() = default;

    std::string makeKey(std::string_view pattern, bool ci) {
        std::string key(pattern);
        if (ci) key += "\x01CI";
        return key;
    }

    std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<RE2>> cache_;
};

// Some techniques cannot be expressed as a regex - runtime string assembly, for
// one, needs the fragments folded before there is anything to compare against.
// Such rules supply an analyzer instead of patterns.
using RuleAnalyzer = std::vector<MatchResult> (*)(std::string_view content);

// Built-in rule definition
struct BuiltinRule {
    RuleCode code;
    std::string_view name;
    std::string_view description;
    Severity severity;
    std::span<const Pattern> patterns;
    RuleAnalyzer analyzer = nullptr;  // Optional: used instead of `patterns`

    // Check if any pattern matches
    bool matches(std::string_view content) const {
        if (analyzer) {
            return !analyzer(content).empty();
        }

        auto& cache = PatternCache::instance();

        for (const auto& pattern : patterns) {
            const RE2* re = cache.get(pattern.regex, pattern.case_insensitive);
            if (re && RE2::PartialMatch(re2::StringPiece(content.data(), content.size()), *re)) {
                return true;
            }
        }
        return false;
    }

    // Get all matches with positions
    std::vector<MatchResult> findMatches(std::string_view content) const {
        if (analyzer) {
            return analyzer(content);
        }

        std::vector<MatchResult> results;
        auto& cache = PatternCache::instance();

        for (const auto& pattern : patterns) {
            // Get pattern wrapped in capture group so we can extract matched text
            const RE2* re = cache.get(pattern.regex, pattern.case_insensitive, true);
            if (!re) continue;

            re2::StringPiece input(content.data(), content.size());
            re2::StringPiece match;

            while (RE2::FindAndConsume(&input, *re, &match)) {
                // Calculate position in original content
                size_t matchPos = static_cast<size_t>(match.data() - content.data());
                auto [line, col] = positionToLineCol(content, matchPos);

                MatchResult res;
                res.line = line;
                res.column = col;
                res.matched = std::string_view(match.data(), match.size());
                results.push_back(res);

                // Handle zero-width matches to prevent infinite loop
                if (match.empty() && !input.empty()) {
                    input.remove_prefix(1);
                }
            }
        }

        return results;
    }
};

// Helper macro to define patterns - now just stores the string
#define PATTERN(regex_str, desc) { regex_str, desc, false }
#define PATTERN_CI(regex_str, desc) { regex_str, desc, true }

// For backward compatibility with existing rule files
// This is now a simple identity function since we store strings directly
template<auto>
constexpr std::string_view makePattern() = delete;  // Force use of string literals

} // namespace lyxbosa::rules
