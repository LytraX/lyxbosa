#include "Rule.h"
#include "patterns/StringPattern.h"
#include "patterns/RegexPattern.h"
#include "patterns/HeuristicPattern.h"
#include <unordered_set>

namespace lyxbosa {

Rule::Rule(const RuleConfig& config)
    : name_(config.name)
    , description_(config.description)
    , severity_(config.severity)
    , category_(config.category) {

    for (const auto& pc : config.patterns) {
        std::unique_ptr<Pattern> pattern;

        bool caseInsensitive = pc.flags.find('i') != std::string::npos;

        switch (pc.type) {
            case PatternType::String:
                pattern = std::make_unique<StringPattern>(pc.value, caseInsensitive);
                break;

            case PatternType::Regex: {
                auto regexPattern = std::make_unique<RegexPattern>(pc.value, caseInsensitive);
                if (regexPattern->isValid()) {
                    pattern = std::move(regexPattern);
                }
                // Invalid regex patterns are silently skipped
                break;
            }

            case PatternType::Heuristic:
                pattern = std::make_unique<HeuristicPattern>(
                    pc.heuristicType,
                    pc.minOccurrences,
                    pc.minStringLength
                );
                break;

            case PatternType::Hex:
            case PatternType::Entropy:
            case PatternType::Hash:
                // These pattern types are not yet implemented (Phase 3)
                // Skip for now
                break;
        }

        if (pattern) {
            patterns_.push_back(std::move(pattern));
        }
    }
}

std::vector<FileMatch> Rule::match(std::string_view content) const {
    std::vector<FileMatch> matches;
    std::unordered_set<size_t> matchedLines;  // Track which lines already matched this rule

    for (const auto& pattern : patterns_) {
        auto patternMatches = pattern->match(content);

        for (auto& pm : patternMatches) {
            // Skip if we already have a match on this line for this rule
            if (matchedLines.count(pm.line) > 0) {
                continue;
            }
            matchedLines.insert(pm.line);

            FileMatch fm;
            fm.ruleName = name_;
            fm.severity = severity_;
            fm.category = category_;
            fm.patternType = std::string(pattern->type());
            fm.offset = pm.offset;
            fm.line = pm.line;
            fm.column = pm.column;
            fm.matchedText = std::move(pm.matchedText);
            fm.context = std::move(pm.context);
            matches.push_back(std::move(fm));
        }
    }

    return matches;
}

}  // namespace lyxbosa
