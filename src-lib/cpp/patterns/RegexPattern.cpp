#include "RegexPattern.h"
#include <fmt/core.h>

namespace lyxbosa {

RegexPattern::RegexPattern(std::string_view pattern, bool caseInsensitive)
    : pattern_(pattern), caseInsensitive_(caseInsensitive) {

    RE2::Options options;
    options.set_case_sensitive(!caseInsensitive_);
    options.set_log_errors(false);  // Don't spam stderr
    options.set_max_mem(64 << 20);  // 64MB DFA cache - prevents NFA fallback on large binary files

    // Wrap the pattern in a capturing group so we can extract the match
    std::string wrappedPattern = "(" + std::string(pattern) + ")";
    regex_ = std::make_unique<RE2>(wrappedPattern, options);
}

bool RegexPattern::isValid() const {
    return regex_ && regex_->ok();
}

std::string RegexPattern::error() const {
    if (!regex_) {
        return "regex not initialized";
    }
    return regex_->error();
}

std::vector<PatternMatch> RegexPattern::match(std::string_view content) const {
    std::vector<PatternMatch> matches;

    if (!isValid() || content.empty()) {
        return matches;
    }

    // Helper to skip to next line
    auto skipToNextLine = [&content](size_t pos) -> size_t {
        size_t nextLine = content.find('\n', pos);
        return (nextLine == std::string_view::npos) ? content.size() : nextLine + 1;
    };

    re2::StringPiece input(content.data(), content.size());
    re2::StringPiece matchPiece;

    size_t searchStart = 0;

    while (searchStart < content.size()) {
        re2::StringPiece remaining(content.data() + searchStart, content.size() - searchStart);

        if (!RE2::PartialMatch(remaining, *regex_, &matchPiece)) {
            break;
        }

        // Calculate the actual offset in the original content
        size_t matchOffset = searchStart + (matchPiece.data() - remaining.data());

        PatternMatch m;
        m.offset = matchOffset;
        auto [line, column] = computeLineColumn(content, matchOffset);
        m.line = line;
        m.column = column;
        m.matchedText = std::string(matchPiece.data(), matchPiece.size());
        m.context = extractContext(content, matchOffset, matchPiece.size());
        matches.push_back(std::move(m));

        // Skip to next line - one match per line is enough
        searchStart = skipToNextLine(matchOffset);
    }

    return matches;
}

}  // namespace lyxbosa
