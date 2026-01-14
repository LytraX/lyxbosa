#include "StringPattern.h"
#include <algorithm>
#include <cctype>

namespace lyxbosa {

// Helper implementation for Pattern base class
std::pair<size_t, size_t> Pattern::computeLineColumn(std::string_view content, size_t offset) {
    size_t line = 1;
    size_t lastNewline = 0;

    for (size_t i = 0; i < offset && i < content.size(); ++i) {
        if (content[i] == '\n') {
            ++line;
            lastNewline = i + 1;
        }
    }

    size_t column = offset - lastNewline + 1;
    return {line, column};
}

std::string Pattern::extractContext(std::string_view content, size_t offset, size_t matchLen, size_t contextChars) {
    // Find start of context (don't go before start of content)
    size_t start = (offset > contextChars) ? offset - contextChars : 0;

    // Find end of context (don't go past end of content)
    size_t end = offset + matchLen + contextChars;
    if (end > content.size()) {
        end = content.size();
    }

    // Adjust to not break in the middle of lines if possible
    // Find previous newline for start
    while (start > 0 && content[start - 1] != '\n') {
        if (offset - start > contextChars * 2) break;  // Don't go too far
        --start;
    }

    // Find next newline for end
    while (end < content.size() && content[end] != '\n') {
        if (end - (offset + matchLen) > contextChars * 2) break;
        ++end;
    }

    std::string result(content.substr(start, end - start));

    // Replace tabs with spaces for display
    std::replace(result.begin(), result.end(), '\t', ' ');

    // Truncate long lines with ellipsis
    if (result.size() > 120) {
        result = result.substr(0, 117) + "...";
    }

    return result;
}

StringPattern::StringPattern(std::string_view needle, bool caseInsensitive)
    : needle_(needle), caseInsensitive_(caseInsensitive) {
    if (caseInsensitive_) {
        needleLower_.resize(needle_.size());
        std::transform(needle_.begin(), needle_.end(), needleLower_.begin(),
                       [](unsigned char c) { return std::tolower(c); });
    }
}

std::vector<PatternMatch> StringPattern::match(std::string_view content) const {
    std::vector<PatternMatch> matches;

    if (needle_.empty() || content.empty()) {
        return matches;
    }

    // Helper to skip to next line
    auto skipToNextLine = [&content](size_t pos) -> size_t {
        size_t nextLine = content.find('\n', pos);
        return (nextLine == std::string::npos) ? content.size() : nextLine + 1;
    };

    if (caseInsensitive_) {
        // Case-insensitive search
        // Create lowercase version of content for searching
        std::string contentLower(content.size(), '\0');
        std::transform(content.begin(), content.end(), contentLower.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        size_t pos = 0;
        while ((pos = contentLower.find(needleLower_, pos)) != std::string::npos) {
            PatternMatch m;
            m.offset = pos;
            auto [line, column] = computeLineColumn(content, pos);
            m.line = line;
            m.column = column;
            m.matchedText = std::string(content.substr(pos, needle_.size()));
            m.context = extractContext(content, pos, needle_.size());
            matches.push_back(std::move(m));
            // Skip to next line - one match per line is enough
            pos = skipToNextLine(pos);
        }
    } else {
        // Case-sensitive search (faster)
        size_t pos = 0;
        while ((pos = content.find(needle_, pos)) != std::string::npos) {
            PatternMatch m;
            m.offset = pos;
            auto [line, column] = computeLineColumn(content, pos);
            m.line = line;
            m.column = column;
            m.matchedText = std::string(content.substr(pos, needle_.size()));
            m.context = extractContext(content, pos, needle_.size());
            matches.push_back(std::move(m));
            // Skip to next line - one match per line is enough
            pos = skipToNextLine(pos);
        }
    }

    return matches;
}

}  // namespace lyxbosa
