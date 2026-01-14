#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <memory>

namespace lyxbosa {

// Result of a pattern match
struct PatternMatch {
    size_t offset = 0;          // byte offset in content
    size_t line = 1;            // 1-based line number
    size_t column = 1;          // 1-based column number
    std::string matchedText;    // the text that matched
    std::string context;        // surrounding text (for display)
};

// Base class for all pattern types
// All pattern implementations must be:
// 1. Immutable after construction (thread-safe)
// 2. Return all matches, not just the first
class Pattern {
public:
    virtual ~Pattern() = default;

    // Find all matches in the given content
    // Returns empty vector if no matches
    virtual std::vector<PatternMatch> match(std::string_view content) const = 0;

    // Return the pattern type identifier
    virtual std::string_view type() const = 0;

    // Return the original pattern string (for display/debugging)
    virtual std::string_view pattern() const = 0;

protected:
    // Helper: compute line and column from byte offset
    static std::pair<size_t, size_t> computeLineColumn(std::string_view content, size_t offset);

    // Helper: extract context around a match
    static std::string extractContext(std::string_view content, size_t offset, size_t matchLen, size_t contextChars = 40);
};

// Factory function type for creating patterns
using PatternFactory = std::unique_ptr<Pattern>(*)(std::string_view pattern, std::string_view flags);

}  // namespace lyxbosa
