#pragma once

#include "Pattern.h"
#include "config/Types.h"
#include <string>

namespace lyxbosa {

// Heuristic pattern matching for behavioral/structural code analysis
// Detects obfuscation patterns and suspicious code structures
class HeuristicPattern : public Pattern {
public:
    // Construct a heuristic pattern
    // @param heuristicType The type of heuristic to apply
    // @param minOccurrences Minimum occurrences for multi-instance detections
    // @param minStringLength Minimum string length for encoded string detection
    explicit HeuristicPattern(HeuristicType heuristicType,
                              size_t minOccurrences = 2,
                              size_t minStringLength = 100);

    std::vector<PatternMatch> match(std::string_view content) const override;
    std::string_view type() const override { return "heuristic"; }
    std::string_view pattern() const override;

    HeuristicType heuristicType() const { return heuristicType_; }

private:
    // Individual heuristic detection methods
    std::vector<PatternMatch> detectMultipleBase64Concat(std::string_view content) const;
    std::vector<PatternMatch> detectStrReplaceFunctionBuild(std::string_view content) const;
    std::vector<PatternMatch> detectVariableFunctionCall(std::string_view content) const;
    std::vector<PatternMatch> detectHexEncodedFunctions(std::string_view content) const;
    std::vector<PatternMatch> detectGotoObfuscation(std::string_view content) const;
    std::vector<PatternMatch> detectLongEncodedStrings(std::string_view content) const;
    std::vector<PatternMatch> detectEvalWithVariable(std::string_view content) const;
    std::vector<PatternMatch> detectCreateFunctionEval(std::string_view content) const;
    std::vector<PatternMatch> detectArrayIndexStringBuild(std::string_view content) const;
    std::vector<PatternMatch> detectCredentialHarvester(std::string_view content) const;

    // Helper functions
    static bool isBase64Char(char c);
    static bool isHexChar(char c);
    static bool looksLikeBase64(std::string_view s);
    static bool looksLikeHex(std::string_view s);
    static bool hexDecodesToReadableAscii(std::string_view hexStr);

    HeuristicType heuristicType_;
    size_t minOccurrences_;
    size_t minStringLength_;
    mutable std::string patternDesc_;
};

}  // namespace lyxbosa
