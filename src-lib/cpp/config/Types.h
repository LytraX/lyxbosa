#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace lyxbosa {

enum class Severity {
    Low,
    Medium,
    High,
    Critical
};

enum class PatternType {
    String,
    Regex,
    Hex,
    Entropy,
    Hash,
    Heuristic  // Behavioral/heuristic detection patterns
};

// Heuristic detection subtypes
enum class HeuristicType {
    MultipleBase64Concat,      // Multiple base64 strings concatenated and decoded
    StrReplaceFunctionBuild,   // str_replace used to construct function names
    VariableFunctionCall,      // $var() dynamic function calls
    HexEncodedFunctions,       // Arrays of hex-encoded function names
    GotoObfuscation,           // goto-based control flow obfuscation
    LongEncodedStrings,        // Long base64/hex encoded strings (>500 chars)
    EvalWithVariable,          // eval($var) or assert($var) patterns
    CreateFunctionEval,        // create_function with eval-like behavior
    ArrayIndexStringBuild,     // $var[N].$var[M]... string building obfuscation
    CredentialHarvester        // Combination of POST data collection + mail/exfiltration
};

enum class ReportFormat {
    Text,
    Json,
    Csv
};

// Convert Severity to string
constexpr std::string_view severityToString(Severity s) {
    switch (s) {
        case Severity::Low:      return "low";
        case Severity::Medium:   return "medium";
        case Severity::High:     return "high";
        case Severity::Critical: return "critical";
    }
    return "unknown";
}

// Parse Severity from string
inline Severity severityFromString(std::string_view s) {
    if (s == "low")      return Severity::Low;
    if (s == "medium")   return Severity::Medium;
    if (s == "high")     return Severity::High;
    if (s == "critical") return Severity::Critical;
    return Severity::Medium;  // default
}

// Convert PatternType to string
constexpr std::string_view patternTypeToString(PatternType t) {
    switch (t) {
        case PatternType::String:    return "string";
        case PatternType::Regex:     return "regex";
        case PatternType::Hex:       return "hex";
        case PatternType::Entropy:   return "entropy";
        case PatternType::Hash:      return "hash";
        case PatternType::Heuristic: return "heuristic";
    }
    return "unknown";
}

// Parse PatternType from string
inline PatternType patternTypeFromString(std::string_view s) {
    if (s == "string")    return PatternType::String;
    if (s == "regex")     return PatternType::Regex;
    if (s == "hex")       return PatternType::Hex;
    if (s == "entropy")   return PatternType::Entropy;
    if (s == "hash")      return PatternType::Hash;
    if (s == "heuristic") return PatternType::Heuristic;
    return PatternType::String;  // default
}

// Convert HeuristicType to string
constexpr std::string_view heuristicTypeToString(HeuristicType h) {
    switch (h) {
        case HeuristicType::MultipleBase64Concat:    return "multiple_base64_concat";
        case HeuristicType::StrReplaceFunctionBuild: return "str_replace_function_build";
        case HeuristicType::VariableFunctionCall:    return "variable_function_call";
        case HeuristicType::HexEncodedFunctions:     return "hex_encoded_functions";
        case HeuristicType::GotoObfuscation:         return "goto_obfuscation";
        case HeuristicType::LongEncodedStrings:      return "long_encoded_strings";
        case HeuristicType::EvalWithVariable:        return "eval_with_variable";
        case HeuristicType::CreateFunctionEval:      return "create_function_eval";
        case HeuristicType::ArrayIndexStringBuild:   return "array_index_string_build";
        case HeuristicType::CredentialHarvester:     return "credential_harvester";
    }
    return "unknown";
}

// Parse HeuristicType from string
inline HeuristicType heuristicTypeFromString(std::string_view s) {
    if (s == "multiple_base64_concat")    return HeuristicType::MultipleBase64Concat;
    if (s == "str_replace_function_build") return HeuristicType::StrReplaceFunctionBuild;
    if (s == "variable_function_call")    return HeuristicType::VariableFunctionCall;
    if (s == "hex_encoded_functions")     return HeuristicType::HexEncodedFunctions;
    if (s == "goto_obfuscation")          return HeuristicType::GotoObfuscation;
    if (s == "long_encoded_strings")      return HeuristicType::LongEncodedStrings;
    if (s == "eval_with_variable")        return HeuristicType::EvalWithVariable;
    if (s == "create_function_eval")      return HeuristicType::CreateFunctionEval;
    if (s == "array_index_string_build")  return HeuristicType::ArrayIndexStringBuild;
    if (s == "credential_harvester")      return HeuristicType::CredentialHarvester;
    return HeuristicType::EvalWithVariable;  // default
}

// Convert ReportFormat to string
constexpr std::string_view reportFormatToString(ReportFormat f) {
    switch (f) {
        case ReportFormat::Text: return "text";
        case ReportFormat::Json: return "json";
        case ReportFormat::Csv:  return "csv";
    }
    return "text";
}

// Parse ReportFormat from string
inline ReportFormat reportFormatFromString(std::string_view s) {
    if (s == "json") return ReportFormat::Json;
    if (s == "csv")  return ReportFormat::Csv;
    return ReportFormat::Text;  // default
}

// Parse file size strings like "5MB", "1GB", "500KB"
inline uint64_t parseFileSize(std::string_view s) {
    if (s.empty()) return 0;

    uint64_t value = 0;
    size_t i = 0;

    // Parse numeric part
    while (i < s.size() && (s[i] >= '0' && s[i] <= '9')) {
        value = value * 10 + (s[i] - '0');
        ++i;
    }

    // Skip whitespace
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) {
        ++i;
    }

    // Parse unit
    if (i < s.size()) {
        char unit = s[i];
        if (unit == 'k' || unit == 'K') {
            value *= 1024ULL;
        } else if (unit == 'm' || unit == 'M') {
            value *= 1024ULL * 1024ULL;
        } else if (unit == 'g' || unit == 'G') {
            value *= 1024ULL * 1024ULL * 1024ULL;
        }
    }

    return value;
}

}  // namespace lyxbosa
