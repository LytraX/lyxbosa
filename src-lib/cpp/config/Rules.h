#pragma once

#include <string>
#include <vector>
#include <optional>
#include "Types.h"

namespace lyxbosa {

// Pattern configuration from YAML
struct PatternConfig {
    PatternType type = PatternType::String;
    std::string value;
    std::string flags;  // e.g., "i" for case-insensitive

    // Entropy-specific settings
    std::string scope;        // "line", "window", or "file"
    size_t windowSize = 256;
    size_t minLength = 500;
    double minEntropy = 4.5;

    // Hash-specific settings
    std::string algorithm;    // "sha256", "md5"

    // Heuristic-specific settings
    HeuristicType heuristicType = HeuristicType::EvalWithVariable;
    size_t minOccurrences = 2;    // For patterns that require multiple hits
    size_t minStringLength = 100; // For long encoded strings detection
};

// Rule configuration from YAML
struct RuleConfig {
    std::string name;
    std::string description;
    Severity severity = Severity::Medium;
    std::string category;
    std::vector<PatternConfig> patterns;
};

// Scan settings from YAML
struct ScanConfig {
    std::vector<std::string> directories;
    bool recursive = true;
    uint64_t maxFileSize = 5 * 1024 * 1024;  // 5MB default
    bool followSymlinks = false;
    std::vector<std::string> include;
    std::vector<std::string> exclude;
};

// Quarantine action settings
struct QuarantineConfig {
    bool enabled = false;
    std::string directory;
    bool preserveStructure = true;
};

// Report action settings
struct ReportConfig {
    bool console = true;
    std::string file;
    ReportFormat format = ReportFormat::Text;
};

// Email alert settings
struct AlertConfig {
    bool enabled = false;
    std::string to;
    std::string from;
    std::string subject;
};

// Actions configuration from YAML
struct ActionsConfig {
    QuarantineConfig quarantine;
    ReportConfig report;
    AlertConfig alert;
};

// Built-in rules configuration
struct BuiltinRulesConfig {
    bool enabled = true;                        // Load built-in rules by default
    std::vector<std::string> use;               // Specific rules/categories to use (empty = all)
    std::vector<std::string> disable;           // Specific rules to disable
};

// Complete configuration
struct AppConfig {
    int version = 1;
    ScanConfig scan;
    std::vector<RuleConfig> rules;              // Custom YAML rules
    BuiltinRulesConfig builtinRules;            // Built-in CTRE rules config
    ActionsConfig actions;
};

}  // namespace lyxbosa
