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

// Archive scanning settings.
//
// Every guard is expressed in *decompressed* bytes or wall-clock time, never in
// archive size: 42.zip is 42 KB and expands to 4.5 PB, so a cap on the file
// protects nothing. The defaults sit far above anything real - the largest
// archive in the malware corpus expands to 16.9 MB against a 256 MB cap, and the
// worst real expansion ratio measured on a production site backup was 5.6x
// against a cap of 100.
struct ArchiveConfig {
    bool enabled = true;
    size_t maxDepth = 2;                          // 1 = top-level archives only
    uint64_t maxMemberSize = 0;                   // 0 = fall back to scan.max_file_size
    uint64_t maxExpansion = 256ULL * 1024 * 1024; // 0 = unlimited
    uint64_t maxRatio = 100;                      // 0 = unlimited
    uint64_t timeBudgetSeconds = 60;              // 0 = unlimited
    bool exhaustive = false;                      // scan every member, not just the code

    // The effective per-member cap, which is scan.max_file_size unless overridden.
    uint64_t memberSizeLimit(uint64_t scanMaxFileSize) const {
        return maxMemberSize > 0 ? maxMemberSize : scanMaxFileSize;
    }
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
    ArchiveConfig archives;                     // Archive (zip/tar/tar.gz) handling
    std::vector<RuleConfig> rules;              // Custom YAML rules
    BuiltinRulesConfig builtinRules;            // Built-in CTRE rules config
    ActionsConfig actions;
};

}  // namespace lyxbosa
