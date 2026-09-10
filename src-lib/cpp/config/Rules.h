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
    // Per-file read cap. See README for the measurement behind 25 MB.
    //
    // 5 MB left 36 code and text files unscanned on one production host, including a
    // 20.7 MB database dump, a 21.5 MB content import and 20.6 MB of page-cache HTML.
    // 25 MB recovers 29 of the 36; the seven it still leaves are logs, and going higher
    // buys 444 MB of log text and nothing else.
    //
    // Measured: +4.3% scan time and *zero* new findings on that host - 230 files stopped
    // being skipped and were read, and none of them matched. This is a coverage change,
    // not a detection one. It is here because "not scanned" must not read as "clean".
    //
    // A cap is kept rather than removed because readFile allocates the whole file: with
    // no cap a 680 MB backup is read into memory, and the tail past 25 MB is media and
    // containers. Containers are unaffected either way - Scanner::scan sniffs an oversize
    // file's head and hands it to ArchiveScanner regardless of this value.
    uint64_t maxFileSize = 25 * 1024 * 1024;
    bool followSymlinks = false;
    std::vector<std::string> include;
    std::vector<std::string> exclude;

    // Emit a per-file record for every file the include/exclude globs rejected.
    //
    // Off by default, and the default matters: globs are how people cut
    // node_modules out of a scan, so on a real tree this can be hundreds of
    // thousands of records - larger than the findings by orders of magnitude.
    // The *count* is always reported either way, so an operator can still tell
    // whether an exclude pattern is doing what they think; this switch is for
    // when they need to know exactly which files it took.
    bool reportExcluded = false;
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
    // Pinned rather than 0 (= track scan.max_file_size) so that raising the loose-file
    // cap to 25 MB does not silently raise the per-member cap with it. A member is
    // inflated into memory and shares the 256 MB expansion budget with every other
    // member of the same archive, so it wants a tighter bound than a loose file - and
    // 5 MB is what this was, via the fallback, before the file cap moved. The largest
    // webshell in the malware corpus is 843 KB.
    uint64_t maxMemberSize = 5 * 1024 * 1024;     // 0 = fall back to scan.max_file_size
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

// THE DEFAULT FOR updates.check, AND THE ONLY PLACE IT IS WRITTEN.
//
// It is one line because it is the operator's call and the argument runs both ways.
// `periodic` nudges the majority who will otherwise run a year-old scanner, and a
// stale security tool is a real harm: v2.1.0 is missing ten rules, one of which
// closes 46 known misses. `off` is the most private, and this tool runs on hosts
// where an outbound connection is itself information about an investigation.
//
// What makes `periodic` defensible rather than merely convenient is the narrowing in
// docs/tasks/UPDATE_PLAN.md 5, which this round implements: never from `check`,
// never under --quiet/--silent/--force, never without a terminal, never in CI, never
// on a development build, and at most once a day otherwise. Without that narrowing
// `off` would be the only honest default.
//
// Config::generateDefault() prints this value rather than repeating it, so flipping
// it here changes the compiled-in default, the generated YAML and the README table
// together. Nothing else names a default.
inline constexpr UpdateCheckMode kDefaultUpdateCheck = UpdateCheckMode::Periodic;

// How often a periodic check may run, when the configuration does not say.
// A day rather than an hour: a rule set does not change hourly, and the point is to
// catch a user months behind rather than minutes.
inline constexpr uint64_t kDefaultUpdateInterval = 24 * 60 * 60;

// Update-check settings. A version check reveals an IP, a version and a timestamp to
// whoever serves it; that is documented in README.md beside the setting.
struct UpdatesConfig {
    UpdateCheckMode check = kDefaultUpdateCheck;
    uint64_t intervalSeconds = kDefaultUpdateInterval;

    // What the file said, kept only so Config::validate can quote it back. Both
    // settings refuse rather than defaulting: a value that does not parse must not
    // silently become whatever the compiled-in default happens to be, because for
    // these two that decides whether the binary reaches the network and how often.
    bool checkValid = true;
    std::string checkRaw;
    std::string intervalRaw;
};

// In-file annotations: `// nolint`, `phpcs:ignore`, `// eslint-disable` and the other
// markers MatchEngine::annotationMarkers() lists, on a matched line or the line before it.
//
// THE DEFAULT IS THE DECISION, AND IT IS OFF.
//
// An annotation is an instruction found inside the file being judged, and whether to obey
// it turns on one thing the bytes cannot say: who wrote them. A developer scanning their
// own repository wrote the marker beside a line they know is a false positive, and
// honouring it is the feature. An incident responder scanning a web root an attacker has
// written to is reading the attacker's file, and the marker is one more line the attacker
// wrote: `$x = "FilesMan"; // nolint` reported a Critical webshell signature as Low, which
// is the severity a quarantine threshold, an alerting rule or a report filter reads. Same
// bytes, opposite meanings, and nothing in the file distinguishes them. Only the operator
// knows which deployment this is, so only the operator's configuration can say - and this
// tool is named for the second deployment, so the compiled-in default serves it.
//
// Measured before the default was chosen: over the 197,553 files of the stock CMS trees
// the scanner reports 148 matches and not one has a marker on its line or the line
// before, in trees where more than 15,000 files carry `phpcs:ignore` or `phpcs:disable`
// somewhere; over the 182 shipped malicious samples, 175 matches and none. `false` holds
// back nothing and closes the repro.
struct AnnotationsConfig {
    bool trust = false;
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
    AnnotationsConfig annotations;              // Whether a file may mark its own findings
    ActionsConfig actions;
    UpdatesConfig updates;                      // Whether and how often to look for a newer release
};

}  // namespace lyxbosa
