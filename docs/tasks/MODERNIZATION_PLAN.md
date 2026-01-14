# LyxBoSa Modernization Plan

## Overview

LyxBoSa is a modern C++20 malware/bot signature scanner, evolved from the original **wizbosa** project (2012-2016). It scans directories for files matching patterns and detects malicious content using various pattern matching techniques.

---

## Original Project Analysis (wizbosa)

### Features
- Directory traversal with file filtering
- Plain string keyword matching
- Quarantine infected files
- Email alerts with scan reports
- libconfig-based configuration

### Limitations
1. **String matching only** - no regex support
2. **Single-threaded** - slow on large directories
3. **No YARA-like rules** - just plain keyword lists
4. **libconfig format** - verbose, less human-friendly than YAML
5. **No severity levels** - all matches treated equally
6. **No entropy analysis** - can't detect obfuscated/encoded content
7. **No file hash checks** - can't match known malware by hash
8. **Manual CLI parsing** - no modern argument handling

---

## Modern LyxBoSa Architecture

### Configuration Format (YAML)

YAML is used for configuration. Note that regex patterns don't need escaping in YAML - backslashes are literal in unquoted or single-quoted strings.

```yaml
# lyxbosa.yaml
version: 1

scan:
  directories:
    - /var/www
    - /home/user/public_html
  recursive: true
  max_file_size: 5MB
  follow_symlinks: false

  # File filters (include/exclude)
  include:
    - "*.php"
    - "*.js"
    - "*.html"
  exclude:
    - node_modules/**
    - vendor/**
    - "*.min.js"

# Pattern rules with categories and severity
rules:
  - name: PHP eval base64
    description: Obfuscated PHP code execution
    severity: critical
    category: webshell
    patterns:
      - type: string
        value: eval(base64_decode(
      - type: regex
        value: eval\s*\(\s*base64_decode\s*\(
        flags: i  # case insensitive

  - name: C99 Shell
    description: Known C99 webshell signatures
    severity: critical
    category: webshell
    patterns:
      - type: string
        value: c99shell
      - type: string
        value: c99shexit

  - name: Suspicious high entropy
    description: High entropy content (possible obfuscation)
    severity: medium
    category: obfuscation
    patterns:
      - type: entropy
        scope: line          # 'line', 'window', or 'file'
        window_size: 256     # bytes (only used when scope: window)
        min_length: 500      # minimum content length to analyze
        min_entropy: 4.5     # Shannon entropy threshold (0-8 for bytes)

  - name: Known malware hash
    severity: critical
    category: known_malware
    patterns:
      - type: hash
        algorithm: sha256
        value: abc123...

actions:
  quarantine:
    enabled: true
    directory: /var/quarantine
    preserve_structure: true

  report:
    console: true
    file: /var/log/lyxbosa/scan.log
    format: json  # or text, csv

  alert:
    enabled: true
    email:
      to: admin@example.com
      from: lyxbosa@server.com
      subject: LyxBoSa Scan Report
```

### Pattern Types

| Type | Description | Example |
|------|-------------|---------|
| `string` | Exact substring match (fast) | `eval(base64_decode(` |
| `regex` | Regular expression | `eval\s*\(.*\)` |
| `hex` | Hex byte sequence | `4D5A90` (MZ header) |
| `entropy` | High entropy detection | Detects obfuscated code |
| `hash` | File hash match | SHA256/MD5 of known malware |
| `yara` | YARA rule file (optional) | External .yar files |

### Severity Levels

| Level | Description |
|-------|-------------|
| `critical` | Known malware, webshells, immediate threat |
| `high` | Suspicious code patterns, likely malicious |
| `medium` | Potentially unwanted, obfuscation detected |
| `low` | Informational, worth reviewing |

---

## Project Structure

```
LyxBoSa/
├── CMakeLists.txt
├── CMakePresets.json
├── vcpkg.json
├── docs/
│   └── tasks/
│       └── MODERNIZATION_PLAN.md
├── src-cli/
│   └── lyxbosa.cpp              # CLI entry point
├── src-lib/cpp/
│   ├── core/
│   │   ├── Scanner.h/cpp        # Main scanner orchestrator
│   │   ├── FileWalker.h/cpp     # Directory traversal
│   │   └── MatchEngine.h/cpp    # Pattern matching engine
│   ├── patterns/
│   │   ├── Pattern.h            # Base pattern interface
│   │   ├── StringPattern.h/cpp  # Exact string match
│   │   ├── RegexPattern.h/cpp   # Regex match (std::regex or CTRE)
│   │   ├── EntropyPattern.h/cpp # Entropy analysis
│   │   └── HashPattern.h/cpp    # File hash match
│   ├── config/
│   │   ├── Config.h/cpp         # YAML config loading
│   │   └── Rules.h/cpp          # Rule definitions
│   ├── actions/
│   │   ├── Quarantine.h/cpp     # Move infected files
│   │   ├── Reporter.h/cpp       # Generate reports
│   │   └── Alerter.h/cpp        # Send notifications
│   ├── infrastructure/
│   │   └── Console.h/cpp        # Console output
│   ├── system/
│   │   └── CliArgs.h            # CLI argument definitions
│   └── utils/
│       ├── PathUtils.h          # Path utilities
│       └── StringUtils.h        # String utilities
└── tests/
    └── ...                      # Unit tests
```

---

## CLI Interface

```bash
# Basic scan
lyxbosa scan /var/www

# With config file
lyxbosa scan -c /etc/lyxbosa/rules.yaml /var/www

# Quick scan (skip large files, no quarantine)
lyxbosa scan --quick /var/www

# Dry run (no actions, just report)
lyxbosa scan --dry-run /var/www

# Output formats
lyxbosa scan -o json /var/www > results.json
lyxbosa scan -o csv /var/www > results.csv

# Check specific file
lyxbosa check /var/www/suspicious.php

# Validate config
lyxbosa validate-config /etc/lyxbosa/rules.yaml

# Generate default config
lyxbosa init-config > lyxbosa.yaml
```

---

## Dependencies

Current `vcpkg.json`:
```json
{
  "dependencies": [
    "argparse",      // CLI argument parsing
    "yaml-cpp",      // YAML config parsing
    "fmt",           // Modern formatting
    "reflectcpp",    // Struct serialization (brings CTRE as transitive dep)
    "re2",           // Google RE2 regex library
    "xxhash"         // Fast hashing for caching/dedup
  ]
}
```

### Regex Strategy: CTRE + RE2

We use **two regex libraries** for different purposes:

| Library | Use Case | Patterns | Performance |
|---------|----------|----------|-------------|
| **CTRE** | Built-in hardcoded signatures | Compile-time | Extremely fast (zero runtime overhead) |
| **RE2** | User-defined patterns from YAML config | Runtime | Fast with safety guarantees |

#### Why CTRE for built-in signatures?
- **Zero runtime cost**: Patterns are compiled into machine code at compile time
- **Type-safe**: Compile errors for invalid regex syntax
- **Optimized**: Can be 10-100x faster than runtime regex engines
- Already available as transitive dependency of reflectcpp

#### Why RE2 for dynamic patterns?
- **Safe**: Guarantees linear time matching (no catastrophic backtracking)
- **Fast**: Optimized for high-performance pattern matching
- **Battle-tested**: Used extensively at Google for log scanning, security tools
- **Runtime patterns**: Supports patterns loaded at runtime from config files

### Hashing Strategy: xxHash + SHA-256

We use **two hash algorithms** for different purposes:

| Hash | Purpose | Speed | Use Case |
|------|---------|-------|----------|
| **xxHash (xxh3)** | Internal caching, dedup | 20-40 GB/s | "Already scanned this file?" |
| **SHA-256** | Malware identification | ~500 MB/s | Known malware hash matching |

#### Scan Flow with Hash Optimization
```
1. xxHash → Check cache "have we seen this file before?"
   ↓ (cache miss)
2. String/Regex patterns → Fast content scan
   ↓ (if hash rules exist AND not already flagged critical)
3. SHA-256 → Match against known malware hashes
```

#### Why xxHash for caching?
- **Extremely fast**: 20-40 GB/s throughput
- **Good distribution**: Excellent for hash tables
- **Not for security**: Never use for malware identification

#### Why SHA-256 for malware hashes?
- **Collision-resistant**: Cryptographically secure
- **Interoperable**: Standard format for threat intelligence feeds
- **Forensically sound**: Accepted in security contexts

**Rule**: xxHash improves performance. SHA-256 preserves correctness. They solve different problems.

---

## Implementation Phases

### Phase 1: Foundation
- [ ] Project structure setup (directories, headers)
- [ ] YAML config loading with yaml-cpp
- [ ] CLI argument parsing with argparse (subcommands: scan, check, init-config)
- [ ] Basic directory traversal with std::filesystem
- [ ] String pattern matching
- [ ] Basic console output with match results

### Phase 2: Pattern Engine
- [ ] Pattern base class and interface
- [ ] StringPattern implementation
- [ ] RegexPattern implementation (using Google RE2)
- [ ] Rule severity levels and categories
- [ ] Match context (line number, column, surrounding text)

### Phase 3: Advanced Patterns
- [ ] EntropyPattern - Shannon entropy calculation
- [ ] HashPattern - File hash matching (SHA256, MD5)
- [ ] HexPattern - Hex byte sequence matching

### Phase 4: Actions
- [ ] Quarantine with directory structure preservation
- [ ] Reporter - JSON/CSV/text report generation
- [ ] Alerter - Email notifications (optional, may defer)

### Phase 5: Performance
- [ ] Multi-threaded scanning (thread pool)
- [ ] Memory-mapped file reading for large files
- [ ] Progress reporting (files scanned, matches found)
- [ ] Benchmarking against original wizbosa
- [ ] xxHash-based scan caching (skip unchanged files)

### Phase 6: Optional Enhancements
- [ ] YARA rule integration (libyara)
- [ ] Watch mode (inotify on Linux, FSEvents on macOS)
- [ ] Interactive mode (review matches, decide actions)
- [ ] Web UI for viewing results

---

## Core Component Designs

### Scanner (orchestrator)
```cpp
class Scanner {
public:
    Scanner(const Config& config);

    void scan();
    void scanFile(const std::filesystem::path& file);

    const ScanResult& getResults() const;

private:
    Config config_;
    MatchEngine engine_;
    ScanResult results_;
};
```

### MatchEngine (pattern matching)
```cpp
class MatchEngine {
public:
    void addRule(std::unique_ptr<Rule> rule);
    void loadRules(const std::vector<RuleConfig>& rules);

    std::vector<Match> match(std::string_view content, const FileInfo& info);

private:
    std::vector<std::unique_ptr<Rule>> rules_;
};
```

### Pattern (polymorphic interface)
```cpp
class Pattern {
public:
    virtual ~Pattern() = default;

    // Returns ALL matches in content (not just first)
    virtual std::vector<Match> match(std::string_view content) const = 0;
    virtual std::string_view type() const = 0;
};

class StringPattern : public Pattern {
public:
    explicit StringPattern(std::string_view needle);

    std::vector<Match> match(std::string_view content) const override;
    std::string_view type() const override { return "string"; }

private:
    std::string needle_;
};

class RegexPattern : public Pattern {
public:
    explicit RegexPattern(std::string_view pattern, bool case_insensitive = false);

    std::vector<Match> match(std::string_view content) const override;
    std::string_view type() const override { return "regex"; }

private:
    std::unique_ptr<RE2> regex_;
};
```

**Design Note**: Patterns return `std::vector<Match>` to support multiple matches per file (e.g., a regex could match dozens of times). For memory-constrained scenarios, a callback-based API could be added later:
```cpp
void match(std::string_view content, std::function<void(Match)> sink) const;
```

### Rule (groups patterns)
```cpp
enum class Severity { Low, Medium, High, Critical };

struct Rule {
    std::string name;
    std::string description;
    Severity severity;
    std::string category;
    std::vector<std::unique_ptr<Pattern>> patterns;

    std::vector<Match> match(std::string_view content) const;
};
```

### Match (result)
```cpp
struct Match {
    std::string ruleName;
    Severity severity;
    std::string category;
    std::string patternType;
    size_t offset;          // byte offset in file
    size_t line;            // line number (1-based)
    size_t column;          // column number (1-based)
    std::string context;    // surrounding text snippet
    std::string matchedText;
};
```

### ScanResult (aggregated results)
```cpp
struct FileResult {
    std::filesystem::path path;
    std::vector<Match> matches;
    bool quarantined = false;
};

struct ScanResult {
    std::vector<FileResult> files;
    size_t totalFilesScanned = 0;
    size_t totalDirectoriesScanned = 0;
    size_t filesWithMatches = 0;
    size_t filesQuarantined = 0;
    size_t filesSkippedSize = 0;
    std::chrono::milliseconds duration;
};
```

---

## Threading Model & Constraints

To enable safe multi-threaded scanning in Phase 5, the following constraints must be enforced from Phase 1:

### Immutability Requirements
1. **Patterns are immutable after construction** - No mutable state in pattern classes
2. **Rules are immutable after loading** - Rule vectors are built once, then read-only
3. **Config is immutable during scan** - Load config, then freeze

### Thread-Safe Design
```cpp
// Pattern::match() must be const and thread-safe
std::vector<Match> match(std::string_view content) const;  // ✓ Safe

// Never store per-file state in patterns
class BadPattern {
    mutable int lastMatchCount_;  // ✗ Not thread-safe
};
```

### Threading Architecture (Phase 5)
```
┌─────────────────────────────────────────────────┐
│                 Main Thread                      │
│  - Load config (immutable after load)           │
│  - Build rule engine (immutable after build)    │
│  - Spawn worker threads                         │
│  - Aggregate results                            │
└─────────────────────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
┌──────────────┐┌──────────────┐┌──────────────┐
│  Worker 1    ││  Worker 2    ││  Worker N    │
│  - Get file  ││  - Get file  ││  - Get file  │
│  - Read      ││  - Read      ││  - Read      │
│  - Match     ││  - Match     ││  - Match     │
│  - Report    ││  - Report    ││  - Report    │
└──────────────┘└──────────────┘└──────────────┘
```

### File Queue
- Thread-safe queue distributes files to workers
- Each worker processes files independently
- Results collected in thread-safe aggregator

---

## Notes

### YAML Regex Escaping
In YAML, backslashes are **literal** in unquoted and single-quoted strings:
```yaml
# These are equivalent - no escaping needed
pattern: eval\s*\(
pattern: 'eval\s*\('

# Double quotes require escaping (like JSON)
pattern: "eval\\s*\\("
```

Recommendation: Use unquoted or single-quoted strings for regex patterns.

### CTRE Usage (Built-in Signatures)
CTRE is used for hardcoded, compile-time regex patterns:

```cpp
#include <ctre.hpp>

// Compile-time pattern - zero runtime overhead
static constexpr auto eval_base64 = ctll::fixed_string{R"(eval\s*\(\s*base64_decode)"};

// Match check
if (ctre::search<eval_base64>(content)) {
    // Found match
}

// Get match with position
if (auto match = ctre::search<eval_base64>(content)) {
    auto matched_text = match.to_view();
    auto start_pos = match.data() - content.data();
}

// Multiple patterns in one pass
static constexpr auto webshell_patterns = ctll::fixed_string{
    R"(c99shell|FilesMan|Web Shell by)"
};
```

### Google RE2 Usage (Dynamic Patterns)
RE2 is used for user-defined patterns loaded from YAML config:

```cpp
#include <re2/re2.h>

// Create pattern from config (compiled once, reused many times)
RE2 pattern("eval\\s*\\(");  // Note: C++ string escaping

// Case-insensitive
RE2::Options options;
options.set_case_sensitive(false);
RE2 pattern_ci("eval\\s*\\(", options);

// Match
if (RE2::PartialMatch(content, pattern)) {
    // Found match
}

// Find with position
re2::StringPiece input(content);
re2::StringPiece match;
if (RE2::FindAndConsume(&input, pattern, &match)) {
    // match contains the matched text
}
```

Note: RE2 uses backslash escaping in C++ strings, but in YAML config files, backslashes are literal.

---

## Migration from wizbosa

### Config Conversion
Old libconfig format:
```
wizbosa = {
    keywords = ["eval(base64_decode(", "c99shell"];
    search_directory = "/var/www";
    recurse_subdirectories = true;
};
```

New YAML format:
```yaml
scan:
  directories:
    - /var/www
  recursive: true

rules:
  - name: Legacy keywords
    severity: high
    category: malware
    patterns:
      - type: string
        value: eval(base64_decode(
      - type: string
        value: c99shell
```

A conversion utility could be provided: `lyxbosa convert-config wizbosa.cfg > lyxbosa.yaml`
