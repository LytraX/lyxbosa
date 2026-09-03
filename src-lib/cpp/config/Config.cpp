#include "Config.h"
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <sstream>
#include <fmt/format.h>

namespace lyxbosa {

namespace {

PatternConfig parsePatternConfig(const YAML::Node& node) {
    PatternConfig pc;

    if (node["type"]) {
        pc.type = patternTypeFromString(node["type"].as<std::string>());
    }
    if (node["value"]) {
        pc.value = node["value"].as<std::string>();
    }
    if (node["flags"]) {
        pc.flags = node["flags"].as<std::string>();
    }

    // Entropy-specific
    if (node["scope"]) {
        pc.scope = node["scope"].as<std::string>();
    }
    if (node["window_size"]) {
        pc.windowSize = node["window_size"].as<size_t>();
    }
    if (node["min_length"]) {
        pc.minLength = node["min_length"].as<size_t>();
    }
    if (node["min_entropy"]) {
        pc.minEntropy = node["min_entropy"].as<double>();
    }

    // Hash-specific
    if (node["algorithm"]) {
        pc.algorithm = node["algorithm"].as<std::string>();
    }

    // Heuristic-specific
    if (node["heuristic_type"]) {
        pc.heuristicType = heuristicTypeFromString(node["heuristic_type"].as<std::string>());
    }
    if (node["min_occurrences"]) {
        pc.minOccurrences = node["min_occurrences"].as<size_t>();
    }
    if (node["min_string_length"]) {
        pc.minStringLength = node["min_string_length"].as<size_t>();
    }

    return pc;
}

RuleConfig parseRuleConfig(const YAML::Node& node) {
    RuleConfig rc;

    if (node["name"]) {
        rc.name = node["name"].as<std::string>();
    }
    if (node["description"]) {
        rc.description = node["description"].as<std::string>();
    }
    if (node["severity"]) {
        rc.severity = severityFromString(node["severity"].as<std::string>());
    }
    if (node["category"]) {
        rc.category = node["category"].as<std::string>();
    }

    if (node["patterns"] && node["patterns"].IsSequence()) {
        for (const auto& pn : node["patterns"]) {
            rc.patterns.push_back(parsePatternConfig(pn));
        }
    }

    return rc;
}

ScanConfig parseScanConfig(const YAML::Node& node) {
    ScanConfig sc;

    if (node["directories"] && node["directories"].IsSequence()) {
        for (const auto& dir : node["directories"]) {
            sc.directories.push_back(dir.as<std::string>());
        }
    }

    if (node["recursive"]) {
        sc.recursive = node["recursive"].as<bool>();
    }

    if (node["max_file_size"]) {
        auto sizeStr = node["max_file_size"].as<std::string>();
        sc.maxFileSize = parseFileSize(sizeStr);
    }

    if (node["follow_symlinks"]) {
        sc.followSymlinks = node["follow_symlinks"].as<bool>();
    }

    if (node["report_excluded"]) {
        sc.reportExcluded = node["report_excluded"].as<bool>();
    }

    if (node["include"] && node["include"].IsSequence()) {
        for (const auto& inc : node["include"]) {
            sc.include.push_back(inc.as<std::string>());
        }
    }

    if (node["exclude"] && node["exclude"].IsSequence()) {
        for (const auto& exc : node["exclude"]) {
            sc.exclude.push_back(exc.as<std::string>());
        }
    }

    return sc;
}

ArchiveConfig parseArchivesConfig(const YAML::Node& node) {
    ArchiveConfig ac;

    if (node["enabled"]) {
        ac.enabled = node["enabled"].as<bool>();
    }
    if (node["max_depth"]) {
        ac.maxDepth = node["max_depth"].as<size_t>();
    }
    if (node["max_member_size"]) {
        ac.maxMemberSize = parseFileSize(node["max_member_size"].as<std::string>());
    }
    if (node["max_expansion"]) {
        ac.maxExpansion = parseFileSize(node["max_expansion"].as<std::string>());
    }
    if (node["max_ratio"]) {
        ac.maxRatio = node["max_ratio"].as<uint64_t>();
    }
    if (node["time_budget"]) {
        ac.timeBudgetSeconds = parseDurationSeconds(node["time_budget"].as<std::string>());
    }
    if (node["exhaustive"]) {
        ac.exhaustive = node["exhaustive"].as<bool>();
    }

    return ac;
}

ActionsConfig parseActionsConfig(const YAML::Node& node) {
    ActionsConfig ac;

    if (node["quarantine"]) {
        auto& qn = node["quarantine"];
        if (qn["enabled"]) {
            ac.quarantine.enabled = qn["enabled"].as<bool>();
        }
        if (qn["directory"]) {
            ac.quarantine.directory = qn["directory"].as<std::string>();
        }
        if (qn["preserve_structure"]) {
            ac.quarantine.preserveStructure = qn["preserve_structure"].as<bool>();
        }
    }

    if (node["report"]) {
        auto& rn = node["report"];
        if (rn["console"]) {
            ac.report.console = rn["console"].as<bool>();
        }
        if (rn["file"]) {
            ac.report.file = rn["file"].as<std::string>();
        }
        if (rn["format"]) {
            ac.report.format = reportFormatFromString(rn["format"].as<std::string>());
        }
    }

    if (node["alert"]) {
        auto& an = node["alert"];
        if (an["enabled"]) {
            ac.alert.enabled = an["enabled"].as<bool>();
        }
        if (an["email"]) {
            auto& em = an["email"];
            if (em["to"]) {
                ac.alert.to = em["to"].as<std::string>();
            }
            if (em["from"]) {
                ac.alert.from = em["from"].as<std::string>();
            }
            if (em["subject"]) {
                ac.alert.subject = em["subject"].as<std::string>();
            }
        }
    }

    return ac;
}

BuiltinRulesConfig parseBuiltinRulesConfig(const YAML::Node& node) {
    BuiltinRulesConfig bc;

    if (node["enabled"]) {
        bc.enabled = node["enabled"].as<bool>();
    }

    if (node["use"] && node["use"].IsSequence()) {
        for (const auto& item : node["use"]) {
            bc.use.push_back(item.as<std::string>());
        }
    }

    if (node["disable"] && node["disable"].IsSequence()) {
        for (const auto& item : node["disable"]) {
            bc.disable.push_back(item.as<std::string>());
        }
    }

    return bc;
}

}  // namespace

AppConfig Config::loadFromFile(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        throw ConfigError(fmt::format("Configuration file not found: {}", path.string()));
    }

    std::ifstream file(path);
    if (!file) {
        throw ConfigError(fmt::format("Cannot open configuration file: {}", path.string()));
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return loadFromString(buffer.str());
}

AppConfig Config::loadFromString(std::string_view yaml) {
    AppConfig config;

    try {
        YAML::Node root = YAML::Load(std::string(yaml));

        if (root["version"]) {
            config.version = root["version"].as<int>();
        }

        if (root["scan"]) {
            config.scan = parseScanConfig(root["scan"]);
        }

        if (root["archives"]) {
            config.archives = parseArchivesConfig(root["archives"]);
        }

        if (root["rules"] && root["rules"].IsSequence()) {
            for (const auto& rn : root["rules"]) {
                config.rules.push_back(parseRuleConfig(rn));
            }
        }

        if (root["actions"]) {
            config.actions = parseActionsConfig(root["actions"]);
        }

        if (root["builtin_rules"]) {
            config.builtinRules = parseBuiltinRulesConfig(root["builtin_rules"]);
        }

    } catch (const YAML::Exception& e) {
        throw ConfigError(fmt::format("YAML parse error: {}", e.what()));
    }

    // Validate the loaded config
    auto error = validate(config);
    if (!error.empty()) {
        throw ConfigError(error);
    }

    return config;
}

std::string Config::generateDefault() {
    return R"(# LyxBoSa Configuration
# https://github.com/Lyr-7D1h/LyxBoSa
version: 1

scan:
  directories:
    - /var/www
  recursive: true
  # Files larger than this are reported as skipped rather than read. Archives are
  # not governed by it: a container past this size still has its index read.
  max_file_size: 25MB
  follow_symlinks: false

  # List every file the filters below rejected, not just count them.
  #
  # The count is always reported. This adds a per-file record for each one, which
  # on a tree where a glob cuts node_modules is far larger than the findings - so
  # it is off unless you need to know exactly which files a pattern took.
  report_excluded: false

  # File filters
  #
  # Never trust an extension to tell you what a file is. Real incidents have put
  # executable PHP behind .jpeg, .tif, .ico, .php0, .zip and .txt, so this list is
  # deliberately wide: it decides what gets *opened*, not what gets *reported*.
  # Content still has to match a rule to become a finding.
  include:
    - "!ext"          # Files without extension - webshells often have none

    # PHP and PHP-adjacent
    - "*.php*"        # .php .php5 .php0 .phps .php.bak .php.suspected .php_expire
    - "*.pht"
    - "*.phtm"
    - "*.phtml"
    - "*.phar"        # PHP archive - directly executable
    - "*.inc"
    - "*.tpl"         # Smarty
    - "*.ctp"         # CakePHP
    - "*.module"      # Drupal carries PHP in these
    - "*.install"
    - "*.engine"
    - "*.theme"
    - "*.profile"

    # Other server-side languages
    - "*.pl"
    - "*.pm"
    - "*.cgi"
    - "*.py"
    - "*.rb"
    - "*.lua"
    - "*.sh"
    - "*.bash"
    - "*.ksh"
    - "*.zsh"
    - "*.jsp"
    - "*.jspx"
    - "*.asp"
    - "*.aspx"
    - "*.ashx"
    - "*.asmx"
    - "*.cfm"
    - "*.ps1"
    - "*.bat"
    - "*.c"
    - "*.cpp"
    - "*.h"

    # Client-side and markup
    - "*.js"
    - "*.mjs"
    - "*.cjs"
    - "*.jsx"
    - "*.ts"
    - "*.vue"
    - "*.html"
    - "*.htm"
    - "*.xhtml"
    - "*.shtml"       # server-side includes
    - "*.css"
    - "*.svg"

    # Images - polyglot carriers. This is not hypothetical: incident response has
    # recovered working webshells hidden in .jpeg, .tif and .ico.
    - "*.gif"
    - "*.png"
    - "*.jpg"
    - "*.jpe"
    - "*.jpeg"
    - "*.jfif"
    - "*.ico"
    - "*.bmp"
    - "*.webp"
    - "*.avif"
    - "*.tif"
    - "*.tiff"
    - "*.psd"
    - "*.tga"
    - "*.xbm"
    - "*.jpx"
    - "*.jp2"

    # Video and audio containers - same trick, larger haystack
    - "*.flv"
    - "*.mp4"
    - "*.m4v"
    - "*.avi"
    - "*.mpg"
    - "*.mpeg"
    - "*.mov"
    - "*.wmv"
    - "*.mkv"
    - "*.webm"
    - "*.3gp"
    - "*.ogv"
    - "*.mp3"
    - "*.wav"
    - "*.ogg"
    - "*.m4a"
    - "*.wma"
    - "*.flac"

    # Documents and fonts
    - "*.pdf"
    - "*.rtf"
    - "*.doc*"
    - "*.xls*"
    - "*.ppt*"
    - "*.ttf"
    - "*.otf"
    - "*.eot"
    - "*.woff"
    - "*.woff2"

    # Archives - payloads get staged inside these
    - "*.zip"
    - "*.tar"
    - "*.gz"
    - "*.tgz"
    - "*.bz2"
    - "*.xz"
    - "*.7z"
    - "*.rar"

    # Data, config, backups and leftovers
    - "*.txt"
    - "*.log"
    - "*.dat"
    - "*.bin"
    - "*.json"
    - "*.xml"
    - "*.yml"
    - "*.yaml"
    - "*.ini"
    - "*.conf"
    - "*.cfg"
    - "*.env"
    - "*.sql"
    - "*.bak"
    - "*.old"
    - "*.orig"
    - "*.save"
    - "*.swp"
    - "*.tmp"
    - "*.suspected"   # Imunify360 renames quarantined PHP to this
    - "*.disabled"
    - "*~"
    - ".htaccess"
    - ".htpasswd"
    - ".user.ini"
    - "web.config"
  # Exclusions.
  #
  # CAREFUL: `node_modules/**` and `vendor/**` match nothing, and that is currently
  # load-bearing. matchesFilters compares a pattern against the *filename* first and
  # against the full path only when the pattern contains `**`, using fnmatch with
  # FNM_PATHNAME - under which `*` does not cross a `/`. So `vendor/**` can only match
  # a path that *begins* with `vendor/`, and every path here is absolute. Verified
  # directly against fnmatch(3). Only filename patterns like `*.min.js` do anything.
  #
  # Do not "fix" this without deciding what should happen next. Making these live would
  # silently stop scanning `vendor/` and `node_modules/`, and on the production host this
  # was measured against, a large share of the real malware sits under vendored paths -
  # webshells dropped in `vendor/psr/log/Psr/Log/index.php` and the like. The broken
  # glob is protecting coverage by accident.
  #
  # The `excluded` count in the skip tally is dominated by the *include* allow-list
  # rejecting file types, not by these patterns, so it will not tell you they are dead.
  exclude:
    - node_modules/**
    - vendor/**
    - "*.min.js"

# Archives
#
# A .zip or .tar.gz is not opaque bytes: it is a directory that happens to be one
# file. Two different things are found by opening one - malware staged inside a
# payload archive, and a forgotten site backup that hands its own database
# password to anyone who guesses the URL.
#
# Every guard below is expressed in decompressed bytes or wall-clock time, never
# in the size of the archive: 42.zip is 42 KB and expands to 4.5 PB, so a cap on
# the file protects nothing at all.
archives:
  enabled: true
  max_depth: 2            # 1 = top-level archives only; an archive inside an
                          # archive needs 2
  max_member_size: 5MB    # 0 = fall back to scan.max_file_size
  max_expansion: 256MB    # total decompressed bytes per archive; 0 = unlimited
  max_ratio: 100          # decompressed / compressed; 0 = unlimited
  time_budget: 60s        # per archive; 0 = unlimited
  exhaustive: false       # true scans every member, not only the code. Scripts,
                          # then markup, then everything else - on a real site the
                          # first two are 54% of the files and 5.6% of the bytes.

# Built-in detection rules (CTRE compile-time regex - extremely fast)
# Categories: WS (Webshell), BD (Backdoor), OBF (Obfuscation), PHI (Phishing),
#             EXP (Exploit), DRP (Dropper), RCE (CodeExec), CRED (CredTheft),
#             SEO (SeoSpam), DEFC (Defacement), PL (Perl), ARC (Archive)
builtin_rules:
  enabled: true
  # use: []                    # Empty = load all rules (default)
  # use:                       # Or specify specific rules/categories:
  #   - category:WS            # Load all Webshell rules
  #   - category:RCE           # Load all CodeExec rules
  #   - WS001                   # Load specific rule by code
  #   - BD005                   # Load another specific rule
  # disable:                   # Disable specific rules (applied after use):
  #   - OBF003                  # Disable rule OBF003
  #   - SEO002                  # Disable rule SEO002

# Custom rules (optional - in addition to built-in rules)
# Add your own patterns here. These are checked AFTER built-in rules.
# rules:
#   - name: My Custom Pattern
#     description: Description of what this detects
#     severity: critical    # critical, high, medium, low
#     category: webshell    # any category name
#     patterns:
#       - type: string      # string, regex, entropy, hash, heuristic
#         value: "pattern to match"
#       - type: regex
#         value: "regex\\s+pattern"
#         flags: i          # i = case insensitive

# Actions
actions:
  quarantine:
    enabled: false
    directory: /var/quarantine
    preserve_structure: true

  report:
    console: true
    format: text

  alert:
    enabled: false
)";
}

std::string Config::validate(const AppConfig& config) {
    // Check for at least one rule (either built-in or custom)
    if (config.rules.empty() && !config.builtinRules.enabled) {
        return "Configuration must have at least one rule (enable builtin_rules or define custom rules)";
    }

    // Check each custom rule has at least one pattern
    for (const auto& rule : config.rules) {
        if (rule.name.empty()) {
            return "Each rule must have a name";
        }
        if (rule.patterns.empty()) {
            return fmt::format("Rule '{}' must have at least one pattern", rule.name);
        }
        for (const auto& pattern : rule.patterns) {
            // Heuristic and Entropy patterns don't require a value
            if (pattern.value.empty() &&
                pattern.type != PatternType::Entropy &&
                pattern.type != PatternType::Heuristic) {
                return fmt::format("Pattern in rule '{}' must have a value", rule.name);
            }
        }
    }

    // Check quarantine directory if enabled
    if (config.actions.quarantine.enabled && config.actions.quarantine.directory.empty()) {
        return "Quarantine is enabled but no directory specified";
    }

    return "";  // Valid
}

std::vector<std::string> Config::warnings(const AppConfig& config) {
    std::vector<std::string> out;

    if (!config.archives.enabled) {
        return out;
    }

    // "0 = unlimited" is accepted, because an operator scanning a known-good
    // archive should be able to turn a guard off. It is warned about because
    // unlimited plus a crafted bomb is a hang rather than a finding, and a hang
    // during an incident looks exactly like a scanner that found nothing.
    if (config.archives.maxExpansion == 0) {
        out.push_back("archives.max_expansion is 0 (unlimited): a decompression bomb "
                      "will be inflated until it runs out of disk or patience");
    }
    if (config.archives.maxRatio == 0) {
        out.push_back("archives.max_ratio is 0 (unlimited): the compression-ratio guard "
                      "is off, so a bomb is only bounded by the expansion and time budgets");
    }
    if (config.archives.timeBudgetSeconds == 0) {
        out.push_back("archives.time_budget is 0 (unlimited): a single archive can hold "
                      "the scan for as long as it takes to read");
    }
    if (config.archives.maxExpansion == 0 && config.archives.timeBudgetSeconds == 0) {
        out.push_back("with both the expansion and time budgets unlimited, nothing bounds "
                      "an archive at all");
    }
    if (config.archives.maxDepth > 4) {
        out.push_back(fmt::format("archives.max_depth is {}: no observed sample nests "
                                  "archives at all, and every level multiplies the work",
                                  config.archives.maxDepth));
    }

    return out;
}

void Config::printSummary(const AppConfig& config) {
    fmt::print(stderr, "\n=== LyxBoSa Configuration ===\n\n");

    // Directories
    fmt::print(stderr, "Scan directories ({}):\n", config.scan.directories.size());
    for (const auto& dir : config.scan.directories) {
        fmt::print(stderr, "  - {}\n", dir);
    }

    fmt::print(stderr, "\nOptions:\n");
    fmt::print(stderr, "  Recursive: {}\n", config.scan.recursive ? "yes" : "no");
    fmt::print(stderr, "  Max file size: {} bytes\n", config.scan.maxFileSize);
    fmt::print(stderr, "  Follow symlinks: {}\n", config.scan.followSymlinks ? "yes" : "no");

    // Filters
    if (!config.scan.include.empty()) {
        fmt::print(stderr, "\nInclude patterns ({}):\n", config.scan.include.size());
        for (const auto& pat : config.scan.include) {
            fmt::print(stderr, "  - {}\n", pat);
        }
    }

    if (!config.scan.exclude.empty()) {
        fmt::print(stderr, "\nExclude patterns ({}):\n", config.scan.exclude.size());
        for (const auto& pat : config.scan.exclude) {
            fmt::print(stderr, "  - {}\n", pat);
        }
    }

    // Archives
    fmt::print(stderr, "\nArchives: {}\n", config.archives.enabled ? "opened" : "not opened");
    if (config.archives.enabled) {
        fmt::print(stderr, "  Nesting depth: {}\n", config.archives.maxDepth);
        fmt::print(stderr, "  Per-member limit: {} bytes\n",
                   config.archives.memberSizeLimit(config.scan.maxFileSize));
        fmt::print(stderr, "  Expansion budget: {}\n",
                   config.archives.maxExpansion == 0
                       ? std::string("unlimited")
                       : fmt::format("{} bytes", config.archives.maxExpansion));
        fmt::print(stderr, "  Time budget: {}\n",
                   config.archives.timeBudgetSeconds == 0
                       ? std::string("unlimited")
                       : fmt::format("{}s", config.archives.timeBudgetSeconds));
        if (config.archives.exhaustive) {
            fmt::print(stderr, "  Exhaustive: every member, not only code\n");
        }
    }

    // Built-in rules info
    fmt::print(stderr, "\nBuilt-in rules: {}\n", config.builtinRules.enabled ? "enabled" : "disabled");
    if (config.builtinRules.enabled) {
        if (config.builtinRules.use.empty()) {
            fmt::print(stderr, "  Loading: all rules\n");
        } else {
            fmt::print(stderr, "  Loading: {} specified rules/categories\n", config.builtinRules.use.size());
        }
        if (!config.builtinRules.disable.empty()) {
            fmt::print(stderr, "  Disabled: {} rules\n", config.builtinRules.disable.size());
        }
    }

    // Custom rules summary
    if (!config.rules.empty()) {
        fmt::print(stderr, "\nCustom rules ({}):\n", config.rules.size());
        size_t criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
        for (const auto& rule : config.rules) {
            switch (rule.severity) {
                case Severity::Critical: ++criticalCount; break;
                case Severity::High:     ++highCount; break;
                case Severity::Medium:   ++mediumCount; break;
                case Severity::Low:      ++lowCount; break;
            }
        }
        fmt::print(stderr, "  Critical: {}, High: {}, Medium: {}, Low: {}\n",
                   criticalCount, highCount, mediumCount, lowCount);
    }

    // Actions
    fmt::print(stderr, "\nActions:\n");
    fmt::print(stderr, "  Quarantine: {}", config.actions.quarantine.enabled ? "enabled" : "disabled");
    if (config.actions.quarantine.enabled) {
        fmt::print(stderr, " ({})", config.actions.quarantine.directory);
    }
    fmt::print(stderr, "\n");

    fmt::print(stderr, "  Report: console={}, format={}\n",
               config.actions.report.console ? "yes" : "no",
               reportFormatToString(config.actions.report.format));

    if (config.actions.alert.enabled) {
        fmt::print(stderr, "  Alert: enabled (to: {})\n", config.actions.alert.to);
    } else {
        fmt::print(stderr, "  Alert: disabled\n");
    }

    fmt::print(stderr, "\n");
}

}  // namespace lyxbosa
