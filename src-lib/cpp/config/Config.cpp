#include "Config.h"
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <sstream>
#include <fmt/core.h>

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

        if (root["rules"] && root["rules"].IsSequence()) {
            for (const auto& rn : root["rules"]) {
                config.rules.push_back(parseRuleConfig(rn));
            }
        }

        if (root["actions"]) {
            config.actions = parseActionsConfig(root["actions"]);
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
version: 1

scan:
  directories:
    - /var/www
  recursive: true
  max_file_size: 5MB
  follow_symlinks: false

  # File filters
  include:
    - "!ext"
    - "*.php"
    - "*.php?"
    - "*.phtml"
    - "*.js"
    - "*.html"
    - "*.htm"
    - "*.c"
    - "*.cpp"
    - "*.h"
    - "*.sh"
    - "*.pl"
    - "*.py"
    - "*.rb"
    - "*.ttf
    - ".htaccess"
  exclude:
    - node_modules/**
    - vendor/**
    - "*.min.js"

# Detection rules
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
        flags: i

  - name: C99 Shell
    description: Known C99 webshell signatures
    severity: critical
    category: webshell
    patterns:
      - type: string
        value: c99shell
      - type: string
        value: c99shexit

  - name: FilesMan Shell
    description: FilesMan webshell signature
    severity: critical
    category: webshell
    patterns:
      - type: regex
        value: \$GLOBALS\s*\[\s*['"]FilesMan['"]\s*\]
      - type: regex
        value: \$FilesMan\s*=
      - type: regex
        value: function\s+FilesMan\s*\(

  - name: Suspicious gzinflate
    description: PHP code using gzinflate for obfuscation
    severity: high
    category: obfuscation
    patterns:
      - type: string
        value: eval(gzinflate(

  - name: Suspicious preg_replace e modifier
    description: PHP preg_replace with dangerous /e modifier
    severity: critical
    category: code_execution
    patterns:
      - type: regex
        value: preg_replace\s*\(\s*['"]/[^/]*/e
      - type: regex
        value: |-
          preg_replace\s*\(\s*['"][^'"]*[/\\x65]
        flags: i

  - name: Weevely Shell obfuscation
    description: Weevely webshell string obfuscation patterns
    severity: critical
    category: webshell
    patterns:
      - type: string
        value: zbazszez6z4z_dzezczodze
      - type: string
        value: obcobreobaobtobe_obfunctobion
      - type: string
        value: vsvtrv_revpvlvace

  - name: Gzuncompress eval
    description: PHP eval with gzuncompress obfuscation
    severity: critical
    category: obfuscation
    patterns:
      - type: string
        value: eval(gzuncompress(base64_decode(

  - name: Web Shell by oRb
    description: Known oRb webshell signature
    severity: critical
    category: webshell
    patterns:
      - type: string
        value: Web Shell by oRb

  - name: FaTaLisTiCz_Fx
    description: FaTaLisTiCz webshell signature
    severity: critical
    category: webshell
    patterns:
      - type: string
        value: FaTaLisTiCz_Fx

  - name: IRC Bot
    description: IRC bot connection signature
    severity: high
    category: botnet
    patterns:
      - type: string
        value: "@irc."

  - name: Back connect
    description: Reverse shell/back connect signature
    severity: critical
    category: backdoor
    patterns:
      - type: string
        value: $back_connect_p=

  - name: Shell exec
    description: Direct shell command execution
    severity: critical
    category: code_execution
    patterns:
      - type: string
        value: shell_exec($cmd)
      - type: string
        value: shell_exec($comd)

  - name: System command execution
    description: System() function for command execution
    severity: critical
    category: code_execution
    patterns:
      - type: regex
        value: |-
          system\s*\(\s*\$_(GET|POST|REQUEST)\s*\[
        flags: i
      - type: regex
        value: |-
          system\s*\(\s*\$cmd\s*\)
        flags: i

  - name: Embedded PHP shell string
    description: PHP shell code embedded in string variable
    severity: critical
    category: exploit_tool
    patterns:
      - type: regex
        value: |-
          ["']\s*<\?php.*system\s*\(
        flags: i
      - type: regex
        value: |-
          ["']\s*<\?php.*passthru\s*\(
        flags: i
      - type: regex
        value: |-
          ["']\s*<\?php.*shell_exec\s*\(
        flags: i
      - type: regex
        value: |-
          ["']\s*<\?php.*exec\s*\(
        flags: i

  - name: Exploit tool indicators
    description: Remote exploit/hacking tool signatures
    severity: critical
    category: exploit_tool
    patterns:
      - type: regex
        value: |-
          (RCE|Remote\s+Code\s+Execution|exploit|vulnerability)
        flags: i
      - type: regex
        value: |-
          (PWNED|pwn|shell\.php|backdoor)
        flags: i

  - name: HTTP attack tool
    description: Script using fsockopen for HTTP attacks
    severity: high
    category: exploit_tool
    patterns:
      - type: regex
        value: |-
          fsockopen\s*\(.*\$host.*HTTP
        flags: i
      - type: regex
        value: |-
          fputs\s*\(.*HTTP/1\.[01]
        flags: i

  - name: File upload exploit
    description: Exploit targeting file upload vulnerabilities
    severity: critical
    category: exploit_tool
    patterns:
      - type: regex
        value: |-
          multipart/form-data.*Filedata.*\.php
        flags: i
      - type: regex
        value: |-
          upload.*\.php.*rename.*extension
        flags: i

  - name: Str rot13 decode
    description: ROT13 obfuscation with base64
    severity: high
    category: obfuscation
    patterns:
      - type: string
        value: str_rot13(base64_decode(

  - name: Assert execution
    description: PHP assert used for code execution
    severity: high
    category: code_execution
    patterns:
      - type: regex
        value: assert\s*\(\s*\$

  - name: Create function eval
    description: Dynamic function creation for code execution
    severity: critical
    category: code_execution
    patterns:
      - type: regex
        value: create_function\s*\(\s*['"]['"]\s*,

  - name: Encoded goto obfuscation
    description: PHP goto-based obfuscation pattern
    severity: high
    category: obfuscation
    patterns:
      - type: regex
        value: goto\s+\w+;.*@eval\s*\(

  # Heuristic detection rules (behavioral patterns)
  - name: Multiple base64 concatenation
    description: Multiple base64-encoded variables likely used for payload assembly
    severity: high
    category: obfuscation
    patterns:
      - type: heuristic
        heuristic_type: multiple_base64_concat
        min_occurrences: 3

  - name: String replace function building
    description: Using str_replace to build obfuscated function names
    severity: high
    category: obfuscation
    patterns:
      - type: heuristic
        heuristic_type: str_replace_function_build

  - name: Variable function calls
    description: Dynamic function invocation via variables
    severity: medium
    category: obfuscation
    patterns:
      - type: heuristic
        heuristic_type: variable_function_call
        min_occurrences: 3

  - name: Hex-encoded function arrays
    description: Arrays containing hex-encoded function names
    severity: high
    category: obfuscation
    patterns:
      - type: heuristic
        heuristic_type: hex_encoded_functions
        min_occurrences: 3

  - name: Goto-based obfuscation
    description: Excessive use of goto for control flow obfuscation
    severity: high
    category: obfuscation
    patterns:
      - type: heuristic
        heuristic_type: goto_obfuscation

  - name: Long encoded strings
    description: Very long base64 or hex encoded strings (likely payloads)
    severity: medium
    category: obfuscation
    patterns:
      - type: heuristic
        heuristic_type: long_encoded_strings
        min_string_length: 500

  - name: Eval with variable
    description: eval() or assert() called with a variable (dynamic code execution)
    severity: critical
    category: code_execution
    patterns:
      - type: heuristic
        heuristic_type: eval_with_variable

  - name: Create function for eval
    description: create_function with empty params (eval alternative)
    severity: critical
    category: code_execution
    patterns:
      - type: heuristic
        heuristic_type: create_function_eval

  - name: Array index string obfuscation
    description: Building strings via array index concatenation ($var[N].$var[M]...)
    severity: critical
    category: obfuscation
    patterns:
      - type: heuristic
        heuristic_type: array_index_string_build
        min_occurrences: 5

  # Dropper and payload deployment patterns
  - name: Base64 payload dropper
    description: Writing base64-decoded data to file (payload deployment)
    severity: critical
    category: dropper
    patterns:
      - type: regex
        value: |-
          file_put_contents\s*\([^,]+,\s*base64_decode\s*\(
        flags: i
      - type: regex
        value: |-
          fwrite\s*\([^,]+,\s*base64_decode\s*\(
        flags: i

  - name: ZIP/Archive extraction dropper
    description: Creating and extracting ZIP archives (dropper behavior)
    severity: high
    category: dropper
    patterns:
      - type: regex
        value: |-
          file_put_contents\s*\([^,]*\.zip["']\s*,
        flags: i
      - type: regex
        value: |-
          ->extract\s*\(\s*\)
        flags: i

  - name: Backdoor test probe
    description: Test parameter check for backdoor availability verification
    severity: critical
    category: backdoor
    patterns:
      - type: regex
        value: |-
          \$_(REQUEST|GET|POST)\s*\[\s*["'](test_url|test|check|ping|verify)["']\s*\]
        flags: i

  - name: Webshell filename dropper
    description: Creating files with suspicious webshell-like names
    severity: critical
    category: dropper
    patterns:
      - type: regex
        value: |-
          file_put_contents\s*\([^,]*(shell|backdoor|cmd|hack|c99|r57|b374k|webshell|wp-ss)
        flags: i

  - name: Embedded ZIP payload
    description: Base64-encoded ZIP data embedded in script (PK header signature)
    severity: critical
    category: dropper
    patterns:
      - type: regex
        value: base64_decode.*UEs
        flags: i

  - name: PclZip library embedded
    description: Embedded PclZip library (often used by droppers)
    severity: medium
    category: dropper
    patterns:
      - type: string
        value: PCLZIP_READ_BLOCK_SIZE
      - type: string
        value: class PclZip

  - name: Dropper success beacon
    description: Numeric success code output (C2 communication beacon)
    severity: high
    category: dropper
    patterns:
      - type: regex
        value: |-
          die\s*\(\s*["']\d{8,}["']\s*\)
        flags: i
      - type: regex
        value: |-
          echo\s+["']\d{8,}["']\s*;
        flags: i

  # PHP eval evasion techniques
  - name: Eval with PHP close tag
    description: eval() with PHP close tag to evade detection
    severity: critical
    category: code_execution
    patterns:
      - type: regex
        value: |-
          eval\s*\(\s*["']\s*\?>\s*["']\s*\.\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(
        flags: i

  - name: GIF header with PHP code
    description: Fake GIF image containing PHP code (image upload bypass)
    severity: critical
    category: webshell
    patterns:
      - type: regex
        value: |-
          GIF89a.*<\?php
        flags: i
      - type: regex
        value: |-
          GIF87a.*<\?php
        flags: i

  - name: JPEG header with PHP code
    description: Fake JPEG image containing PHP code (image upload bypass)
    severity: critical
    category: webshell
    patterns:
      - type: regex
        value: |-
          JFIF.*<\?php
        flags: i
      - type: string
        value: ÿØÿà

  - name: Goto obfuscation webshell
    description: Heavy use of goto statements for control flow obfuscation
    severity: critical
    category: webshell
    patterns:
      - type: regex
        value: |-
          goto\s+\w+;.*goto\s+\w+;.*goto\s+\w+;
        flags: i

  - name: Hex-encoded string parameters
    description: Function calls with hex-encoded string parameters
    severity: high
    category: obfuscation
    patterns:
      - type: regex
        value: |-
          \$_(?:GET|POST|REQUEST|FILES)\s*\[\s*["']\\x[0-9a-f]{2}\\x[0-9a-f]{2}
        flags: i

  - name: File manager webshell
    description: File manager functionality (upload, download, edit, delete)
    severity: critical
    category: webshell
    patterns:
      - type: regex
        value: |-
          move_uploaded_file.*\$_FILES.*scandir
        flags: i
      - type: regex
        value: |-
          scandir.*unlink.*rename.*file_put_contents
        flags: i

  - name: Hex escape obfuscation
    description: PHP using hex escapes to build function names
    severity: high
    category: obfuscation
    patterns:
      - type: regex
        value: |-
          \$\w+=["']\\x[0-9a-f]{2}["'];\$\w+=["']\\x[0-9a-f]{2}["']
        flags: i

  - name: Reversed function names
    description: Building function names by reversing strings (common obfuscation)
    severity: critical
    category: obfuscation
    patterns:
      - type: regex
        value: |-
          array_reverse\s*\([^)]*\)\s*\)\s*;
        flags: i
      - type: regex
        value: |-
          implode\s*\(\s*["']["']\s*,\s*array_reverse
        flags: i
      - type: regex
        value: |-
          strrev\s*\(\s*["'][a-z_]+["']\s*\.\s*["'][a-z_]+["']
        flags: i
      - type: regex
        value: |-
          strrev\s*\([^)]+\)\s*\(
        flags: i

  - name: GLOBALS function obfuscation
    description: Calling functions via $GLOBALS with obfuscated keys
    severity: critical
    category: obfuscation
    patterns:
      - type: regex
        value: |-
          \$GLOBALS\s*\[\s*["'][b6]{6,}["']\s*\]

  - name: SEO spam backdoor
    description: SEO spam/cloaking backdoor indicators
    severity: critical
    category: backdoor
    patterns:
      - type: string
        value: urlgz=
      - type: string
        value: yumingid=
      - type: string
        value: lineid=
      - type: regex
        value: |-
          sps=\d+
        flags: i

  - name: Obfuscated variable names
    description: Variables using repetitive character patterns (b6, l1, etc)
    severity: high
    category: obfuscation
    patterns:
      - type: regex
        value: |-
          \$[bl]\d[a-z0-9]{3,}\s*=
        flags: i

  - name: Custom base64 decoder
    description: Custom base64 decoding implementation (evasion technique)
    severity: critical
    category: obfuscation
    patterns:
      - type: string
        value: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=

  - name: Bot detection cloaking
    description: User-agent based bot detection for cloaking
    severity: high
    category: seo_spam
    patterns:
      - type: regex
        value: |-
          HTTP_USER_AGENT.*bot|googlebot|bingbot
        flags: i
      - type: regex
        value: |-
          preg_match.*HTTP_USER_AGENT
        flags: i

  - name: Sitemap manipulation
    description: Dynamic sitemap generation (SEO spam indicator)
    severity: high
    category: seo_spam
    patterns:
      - type: string
        value: sitemaps.org/schemas/sitemap
      - type: regex
        value: |-
          <urlset.*xmlns
        flags: i

  - name: Robots.txt manipulation
    description: Dynamic robots.txt generation
    severity: high
    category: seo_spam
    patterns:
      - type: regex
        value: |-
          robots\.txt.*fopen|fwrite.*robots\.txt
        flags: i

  # Credential harvester detection
  - name: Credential harvester mailer
    description: Script that collects credentials and emails them
    severity: critical
    category: phishing
    patterns:
      - type: heuristic
        heuristic_type: credential_harvester

  - name: POST data exfiltration
    description: Collecting POST data (login/password) for exfiltration
    severity: high
    category: phishing
    patterns:
      - type: regex
        value: |-
          \$_POST\s*\[\s*["'](login|user|username|email|passwd|password|pass|pwd)["']\s*\]
        flags: i

  - name: IP logging for phishing
    description: Collecting visitor IP address (common in phishing)
    severity: medium
    category: phishing
    patterns:
      - type: regex
        value: |-
          getenv\s*\(\s*["']REMOTE_ADDR["']\s*\)
        flags: i
      - type: string
        value: $_SERVER["REMOTE_ADDR"]
      - type: string
        value: $_SERVER['REMOTE_ADDR']

  - name: Mail with stolen data
    description: Using mail() function to send collected data
    severity: high
    category: phishing
    patterns:
      - type: regex
        value: |-
          mail\s*\([^)]*\$_(POST|GET|REQUEST)
        flags: i
      - type: regex
        value: |-
          mail\s*\([^)]*\$message
        flags: i

  - name: Phishing redirect
    description: Redirecting to legitimate site after credential theft
    severity: medium
    category: phishing
    patterns:
      - type: regex
        value: |-
          header\s*\(\s*["']Location:\s*https?://(www\.)?(google|yahoo|facebook|paypal|apple|microsoft|amazon)
        flags: i

  # Remote File Inclusion (RFI) vulnerabilities
  - name: Remote file inclusion via GET
    description: Including files from user-controlled GET parameter (RFI vulnerability)
    severity: critical
    category: file_inclusion
    patterns:
      - type: regex
        value: |-
          (include|include_once|require|require_once)\s*\(\s*\$_GET\s*\[
        flags: i

  - name: Remote file inclusion via POST
    description: Including files from user-controlled POST parameter (RFI vulnerability)
    severity: critical
    category: file_inclusion
    patterns:
      - type: regex
        value: |-
          (include|include_once|require|require_once)\s*\(\s*\$_POST\s*\[
        flags: i

  - name: Remote file inclusion via REQUEST
    description: Including files from user-controlled REQUEST parameter (RFI vulnerability)
    severity: critical
    category: file_inclusion
    patterns:
      - type: regex
        value: |-
          (include|include_once|require|require_once)\s*\(\s*\$_REQUEST\s*\[
        flags: i

  - name: PHP security bypass attempt
    description: Attempting to bypass PHP security restrictions (safe_mode/open_basedir)
    severity: critical
    category: security_bypass
    patterns:
      - type: regex
        value: |-
          ini_restore\s*\(\s*["'](safe_mode|open_basedir|disable_functions)["']\s*\)
        flags: i
      - type: regex
        value: |-
          ini_set\s*\(\s*["'](safe_mode|open_basedir|disable_functions)["']\s*,\s*["']?(off|0|none|)["']?\s*\)
        flags: i

  - name: Dynamic file inclusion
    description: Including files based on variable input (potential LFI/RFI)
    severity: high
    category: file_inclusion
    patterns:
      - type: regex
        value: |-
          (include|include_once|require|require_once)\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)
        flags: i

  # Tracking pixel exfiltration
  - name: Tracking pixel exfiltration
    description: Using invisible image to exfiltrate data to external server
    severity: high
    category: tracking
    patterns:
      - type: regex
        value: |-
          new\s+Image\s*\(\s*1\s*,\s*1\s*\)\s*;\s*[^;]*\.src\s*=
        flags: i

  - name: URL data collection
    description: Collecting page URL, title and referrer for exfiltration
    severity: medium
    category: tracking
    patterns:
      - type: regex
        value: |-
          encodeURIComponent\s*\(\s*document\.location\.(href|pathname)\s*\).*encodeURIComponent\s*\(\s*document\.(title|referrer)\s*\)
        flags: i

  - name: External tracking beacon
    description: Sending tracking data to external analytics server
    severity: high
    category: tracking
    patterns:
      - type: regex
        value: |-
          (scorecardresearch|doubleclick|googleadservices|facebook\.com\/tr|analytics)\.com.*\?.*document\.(location|referrer|title)
        flags: i

  - name: Hidden iframe tracking
    description: Creating hidden iframe for cross-domain tracking
    severity: medium
    category: tracking
    patterns:
      - type: regex
        value: |-
          createElement\s*\(\s*["']iframe["']\s*\).*display\s*:\s*none|width\s*:\s*["']?0|height\s*:\s*["']?0
        flags: i

  - name: Cookie fingerprinting
    description: Creating persistent tracking cookies for user fingerprinting
    severity: medium
    category: tracking
    patterns:
      - type: regex
        value: |-
          document\.cookie\s*=.*expires.*toGMTString\s*\(\s*\).*domain.*path
        flags: i

  - name: Session tracking beacon
    description: Logging page views and user sessions to external server
    severity: high
    category: tracking
    patterns:
      - type: regex
        value: |-
          (pview|pageview|log)\s*["']\s*\).*sessionID.*fpc
        flags: i

  # Network attack tools (C/C++)
  - name: Raw socket creation
    description: Raw socket creation often used in network attack tools
    severity: high
    category: network_attack
    patterns:
      - type: regex
        value: socket\s*\(\s*AF_INET\s*,\s*SOCK_RAW
      - type: regex
        value: socket\s*\(\s*PF_INET\s*,\s*SOCK_RAW

  - name: Flood attack tool
    description: Network flood/DoS attack tool indicators
    severity: critical
    category: network_attack
    patterns:
      - type: regex
        value: flood\s*(program|tool|attack)
        flags: i
      - type: string
        value: sendto(
      - type: regex
        value: for\s*\(\s*;\s*;\s*\)\s*\{[^}]*send

  - name: Smurf attack
    description: ICMP smurf amplification attack signatures
    severity: critical
    category: network_attack
    patterns:
      - type: regex
        value: smurf
        flags: i
      - type: string
        value: ICMP_ECHO
      - type: regex
        value: broadcast.*flood
        flags: i

  - name: SYN flood tool
    description: TCP SYN flood attack tool
    severity: critical
    category: network_attack
    patterns:
      - type: regex
        value: syn\s*(flood|attack)
        flags: i
      - type: string
        value: send_tcp_segment

  - name: IP spoofing code
    description: IP address spoofing implementation
    severity: high
    category: network_attack
    patterns:
      - type: regex
        value: (spoof|fake).*addr
        flags: i
      - type: regex
        value: ip->saddr\s*=

  # Phishing kit detection
  - name: Phishing form
    description: Form posting credentials to local PHP handler
    severity: critical
    category: phishing
    patterns:
      - type: regex
        value: |-
          <form[^>]*action\s*=\s*["'][^"']*\.php["']
        flags: i
      - type: regex
        value: |-
          <input[^>]*name\s*=\s*["'](password|passwd|pwd|login_password)["']
        flags: i

  - name: Credit card form fields
    description: HTML form collecting credit card information
    severity: critical
    category: phishing
    patterns:
      - type: regex
        value: |-
          name\s*=\s*["'](cc_number|card_number|cardnumber|creditcard)["']
        flags: i
      - type: regex
        value: |-
          name\s*=\s*["'](cvv|cvv2|cvc|cvv2_number|security_code)["']
        flags: i
      - type: regex
        value: |-
          name\s*=\s*["'](expdate|exp_date|expiry|expdate_month|expdate_year)["']
        flags: i

  - name: PayPal phishing kit
    description: Fake PayPal page impersonating legitimate site
    severity: critical
    category: phishing
    patterns:
      - type: string
        value: paypal_logo.gif
      - type: string
        value: Connexion - PayPal
      - type: regex
        value: |-
          PayPal.*Confirmation.*compte
        flags: i
      - type: regex
        value: |-
          login_form.*login_email.*login_password
        flags: i

  - name: Bank impersonation
    description: Fake banking page impersonating legitimate banks
    severity: critical
    category: phishing
    patterns:
      - type: regex
        value: (lloyds|barclays|hsbc|natwest|santander).*online.*banking
        flags: i
      - type: regex
        value: (Online|Internet)\s+Banking.*Verification
        flags: i

  - name: Credential harvester
    description: Script collecting and exfiltrating user credentials
    severity: critical
    category: phishing
    patterns:
      - type: string
        value: $_POST['password']
      - type: string
        value: $_POST["password"]
      - type: regex
        value: _POST\[['"]card.?number['"]\]
        flags: i
      - type: regex
        value: mail\s*\([^)]*_(POST|GET|REQUEST)
      - type: regex
        value: _POST\[['"](pin|cvv|cvv2|cvc|security.?code)['"]\]
        flags: i

  - name: Phishing data exfiltration
    description: Exfiltrating stolen credentials via email
    severity: critical
    category: phishing
    patterns:
      - type: regex
        value: mail\s*\([^)]*@(hotmail|gmail|yahoo)
        flags: i
      - type: regex
        value: \$message\s*\.=.*\$_POST

  - name: Hacked by signature
    description: Hacker/defacement signature in code
    severity: high
    category: defacement
    patterns:
      - type: regex
        value: (hacked|pwned|owned)\s+by
        flags: i
      - type: regex
        value: created\s+by\s+\w+\s*\+
        flags: i

  # Remote code loader / Dropper patterns
  - name: Remote code loader
    description: Downloads and executes remote PHP code (dropper pattern)
    severity: critical
    category: backdoor
    patterns:
      - type: regex
        value: (file_get_contents|curl_exec)\s*\([^)]*\)\s*;[^;]*(@?include|@?require|@?include_once|@?require_once)
      - type: regex
        value: file_put_contents\s*\([^,]+,\s*(file_get_contents|curl_exec|\$\w+)\s*\(
      - type: regex
        value: (curl_exec|file_get_contents)\s*\([^)]+\)[^;]*file_put_contents
      - type: regex
        value: tmpfile\s*\(\s*\)[^;]*fwrite[^;]*(@?include|@?require)

  - name: Tmpfile code execution
    description: Writes code to temp file and includes it
    severity: critical
    category: backdoor
    patterns:
      - type: string
        value: tmpfile()
      - type: regex
        value: stream_get_meta_data\s*\([^)]+\)[^;]*\['uri'\]
      - type: regex
        value: fwrite\s*\([^,]+,\s*\$code\s*\)

  # Obfuscation patterns for lock360-style malware
  - name: Hex-encoded GLOBALS access
    description: Accessing superglobals via hex-encoded strings
    severity: critical
    category: obfuscation
    patterns:
      - type: string
        value: '${"\x47\x4c\x4f\x42\x41\x4c\x53"}'
      - type: string
        value: '${"\x5f\x53\x45\x52\x56\x45\x52"}'
      - type: string
        value: '${"\x5f\x47\x45\x54"}'
      - type: string
        value: '${"\x5f\x50\x4f\x53\x54"}'
      - type: string
        value: '${"\x5f\x52\x45\x51\x55\x45\x53\x54"}'
      - type: regex
        value: '\$\{["'']\\x[0-9a-f]{2}(\\x[0-9a-f]{2})+["'']\}'
        flags: i

  - name: Obfuscated variable names
    description: Variables using O/0/_ patterns to confuse (ionCube-style)
    severity: high
    category: obfuscation
    patterns:
      - type: regex
        value: \$[O0_]{5,}\s*=
      - type: regex
        value: \$[O0_]{5,}\s*\(
      - type: regex
        value: \$[O0_]{5,}\[

  - name: Urldecode obfuscation
    description: Using urldecode to build code at runtime
    severity: high
    category: obfuscation
    patterns:
      - type: regex
        value: urldecode\s*\(\s*["']%[0-9a-f]{2}
        flags: i
      - type: regex
        value: \$\w+\s*=\s*urldecode\s*\([^)]+\)\s*;\s*\$\w+\s*=\s*\$\w+\{

  - name: URL string fragmentation
    description: Splitting URLs into fragments to evade detection
    severity: high
    category: obfuscation
    patterns:
      - type: regex
        value: |-
          ["']htt["']\.["']ps?://
        flags: i
      - type: regex
        value: |-
          file_get_contents\s*\(\s*["'][^"']+["']\s*\.\s*["'][^"']+["']
      - type: regex
        value: |-
          curl_setopt[^;]+CURLOPT_URL[^;]+["'][^"']*["']\s*\.\s*["']

  - name: C2 server communication
    description: Command and control server URL patterns
    severity: critical
    category: backdoor
    patterns:
      - type: regex
        value: (zvo\d|icw\d|51la)\.(xyz|com)
        flags: i
      - type: regex
        value: https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/

  - name: Dynamic include with URL
    description: Including remote code from URL
    severity: critical
    category: backdoor
    patterns:
      - type: regex
        value: |-
          @?(include|require|include_once|require_once)\s*\(\s*['"]https?://
      - type: regex
        value: |-
          @?(include|require)\s*\(\s*\$\w+\s*\)\s*;[^;]*(unlink|fclose)
      - type: regex
        value: |-
          @?(include|require)\s*\(\s*\$file_path\s*\)

  - name: Suspicious curl operations
    description: Curl with SSL verification disabled (C2 communication)
    severity: high
    category: backdoor
    patterns:
      - type: string
        value: CURLOPT_SSL_VERIFYPEER, 0
      - type: string
        value: CURLOPT_SSL_VERIFYPEER, false
      - type: regex
        value: curl_setopt[^;]+CURLOPT_RETURNTRANSFER[^;]+curl_exec

  - name: Web shell file manager
    description: Web shell with file management capabilities
    severity: critical
    category: webshell
    patterns:
      - type: regex
        value: (scandir|opendir)\s*\([^)]+\)[^;]*(unlink|rmdir|rename|chmod)
      - type: regex
        value: move_uploaded_file\s*\([^)]+\$_(FILES|POST|GET|REQUEST)
      - type: regex
        value: file_put_contents\s*\([^,]+\$_(POST|GET|REQUEST)

  - name: Self-deletion mechanism
    description: Code that can delete itself after execution
    severity: high
    category: backdoor
    patterns:
      - type: regex
        value: unlink\s*\(\s*\$_SERVER\s*\[\s*['"]SCRIPT_FILENAME['"]\s*\]
      - type: regex
        value: unlink\s*\(\s*__FILE__\s*\)
      - type: regex
        value: |-
          @unlink\s*\(\s*\$file_path\s*\)

  # Simple/minimal backdoor shells
  - name: Eval stdin backdoor
    description: Executes arbitrary code from php://input (stdin backdoor)
    severity: critical
    category: backdoor
    patterns:
      - type: string
        value: php://input
      - type: regex
        value: |-
          eval\s*\(\s*['"]?\?>['"]\s*\.\s*file_get_contents
      - type: regex
        value: |-
          file_get_contents\s*\(\s*['"]php://input['"]

  - name: Minimal upload shell
    description: Simple file upload webshell allowing arbitrary file writes
    severity: critical
    category: webshell
    patterns:
      - type: string
        value: "@copy($_FILES"
      - type: string
        value: "copy($_FILES"
      - type: string
        value: move_uploaded_file

  - name: System information disclosure
    description: Reveals server system information
    severity: medium
    category: reconnaissance
    patterns:
      - type: string
        value: php_uname(
      - type: string
        value: phpinfo(

  # Malicious .htaccess patterns
  - name: Htaccess SEO spam redirect
    description: Redirects search engine visitors to malicious sites
    severity: critical
    category: seo_spam
    patterns:
      - type: regex
        value: |-
          RewriteCond.*HTTP_REFERER.*(google|bing|yahoo|facebook|twitter)
        flags: i
      - type: regex
        value: |-
          RewriteRule.*\[R=301
      - type: regex
        value: |-
          RewriteRule.*http://[^/]+\.(ru|cn|tk|ml|ga|cf|gq)/
        flags: i

  - name: Htaccess malicious redirect
    description: Suspicious redirect to external domain in htaccess
    severity: high
    category: seo_spam
    patterns:
      - type: regex
        value: |-
          ErrorDocument\s+\d+\s+http
      - type: regex
        value: |-
          RewriteRule.*https?://[a-z0-9]+\.(ru|cn|tk|ml|ga|cf|gq|xyz|top|pw|cc)/
        flags: i

  - name: Htaccess cloaking
    description: Htaccess serving different content to crawlers vs users
    severity: critical
    category: seo_spam
    patterns:
      - type: regex
        value: |-
          RewriteCond.*HTTP_USER_AGENT.*(googlebot|bingbot|yahoo|msnbot)
        flags: i
      - type: regex
        value: |-
          RewriteCond.*HTTP_REFERER.*(duckduckgo|ask|dogpile|webcrawler|lycos)
        flags: i

  - name: Suspicious TLD in htaccess
    description: References to high-risk TLDs commonly used in spam
    severity: high
    category: seo_spam
    patterns:
      - type: regex
        value: |-
          https?://[a-z0-9.-]+\.(ru|cn|tk|ml|ga|cf|gq)/
        flags: i

  # Perl credential harvesting / Config spy scripts
  - name: Passwd file reader
    description: Script reads /etc/passwd for user enumeration
    severity: critical
    category: credential_theft
    patterns:
      - type: regex
        value: open\s*\(\s*\w+\s*,\s*['"]/etc/passwd['"]
      - type: string
        value: /etc/passwd
      - type: regex
        value: |-
          getpwent|getpwnam|getpwuid

  - name: Perl password extraction
    description: Regex pattern extracting passwords from config files
    severity: critical
    category: credential_theft
    patterns:
      - type: regex
        value: |-
          =~\s*m?/pass(wd|word)?.*?=/
        flags: i
      - type: regex
        value: |-
          =~\s*m?/pwd.*?=/
        flags: i
      - type: regex
        value: |-
          get_pass|extract_pass|scan_config
        flags: i

  - name: Config file scanner
    description: Script scanning for database/CMS config files
    severity: high
    category: credential_theft
    patterns:
      - type: regex
        value: |-
          ["'](wp-config|configuration|config\.inc|database|dbconnect|db\.inc)\.php["']
        flags: i
      - type: regex
        value: |-
          \$file\s+eq\s+["'](config|database|connect).*\.php["']
        flags: i

  - name: FTP credential testing
    description: Script testing stolen credentials via FTP
    severity: critical
    category: credential_theft
    patterns:
      - type: string
        value: Net::FTP
      - type: regex
        value: |-
          ftp->login\s*\(\s*\$
      - type: regex
        value: |-
          FTP.*success
        flags: i

  - name: Credential logger
    description: Script logging stolen credentials to file
    severity: critical
    category: credential_theft
    patterns:
      - type: regex
        value: |-
          (confspy|passlog|credential|stolen).*\.log
        flags: i
      - type: regex
        value: |-
          write_log.*pass
        flags: i
      - type: regex
        value: |-
          open\s*\(\s*\w+\s*,\s*["']>>[^"']+log["']\s*\)

  - name: Antisecurity/hacker tool
    description: Known malicious tool attribution strings
    severity: critical
    category: malware
    patterns:
      - type: regex
        value: antisecurity\.org
        flags: i
      - type: regex
        value: |-
          (mainhack|hackerteam|vrs-hck)
        flags: i
      - type: regex
        value: |-
          Private\s+Script
        flags: i

  - name: Home directory scanner
    description: Script enumerating user home directories
    severity: high
    category: reconnaissance
    patterns:
      - type: regex
        value: |-
          /home/.*public_html
      - type: regex
        value: |-
          opendir\s*\(\s*DIR\s*,\s*\$.*home
        flags: i
      - type: regex
        value: |-
          push\s*\(\s*@users

  # Advanced obfuscation patterns (akismet-style backdoors)
  - name: Alphabet-based obfuscation
    description: Custom alphabet/lookup table for string decoding (common in disguised backdoors)
    severity: critical
    category: obfuscation
    patterns:
      - type: regex
        value: |-
          \$\w+\s*=\s*["'][a-z0-9;.*/()+_-]{30,}["']
        flags: i
      - type: regex
        value: |-
          \$\w+\[\d+\]\s*\.\s*\$\w+\[\d+\]\s*\.\s*\$\w+\[\d+\]
        flags: i

  - name: REQUEST-based backdoor trigger
    description: Backdoor activation via $_REQUEST parameter with obfuscated code building
    severity: critical
    category: backdoor
    patterns:
      - type: regex
        value: |-
          \$_REQUEST\s*\[\s*["']\w+["']\s*\]\s*\.\s*\$\w+\[
        flags: i
      - type: regex
        value: |-
          if\s*\(\s*isset\s*\(\s*\$_REQUEST\s*\[\s*["']\w+["']\s*\]\s*\)\s*\)
        flags: i
      - type: regex
        value: |-
          \$\w+\s*=\s*\$_REQUEST\s*\[\s*["']\w+["']\s*\]
        flags: i

  - name: Hex escape in string literals
    description: Using hex escapes in strings to obfuscate function/variable names
    severity: high
    category: obfuscation
    patterns:
      - type: regex
        value: |-
          ["']\\x[0-9a-f]{2}[a-z]+\\x[0-9a-f]{2}["']
        flags: i
      - type: regex
        value: |-
          ["'][a-z]*\\x[0-9a-f]{2}[a-z]*\\.["']
        flags: i

  - name: Disguised WordPress backdoor
    description: Backdoor disguised as WordPress/CMS file descriptions or metadata
    severity: critical
    category: backdoor
    patterns:
      - type: regex
        value: |-
          \$\w+\s*=\s*array\s*\([^)]*["'][\w_]+\.php["']\s*=>\s*["'][^"']{100,}["']
        flags: i
      - type: regex
        value: |-
          ["']Template[\s_]*(Name|Description)["']\s*=>\s*["'][^"']{50,}\\x[0-9a-f]
        flags: i

  - name: Concatenated function name obfuscation
    description: Building function names by concatenating string fragments
    severity: critical
    category: obfuscation
    patterns:
      - type: regex
        value: |-
          ["'][a-z]+["']\s*\.\s*["'][a-z]+["']\s*\.\s*["'][a-z_]+["']\s*\.\s*["'][a-z]+["']
        flags: i

  - name: Hidden eval via gzinflate
    description: eval/gzinflate combination with hex escapes to evade detection
    severity: critical
    category: code_execution
    patterns:
      - type: regex
        value: |-
          \\x65val.*gz
        flags: i
      - type: regex
        value: |-
          ["']\\x[0-9a-f]{2}val["']\s*\.\s*["']
        flags: i

  # Perl obfuscation and backdoor patterns
  - name: Perl regex code execution
    description: Perl code execution via regex (?{}) code block (extremely dangerous)
    severity: critical
    category: code_execution
    patterns:
      - type: regex
        value: |-
          =~\s*\(\s*['"]?\(\?\{
      - type: regex
        value: |-
          \(\?\{.*\}\)
      - type: string
        value: "(?{"

  - name: Perl XOR obfuscation
    description: Perl string XOR obfuscation (decodes payload at runtime)
    severity: critical
    category: obfuscation
    patterns:
      - type: regex
        value: |-
          ['"][A-Za-z0-9=+/-]{100,}['"]\s*\^\s*['"][A-Za-z0-9=+/-]{100,}['"]
      - type: regex
        value: |-
          \$\w+\s*\^\s*\$\w+
        flags: i

  - name: Perl eval obfuscation
    description: Perl eval with string manipulation for code execution
    severity: critical
    category: code_execution
    patterns:
      - type: regex
        value: |-
          eval\s*\(\s*pack\s*\(
      - type: regex
        value: |-
          eval\s*\(\s*unpack\s*\(
      - type: regex
        value: |-
          eval\s+chr\s*\(

  - name: Perl reverse shell
    description: Perl reverse shell/backdoor connection
    severity: critical
    category: backdoor
    patterns:
      - type: regex
        value: |-
          socket\s*\(\s*\w+\s*,\s*PF_INET
      - type: regex
        value: |-
          connect\s*\(\s*\w+\s*,\s*sockaddr_in
      - type: regex
        value: |-
          open\s*\(\s*\w+\s*,\s*["']\|

  - name: Perl system execution
    description: Perl system/exec command execution
    severity: high
    category: code_execution
    patterns:
      - type: regex
        value: |-
          system\s*\(\s*\$_(ENV|ARGV)
      - type: regex
        value: |-
          exec\s*\(\s*\$
      - type: regex
        value: |-
          `\$\w+`

  # Custom decoder/decryptor function patterns
  - name: Custom string decoder function
    description: Function that decodes base64 then applies XOR or character manipulation
    severity: critical
    category: obfuscation
    patterns:
      - type: regex
        value: |-
          function\s+\w+\s*\(\s*\$\w+\s*\)\s*\{[^}]*base64_decode[^}]*ord\s*\(
        flags: i
      - type: regex
        value: |-
          base64_decode\s*\(\s*\$\w+\s*\)\s*;[^;]*while\s*\(\s*true\s*\)
        flags: i
      - type: regex
        value: |-
          ord\s*\(\s*\$\w+\s*\[\s*\$\w+\s*\]\s*\)\s*[\^-]
        flags: i

  - name: Variable function call pattern
    description: Calling functions via decoded variable (common backdoor pattern)
    severity: critical
    category: code_execution
    patterns:
      - type: regex
        value: |-
          \$\w+\s*=\s*\w+\s*\(\s*["'][A-Za-z0-9+/=]+["']\s*\)\s*;\s*return\s+\$\w+\s*\(
        flags: i
      - type: regex
        value: |-
          \$\w{5,}\s*=\s*\w+\s*\(\s*["'][A-Za-z0-9+/=]{8,}["']\s*\)\s*;[^;]*\$\w+\s*\(
        flags: i

  - name: Encoded function wrapper class
    description: Class that wraps PHP functions with encoded names (proxy backdoor)
    severity: critical
    category: backdoor
    patterns:
      - type: regex
        value: |-
          static\s+public\s+function\s+\w+\s*\([^)]*\)\s*\{[^}]*\w+\s*\(\s*["'][A-Za-z0-9+/=]+["']\s*\)\s*;[^}]*return\s+\$\w+\s*\(
        flags: i
      - type: regex
        value: |-
          class\s+\w+\s*\{[^}]*static\s+public\s+function[^}]*\w+\(\s*["'][A-Za-z0-9+/=]+["']\s*\)
        flags: i

  - name: PHP proxy backdoor
    description: HTTP proxy functionality for fetching remote content (backdoor/C2)
    severity: critical
    category: backdoor
    patterns:
      - type: regex
        value: |-
          file_get_contents\s*\(\s*["']php://input["']\s*\)
        flags: i
      - type: regex
        value: |-
          \$_SERVER\s*\[\s*["']REQUEST_METHOD["']\s*\].*fsockopen
        flags: i
      - type: regex
        value: |-
          stream_context_create\s*\([^)]*\$_SERVER
        flags: i

  - name: Obfuscated arithmetic expressions
    description: Using complex arithmetic to hide simple values (anti-analysis)
    severity: high
    category: obfuscation
    patterns:
      - type: regex
        value: |-
          \(\s*-?\d{3,}\s*[+-]\s*-?\d{3,}\s*[+-]\s*-?\d{3,}\s*\)
        flags: i
      - type: regex
        value: |-
          \(\s*-\s*\(\s*-\d+\s*\)\s*[+-]
        flags: i

  - name: Cookie-based code execution
    description: Executing code from cookie values (backdoor trigger)
    severity: critical
    category: backdoor
    patterns:
      - type: regex
        value: |-
          \$_COOKIE\s*\[[^]]+\].*\(
        flags: i
      - type: regex
        value: |-
          \w+\s*\([^,]*,\s*\$_COOKIE\s*\[
        flags: i

  - name: Getallheaders custom implementation
    description: Custom getallheaders implementation (often in backdoors for header manipulation)
    severity: high
    category: backdoor
    patterns:
      - type: regex
        value: |-
          function\s+getallheaders\s*\(\s*\)
        flags: i
      - type: regex
        value: |-
          if\s*\(\s*!\s*function_exists\s*\([^)]*getallheaders
        flags: i

  # Hex-encoded function name arrays (webshell pattern)
  - name: Hex-encoded function name array
    description: Array of hex-encoded PHP function names (webshell obfuscation)
    severity: critical
    category: webshell
    patterns:
      - type: regex
        value: |-
          \$\w+\s*=\s*\[\s*['"][0-9a-f]{10,}['"]
        flags: i
      - type: regex
        value: |-
          ['"][0-9a-f]{16,}['"],\s*['"][0-9a-f]{16,}['"]
        flags: i

  - name: Hex decoder function
    description: Custom function to decode hex strings (webshell pattern)
    severity: critical
    category: obfuscation
    patterns:
      - type: regex
        value: |-
          function\s+\w*hex\w*\s*\(\s*\$\w+\s*\)
        flags: i
      - type: regex
        value: |-
          hexdec\s*\(\s*\$\w+\s*\[\s*\$\w+\s*\]
        flags: i
      - type: regex
        value: |-
          chr\s*\(\s*hexdec\s*\(
        flags: i

  - name: Array-based function execution
    description: Calling functions via array index (webshell obfuscation)
    severity: critical
    category: code_execution
    patterns:
      - type: regex
        value: |-
          \$\w+\[\d+\]\s*\(\s*\$
        flags: i
      - type: regex
        value: |-
          \$\w+\[\d+\]\s*\(\s*["']
        flags: i
      - type: regex
        value: |-
          \$\w+\[\d+\]\s*\(\s*\)
        flags: i

  - name: XSS protection disabled
    description: Disabling XSS protection header (malicious intent)
    severity: high
    category: security_bypass
    patterns:
      - type: regex
        value: |-
          header\s*\(\s*["']X-XSS-Protection:\s*0["']
        flags: i

  - name: Self-deletion capability
    description: Script can delete itself (anti-forensics)
    severity: critical
    category: backdoor
    patterns:
      - type: regex
        value: |-
          unlink\s*\(\s*__FILE__\s*\)
        flags: i
      - type: regex
        value: |-
          \$\w+\[\d+\]\s*\(\s*__FILE__\s*\)
        flags: i

  - name: File manager webshell operations
    description: File operations via user input (webshell functionality)
    severity: critical
    category: webshell
    patterns:
      - type: regex
        value: |-
          scandir\s*\(\s*\$
        flags: i
      - type: regex
        value: |-
          fopen\s*\([^,]*\$_(GET|POST|REQUEST)
        flags: i
      - type: regex
        value: |-
          fwrite\s*\(\s*\$\w+\s*,\s*\$_(POST|GET|REQUEST)
        flags: i

  - name: Known webshell signature
    description: Known webshell names or signatures
    severity: critical
    category: webshell
    patterns:
      - type: regex
        value: |-
          (MARIJUANA|NG4R3P|0x5a455553)
        flags: i
      - type: regex
        value: |-
          github\.io.*shell
        flags: i

  - name: Dynamic variable function call
    description: Calling function stored in variable with user input
    severity: critical
    category: code_execution
    patterns:
      - type: regex
        value: |-
          \$\w+\s*\(\s*\$_(POST|GET|REQUEST)\s*\[
        flags: i
      - type: regex
        value: |-
          \$\w+\[\d+\]\s*\(\s*\$_(POST|GET|REQUEST)
        flags: i

  - name: China Chopper webshell
    description: Known China Chopper one-liner backdoor signatures
    severity: critical
    category: webshell
    patterns:
      - type: regex
        value: |-
          \$_POST\s*\[\s*['"]chopper['"]\s*\]
        flags: i
      - type: regex
        value: |-
          \$_(POST|GET|REQUEST)\s*\[\s*['"]z0['"]\s*\]
        flags: i
      - type: regex
        value: |-
          \$_(POST|GET|REQUEST)\s*\[\s*['"]z1['"]\s*\]
        flags: i

  - name: Eval with variable interpolation
    description: Eval using double-quoted string with variable interpolation
    severity: critical
    category: code_execution
    patterns:
      - type: regex
        value: |-
          @?\s*eval\s*\(\s*"\s*\\\$
        flags: i
      - type: regex
        value: |-
          @?\s*eval\s*\(\s*"\s*[^"]*\$\w+
        flags: i

  - name: Base64 decode to eval
    description: Base64 decoded user input directly passed to eval
    severity: critical
    category: code_execution
    patterns:
      - type: regex
        value: |-
          base64_decode\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[
        flags: i
      - type: regex
        value: |-
          \$\w+\s*=\s*base64_decode\s*\([^)]+\);\s*@?\s*eval\s*\(
        flags: i

  - name: Simple one-liner backdoor
    description: Short backdoor pattern with POST/GET check and eval
    severity: critical
    category: webshell
    patterns:
      - type: regex
        value: |-
          if\s*\(\s*\$\w+\s*!=\s*["']{2}\s*\)\s*\{[^}]*eval
        flags: i
      - type: regex
        value: |-
          <\?php\s+\$\w+\s*=\s*\$_(POST|GET)\s*\[.*eval
        flags: i

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
    // Check for at least one rule
    if (config.rules.empty()) {
        return "Configuration must have at least one rule";
    }

    // Check each rule has at least one pattern
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

void Config::printSummary(const AppConfig& config) {
    fmt::print("\n=== LyxBoSa Configuration ===\n\n");

    // Directories
    fmt::print("Scan directories ({}):\n", config.scan.directories.size());
    for (const auto& dir : config.scan.directories) {
        fmt::print("  - {}\n", dir);
    }

    fmt::print("\nOptions:\n");
    fmt::print("  Recursive: {}\n", config.scan.recursive ? "yes" : "no");
    fmt::print("  Max file size: {} bytes\n", config.scan.maxFileSize);
    fmt::print("  Follow symlinks: {}\n", config.scan.followSymlinks ? "yes" : "no");

    // Filters
    if (!config.scan.include.empty()) {
        fmt::print("\nInclude patterns ({}):\n", config.scan.include.size());
        for (const auto& pat : config.scan.include) {
            fmt::print("  - {}\n", pat);
        }
    }

    if (!config.scan.exclude.empty()) {
        fmt::print("\nExclude patterns ({}):\n", config.scan.exclude.size());
        for (const auto& pat : config.scan.exclude) {
            fmt::print("  - {}\n", pat);
        }
    }

    // Rules summary
    fmt::print("\nRules ({}):\n", config.rules.size());
    size_t criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
    for (const auto& rule : config.rules) {
        switch (rule.severity) {
            case Severity::Critical: ++criticalCount; break;
            case Severity::High:     ++highCount; break;
            case Severity::Medium:   ++mediumCount; break;
            case Severity::Low:      ++lowCount; break;
        }
    }
    fmt::print("  Critical: {}, High: {}, Medium: {}, Low: {}\n",
               criticalCount, highCount, mediumCount, lowCount);

    // Actions
    fmt::print("\nActions:\n");
    fmt::print("  Quarantine: {}", config.actions.quarantine.enabled ? "enabled" : "disabled");
    if (config.actions.quarantine.enabled) {
        fmt::print(" ({})", config.actions.quarantine.directory);
    }
    fmt::print("\n");

    fmt::print("  Report: console={}, format={}\n",
               config.actions.report.console ? "yes" : "no",
               reportFormatToString(config.actions.report.format));

    if (config.actions.alert.enabled) {
        fmt::print("  Alert: enabled (to: {})\n", config.actions.alert.to);
    } else {
        fmt::print("  Alert: disabled\n");
    }

    fmt::print("\n");
}

}  // namespace lyxbosa
