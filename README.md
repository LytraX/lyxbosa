# LytraX Bot Search

LyxBoSa is a high-performance malware and webshell detection scanner written in C++20. It recursively scans files and directories for malicious code patterns using a multi-strategy matching engine that combines string, regex (RE2), hex, entropy, hash, and heuristic analysis. With built-in detection rules spanning backdoors, credential theft, code execution, obfuscation, phishing, and more, LyxBoSa is designed to identify compromised websites and server-side threats commonly found in CMS platforms. It supports YAML-based configuration, custom rule definitions, multiple report formats (Text, JSON, CSV), and actions such as quarantine and email alerts.

## Overview

LyxBoSa (LytraX Bot Search) is a command-line security tool built to detect server-side malware, backdoors, webshells, and other malicious code embedded in web applications and hosting environments. It is particularly useful for scanning CMS installations such as WordPress and Joomla, where attackers commonly inject hidden admin accounts, cron persistence scripts, plugin/theme backdoors, and credential-harvesting payloads.

### Detection Engine

At its core, LyxBoSa uses a layered matching engine that applies multiple pattern-matching strategies against each scanned file:

- **String patterns** -- fast literal matching for known malicious signatures.
- **Regex patterns** -- powered by Google's RE2 library for safe, linear-time regular expression matching.
- **Hex patterns** -- binary signature detection for encoded or packed payloads.
- **Entropy analysis** -- identifies high-entropy regions that may indicate encrypted or obfuscated content.
- **Hash matching** -- detects known malicious files by their cryptographic fingerprint (xxHash).
- **Heuristic analysis** -- behavioral detection for techniques like variable function calls, base64 concatenation, and goto-based obfuscation.
- **Constant folding** -- resolves string expressions the way PHP would, so identifiers assembled at runtime (`$f="ba"; $h="s"; $o=$f.$h."e64_decode";`, `strrev()`, `implode()`, `chr()` chains, nested decoders) are detected by what they resolve to rather than by how they were split up.

The engine also includes context-aware filtering, suppression comments, and false-positive reduction by recognizing SQL queries and code comments.

### Built-in Rule Categories

LyxBoSa ships with a comprehensive set of built-in rules organized into 11 categories:

| Code | Category | Description |
|------|----------|-------------|
| BD | Backdoor | Hidden admin creation, cron persistence, plugin/theme backdoors, credential harvesting |
| WS | Webshell | Remote shell access and command execution interfaces |
| RCE | Code Execution | Shell commands, eval() injection, dynamic code execution |
| OBF | Obfuscation | Base64 concatenation, variable function calls, goto obfuscation, encoded strings |
| CRED | Credential Theft | Form handlers, POST data exfiltration, login interception |
| PHI | Phishing | Phishing form and page detection |
| DRP | Dropper | Malware download and deployment scripts |
| EXP | Exploit | Vulnerability exploitation payloads |
| SEO | SEO Spam | SEO injection and hidden link spam |
| DEFC | Defacement | Website defacement markers |
| PL | Perl | Perl-based attack scripts |

Rules can be selectively enabled or disabled by category or individual rule code through the YAML configuration file. Custom rules can also be defined alongside the built-in set.

### CLI Commands

LyxBoSa provides four subcommands:

- **`scan`** -- Scan one or more directories for malicious files, with options for recursive traversal, quick mode, dry-run, verbose output, and configurable output format.
- **`check`** -- Check a single file for malicious content (interactive prompt if no file is specified).
- **`validate-config`** -- Validate a YAML configuration file for correctness.
- **`init-config`** -- Generate a default configuration file to stdout.

### Key Features

- Recursive directory scanning with configurable file size limits (default 5 MB) and symlink control.
- File inclusion/exclusion filters using glob patterns.
- Severity levels (Critical, High, Medium, Low) for prioritizing findings.
- Quarantine support with optional directory structure preservation.
- Report generation in Text, JSON, and CSV formats, written incrementally as the scan
  proceeds so an interrupted run still leaves a complete, well-formed report.
- `-O/--output-file` writes the report to a file while the terminal keeps the readable
  text view, so `--output` selects the file's format rather than what you are watching.
  Honors `actions.report.{file,format,console}` from the configuration.
- Email alert notifications.
- Graceful interrupt handling: the first Ctrl+C finishes the report it has so far and
  exits 130; a second one leaves immediately.
- Progress reporting that follows the streams. The report goes to stdout, progress and
  diagnostics go to stderr, so `lyxbosa scan /var/www > report.txt` shows live progress
  on the terminal while the report accumulates in the file - and the file never
  contains a single escape sequence.
- ANSI colored terminal output, detected per stream and controlled with
  `--color=auto|always|never` (`--no-ansi` is kept as an alias). `NO_COLOR`,
  `CLICOLOR_FORCE` and `TERM=dumb` are honored.
- Live progress showing percentage, files and directories scanned, the severity
  breakdown of what has been found so far, throughput and an ETA. The file count runs
  concurrently with the scan, so scanning starts immediately rather than after a silent
  counting pass; `--no-precount` skips it entirely.
- Progress display selectable with `--progress=auto|plain|none`, `--no-interactive`
  and `-q/--quiet`.
