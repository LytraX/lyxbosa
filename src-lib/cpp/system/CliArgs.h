#pragma once

#include <string>
#include <optional>
#include <vector>
#include <filesystem>
#include <argparse/argparse.hpp>
#include "config/Types.h"

namespace lyxbosa {

enum class Command {
    None,
    Help,
    Scan,
    Check,
    ValidateConfig,
    InitConfig
};

struct CliArgs {
    Command command = Command::None;
    bool success = true;
    std::string errorMessage;

    // Scan command options
    std::vector<std::string> directories;
    std::optional<std::string> configFile;
    ReportFormat outputFormat = ReportFormat::Text;
    bool outputFormatExplicit = false;      // --output was given, so it beats the config
    std::optional<std::string> outputFile;  // -O/--output-file
    bool quick = false;
    bool dryRun = false;
    bool force = false;
    bool verbose = false;  // Verbose output (detailed view)
    std::optional<bool> recursive;
    ProgressWhen progress = ProgressWhen::Auto;
    bool quiet = false;          // Suppress progress and the scan summary
    bool noInteractive = false;  // Never take over stdout with an in-place display

    // Check command options
    std::optional<std::string> checkFile;

    // Validate-config command options
    std::optional<std::string> validateConfigFile;

    // Global options
    bool noAnsi = false;              // Older spelling of --color=never
    ColorWhen color = ColorWhen::Auto;

    // Parse command-line arguments
    static CliArgs parse(int argc, char* argv[]);

    // Get usage/help text (full reference for every command and option)
    static std::string getHelpText();
};

inline std::string CliArgs::getHelpText() {
    return
        "LyxBoSa " LYXBOSA_VERSION " - Modern malware/bot signature scanner\n"
        "\n"
        "Usage:\n"
        "  lyxbosa [--color WHEN] <command> [options]\n"
        "  lyxbosa --help | --version\n"
        "\n"
        "Commands:\n"
        "  scan               Scan directories for malicious files\n"
        "  check              Check a single file for malicious content\n"
        "  validate-config    Validate a configuration file\n"
        "  init-config        Generate default configuration to stdout\n"
        "\n"
        "Global options (before the command):\n"
        "  -h, --help         Show this help message and exit\n"
        "  -v, --version      Show version information and exit\n"
        "      --color WHEN   Colorize output: auto, always or never (default: auto).\n"
        "                     'auto' colors a stream only when it is a terminal, so a\n"
        "                     redirected report never contains escape sequences.\n"
        "                     Also accepted after any command.\n"
        "      --no-ansi      Alias for --color=never (also accepted after any command)\n"
        "\n"
        "scan [options] [DIRECTORY...]\n"
        "  Scan one or more directories for malicious files.\n"
        "\n"
        "  DIRECTORY...       Directories to scan; overrides scan.directories from the\n"
        "                     configuration. Prompts for a directory when omitted and\n"
        "                     no --config is given.\n"
        "  -c, --config FILE  Configuration file path (default: built-in configuration)\n"
        "  -o, --output FORMAT\n"
        "                     Report format: text, json or csv (default: text)\n"
        "  -O, --output-file FILE\n"
        "                     Write the report to FILE instead of stdout. --output then\n"
        "                     selects that file's format, while the terminal keeps the\n"
        "                     readable text view. Overrides actions.report.file from the\n"
        "                     configuration; parent directories are created.\n"
        "  -r, --recursive    Recurse into subdirectories\n"
        "      --no-recursive Do not recurse into subdirectories\n"
        "      --quick        Quick scan: limit files to 1 MB and disable quarantine\n"
        "      --dry-run      Report only; never quarantine files\n"
        "      --force        Skip the configuration summary and confirmation prompt\n"
        "  -v, --verbose      Verbose output with full match details\n"
        "      --progress WHEN\n"
        "                     Progress display: auto, plain or none (default: auto).\n"
        "                     'auto' updates in place on stdout when stdout is a\n"
        "                     terminal, and otherwise prints a single throttled line\n"
        "                     to stderr so that 'lyxbosa scan ... > report.txt' still\n"
        "                     shows progress. 'plain' always uses the stderr line.\n"
        "      --no-interactive\n"
        "                     Never take over stdout; same as --progress=plain\n"
        "  -q, --quiet        Suppress progress and the scan summary\n"
        "      --color WHEN   Colorize output: auto, always or never\n"
        "      --no-ansi      Alias for --color=never\n"
        "  -h, --help         Show help for the scan command\n"
        "\n"
        "check [options] [FILE]\n"
        "  Check a single file for malicious content. Quarantine is always disabled.\n"
        "\n"
        "  FILE               File to check; prompts for a path when omitted\n"
        "  -c, --config FILE  Configuration file path (default: built-in configuration)\n"
        "      --color WHEN   Colorize output: auto, always or never\n"
        "      --no-ansi      Alias for --color=never\n"
        "  -h, --help         Show help for the check command\n"
        "\n"
        "validate-config [options] FILE\n"
        "  Validate a configuration file and report its rule, pattern and directory\n"
        "  counts.\n"
        "\n"
        "  FILE               Configuration file to validate (required)\n"
        "      --color WHEN   Colorize output: auto, always or never\n"
        "      --no-ansi      Alias for --color=never\n"
        "  -h, --help         Show help for the validate-config command\n"
        "\n"
        "init-config [options]\n"
        "  Print the default configuration to stdout.\n"
        "\n"
        "      --color WHEN   Colorize output: auto, always or never\n"
        "      --no-ansi      Alias for --color=never\n"
        "  -h, --help         Show help for the init-config command\n"
        "\n"
        "Configuration:\n"
        "  Without --config the built-in default configuration is used. Write it to a\n"
        "  file with 'lyxbosa init-config > lyxbosa.yaml', edit it, then pass it with\n"
        "  --config. The configuration file controls the maximum file size (5 MB by\n"
        "  default), include/exclude globs, symlink handling, enabled rule categories\n"
        "  and custom rules, quarantine, report output and email alerts.\n"
        "\n"
        "Exit codes:\n"
        "  0    Success - no matches found, or the command was cancelled\n"
        "  1    Error - invalid arguments, missing file or invalid configuration\n"
        "  2    Matches found\n"
        "  130  Interrupted with Ctrl+C\n"
        "\n"
        "Examples:\n"
        "  lyxbosa scan /var/www --recursive --force\n"
        "  lyxbosa scan /var/www -o json > report.json\n"
        "  lyxbosa scan /var/www -O report.json -o json --force\n"
        "  lyxbosa scan -c lyxbosa.yaml --dry-run --verbose\n"
        "  lyxbosa check suspicious.php\n"
        "  lyxbosa init-config > lyxbosa.yaml\n"
        "  lyxbosa validate-config lyxbosa.yaml\n";
}

inline CliArgs CliArgs::parse(int argc, char* argv[]) {
    CliArgs result;

    // Help is handled by us (getHelpText covers every command), version by argparse
    argparse::ArgumentParser program("lyxbosa", LYXBOSA_VERSION,
                                     argparse::default_arguments::version);
    program.add_description("Modern malware/bot signature scanner");

    // Global options
    program.add_argument("-h", "--help")
        .help("Show help message and exit")
        .default_value(false)
        .implicit_value(true)
        .nargs(0);

    program.add_argument("--no-ansi")
        .help("Alias for --color=never")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("--color")
        .help("Colorize output: auto, always or never")
        .default_value(std::string("auto"))
        .metavar("WHEN");

    // Subcommands only get --help; -v is reserved for --verbose on scan
    constexpr auto subcommandArgs = argparse::default_arguments::help;

    // Scan subcommand
    argparse::ArgumentParser scanCmd("scan", LYXBOSA_VERSION, subcommandArgs);
    scanCmd.add_description("Scan directories for malicious files");
    scanCmd.add_epilog(
        "Directories given here override scan.directories from the configuration.\n"
        "Exit codes: 0 = no matches, 1 = error, 2 = matches found, 130 = interrupted.\n"
        "\n"
        "Examples:\n"
        "  lyxbosa scan /var/www --recursive --force\n"
        "  lyxbosa scan /var/www -o json > report.json\n"
        "  lyxbosa scan -c lyxbosa.yaml --dry-run --verbose");

    scanCmd.add_argument("directories")
        .help("Directories to scan (prompts if omitted and no --config given)")
        .nargs(argparse::nargs_pattern::any);

    scanCmd.add_argument("-c", "--config")
        .help("Configuration file path (default: built-in configuration)")
        .metavar("FILE");

    scanCmd.add_argument("-o", "--output")
        .help("Report format: text, json or csv")
        .default_value(std::string("text"))
        .metavar("FORMAT");

    scanCmd.add_argument("-O", "--output-file")
        .help("Write the report to FILE instead of stdout")
        .metavar("FILE");

    scanCmd.add_argument("--quick")
        .help("Quick scan: limit files to 1 MB and disable quarantine")
        .default_value(false)
        .implicit_value(true);

    scanCmd.add_argument("--dry-run")
        .help("Report only, no actions (quarantine)")
        .default_value(false)
        .implicit_value(true);

    scanCmd.add_argument("--force")
        .help("Skip the summary and confirmation prompt")
        .default_value(false)
        .implicit_value(true);

    scanCmd.add_argument("-r", "--recursive")
        .help("Recurse subdirectories")
        .default_value(false)
        .implicit_value(true);

    scanCmd.add_argument("--no-recursive")
        .help("Don't recurse subdirectories")
        .default_value(false)
        .implicit_value(true);

    scanCmd.add_argument("-v", "--verbose")
        .help("Verbose output with full match details")
        .default_value(false)
        .implicit_value(true);

    scanCmd.add_argument("--progress")
        .help("Progress display: auto, plain or none")
        .default_value(std::string("auto"))
        .metavar("WHEN");

    scanCmd.add_argument("--no-interactive")
        .help("Never take over stdout; same as --progress=plain")
        .default_value(false)
        .implicit_value(true);

    scanCmd.add_argument("-q", "--quiet")
        .help("Suppress progress and the scan summary")
        .default_value(false)
        .implicit_value(true);

    scanCmd.add_argument("--color")
        .help("Colorize output: auto, always or never")
        .default_value(std::string("auto"))
        .metavar("WHEN");

    scanCmd.add_argument("--no-ansi")
        .help("Alias for --color=never")
        .default_value(false)
        .implicit_value(true);

    // Check subcommand
    argparse::ArgumentParser checkCmd("check", LYXBOSA_VERSION, subcommandArgs);
    checkCmd.add_description("Check a single file for malicious content");
    checkCmd.add_epilog(
        "Quarantine is always disabled for a single file check.\n"
        "Exit codes: 0 = no matches, 1 = error, 2 = matches found.\n"
        "\n"
        "Example:\n"
        "  lyxbosa check suspicious.php");

    checkCmd.add_argument("file")
        .help("File to check (prompts if not provided)")
        .nargs(argparse::nargs_pattern::optional);

    checkCmd.add_argument("-c", "--config")
        .help("Configuration file path (default: built-in configuration)")
        .metavar("FILE");

    checkCmd.add_argument("--color")
        .help("Colorize output: auto, always or never")
        .default_value(std::string("auto"))
        .metavar("WHEN");

    checkCmd.add_argument("--no-ansi")
        .help("Alias for --color=never")
        .default_value(false)
        .implicit_value(true);

    // Validate-config subcommand
    argparse::ArgumentParser validateCmd("validate-config", LYXBOSA_VERSION, subcommandArgs);
    validateCmd.add_description("Validate a configuration file");
    validateCmd.add_epilog(
        "Exit codes: 0 = valid, 1 = invalid or unreadable.\n"
        "\n"
        "Example:\n"
        "  lyxbosa validate-config lyxbosa.yaml");

    validateCmd.add_argument("file")
        .help("Configuration file to validate")
        .required();

    validateCmd.add_argument("--color")
        .help("Colorize output: auto, always or never")
        .default_value(std::string("auto"))
        .metavar("WHEN");

    validateCmd.add_argument("--no-ansi")
        .help("Alias for --color=never")
        .default_value(false)
        .implicit_value(true);

    // Init-config subcommand
    argparse::ArgumentParser initCmd("init-config", LYXBOSA_VERSION, subcommandArgs);
    initCmd.add_description("Generate default configuration to stdout");
    initCmd.add_epilog(
        "Example:\n"
        "  lyxbosa init-config > lyxbosa.yaml");

    initCmd.add_argument("--color")
        .help("Colorize output: auto, always or never")
        .default_value(std::string("auto"))
        .metavar("WHEN");

    initCmd.add_argument("--no-ansi")
        .help("Alias for --color=never")
        .default_value(false)
        .implicit_value(true);

    // Add subcommands
    program.add_subparser(scanCmd);
    program.add_subparser(checkCmd);
    program.add_subparser(validateCmd);
    program.add_subparser(initCmd);

    try {
        program.parse_args(argc, argv);
    } catch (const std::exception& err) {
        result.success = false;
        result.errorMessage = err.what();
        return result;
    }

    // Global --no-ansi applies to every command; each command also accepts its own
    const bool globalNoAnsi = program.get<bool>("--no-ansi");
    result.noAnsi = globalNoAnsi;

    // --color is accepted globally and per command; the command's spelling wins
    // when both are given. Applied only when explicitly used, so that a command's
    // default "auto" does not silently undo a global --color=never.
    auto applyColor = [&result](const argparse::ArgumentParser& parser) {
        if (!parser.is_used("--color")) {
            return true;
        }
        const auto value = parser.get<std::string>("--color");
        if (!colorWhenFromString(value, result.color)) {
            result.success = false;
            result.errorMessage =
                "Invalid --color value: '" + value + "'. Valid values are: auto, always, never";
            return false;
        }
        return true;
    };

    if (!applyColor(program)) {
        return result;
    }

    if (program.get<bool>("--help")) {
        result.command = Command::Help;
        return result;
    }

    // Determine which subcommand was used
    if (program.is_subcommand_used("scan")) {
        result.command = Command::Scan;

        auto dirs = scanCmd.get<std::vector<std::string>>("directories");
        result.directories = std::move(dirs);

        if (auto config = scanCmd.present<std::string>("--config")) {
            result.configFile = *config;
        }

        // Validated here rather than with choices(): argparse reports an unknown
        // choice as a stray positional, which hides the real mistake
        const auto format = scanCmd.get<std::string>("--output");
        if (format != "text" && format != "json" && format != "csv") {
            result.success = false;
            result.errorMessage =
                "Invalid output format: '" + format + "'. Valid formats are: text, json, csv";
            return result;
        }
        result.outputFormat = reportFormatFromString(format);
        result.outputFormatExplicit = scanCmd.is_used("--output");

        if (auto outputFile = scanCmd.present<std::string>("--output-file")) {
            result.outputFile = *outputFile;
        }
        result.quick = scanCmd.get<bool>("--quick");
        result.dryRun = scanCmd.get<bool>("--dry-run");
        result.force = scanCmd.get<bool>("--force");

        if (scanCmd.get<bool>("--recursive")) {
            result.recursive = true;
        } else if (scanCmd.get<bool>("--no-recursive")) {
            result.recursive = false;
        }

        result.verbose = scanCmd.get<bool>("--verbose");
        result.noAnsi = globalNoAnsi || scanCmd.get<bool>("--no-ansi");

        const auto progressValue = scanCmd.get<std::string>("--progress");
        if (!progressWhenFromString(progressValue, result.progress)) {
            result.success = false;
            result.errorMessage = "Invalid --progress value: '" + progressValue +
                                  "'. Valid values are: auto, plain, none";
            return result;
        }

        result.noInteractive = scanCmd.get<bool>("--no-interactive");
        result.quiet = scanCmd.get<bool>("--quiet");

        if (!applyColor(scanCmd)) {
            return result;
        }

    } else if (program.is_subcommand_used("check")) {
        result.command = Command::Check;

        // File is now optional - will prompt if not provided
        if (auto file = checkCmd.present<std::string>("file")) {
            result.checkFile = *file;
        }

        if (auto config = checkCmd.present<std::string>("--config")) {
            result.configFile = *config;
        }

        result.noAnsi = globalNoAnsi || checkCmd.get<bool>("--no-ansi");
        if (!applyColor(checkCmd)) {
            return result;
        }

    } else if (program.is_subcommand_used("validate-config")) {
        result.command = Command::ValidateConfig;
        result.validateConfigFile = validateCmd.get<std::string>("file");
        result.noAnsi = globalNoAnsi || validateCmd.get<bool>("--no-ansi");
        if (!applyColor(validateCmd)) {
            return result;
        }

    } else if (program.is_subcommand_used("init-config")) {
        result.command = Command::InitConfig;
        result.noAnsi = globalNoAnsi || initCmd.get<bool>("--no-ansi");
        if (!applyColor(initCmd)) {
            return result;
        }

    } else {
        // No subcommand - show help
        result.success = false;
        result.errorMessage = getHelpText();
    }

    // --no-ansi is the older, coarser spelling and always wins.
    if (result.noAnsi) {
        result.color = ColorWhen::Never;
    }

    return result;
}

}  // namespace lyxbosa
