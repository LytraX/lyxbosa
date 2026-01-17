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
    bool quick = false;
    bool dryRun = false;
    bool force = false;
    bool verbose = false;  // Verbose output (detailed view)
    std::optional<bool> recursive;

    // Check command options
    std::optional<std::string> checkFile;

    // Validate-config command options
    std::optional<std::string> validateConfigFile;

    // Global options
    bool noAnsi = false;

    // Parse command-line arguments
    static CliArgs parse(int argc, char* argv[]);

    // Get usage/help text
    static std::string getHelpText();
};

inline CliArgs CliArgs::parse(int argc, char* argv[]) {
    CliArgs result;

    argparse::ArgumentParser program("lyxbosa", "1.0.0");
    program.add_description("Modern malware/bot signature scanner");

    // Global options
    program.add_argument("--no-ansi")
        .help("Disable colored output")
        .default_value(false)
        .implicit_value(true);

    // Scan subcommand
    argparse::ArgumentParser scanCmd("scan");
    scanCmd.add_description("Scan directories for malicious files");

    scanCmd.add_argument("directories")
        .help("Directories to scan")
        .nargs(argparse::nargs_pattern::any);

    scanCmd.add_argument("-c", "--config")
        .help("Configuration file path")
        .metavar("FILE");

    scanCmd.add_argument("-o", "--output")
        .help("Output format (text, json, csv)")
        .default_value(std::string("text"))
        .metavar("FORMAT");

    scanCmd.add_argument("--quick")
        .help("Quick scan (skip large files)")
        .default_value(false)
        .implicit_value(true);

    scanCmd.add_argument("--dry-run")
        .help("Report only, no actions (quarantine)")
        .default_value(false)
        .implicit_value(true);

    scanCmd.add_argument("--force")
        .help("Skip confirmation prompt")
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

    scanCmd.add_argument("--verbose")
        .help("Verbose output with full match details")
        .default_value(false)
        .implicit_value(true);

    scanCmd.add_argument("--no-ansi")
        .help("Disable colored output")
        .default_value(false)
        .implicit_value(true);

    // Check subcommand
    argparse::ArgumentParser checkCmd("check");
    checkCmd.add_description("Check a single file for malicious content");

    checkCmd.add_argument("file")
        .help("File to check (prompts if not provided)")
        .nargs(argparse::nargs_pattern::optional);

    checkCmd.add_argument("-c", "--config")
        .help("Configuration file path")
        .metavar("FILE");

    checkCmd.add_argument("--no-ansi")
        .help("Disable colored output")
        .default_value(false)
        .implicit_value(true);

    // Validate-config subcommand
    argparse::ArgumentParser validateCmd("validate-config");
    validateCmd.add_description("Validate a configuration file");

    validateCmd.add_argument("file")
        .help("Configuration file to validate")
        .required();

    validateCmd.add_argument("--no-ansi")
        .help("Disable colored output")
        .default_value(false)
        .implicit_value(true);

    // Init-config subcommand
    argparse::ArgumentParser initCmd("init-config");
    initCmd.add_description("Generate default configuration to stdout");

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

    // Determine which subcommand was used
    if (program.is_subcommand_used("scan")) {
        result.command = Command::Scan;

        auto dirs = scanCmd.get<std::vector<std::string>>("directories");
        result.directories = std::move(dirs);

        if (auto config = scanCmd.present<std::string>("--config")) {
            result.configFile = *config;
        }

        result.outputFormat = reportFormatFromString(scanCmd.get<std::string>("--output"));
        result.quick = scanCmd.get<bool>("--quick");
        result.dryRun = scanCmd.get<bool>("--dry-run");
        result.force = scanCmd.get<bool>("--force");

        if (scanCmd.get<bool>("--recursive")) {
            result.recursive = true;
        } else if (scanCmd.get<bool>("--no-recursive")) {
            result.recursive = false;
        }

        result.verbose = scanCmd.get<bool>("--verbose");
        result.noAnsi = scanCmd.get<bool>("--no-ansi");

    } else if (program.is_subcommand_used("check")) {
        result.command = Command::Check;

        // File is now optional - will prompt if not provided
        if (auto file = checkCmd.present<std::string>("file")) {
            result.checkFile = *file;
        }

        if (auto config = checkCmd.present<std::string>("--config")) {
            result.configFile = *config;
        }

        result.noAnsi = checkCmd.get<bool>("--no-ansi");

    } else if (program.is_subcommand_used("validate-config")) {
        result.command = Command::ValidateConfig;
        result.validateConfigFile = validateCmd.get<std::string>("file");
        result.noAnsi = validateCmd.get<bool>("--no-ansi");

    } else if (program.is_subcommand_used("init-config")) {
        result.command = Command::InitConfig;

    } else {
        // No subcommand - show help
        result.success = false;
        result.errorMessage = program.help().str();
    }

    return result;
}

inline std::string CliArgs::getHelpText() {
    argparse::ArgumentParser program("lyxbosa", "1.0.0");
    program.add_description("Modern malware/bot signature scanner");
    return program.help().str();
}

}  // namespace lyxbosa
