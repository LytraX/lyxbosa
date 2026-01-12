#pragma once

#include <string>
#include <optional>
#include <vector>
#include <filesystem>
#include <argparse/argparse.hpp>

namespace CliArgs {
    struct ParseResult {
        bool success = true;
        std::string errorMessage;
        std::optional<std::string> filePath;
        bool showHelp = false;
        bool showVersion = false;
    };

    /**
     * Parse command-line arguments
     * @param argc Argument count
     * @param argv Argument values
     * @return ParseResult with parsed data or error
     */
    inline ParseResult parse(int argc, char* argv[]) {
        ParseResult result;

        argparse::ArgumentParser program("LyxBoSa", "0.0.1");

        program.add_argument("file")
            .help("Path to file to open")
            .nargs(argparse::nargs_pattern::optional);

        try {
            program.parse_args(argc, argv);
        } catch (const std::exception& err) {
            result.success = false;
            result.errorMessage = std::string(err.what()) + "\n\n" + program.help().str();
            return result;
        }

        // Check if file argument was provided
        if (auto file = program.present("file")) {
            std::filesystem::path path(*file);

            // Check if file exists
            if (!std::filesystem::exists(path)) {
                result.success = false;
                result.errorMessage = "File not found: " + path.string();
                return result;
            }

            // Pass absolute path to app
            result.filePath = std::filesystem::absolute(path).string();
        }

        return result;
    }

    /**
     * Get help text
     */
    inline std::string getHelpText() {
        argparse::ArgumentParser program("LyxBoSa", "0.0.1");
        program.add_argument("file")
            .help("Path to file to open")
            .nargs(argparse::nargs_pattern::optional);
        return program.help().str();
    }
}
