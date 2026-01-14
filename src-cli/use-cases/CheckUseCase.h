#pragma once

#include "infrastructure/Terminal.h"
#include "infrastructure/ResultPrinter.h"
#include "config/Config.h"
#include "core/Scanner.h"
#include "system/CliArgs.h"
#include <filesystem>

namespace lyxbosa {

// Orchestrates the check (single file) command workflow
class CheckUseCase {
public:
    CheckUseCase(const Terminal& terminal, const ResultPrinter& printer)
        : terminal_(terminal), printer_(printer) {}

    int execute(const CliArgs& args) {
        if (!args.checkFile) {
            fmt::print(stderr, "Error: No file specified\n");
            return 1;
        }

        std::filesystem::path filePath(*args.checkFile);
        if (!std::filesystem::exists(filePath)) {
            terminal_.printErr(Terminal::error(), "Error: File not found: {}\n", filePath.string());
            return 1;
        }

        // Load configuration
        AppConfig config;
        if (!loadConfig(args, config)) {
            return 1;
        }

        // Disable quarantine for single file check
        config.actions.quarantine.enabled = false;

        Scanner scanner(config);
        auto result = scanner.scanFile(filePath);

        if (result.matches.empty()) {
            terminal_.print(Terminal::success(), "No matches found in: {}\n", filePath.string());
            return 0;
        }

        terminal_.print(Terminal::info(), "File: {}\n", filePath.string());
        fmt::print("Matches: {}\n\n", result.matches.size());

        for (const auto& match : result.matches) {
            printer_.printMatch(match);
        }

        return 2;  // Matches found
    }

private:
    bool loadConfig(const CliArgs& args, AppConfig& config) {
        if (args.configFile) {
            try {
                config = Config::loadFromFile(*args.configFile);
            } catch (const ConfigError& e) {
                terminal_.printErr(Terminal::error(), "Error: {}\n", e.what());
                return false;
            }
        } else {
            try {
                config = Config::loadFromString(Config::generateDefault());
            } catch (const ConfigError& e) {
                terminal_.printErr(Terminal::error(), "Error: {}\n", e.what());
                return false;
            }
        }
        return true;
    }

    const Terminal& terminal_;
    const ResultPrinter& printer_;
};

}  // namespace lyxbosa
