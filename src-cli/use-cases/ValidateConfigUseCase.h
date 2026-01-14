#pragma once

#include "infrastructure/Terminal.h"
#include "config/Config.h"
#include "system/CliArgs.h"
#include <fmt/core.h>

namespace lyxbosa {

// Orchestrates the validate-config command workflow
class ValidateConfigUseCase {
public:
    explicit ValidateConfigUseCase(const Terminal& terminal)
        : terminal_(terminal) {}

    int execute(const CliArgs& args) {
        if (!args.validateConfigFile) {
            fmt::print(stderr, "Error: No config file specified\n");
            return 1;
        }

        try {
            auto config = Config::loadFromFile(*args.validateConfigFile);
            auto error = Config::validate(config);

            if (!error.empty()) {
                terminal_.printErr(Terminal::error(), "Validation error: {}\n", error);
                return 1;
            }

            terminal_.print(Terminal::success(), "Configuration is valid.\n");
            fmt::print("  Rules: {}\n", config.rules.size());

            size_t patternCount = 0;
            for (const auto& rule : config.rules) {
                patternCount += rule.patterns.size();
            }
            fmt::print("  Patterns: {}\n", patternCount);
            fmt::print("  Directories: {}\n", config.scan.directories.size());

            return 0;

        } catch (const ConfigError& e) {
            terminal_.printErr(Terminal::error(), "Error: {}\n", e.what());
            return 1;
        }
    }

private:
    const Terminal& terminal_;
};

}  // namespace lyxbosa
