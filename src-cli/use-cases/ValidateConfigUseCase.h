#pragma once

#include "infrastructure/Delivery.h"
#include "infrastructure/PathUtils.h"
#include "infrastructure/Terminal.h"
#include "config/Config.h"
#include "system/CliArgs.h"
#include <fmt/base.h>

namespace lyxbosa {

// Orchestrates the validate-config command workflow
class ValidateConfigUseCase {
public:
    explicit ValidateConfigUseCase(const Terminal& terminal)
        : terminal_(terminal) {}

    // "Configuration is valid." and the counts under it are the answer, and a script that
    // runs `lyxbosa validate-config site.yaml > check.log` reads the exit code as saying they
    // were written. So they go through one CheckedOutput and are asked whether they arrived -
    // see Delivery.h. A refusal of the configuration is on stderr and keeps its 1.
    int execute(const CliArgs& args) {
        CheckedOutput out(stdout);
        const int code = run(args, out);
        return finishAnswerOnStandardOutput(terminal_, out, "the validation result", code);
    }

private:
    int run(const CliArgs& args, CheckedOutput& out) {
        if (!args.validateConfigFile) {
            fmt::print(stderr, "Error: No config file specified\n");
            return 1;
        }

        try {
            auto config = Config::loadFromFile(pathFromUtf8(*args.validateConfigFile));
            auto error = Config::validate(config);

            if (!error.empty()) {
                terminal_.printErr(Terminal::error(), "Validation error: {}\n", error);
                return 1;
            }

            terminal_.printTo(out, Terminal::success(), "Configuration is valid.\n");
            out.print("  Rules: {}\n", config.rules.size());

            size_t patternCount = 0;
            for (const auto& rule : config.rules) {
                patternCount += rule.patterns.size();
            }
            out.print("  Patterns: {}\n", patternCount);
            out.print("  Directories: {}\n", config.scan.directories.size());

            return 0;

        } catch (const ConfigError& e) {
            terminal_.printErr(Terminal::error(), "Error: {}\n", e.what());
            return 1;
        }
    }

    const Terminal& terminal_;
};

}  // namespace lyxbosa
