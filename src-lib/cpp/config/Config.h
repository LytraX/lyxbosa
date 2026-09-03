#pragma once

#include "Rules.h"
#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <stdexcept>

namespace lyxbosa {

// Exception for configuration errors
class ConfigError : public std::runtime_error {
public:
    explicit ConfigError(const std::string& msg) : std::runtime_error(msg) {}
};

// YAML configuration loader
class Config {
public:
    // Load configuration from a YAML file
    // Throws ConfigError if file cannot be read or parsed
    static AppConfig loadFromFile(const std::filesystem::path& path);

    // Load configuration from a YAML string
    // Throws ConfigError if YAML is invalid
    static AppConfig loadFromString(std::string_view yaml);

    // Generate default configuration as YAML string
    static std::string generateDefault();

    // Validate a configuration, returns error message or empty string if valid
    static std::string validate(const AppConfig& config);

    // Settings that are legal but worth saying out loud - a guard turned off,
    // mostly. Returns one line per warning, empty when there is nothing to say.
    static std::vector<std::string> warnings(const AppConfig& config);

    // Print configuration summary to stdout (for confirmation prompt)
    // The pre-scan confirmation summary.
    //
    // `width` is the terminal width, used to flow the filter lists instead of
    // printing 127 patterns one per line. `verbose` lists every pattern; without it
    // a long list is summarised, because the prompt exists so an operator can check
    // *what will be touched*, and burying that under six screens of globs defeats it.
    static void printSummary(const AppConfig& config, size_t width = 80,
                             bool verbose = false);
};

}  // namespace lyxbosa
