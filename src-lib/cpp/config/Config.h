#pragma once

#include "Rules.h"
#include <string>
#include <string_view>
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

    // Print configuration summary to stdout (for confirmation prompt)
    static void printSummary(const AppConfig& config);
};

}  // namespace lyxbosa
