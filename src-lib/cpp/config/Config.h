#pragma once

#include "Rules.h"
#include <optional>
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

    // Why a value in this configuration that becomes a path, or is matched against one, is not
    // valid UTF-8 - naming the key, the entry of a list, the byte and its offset, and telling
    // the operator to save the file as UTF-8 - or nullopt when every such value is.
    //
    // A question about the text alone, answered the same on every platform. validate() asks it
    // only where kPathsAreUtf16 says a path is UTF-16, because only there can such a value name
    // nothing; on Linux and macOS the same bytes are a real name and are accepted.
    static std::optional<std::string> pathValueNotUtf8(const AppConfig& config);

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
