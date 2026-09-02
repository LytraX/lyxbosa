#pragma once

#include "utils/SafeText.h"

#include "infrastructure/Terminal.h"
#include "infrastructure/TerminalCaps.h"
#include "infrastructure/InputPrompt.h"
#include "infrastructure/PathUtils.h"
#include "config/Config.h"
#include "core/Scanner.h"
#include "system/CliArgs.h"
#include <filesystem>
#include <map>

namespace lyxbosa {

// Orchestrates the check (single file) command workflow
class CheckUseCase {
public:
    CheckUseCase(const Terminal& terminal, const TerminalCaps& caps)
        : terminal_(terminal), caps_(caps) {}

    int execute(CliArgs& args) {
        // Prompt for file if none provided
        if (!args.checkFile) {
            if (!caps_.stdinIsTty()) {
                terminal_.printErr(Terminal::error(),
                    "Error: No file given and stdin is not a terminal.\n"
                    "Pass a file path on the command line.\n");
                return 1;
            }

            InputPrompt prompt(terminal_);
            auto file = prompt.promptFile("File to check");

            if (!file || file->empty()) {
                fmt::print("Check cancelled.\n");
                return 0;
            }

            args.checkFile = *file;
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

        // A container is checked like the directory it is: findings inside it are
        // reported as they are found, addressed `archive.zip!member/path.php`.
        std::vector<FileResult> members;
        scanner.setFileResultCallback([&members](const FileResult& member) {
            members.push_back(member);
        });

        auto result = scanner.scanFile(filePath);

        if (result.matches.empty() && members.empty()) {
            terminal_.print(Terminal::success(), "No matches found in: {}\n", filePath.string());
            return 0;
        }

        if (!result.matches.empty()) {
            terminal_.print(Terminal::info(), "File: {}\n", filePath.string());
            fmt::print("Matches: {}\n\n", result.matches.size());
            printCompactMatches(result.matches);
        }

        for (const auto& member : members) {
            terminal_.print(Terminal::info(), "\nMember: {}\n", pathForDisplay(member.path));
            fmt::print("Matches: {}\n\n", member.matches.size());
            printCompactMatches(member.matches);
        }

        return 2;  // Matches found
    }

private:
    // Group key: rule category + line number
    struct MatchGroup {
        const FileMatch* first;  // First match (for context display)
        size_t count;
        size_t minCol;
        size_t maxCol;
    };

    void printCompactMatches(const std::vector<FileMatch>& matches) const {
        // Group matches by category+line
        std::map<std::string, MatchGroup> groups;

        for (const auto& match : matches) {
            std::string key = match.category + ":" + std::to_string(match.line);

            auto it = groups.find(key);
            if (it == groups.end()) {
                groups[key] = {&match, 1, match.column, match.column};
            } else {
                it->second.count++;
                it->second.minCol = std::min(it->second.minCol, match.column);
                it->second.maxCol = std::max(it->second.maxCol, match.column);
            }
        }

        // Print grouped matches
        for (const auto& [key, group] : groups) {
            const auto& match = *group.first;

            fmt::print("  ");
            switch (match.severity) {
                case Severity::Critical:
                    terminal_.print(Terminal::critical(), "[CRITICAL]");
                    break;
                case Severity::High:
                    terminal_.print(Terminal::high(), "[HIGH]");
                    break;
                case Severity::Medium:
                    terminal_.print(Terminal::medium(), "[MEDIUM]");
                    break;
                case Severity::Low:
                    terminal_.print(Terminal::low(), "[LOW]");
                    break;
            }

            // Show line with column range if multiple hits
            if (group.count > 1) {
                fmt::print(" {} ({}:{}-{}) - {}", match.ruleName, match.line,
                          group.minCol, group.maxCol, match.category);
                terminal_.print(Terminal::medium(), " x{} hits", group.count);
                fmt::print("\n");
            } else {
                fmt::print(" {} ({}:{}) - {}\n", match.ruleName, match.line, match.column, match.category);
            }

            // Show context only for first match in group
            if (!match.context.empty()) {
                terminal_.print(Terminal::context(), "    {}\n", match.context);
            }
        }
    }

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
    const TerminalCaps& caps_;
};

}  // namespace lyxbosa
