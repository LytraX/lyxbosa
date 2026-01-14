#pragma once

#include "infrastructure/Terminal.h"
#include "infrastructure/ResultPrinter.h"
#include "config/Config.h"
#include "core/Scanner.h"
#include "system/CliArgs.h"
#include <chrono>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace lyxbosa {

// Orchestrates the scan command workflow
class ScanUseCase {
public:
    ScanUseCase(const Terminal& terminal, const ResultPrinter& printer)
        : terminal_(terminal), printer_(printer) {}

    int execute(const CliArgs& args) {
        // Load configuration
        AppConfig config;
        if (!loadConfig(args, config)) {
            return 1;
        }

        // Apply CLI overrides
        applyOverrides(args, config);

        // Validate directories
        if (config.scan.directories.empty()) {
            terminal_.printErr(Terminal::error(),
                "Error: No directories to scan. Specify directories on command line or in config file.\n");
            return 1;
        }

        // Show confirmation unless forced
        if (!args.force) {
            Config::printSummary(config);

            if (args.dryRun) {
                terminal_.print(Terminal::warning(), "[DRY RUN MODE - No files will be quarantined]\n\n");
            }

            if (!confirmScan()) {
                fmt::print("Scan cancelled.\n");
                return 0;
            }
        }

        // Run scan
        return runScan(config, args);
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
                terminal_.printErr(Terminal::error(), "Error loading default config: {}\n", e.what());
                return false;
            }
        }
        return true;
    }

    void applyOverrides(const CliArgs& args, AppConfig& config) {
        if (!args.directories.empty()) {
            config.scan.directories = args.directories;
        }

        if (args.recursive.has_value()) {
            config.scan.recursive = *args.recursive;
        }

        if (args.quick) {
            config.scan.maxFileSize = 1024 * 1024;  // 1MB in quick mode
            config.actions.quarantine.enabled = false;
        }
    }

    bool confirmScan() {
        fmt::print("Proceed with scan? [Y/n] ");
        std::cout.flush();

        std::string input;
        std::getline(std::cin, input);

        return input.empty() || input[0] == 'y' || input[0] == 'Y';
    }

    int runScan(const AppConfig& config, const CliArgs& args) {
        Scanner scanner(config);
        scanner.setDryRun(args.dryRun);

        // Progress state
        struct ProgressState {
            std::chrono::steady_clock::time_point lastCountUpdate;
            size_t lastDisplayedCount = 0;
            bool initialized = false;
        };
        ProgressState progressState;

        // Setup progress callback for text output only
        if (args.outputFormat == ReportFormat::Text) {
            scanner.setProgressCallback([this, &progressState](const ScanProgress& progress) {
                updateProgress(progress, progressState);
            });

            // Callback when file counting is done
            scanner.setCountingDoneCallback([this](size_t totalFiles) {
                // Clear "Globbing files..." line and print empty progress lines
                terminal_.moveUp(1);
                terminal_.clearLine();
                fmt::print("\n\n");  // Two empty lines for progress display
                terminal_.moveUp(2);
                std::cout.flush();
            });

            fmt::print("\nGlobbing files...\n");
            terminal_.hideCursor();
        }

        auto result = scanner.scan();

        // Show cursor after scan
        if (args.outputFormat == ReportFormat::Text) {
            terminal_.showCursor();
            // Clear progress lines
            terminal_.moveUp(2);
            terminal_.clearLine();
            fmt::print("\n");
            terminal_.clearLine();
            fmt::print("\n");
            terminal_.moveUp(2);
        }

        // Check if interrupted (only show message for text output)
        if (scanner.wasInterrupted() && args.outputFormat == ReportFormat::Text) {
            terminal_.print(Terminal::warning(), "\nHalted by user\n\n");
        }

        // Output results (including partial results if interrupted)
        printer_.printResults(result, args.outputFormat);

        // Return 130 on interrupt (standard convention), 2 if matches found, 0 otherwise
        if (scanner.wasInterrupted()) {
            return 130;
        }
        return result.filesWithMatches > 0 ? 2 : 0;
    }

    void updateProgress(const ScanProgress& progress, auto& state) {
        auto now = std::chrono::steady_clock::now();

        if (!state.initialized) {
            state.lastCountUpdate = now;
            state.lastDisplayedCount = progress.filesScanned;
            state.initialized = true;

            printProgressLine(progress);
            printFilePath(progress.currentFile);
            std::cout.flush();
            return;
        }

        auto countElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - state.lastCountUpdate).count();
        bool updateCount = countElapsed >= 1000;
        bool updateFile = (progress.filesScanned - state.lastDisplayedCount) >= 10;

        if (!updateCount && !updateFile) {
            return;
        }

        terminal_.moveUp(2);

        if (updateCount) {
            terminal_.clearLine();
            printProgressLine(progress);
            state.lastCountUpdate = now;
        } else {
            fmt::print("\n");
        }

        if (updateFile) {
            terminal_.clearLine();
            printFilePath(progress.currentFile);
            state.lastDisplayedCount = progress.filesScanned;
        } else {
            fmt::print("\n");
        }

        std::cout.flush();
    }

    void printProgressLine(const ScanProgress& progress) const {
        fmt::print("Scanning {}/{}", progress.filesScanned, progress.totalFiles);
        if (progress.totalMatchCount > 0) {
            terminal_.print(Terminal::critical(), " ({} hits)", progress.totalMatchCount);
        }
        fmt::print("\n");
    }

    void printFilePath(const std::filesystem::path& path) const {
        std::string pathStr = path.string();
        size_t termWidth = getTerminalWidth();

        if (pathStr.length() <= termWidth) {
            fmt::print("{}\n", pathStr);
        } else {
            // Truncate from the beginning: "...rest/of/path"
            size_t keep = termWidth - 3;  // Reserve space for "..."
            fmt::print("...{}\n", pathStr.substr(pathStr.length() - keep));
        }
    }

    static size_t getTerminalWidth() {
#ifdef _WIN32
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
            return csbi.srWindow.Right - csbi.srWindow.Left + 1;
        }
#else
        struct winsize w;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 0) {
            return w.ws_col;
        }
#endif
        return 80;  // Default fallback
    }

    const Terminal& terminal_;
    const ResultPrinter& printer_;
};

}  // namespace lyxbosa
