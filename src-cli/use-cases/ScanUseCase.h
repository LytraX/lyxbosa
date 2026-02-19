#pragma once

#include "infrastructure/Terminal.h"
#include "infrastructure/ResultPrinter.h"
#include "infrastructure/InputPrompt.h"
#include "infrastructure/PathUtils.h"
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

    int execute(CliArgs& args) {
        // Prompt for directory if none provided on CLI and no config file specified
        // (i.e., using default config which has placeholder directories)
        if (args.directories.empty() && !args.configFile) {
            InputPrompt prompt(terminal_);
            auto dir = prompt.promptDirectory("Directory to scan", ".");

            if (!dir || dir->empty()) {
                fmt::print("Scan cancelled.\n");
                return 0;
            }

            args.directories.push_back(*dir);
        }

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
            ScanProgress lastProgress;  // Store last progress for re-rendering
        };
        ProgressState progressState;

        // Setup progress callback for text output only
        if (args.outputFormat == ReportFormat::Text) {
            scanner.setProgressCallback([this, &progressState](const ScanProgress& progress) {
                progressState.lastProgress = progress;
                updateProgress(progress, progressState);
            });

            // Match callback for real-time result output
            scanner.setMatchCallback([this, &progressState, &args](const FileResult& fileResult) {
                // Skip if progress not yet initialized (shouldn't happen but be safe)
                if (!progressState.initialized) {
                    return;
                }

                // Cursor is at end of filepath line (no newline)
                // Clear all 3 lines: filepath (current), progress (up 1), separator (up 2)
                terminal_.clearLine();  // Clear filepath
                terminal_.moveUp(1);
                terminal_.clearLine();  // Clear progress
                terminal_.moveUp(1);
                terminal_.clearLine();  // Clear separator

                // Now at separator line, print the result
                if (args.verbose) {
                    printer_.printFileResult(fileResult);
                } else {
                    printer_.printFileResultCompact(fileResult, getTerminalWidth());
                }

                // Re-print the 3-line progress display (separator + progress + filepath)
                // Result printing ends with newline, so we're on a new line
                fmt::print("\n");  // Empty line separator
                printProgressLine(progressState.lastProgress);  // Ends with \n
                printFilePathNoNewline(progressState.lastProgress.currentFile);  // No newline
                std::cout.flush();
            });

            // Callback when file counting is done - show initial progress
            scanner.setCountingDoneCallback([this, &progressState](size_t totalFiles) {
                // Clear "Globbing files..." line
                terminal_.moveUp(1);
                terminal_.clearLine();

                // Initialize progress state and show initial display
                progressState.lastCountUpdate = std::chrono::steady_clock::now();
                progressState.lastDisplayedCount = 0;
                progressState.initialized = true;
                progressState.lastProgress.totalFiles = totalFiles;
                progressState.lastProgress.filesScanned = 0;
                progressState.lastProgress.totalMatchCount = 0;

                // Print initial 3-line display: empty separator + progress + placeholder
                // Cursor stays at end (after newlines) for subsequent updates
                fmt::print("\n");  // Empty line separator
                fmt::print("Scanning 0/{}\n", totalFiles);
                fmt::print("Starting...");  // No newline - cursor stays on this line
                std::cout.flush();
            });

            fmt::print("Globbing files...\n");
            terminal_.hideCursor();
        }

        auto result = scanner.scan();

        // Show cursor after scan
        if (args.outputFormat == ReportFormat::Text) {
            terminal_.showCursor();
            // Cursor is at end of filepath line (no newline)
            // Clear all 3 lines and position for summary output
            terminal_.clearLine();  // Clear filepath
            terminal_.moveUp(1);
            terminal_.clearLine();  // Clear progress
            terminal_.moveUp(1);
            terminal_.clearLine();  // Clear separator - cursor now here
        }

        // Check if interrupted (only show message for text output)
        if (scanner.wasInterrupted() && args.outputFormat == ReportFormat::Text) {
            terminal_.print(Terminal::warning(), "\nHalted by user\n\n");
        }

        // Output summary only (results already printed in real-time)
        if (args.outputFormat == ReportFormat::Text) {
            printer_.printSummary(result);
        } else {
            printer_.printResults(result, args.outputFormat);
        }

        // Return 130 on interrupt (standard convention), 2 if matches found, 0 otherwise
        if (scanner.wasInterrupted()) {
            return 130;
        }
        return result.filesWithMatches > 0 ? 2 : 0;
    }

    void updateProgress(const ScanProgress& progress, auto& state) {
        auto now = std::chrono::steady_clock::now();

        // Progress should already be initialized by counting done callback
        if (!state.initialized) {
            return;
        }

        auto countElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - state.lastCountUpdate).count();
        bool updateCount = countElapsed >= 1000;
        bool updateFile = (progress.filesScanned - state.lastDisplayedCount) >= 10;

        // Force immediate update on very first file to replace "Starting..."
        bool firstUpdate = (state.lastDisplayedCount == 0 && progress.filesScanned > 0);

        if (!updateCount && !updateFile && !firstUpdate) {
            return;
        }

        // Cursor is at end of filepath line
        // Move to progress line
        fmt::print("\r");       // Go to start of current line
        terminal_.moveUp(1);    // Move to progress line

        if (updateCount || firstUpdate) {
            fmt::print("\r");   // Go to start of progress line
            printProgressLineNoNewline(progress);
            terminal_.clearToEndOfLine();
            fmt::print("\n");   // Move to filepath line
            state.lastCountUpdate = now;
        } else {
            fmt::print("\n");   // Move to filepath line
        }

        // Now on filepath line - always update to avoid flicker
        printFilePathNoNewline(progress.currentFile);  // Includes \r and clearToEndOfLine
        if (updateFile || firstUpdate) {
            state.lastDisplayedCount = progress.filesScanned;
        }

        std::cout.flush();
    }

    void printProgressLineNoNewline(const ScanProgress& progress) const {
        fmt::print("Scanning {}/{}", progress.filesScanned, progress.totalFiles);
        if (progress.totalMatchCount > 0) {
            terminal_.print(Terminal::critical(), " ({} hits)", progress.totalMatchCount);
        }
    }

    void printProgressLine(const ScanProgress& progress) const {
        printProgressLineNoNewline(progress);
        fmt::print("\n");
    }

    void printFilePath(const std::filesystem::path& path) const {
        printFilePathNoNewline(path);
        fmt::print("\n");
    }

    void printFilePathNoNewline(const std::filesystem::path& path) const {
        fmt::print("\r");  // Go to start of line
        std::string pathStr = pathToUtf8(path);
        size_t termWidth = getTerminalWidth();

        if (pathStr.length() <= termWidth) {
            fmt::print("{}", pathStr);
        } else {
            // Truncate from the beginning: "...rest/of/path"
            size_t keep = termWidth - 3;  // Reserve space for "..."
            fmt::print("...{}", pathStr.substr(pathStr.length() - keep));
        }
        terminal_.clearToEndOfLine();  // Clear any leftover chars from previous longer path
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
