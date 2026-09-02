#pragma once

#include "infrastructure/Terminal.h"
#include "infrastructure/TerminalCaps.h"
#include "infrastructure/PlainProgress.h"
#include "infrastructure/ResultPrinter.h"
#include "infrastructure/InputPrompt.h"
#include "infrastructure/PathUtils.h"
#include "config/Config.h"
#include "core/Scanner.h"
#include "system/CliArgs.h"
#include <chrono>
#include <iostream>

namespace lyxbosa {

// Orchestrates the scan command workflow
class ScanUseCase {
public:
    ScanUseCase(const Terminal& terminal, const ResultPrinter& printer, const TerminalCaps& caps)
        : terminal_(terminal), printer_(printer), caps_(caps) {}

    int execute(CliArgs& args) {
        // Prompt for directory if none provided on CLI and no config file specified
        // (i.e., using default config which has placeholder directories)
        if (args.directories.empty() && !args.configFile) {
            if (!caps_.stdinIsTty()) {
                terminal_.printErr(Terminal::error(),
                    "Error: No directories to scan and stdin is not a terminal.\n"
                    "Pass directories on the command line or use --config.\n");
                return 1;
            }

            InputPrompt prompt(terminal_);
            auto dir = prompt.promptDirectory("Directory to scan", ".");

            if (!dir || dir->empty()) {
                fmt::print(stderr, "Scan cancelled.\n");
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
            // Without a terminal there is nobody to answer, and treating that as
            // consent would let a piped or cron invocation quarantine files that
            // were never confirmed.
            if (!caps_.stdinIsTty()) {
                terminal_.printErr(Terminal::error(),
                    "Error: Refusing to scan unconfirmed because stdin is not a terminal.\n"
                    "Re-run with --force to scan non-interactively.\n");
                return 1;
            }

            Config::printSummary(config);

            if (args.dryRun) {
                terminal_.printErr(Terminal::warning(), "[DRY RUN MODE - No files will be quarantined]\n\n");
            }

            if (!confirmScan()) {
                fmt::print(stderr, "Scan cancelled.\n");
                return 0;
            }
        }

        // Run scan
        return runScan(config, args);
    }

private:
    // How the scan reports progress.
    enum class ProgressStyle {
        None,     // no progress display at all
        Inline,   // in-place, multi-line, on stdout (stdout is a terminal)
        Plain     // one throttled line on stderr, leaving stdout untouched
    };

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
        fmt::print(stderr, "Proceed with scan? [Y/n] ");
        std::fflush(stderr);

        std::string input;
        if (!std::getline(std::cin, input)) {
            // EOF or a read error is not consent.
            fmt::print(stderr, "\n");
            return false;
        }

        return input.empty() || input[0] == 'y' || input[0] == 'Y';
    }

    // The in-place display owns stdout, so it can only be used when stdout is a
    // terminal that accepts escape sequences and is not carrying a machine
    // report. Everything else falls back to a single line on stderr, which is
    // what makes `lyxbosa scan ... > report.txt` show progress at all.
    ProgressStyle chooseProgressStyle(const CliArgs& args) const {
        if (args.quiet || args.progress == ProgressWhen::None) {
            return ProgressStyle::None;
        }

        const bool inlineUsable = caps_.stdoutIsTty()
                               && terminal_.colorOnStdout()
                               && args.outputFormat == ReportFormat::Text
                               && !args.noInteractive
                               && args.progress != ProgressWhen::Plain;

        if (inlineUsable) {
            return ProgressStyle::Inline;
        }
        return caps_.stderrIsTty() ? ProgressStyle::Plain : ProgressStyle::None;
    }

    int runScan(const AppConfig& config, const CliArgs& args) {
        Scanner scanner(config);
        scanner.setDryRun(args.dryRun);

        const ProgressStyle style = chooseProgressStyle(args);

        // Text findings are streamed as they are found: for text output they are
        // the report, so streaming also means a partial report survives Ctrl+C.
        // JSON and CSV are still emitted whole at the end (see phase 1).
        const bool streamFindings = (args.outputFormat == ReportFormat::Text);

        // Progress state for the in-place display
        struct ProgressState {
            std::chrono::steady_clock::time_point lastCountUpdate;
            size_t lastDisplayedCount = 0;
            bool initialized = false;
            ScanProgress lastProgress;  // Store last progress for re-rendering
        };
        ProgressState progressState;
        PlainProgress plain(caps_);

        if (style == ProgressStyle::Inline) {
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
                printFinding(fileResult, args);

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
        } else {
            if (style == ProgressStyle::Plain) {
                scanner.setProgressCallback([&plain](const ScanProgress& progress) {
                    plain.update(progress);
                });
                scanner.setCountingDoneCallback([&plain](size_t totalFiles) {
                    plain.onCountingDone(totalFiles);
                });
                plain.onCountingStart();
            }

            if (streamFindings) {
                // Progress lives on stderr here, so findings need no cursor
                // choreography - just erase the status line and write.
                scanner.setMatchCallback([this, &plain, &args, style](const FileResult& fileResult) {
                    if (style == ProgressStyle::Plain) {
                        plain.clear();
                    }
                    printFinding(fileResult, args);
                    std::cout.flush();
                });
            }
        }

        auto result = scanner.scan();

        if (style == ProgressStyle::Inline) {
            terminal_.showCursor();
            // Cursor is at end of filepath line (no newline)
            // Clear all 3 lines and position for summary output
            terminal_.clearLine();  // Clear filepath
            terminal_.moveUp(1);
            terminal_.clearLine();  // Clear progress
            terminal_.moveUp(1);
            terminal_.clearLine();  // Clear separator - cursor now here
        } else if (style == ProgressStyle::Plain) {
            plain.finish();
        }

        // Interruption is a diagnostic, not report data.
        if (scanner.wasInterrupted() && !args.quiet) {
            terminal_.printErr(Terminal::warning(), "\nHalted by user\n\n");
        }

        if (streamFindings) {
            // Findings were already written as they were found.
            if (!args.quiet) {
                printer_.printSummary(result);
            }
        } else {
            printer_.printResults(result, args.outputFormat);
        }

        // Return 130 on interrupt (standard convention), 2 if matches found, 0 otherwise
        if (scanner.wasInterrupted()) {
            return 130;
        }
        return result.filesWithMatches > 0 ? 2 : 0;
    }

    void printFinding(const FileResult& fileResult, const CliArgs& args) const {
        if (args.verbose) {
            printer_.printFileResult(fileResult);
        } else {
            printer_.printFileResultCompact(fileResult, caps_.width());
        }
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

    void printFilePathNoNewline(const std::filesystem::path& path) const {
        fmt::print("\r");  // Go to start of line
        std::string pathStr = pathToUtf8(path);
        size_t termWidth = caps_.width();

        if (pathStr.length() <= termWidth) {
            fmt::print("{}", pathStr);
        } else {
            // Truncate from the beginning: "...rest/of/path"
            size_t keep = termWidth - 3;  // Reserve space for "..."
            fmt::print("...{}", pathStr.substr(pathStr.length() - keep));
        }
        terminal_.clearToEndOfLine();  // Clear any leftover chars from previous longer path
    }

    const Terminal& terminal_;
    const ResultPrinter& printer_;
    const TerminalCaps& caps_;
};

}  // namespace lyxbosa
