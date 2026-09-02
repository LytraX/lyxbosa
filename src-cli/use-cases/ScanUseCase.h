#pragma once

#include "infrastructure/Terminal.h"
#include "infrastructure/TerminalCaps.h"
#include "infrastructure/PlainProgress.h"
#include "infrastructure/ProgressModel.h"
#include "infrastructure/InputPrompt.h"
#include "infrastructure/PathUtils.h"
#include "infrastructure/report/ReportWriterFactory.h"
#include "config/Config.h"
#include "core/Scanner.h"
#include "system/CliArgs.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <system_error>

namespace lyxbosa {

// Orchestrates the scan command workflow
class ScanUseCase {
public:
    ScanUseCase(const Terminal& terminal, const TerminalCaps& caps)
        : terminal_(terminal), caps_(caps) {}

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
    // Width used for the text format when it is written to a file rather than a
    // terminal, which has no width of its own.
    static constexpr size_t kFileReportWidth = 100;

    // How the scan reports progress.
    enum class ProgressStyle {
        None,     // no progress display at all
        Inline,   // in-place, multi-line, on stdout (stdout is a terminal)
        Plain     // one throttled line on stderr, leaving stdout untouched
    };

    // Where the report goes and in what format, after the command line and the
    // configuration have been reconciled.
    struct ReportPlan {
        std::optional<std::string> file;
        ReportFormat format = ReportFormat::Text;
        bool console = true;
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

    // The command line wins over actions.report.* from the configuration, which
    // until now was parsed and then ignored by everything.
    static ReportPlan planReport(const CliArgs& args, const AppConfig& config) {
        ReportPlan plan;
        plan.format = args.outputFormatExplicit ? args.outputFormat
                                                : config.actions.report.format;
        if (args.outputFile) {
            plan.file = *args.outputFile;
        } else if (!config.actions.report.file.empty()) {
            plan.file = config.actions.report.file;
        }
        plan.console = config.actions.report.console;
        return plan;
    }

    // Writing the report into the tree being scanned means scanning our own
    // output on the next run, and can mean scanning it during this one.
    void warnIfOutputInsideScanTree(const std::string& file, const AppConfig& config) const {
        std::error_code ec;
        const auto outPath = std::filesystem::weakly_canonical(std::filesystem::path(file), ec);
        if (ec) {
            return;
        }
        for (const auto& dir : config.scan.directories) {
            const auto scanPath = std::filesystem::weakly_canonical(std::filesystem::path(dir), ec);
            if (ec) {
                continue;
            }
            auto [mismatch, unused] = std::mismatch(scanPath.begin(), scanPath.end(),
                                                    outPath.begin(), outPath.end());
            if (mismatch == scanPath.end()) {
                terminal_.printErr(Terminal::warning(),
                    "Warning: the report file is inside a scanned directory ({}).\n"
                    "         It will be picked up by later scans.\n", dir);
                return;
            }
        }
    }

    // The in-place display owns stdout, so it can only be used when stdout is a
    // terminal that accepts escape sequences and is carrying the readable text
    // view. Everything else falls back to a single line on stderr, which is what
    // makes `lyxbosa scan ... > report.txt` show progress at all.
    ProgressStyle chooseProgressStyle(const CliArgs& args,
                                      ReportFormat consoleFormat,
                                      bool haveConsoleWriter) const {
        if (args.quiet || args.progress == ProgressWhen::None) {
            return ProgressStyle::None;
        }

        const bool inlineUsable = caps_.stdoutIsTty()
                               && terminal_.colorOnStdout()
                               && haveConsoleWriter
                               && consoleFormat == ReportFormat::Text
                               && !args.noInteractive
                               && args.progress != ProgressWhen::Plain;

        if (inlineUsable) {
            return ProgressStyle::Inline;
        }
        return caps_.stderrIsTty() ? ProgressStyle::Plain : ProgressStyle::None;
    }

    int runScan(const AppConfig& config, const CliArgs& args) {
        const ReportPlan plan = planReport(args, config);

        // Open the report file before scanning: discovering it is unwritable
        // after a forty-minute scan would be cruel.
        std::ofstream fileStream;
        std::unique_ptr<ReportWriter> fileWriter;
        if (plan.file) {
            const std::filesystem::path outPath(*plan.file);
            if (outPath.has_parent_path()) {
                std::error_code ec;
                std::filesystem::create_directories(outPath.parent_path(), ec);
            }
            fileStream.open(outPath, std::ios::out | std::ios::trunc);
            if (!fileStream) {
                terminal_.printErr(Terminal::error(),
                    "Error: cannot open output file for writing: {}\n", *plan.file);
                return 1;
            }
            warnIfOutputInsideScanTree(*plan.file, config);
            fileWriter = makeReportWriter(plan.format, fileStream, /*color=*/false,
                                          kFileReportWidth, args.verbose, /*summary=*/true);
        }

        // With an output file the terminal keeps the readable view: --output
        // selects the file's format, not what the user is watching. Without one,
        // stdout is the report.
        const ReportFormat consoleFormat = plan.file ? ReportFormat::Text : plan.format;
        const bool consoleWanted = plan.console && (!plan.file || caps_.stdoutIsTty());

        std::unique_ptr<ReportWriter> consoleWriter;
        if (consoleWanted) {
            consoleWriter = makeReportWriter(
                consoleFormat, std::cout,
                consoleFormat == ReportFormat::Text && terminal_.colorOnStdout(),
                caps_.width(), args.verbose, /*summary=*/!args.quiet);
        }

        Scanner scanner(config);
        scanner.setDryRun(args.dryRun);
        scanner.setPreCount(!args.noPreCount);

        const ProgressStyle style =
            chooseProgressStyle(args, consoleFormat, consoleWriter != nullptr);

        // Progress state for the in-place display
        struct ProgressState {
            std::chrono::steady_clock::time_point lastCountUpdate;
            size_t lastDisplayedCount = 0;
            bool initialized = false;
            ScanProgress lastProgress;  // Store last progress for re-rendering
            ProgressModel model;
        };
        ProgressState progressState;
        PlainProgress plain(caps_);

        if (consoleWriter) consoleWriter->begin();
        if (fileWriter) fileWriter->begin();

        scanner.setFileResultCallback([&](const FileResult& fileResult) {
            if (fileWriter) {
                fileWriter->onFile(fileResult);
            }
            if (!consoleWriter) {
                return;
            }

            if (style == ProgressStyle::Inline) {
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

                consoleWriter->onFile(fileResult);

                // Re-print the 3-line progress display (separator + progress + filepath)
                fmt::print("\n");  // Empty line separator
                printProgressLine(progressState.model);  // Ends with \n
                printFilePathNoNewline(progressState.lastProgress.currentFile);  // No newline
                std::cout.flush();
                return;
            }

            // Progress lives on stderr here, so findings need no cursor
            // choreography - just erase the status line and write.
            if (style == ProgressStyle::Plain) {
                plain.clear();
            }
            consoleWriter->onFile(fileResult);
        });

        if (style == ProgressStyle::Inline) {
            scanner.setProgressCallback([this, &progressState](const ScanProgress& progress) {
                progressState.lastProgress = progress;
                updateProgress(progress, progressState);
            });

            // The count now runs concurrently with the scan, so there is no
            // waiting phase to announce - draw the display and start.
            progressState.lastCountUpdate = std::chrono::steady_clock::now();
            progressState.initialized = true;
            fmt::print("\n");            // Empty line separator
            fmt::print("Scanning...\n");  // Progress line
            fmt::print("Starting...");    // No newline - cursor stays on this line
            std::cout.flush();
            terminal_.hideCursor();
        } else if (style == ProgressStyle::Plain) {
            scanner.setProgressCallback([&plain](const ScanProgress& progress) {
                plain.update(progress);
            });
            plain.start();
        }

        auto result = scanner.scan();

        if (style == ProgressStyle::Inline) {
            terminal_.showCursor();
            // Cursor is at end of filepath line (no newline)
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

        // Close both reports off properly, interrupted or not.
        if (consoleWriter) consoleWriter->end(result, scanner.wasInterrupted());
        if (fileWriter) {
            fileWriter->end(result, scanner.wasInterrupted());
            fileStream.close();
            if (!args.quiet) {
                terminal_.printErr(Terminal::success(), "Report written to {}\n", *plan.file);
            }
        }

        // Return 130 on interrupt (standard convention), 2 if matches found, 0 otherwise
        if (scanner.wasInterrupted()) {
            return 130;
        }
        return result.filesWithMatches > 0 ? 2 : 0;
    }

    void updateProgress(const ScanProgress& progress, auto& state) {
        auto now = std::chrono::steady_clock::now();
        state.model.update(progress, now);

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

        // Cursor is at end of filepath line; move to progress line
        fmt::print("\r");
        terminal_.moveUp(1);

        if (updateCount || firstUpdate) {
            fmt::print("\r");
            printProgressLineNoNewline(state.model);
            terminal_.clearToEndOfLine();
            fmt::print("\n");   // Move to filepath line
            state.lastCountUpdate = now;
        } else {
            fmt::print("\n");   // Move to filepath line
        }

        // Now on filepath line - always update to avoid flicker
        printFilePathNoNewline(progress.currentFile);
        if (updateFile || firstUpdate) {
            state.lastDisplayedCount = progress.filesScanned;
        }

        std::cout.flush();
    }

    void printProgressLineNoNewline(const ProgressModel& model) const {
        const ScanProgress& progress = model.progress();

        if (model.totalKnown()) {
            fmt::print("Scanning {}/{} ({}%)",
                       progress.filesScanned, progress.totalFiles, model.percent());
        } else if (progress.discoveredFiles > progress.filesScanned) {
            fmt::print("Scanning {} of {}+", progress.filesScanned, progress.discoveredFiles);
        } else {
            fmt::print("Scanning {}", progress.filesScanned);
        }

        if (progress.directoriesScanned > 0) {
            fmt::print("  {} dirs", progress.directoriesScanned);
        }

        if (progress.criticalCount > 0) terminal_.print(Terminal::critical(), "  C:{}", progress.criticalCount);
        if (progress.highCount > 0)     terminal_.print(Terminal::high(),     "  H:{}", progress.highCount);
        if (progress.mediumCount > 0)   terminal_.print(Terminal::medium(),   "  M:{}", progress.mediumCount);
        if (progress.lowCount > 0)      terminal_.print(Terminal::low(),      "  L:{}", progress.lowCount);

        if (const auto eta = model.eta()) {
            fmt::print("  ETA {}", formatDuration(*eta));
        }
    }

    void printProgressLine(const ProgressModel& model) const {
        printProgressLineNoNewline(model);
        fmt::print("\n");
    }

    void printFilePathNoNewline(const std::filesystem::path& path) const {
        fmt::print("\r");
        fmt::print("{}", ResultPrinter::truncatePath(pathToUtf8(path), caps_.width()));
        terminal_.clearToEndOfLine();
    }

    const Terminal& terminal_;
    const TerminalCaps& caps_;
};

}  // namespace lyxbosa
