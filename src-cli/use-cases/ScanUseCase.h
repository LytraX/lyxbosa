#pragma once

#include "infrastructure/Terminal.h"
#include "infrastructure/TerminalCaps.h"
#include "infrastructure/PlainProgress.h"
#include "infrastructure/ProgressModel.h"
#include "infrastructure/TuiReporter.h"
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
#include <sstream>
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

        // Guards that have been turned off are legal, and worth saying out loud
        // before a scan rather than after one that never came back.
        if (!args.silent) {
            for (const auto& warning : Config::warnings(config)) {
                terminal_.printErr(Terminal::warning(), "Warning: {}\n", warning);
            }
        }

        const ReportPlan plan = planReport(args, config);

        // A silent run with nowhere to write is a scan nobody can ever read.
        if (args.silent && !plan.file) {
            terminal_.printErr(Terminal::error(),
                "Error: --silent produces no output at all, so the report needs somewhere\n"
                "to go. Pass -O/--output-file FILE, or set actions.report.file in the\n"
                "configuration.\n");
            return 1;
        }

        // Quarantining into a directory that is itself being scanned does not
        // remove anything from the tree: it changes the path, re-finds the same
        // file on the next run, and - if that path is still served - leaves the
        // malware reachable under a new URL while reporting it as handled.
        if (config.actions.quarantine.enabled && !args.dryRun) {
            if (const auto under = quarantineInsideScanTree(config)) {
                terminal_.printErr(Terminal::error(),
                    "Error: the quarantine directory ({}) is inside a scanned directory\n"
                    "       ({}). Moving a file there does not take it out of the tree:\n"
                    "       the next scan finds it again, and if that path is served the\n"
                    "       file is still reachable. Point quarantine.directory somewhere\n"
                    "       outside every scanned root.\n",
                    config.actions.quarantine.directory, *under);
                return 1;
            }
        }

        // Quarantining moves files and cannot be undone. An unattended run has
        // nobody to confirm it, so it has to have been asked for explicitly.
        if (config.actions.quarantine.enabled && !args.dryRun) {
            const bool unattended = args.force || !caps_.stdinIsTty();
            if (unattended && args.quarantine != true) {
                terminal_.printErr(Terminal::error(),
                    "Error: quarantine is enabled, which moves matched files to {}.\n"
                    "       An unattended run will not do that unless it is asked for\n"
                    "       explicitly: add --quarantine to confirm, --no-quarantine to\n"
                    "       scan without moving anything, or --dry-run to report only.\n",
                    config.actions.quarantine.directory.empty()
                        ? "the quarantine directory"
                        : config.actions.quarantine.directory);
                return 1;
            }
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

            Config::printSummary(config, caps_.width(), args.verbose);

            if (args.dryRun) {
                terminal_.printErr(Terminal::warning(), "[DRY RUN MODE - No files will be quarantined]\n\n");
            }

            if (!confirmScan()) {
                fmt::print(stderr, "Scan cancelled.\n");
                return 0;
            }
        }

        // Run scan
        return runScan(config, args, plan);
    }

private:
    // Width used for the text format when it is written to a file rather than a
    // terminal, which has no width of its own.
    static constexpr size_t kFileReportWidth = 100;

    // How the scan reports progress.
    enum class ProgressStyle {
        None,   // no progress display at all
        Tui,    // full-screen UI on the alternate screen buffer
        Plain   // one throttled line on stderr, leaving stdout untouched
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

        if (args.quarantine.has_value()) {
            config.actions.quarantine.enabled = *args.quarantine;
        }

        if (args.archives.has_value()) {
            config.archives.enabled = *args.archives;
        }
        if (args.exhaustiveArchives) {
            config.archives.exhaustive = true;
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

    // The scanned root the quarantine directory sits under, if it sits under one.
    static std::optional<std::string> quarantineInsideScanTree(const AppConfig& config) {
        if (config.actions.quarantine.directory.empty()) {
            return std::nullopt;
        }

        std::error_code ec;
        const auto dest = std::filesystem::weakly_canonical(
            std::filesystem::path(config.actions.quarantine.directory), ec);
        if (ec) {
            return std::nullopt;
        }

        for (const auto& dir : config.scan.directories) {
            const auto root =
                std::filesystem::weakly_canonical(std::filesystem::path(dir), ec);
            if (ec) {
                continue;
            }
            auto [mismatch, unused] =
                std::mismatch(root.begin(), root.end(), dest.begin(), dest.end());
            if (mismatch == root.end()) {
                return dir;
            }
        }
        return std::nullopt;
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

    // Is the full-screen UI compiled in at all?
    static constexpr bool tuiAvailable() {
#ifdef LYXBOSA_TUI_ENABLED
        return true;
#else
        return false;
#endif
    }

    // The full-screen UI owns stdout, so it can only run when stdout is a
    // terminal that supports it and is carrying the readable text view rather
    // than a machine report. Everything else falls back to a single line on
    // stderr, which is what makes `lyxbosa scan ... > report.txt` show progress.
    ProgressStyle chooseProgressStyle(const CliArgs& args,
                                      ReportFormat consoleFormat,
                                      bool haveConsoleWriter) const {
        if (args.quiet || args.silent || args.progress == ProgressWhen::None) {
            return ProgressStyle::None;
        }

        const bool wantsTui = args.progress == ProgressWhen::Auto ||
                              args.progress == ProgressWhen::Tui;
        const bool usable = tuiAvailable()
                         && haveConsoleWriter
                         && consoleFormat == ReportFormat::Text
                         && !args.noInteractive
                         && caps_.stdoutIsTty()
                         && caps_.supportsFullScreen(args.color);

        if (wantsTui && usable) {
            return ProgressStyle::Tui;
        }

        // Asking for it explicitly and not getting it deserves an explanation.
        if (args.progress == ProgressWhen::Tui && !usable) {
            terminal_.printErr(Terminal::warning(),
                "Note: the full-screen UI is unavailable here ({}); using --progress=plain.\n",
                tuiUnavailableReason(args, consoleFormat, haveConsoleWriter));
        }

        return caps_.stderrIsTty() ? ProgressStyle::Plain : ProgressStyle::None;
    }

    std::string tuiUnavailableReason(const CliArgs& args, ReportFormat consoleFormat,
                                     bool haveConsoleWriter) const {
        if (!tuiAvailable())            return "built without LYXBOSA_TUI";
        if (!caps_.stdoutIsTty())       return "stdout is not a terminal";
        if (!haveConsoleWriter)         return "console output is disabled";
        if (consoleFormat != ReportFormat::Text)
                                        return "stdout is carrying a machine-readable report";
        if (args.noInteractive)         return "--no-interactive";
        if (caps_.isCI())               return "running in CI";
        if (!terminal_.colorOnStdout()) return "colour is disabled";
        return fmt::format("terminal is {}x{}, minimum is {}x{}",
                           caps_.width(), caps_.height(),
                           TerminalCaps::kMinColumns, TerminalCaps::kMinRows);
    }

    int runScan(const AppConfig& config, const CliArgs& args, const ReportPlan& plan) {
        // --silent suppresses everything --quiet does, and the findings too.
        const bool quiet = args.quiet || args.silent;

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
        const bool consoleWanted =
            !args.silent && plan.console && (!plan.file || caps_.stdoutIsTty());

        const ProgressStyle style = chooseProgressStyle(args, consoleFormat, consoleWanted);

        // The full-screen UI owns stdout while it runs, and the alternate screen
        // takes its contents with it on exit. So the console report is buffered
        // and written into the primary buffer once the UI stands down - that is
        // what keeps grep, copy-paste and scrollback working afterwards.
        const bool bufferConsole = (style == ProgressStyle::Tui);
        std::ostringstream consoleBuffer;
        std::ostream& consoleStream =
            bufferConsole ? static_cast<std::ostream&>(consoleBuffer) : std::cout;

        std::unique_ptr<ReportWriter> consoleWriter;
        if (consoleWanted) {
            consoleWriter = makeReportWriter(
                consoleFormat, consoleStream,
                consoleFormat == ReportFormat::Text && terminal_.colorOnStdout(),
                caps_.width(), args.verbose, /*summary=*/!quiet);
        }

        Scanner scanner(config);
        scanner.setDryRun(args.dryRun);
        scanner.setPreCount(!args.noPreCount);

        PlainProgress plain(caps_);
#ifdef LYXBOSA_TUI_ENABLED
        std::unique_ptr<TuiReporter> tui;
        if (style == ProgressStyle::Tui) {
            tui = std::make_unique<TuiReporter>(args.dryRun);
        }
#endif

        if (consoleWriter) consoleWriter->begin();
        if (fileWriter) fileWriter->begin();

        scanner.setFileResultCallback([&](const FileResult& fileResult) {
            if (fileWriter) {
                fileWriter->onFile(fileResult);
            }
            if (consoleWriter) {
                // The plain line lives on stderr; erase it before stdout writes
                // so the two do not interleave on a shared terminal.
                if (style == ProgressStyle::Plain) {
                    plain.clear();
                }
                consoleWriter->onFile(fileResult);
            }
#ifdef LYXBOSA_TUI_ENABLED
            if (tui) {
                tui->onFinding(fileResult);
            }
#endif
        });

        if (style == ProgressStyle::Plain) {
            scanner.setProgressCallback([&plain](const ScanProgress& progress) {
                plain.update(progress);
            });
            plain.start();
        }
#ifdef LYXBOSA_TUI_ENABLED
        else if (tui) {
            scanner.setProgressCallback([&tui](const ScanProgress& progress) {
                tui->onProgress(progress);
            });
            tui->begin();
        }
#endif

        auto result = scanner.scan();

        if (style == ProgressStyle::Plain) {
            plain.finish();
        }
#ifdef LYXBOSA_TUI_ENABLED
        if (tui) {
            tui->finish();  // leaves the alternate screen; stdout is ours again
        }
#endif

        const bool interrupted = scanner.wasInterrupted();

        // Interruption is a diagnostic, not report data.
        if (interrupted && !quiet) {
            terminal_.printErr(Terminal::warning(), "\nHalted by user\n\n");
        }

        // Close both reports off properly, interrupted or not.
        if (consoleWriter) {
            consoleWriter->end(result, interrupted);
        }
        if (fileWriter) {
            fileWriter->end(result, interrupted);
            fileStream.close();
            if (!quiet) {
                terminal_.printErr(Terminal::success(), "Report written to {}\n", *plan.file);
            }
        }

        // Hand the buffered findings and summary to the primary buffer.
        if (bufferConsole) {
            std::cout << consoleBuffer.str();
            std::cout.flush();
        }

        // Return 130 on interrupt (standard convention), 2 if matches found, 0 otherwise
        if (interrupted) {
            return 130;
        }
        return result.filesWithMatches > 0 ? 2 : 0;
    }

    const Terminal& terminal_;
    const TerminalCaps& caps_;
};

}  // namespace lyxbosa
