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
#include "update/BuildIdentity.h"
#include "update/UpdateCheck.h"
#include "update/UpdateState.h"
#include "update/VersionSource.h"
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

        // A root the operator named and that is not there is their mistake, and the
        // walk used to step over it: "Files scanned: 0", "No matches found", exit 0 -
        // which is what a clean tree reports. A typo in a cron entry therefore agreed
        // with itself forever. `check` already refuses a file that is not there, and
        // this is the same refusal one level up.
        //
        // Before any work, so that a set of roots which was wrong from the start does
        // not cost a forty-minute scan first - and before the update check below, so a
        // run that refuses here has not spent its interval either.
        if (!refuseUnusableRoots(config)) {
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

        // Started here, and here specifically. Every run that is allowed to check is
        // by definition a run that shows the prompt below - a --force run never
        // checks - so the request gets the summary render and the human's answer to
        // cover it. Without that head start a scan of one small directory finishes
        // first, the reply is discarded, and the interval has been spent for nothing.
        //
        // It is also the last thing before the prompt rather than the first thing in
        // this function, so a run that refuses for one of the reasons above has not
        // spent its interval either.
        //
        // The request therefore goes out before the operator answers the prompt, and
        // does not wait to find out whether they say yes. That is deliberate: the
        // check is tied to having run the tool interactively, not to having completed
        // a scan, and making it depend on the answer would mean a cancelled scan
        // silently paying the same daily interval while learning nothing.
        auto updateCheck = maybeStartUpdateCheck(config, args);

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
        return runScan(config, args, plan, updateCheck);
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

    // Every named root that cannot be walked, one formatted line each. Empty when the
    // scan can go ahead.
    static std::vector<std::string> unusableRoots(const AppConfig& config) {
        std::vector<std::string> lines;
        for (const auto& dir : config.scan.directories) {
            if (const auto why = rootUnusableReason(dir)) {
                lines.push_back(fmt::format(
                    "{}: {}", pathForDisplay(std::filesystem::path(dir)), *why));
            }
        }
        return lines;
    }

    // False when the scan must not start. One root that is not there refuses the whole
    // run rather than scanning the others: scanning three of four roots and reporting
    // the result as the scan is the same shape of quiet under-coverage, one level up,
    // and an operator who is told which path is wrong can fix it in a second.
    bool refuseUnusableRoots(const AppConfig& config) const {
        const auto unusable = unusableRoots(config);
        if (unusable.empty()) {
            return true;
        }

        const size_t total = config.scan.directories.size();
        if (total == 1) {
            terminal_.printErr(Terminal::error(),
                "Error: the directory to scan is not usable:\n");
        } else {
            terminal_.printErr(Terminal::error(),
                "Error: {} of the {} directories to scan {} not usable:\n",
                unusable.size(), total, unusable.size() == 1 ? "is" : "are");
        }
        for (const auto& line : unusable) {
            terminal_.printErr(Terminal::error(), "       {}\n", line);
        }
        if (total == unusable.size()) {
            terminal_.printErr(Terminal::error(), "       Nothing has been scanned.\n");
        } else {
            terminal_.printErr(Terminal::error(),
                "       Nothing has been scanned, not even the roots that are there.\n");
        }
        terminal_.printErr(Terminal::error(),
            "       A run that stepped over a missing root would report what a clean\n"
            "       tree reports, so the whole scan is refused instead. Correct the\n"
            "       path, or take it out of the directories to scan.\n");
        return false;
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

    int runScan(const AppConfig& config, const CliArgs& args, const ReportPlan& plan,
                const UpdateCheckHandle& updateCheck) {
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

        // Delivering the report is part of completing the command. The stream used to
        // be checked when it was opened and never again, so a full disk produced
        // "Report written to /dev/full" and an exit code that said the run succeeded -
        // and the run that matters is the unattended one, which then has neither a
        // report nor anything saying it lost one. The write, the flush and the close
        // are all asked, because they fail at different moments: a short report never
        // leaves the buffer until close.
        bool reportUndelivered = false;
        if (fileWriter) {
            fileWriter->end(result, interrupted);
            fileStream.flush();
            fileStream.close();
            reportUndelivered = fileStream.fail();

            if (reportUndelivered) {
                // Held back only by --silent, which promises no output at all. --quiet
                // suppresses progress and the summary, and this is neither: it is the
                // command's own deliverable not existing.
                if (!args.silent) {
                    terminal_.printErr(Terminal::error(),
                        "\nError: the report could not be written to {}\n"
                        "       what is on disk there, if anything, is incomplete\n",
                        *plan.file);
                }
            } else if (!quiet) {
                terminal_.printErr(Terminal::success(), "Report written to {}\n", *plan.file);
            }
        }

        // Hand the buffered findings and summary to the primary buffer.
        if (bufferConsole) {
            std::cout << consoleBuffer.str();
            std::cout.flush();
        }

        // A newer release, if the check happened and finished and found one. It is
        // read with a non-blocking poll: a check still in flight is a check that
        // never happened, because the alternative is making a person wait for
        // GitHub after their scan has already printed.
        //
        // Deliberately the last thing before the exit code, and deliberately without
        // a `return` of its own: the four lines below decide the exit status of this
        // command, and nothing about an update may reach them.
        if (updateCheck.mayNotify && !quiet) {
            const auto fresh = updateCheck.live ? updateCheck.live->resultIfReady()
                                                : std::nullopt;
            const std::string notice =
                updateNotice(fresh, updateCheck.known, runningVersion());
            if (!notice.empty()) {
                terminal_.printErr(Terminal::warning(), "\nNote: {}", notice);
            }
        }

        // And the periodic line about being the portable build on a host that did not
        // need it. Its own block rather than the one above, because it is not gated on
        // updates.check: it reaches no network, so the setting that says "do not touch
        // the network" has no opinion about it - and for the same reason it keeps its own
        // interval rather than borrowing updates.interval.
        maybeSayThisIsThePortableBuild(args);

        // The refusal in execute() proves every named root was there when the command
        // started. This is the race that one cannot cover: a root taken away while the
        // scan was running. Not the operator's mistake, so the findings stand and are
        // printed and written - but the tree below it was not covered, and only the
        // operator can decide what that means. Printed under --quiet, which suppresses
        // progress and the summary; only --silent, which promises no output at all,
        // holds it back.
        if (!result.rootsMissing.empty() && !args.silent) {
            terminal_.printErr(Terminal::error(),
                "\nError: a directory named for this scan was gone by the time the scan\n"
                "       reached it, so nothing below it was covered:\n");
            for (const auto& root : result.rootsMissing) {
                terminal_.printErr(Terminal::error(), "       {}\n", pathForDisplay(root));
            }
        }

        // Files the tool was asked to contain and could not. Not the same fact as
        // `filesQuarantined < filesWithMatches`, which is also what an exposure finding
        // and a run without --quarantine look like: these are webshells still sitting
        // where they were found, and the operator has to be told which. Printed under
        // --quiet like the block above, and for the same reason.
        if (result.filesQuarantineFailed > 0 && !args.silent) {
            terminal_.printErr(Terminal::error(),
                "\nError: {} file{} could not be moved to the quarantine directory and\n"
                "       {} still where {} found:\n",
                result.filesQuarantineFailed,
                result.filesQuarantineFailed == 1 ? "" : "s",
                result.filesQuarantineFailed == 1 ? "is" : "are",
                result.filesQuarantineFailed == 1 ? "it was" : "they were");
            printQuarantineFailures(result);
        }

        // Return 130 on interrupt (standard convention), 2 if matches found, 0 otherwise
        if (interrupted) {
            return 130;
        }
        // A scan that did not cover what it was asked to cover is an error, and it
        // outranks the findings for the same reason the interrupt above already does:
        // the exit code answers "did this do what I asked", not "what did it find",
        // and the findings are in the report either way.
        //
        // A report that could not be written joins it, because for `-O` the report IS
        // the answer: exiting 2 would tell an unattended caller to go and read a file
        // that is truncated or empty. A quarantine that failed deliberately does not
        // join it - the answer is complete and delivered, the failure is named in it
        // and on stderr, and ranking it above the findings would turn every such run
        // into a 1 and hide a real detection from a caller watching for 2.
        if (!result.rootsMissing.empty() || reportUndelivered) {
            return 1;
        }
        return result.filesWithMatches > 0 ? 2 : 0;
    }

    // The paths, because a count cannot be acted on. Capped: a quarantine directory on
    // a read-only mount fails for every hostile file in the tree, and a thousand lines
    // of stderr would bury the sentence above them. The report carries all of them.
    void printQuarantineFailures(const ScanResult& result) const {
        constexpr size_t kMaxListed = 10;
        size_t listed = 0;
        for (const auto& file : result.files) {
            if (!file.quarantineFailed) {
                continue;
            }
            if (listed == kMaxListed) {
                terminal_.printErr(Terminal::error(), "       ... and {} more, all in the report\n",
                                   result.filesQuarantineFailed - listed);
                break;
            }
            terminal_.printErr(Terminal::error(), "       {}\n", pathForDisplay(file.path));
            ++listed;
        }
    }

    // The portable build, at most once an interval, on a host that could have run the
    // faster one.
    //
    // The order here is the order of decidePortableNotice(), and it matters for more
    // than tidiness: the host is not read from disk until every other gate has passed,
    // and the state file is written BEFORE the line is printed. A notice recorded only
    // after a successful print is a notice that repeats on every run the first time the
    // terminal goes away mid-write - the same failure the update check's reserve-first
    // write exists for.
    void maybeSayThisIsThePortableBuild(const CliArgs& args) const {
        PortableNoticeContext ctx;
        ctx.callSite = UpdateCallSite::Scan;
        ctx.portableBuild = isPortableBuild();
        ctx.stdoutIsTty = caps_.stdoutIsTty();
        ctx.isCI = caps_.isCI();
        ctx.quiet = args.quiet;
        ctx.silent = args.silent;
        ctx.force = args.force;
        ctx.nowEpoch = currentEpochSeconds();

        // Reading the state has no side effect, so it happens before the decision.
        const std::filesystem::path statePath = defaultUpdateStatePath();
        const auto state = readUpdateState(statePath);
        if (state) {
            ctx.lastShownEpoch = state->portableNoticeEpoch;
            ctx.shownBeforeTimestamps = state->portableNoticeShownLegacy;
        }

        // Everything except the two tests that cost something - reading the host's
        // files, and writing the state - which are assumed to pass here and are each
        // actually performed below. startUpdateCheck() sets stateWritable the same way
        // and for the same reason: a run that fails on a cheap gate must not have
        // touched anything, and that includes the upgrade stamp below.
        ctx.stateWritable = true;
        ctx.standardBuild = StandardBuildHere::Yes;
        if (!portableNoticeWrites(decidePortableNotice(ctx))) return;

        // The first thing that costs: the host's own files. Unknown is not a maybe -
        // it is treated as No by the policy, so a host this cannot read stays quiet.
        ctx.standardBuild = standardBuildHere();
        const PortableNoticeDecision decision = decidePortableNotice(ctx);
        if (!portableNoticeWrites(decision)) return;

        // A state file that carries only the pre-timestamp flag: stamp it with now and
        // say nothing. That is the one outcome that writes without printing, and it is
        // what stops an upgrade both from repeating a line the operator has already
        // dismissed and from staying silent for good on a flag whose meaning changed.
        // Deliberately here rather than above the host probe, so the stamp means the
        // same thing every other stamp in this file means: a run that said the line or
        // would have. An unwritable state file is one more silent run, as everywhere.
        if (decision == PortableNoticeDecision::AdoptLegacyFlag) {
            recordPortableNoticeShown(statePath, ctx.nowEpoch);
            return;
        }

        const std::string notice = portableBuildNotice();
        if (notice.empty()) return;

        // The second cost: the write that is also the probe. It happens BEFORE the line
        // is printed, so a failure here is one silent run rather than a notice on every
        // run until the interval is somehow recorded.
        if (!recordPortableNoticeShown(statePath, ctx.nowEpoch)) return;

        terminal_.printErr(Terminal::warning(), "\nNote: {}", notice);
    }

    // Everything this command knows that the policy needs, and nothing else.
    UpdateCheckHandle maybeStartUpdateCheck(const AppConfig& config,
                                            const CliArgs& args) const {
        UpdateCheckContext ctx;
        ctx.callSite = UpdateCallSite::Scan;
        ctx.mode = config.updates.check;
        ctx.intervalSeconds = config.updates.intervalSeconds;
        ctx.running = runningVersion();
        ctx.stdoutIsTty = caps_.stdoutIsTty();
        ctx.isCI = caps_.isCI();
        ctx.quiet = args.quiet;
        ctx.silent = args.silent;
        ctx.force = args.force;
        ctx.nowEpoch = currentEpochSeconds();

        return startUpdateCheck(ctx, std::make_shared<HttpVersionSource>(),
                                defaultUpdateStatePath());
    }

    const Terminal& terminal_;
    const TerminalCaps& caps_;
};

}  // namespace lyxbosa
