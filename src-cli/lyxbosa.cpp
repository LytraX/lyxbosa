#include <fmt/base.h>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <iostream>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "system/CliArgs.h"
#include "infrastructure/Terminal.h"
#include "infrastructure/TerminalCaps.h"
#include "core/Interrupt.h"
#include "use-cases/ScanUseCase.h"
#include "use-cases/CheckUseCase.h"
#include "use-cases/ValidateConfigUseCase.h"
#include "use-cases/InitConfigUseCase.h"

using namespace lyxbosa;

// Whether escape sequences may be written to each stream. Set once terminal
// capabilities and --color are known; read by the atexit hook and the signal
// handler, which must never write escapes into a redirected file.
static std::atomic<bool> g_escapesOnStdout{false};
static std::atomic<bool> g_escapesOnStderr{false};

// How many interrupts we have seen. The first unwinds gracefully; the second
// means the unwind is not getting us out and we leave immediately.
static std::atomic<int> g_interruptCount{0};

static constexpr char kShowCursor[] = "\033[?25h";
static constexpr size_t kShowCursorLen = sizeof(kShowCursor) - 1;

// Restore the cursor from a signal handler. write() is async-signal-safe;
// fmt::print and the iostreams are not.
static void restoreCursorSignalSafe() {
    if (!g_cursorHidden.load(std::memory_order_relaxed)) {
        return;
    }
#ifdef _WIN32
    if (g_escapesOnStdout.load(std::memory_order_relaxed)) {
        _write(_fileno(stdout), kShowCursor, static_cast<unsigned int>(kShowCursorLen));
    }
    if (g_escapesOnStderr.load(std::memory_order_relaxed)) {
        _write(_fileno(stderr), kShowCursor, static_cast<unsigned int>(kShowCursorLen));
    }
#else
    if (g_escapesOnStdout.load(std::memory_order_relaxed)) {
        ssize_t written = ::write(STDOUT_FILENO, kShowCursor, kShowCursorLen);
        (void)written;
    }
    if (g_escapesOnStderr.load(std::memory_order_relaxed)) {
        ssize_t written = ::write(STDERR_FILENO, kShowCursor, kShowCursorLen);
        (void)written;
    }
#endif
}

// Restore the cursor on normal exit, where the full runtime is available.
static void restoreCursor() {
    if (!g_cursorHidden.load(std::memory_order_relaxed)) {
        return;
    }
    if (g_escapesOnStdout.load(std::memory_order_relaxed)) {
        fmt::print("{}", kShowCursor);
        std::fflush(stdout);
    }
    if (g_escapesOnStderr.load(std::memory_order_relaxed)) {
        fmt::print(stderr, "{}", kShowCursor);
        std::fflush(stderr);
    }
}

// Signal handler for graceful shutdown.
//
// It only raises a flag. Tearing the process down from here - as this used to
// do by re-raising with SIG_DFL - skipped the partial report, the summary and
// the 130 exit code entirely, and would leave the terminal in whatever state
// the progress display was in.
extern "C" void signalHandler(int signal) {
    g_interrupted.store(true, std::memory_order_relaxed);

    // Windows resets the disposition to SIG_DFL once a handler has run, so
    // reinstall to be sure a second Ctrl+C reaches us rather than killing the
    // process outright. On glibc this is a no-op.
    std::signal(signal, signalHandler);

    if (g_interruptCount.fetch_add(1, std::memory_order_relaxed) >= 1) {
        restoreCursorSignalSafe();
        std::_Exit(130);
    }

    // First interrupt: return, and let the scan loop notice the flag and unwind.
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Set console output to UTF-8 so that fmt::print (which uses WriteConsoleW)
    // correctly handles non-ASCII characters in file paths (e.g., Greek, Cyrillic)
    SetConsoleOutputCP(CP_UTF8);
#endif

    // Probe the streams before anything is written to them; on Windows this also
    // switches the console into virtual-terminal mode.
    const TerminalCaps caps = TerminalCaps::detect();

    // Setup signal handlers (cross-platform)
    std::signal(SIGINT, signalHandler);   // Ctrl+C
    std::signal(SIGTERM, signalHandler);  // Termination request

    // Register atexit handler to restore cursor on normal exit
    std::atexit(restoreCursor);

    auto args = CliArgs::parse(argc, argv);

    // Explicit --help goes to stdout with a success exit code
    if (args.success && args.command == Command::Help) {
        fmt::print("{}", CliArgs::getHelpText());
        return 0;
    }

    if (!args.success) {
        fmt::print(stderr, "{}\n", args.errorMessage);
        return 1;
    }

    // stdout carries the report, stderr carries the human. Colour is decided per
    // stream so that a redirected report stays free of escape sequences even
    // while progress is still animating on the terminal.
    const Terminal::Caps termCaps{
        caps.colorOnStdout(args.color),
        caps.colorOnStderr(args.color),
        caps.stdoutIsTty(),
        caps.stderrIsTty(),
    };
    g_escapesOnStdout.store(termCaps.colorOut && termCaps.ttyOut, std::memory_order_relaxed);
    g_escapesOnStderr.store(termCaps.colorErr && termCaps.ttyErr, std::memory_order_relaxed);

    // Setup infrastructure
    Terminal terminal(termCaps);

    // Dispatch to use case (args passed by ref for potential prompting)
    switch (args.command) {
        case Command::Scan:
            return ScanUseCase(terminal, caps).execute(args);

        case Command::Check:
            return CheckUseCase(terminal, caps).execute(args);

        case Command::ValidateConfig:
            return ValidateConfigUseCase(terminal).execute(args);

        case Command::InitConfig:
            return InitConfigUseCase().execute();

        case Command::None:
        default:
            fmt::print(stderr, "No command specified. Use --help for usage.\n");
            return 1;
    }
}
