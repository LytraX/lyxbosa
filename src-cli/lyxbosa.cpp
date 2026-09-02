#include <fmt/core.h>
#include <csignal>
#include <cstdlib>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

#include "system/CliArgs.h"
#include "infrastructure/Terminal.h"
#include "infrastructure/ResultPrinter.h"
#include "core/Scanner.h"  // For g_interrupted
#include "use-cases/ScanUseCase.h"
#include "use-cases/CheckUseCase.h"
#include "use-cases/ValidateConfigUseCase.h"
#include "use-cases/InitConfigUseCase.h"

using namespace lyxbosa;

// Global flag for ANSI support (set after args parsing)
static bool g_useAnsi = true;

// Restore cursor - can be called from signal handler or atexit
static void restoreCursor() {
    if (g_useAnsi) {
        // Show cursor ANSI sequence
        fmt::print("\033[?25h");
        std::cout.flush();
    }
}

// Signal handler for graceful shutdown
extern "C" void signalHandler(int signal) {
    g_interrupted.store(true, std::memory_order_relaxed);
    restoreCursor();

    // Re-raise with default handler for proper exit code
    std::signal(signal, SIG_DFL);
    std::raise(signal);
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Set console output to UTF-8 so that fmt::print (which uses WriteConsoleW)
    // correctly handles non-ASCII characters in file paths (e.g., Greek, Cyrillic)
    SetConsoleOutputCP(CP_UTF8);
#endif

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

    // Set global ANSI flag for signal handler
    g_useAnsi = !args.noAnsi;

    // Setup infrastructure
    Terminal terminal(!args.noAnsi);
    ResultPrinter printer(terminal);

    // Dispatch to use case (args passed by ref for potential prompting)
    switch (args.command) {
        case Command::Scan:
            return ScanUseCase(terminal, printer).execute(args);

        case Command::Check:
            return CheckUseCase(terminal, printer).execute(args);

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
