#include <fmt/core.h>
#include <csignal>

#include "system/CliArgs.h"
#include "infrastructure/Terminal.h"
#include "infrastructure/ResultPrinter.h"
#include "core/Scanner.h"  // For g_interrupted
#include "use-cases/ScanUseCase.h"
#include "use-cases/CheckUseCase.h"
#include "use-cases/ValidateConfigUseCase.h"
#include "use-cases/InitConfigUseCase.h"

using namespace lyxbosa;

// Signal handler for graceful shutdown
extern "C" void signalHandler(int signal) {
    (void)signal;  // Unused
    g_interrupted.store(true, std::memory_order_relaxed);
}

int main(int argc, char* argv[]) {
    // Setup signal handlers (cross-platform)
    std::signal(SIGINT, signalHandler);   // Ctrl+C
    std::signal(SIGTERM, signalHandler);  // Termination request

    auto args = CliArgs::parse(argc, argv);

    if (!args.success) {
        fmt::print(stderr, "{}\n", args.errorMessage);
        return 1;
    }

    // Setup infrastructure
    Terminal terminal(!args.noAnsi);
    ResultPrinter printer(terminal);

    // Dispatch to use case
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
