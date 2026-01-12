#include <iostream>
#include <filesystem>
#include <thread>
#include <string>
#include <unordered_map>
#include <fmt/core.h>

#include "system/CliArgs.h"
#include "utils/PathUtils.h"
#include "lyxbosa.h"

int main(int argc, char* argv[]) {
    // Parse CLI arguments first
    auto cliResult = CliArgs::parse(argc, argv);

    // Compute the "baseDir" where index.html actually lives in dev.
    std::filesystem::path exe = std::filesystem::canonical(argv[0]);
    auto rootDir = PathUtils::locateDevRootDir(exe);
    std::string logFile = (rootDir / "debug.log").string();


    // fmtprint("Application: {} v{}\n", pkg.name(), pkg.version());
    fmt::print("Executable path: {}\n", exe.string());


    return 0;
}
