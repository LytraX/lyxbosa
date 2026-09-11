// The test binary's main. Everything after the first two checks is what
// GTest::gtest_main would have done; the two checks are what this file exists for.
//
// The smoke test in src-lib/cpp/update/InstallPath.cpp runs a verified download with
// --version and installs it only if that exits 0. On Linux the tests hand it a shell
// script, which is a real executable there. On Windows a script is not one, and there
// is no executable a test can count on finding beside itself - except itself. So this
// binary answers --version the way the scanner does, and a Windows case can install a
// copy of it as the "old binary", serve another copy as the "new" one, and have the
// smoke test really run each of them.
//
// --hold-open <file> is the second thing a Windows case needs: a process that keeps
// running from a copy of this binary until told to stop, so that renaming a RUNNING
// image, failing to delete it, and reaping it once the process has exited are all
// observed on a real filesystem rather than argued from documentation. The child polls
// for the file and gives up on its own after a minute, so a case that forgot to release
// it cannot hang the run.
//
// Neither argument reaches gtest, and neither is read once gtest has the command line.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string_view>
#include <thread>

int main(int argc, char** argv) {
    if (argc >= 2 && std::string_view(argv[1]) == "--version") {
        std::printf("lyxbosa_tests %s\n", LYXBOSA_VERSION);
        return 0;
    }

    if (argc >= 3 && std::string_view(argv[1]) == "--hold-open") {
        const std::filesystem::path stop(argv[2]);
        const auto giveUp = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        std::error_code ec;
        while (!std::filesystem::exists(stop, ec) && std::chrono::steady_clock::now() < giveUp) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        return 0;
    }

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
