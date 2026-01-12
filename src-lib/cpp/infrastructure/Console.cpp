#include "Console.h"
#include <chrono>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__)
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#else // Linux
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#endif

namespace Console {

// Initialize global variables
std::unique_ptr<TeeStreamBuf> outBuf = nullptr;
std::unique_ptr<TeeStreamBuf> errBuf = nullptr;
std::streambuf* oldOutBuf = nullptr;
std::streambuf* oldErrBuf = nullptr;
std::string logFilePath;

#ifdef _WIN32
HWND consoleWindow = nullptr;
#else
pid_t terminalPid = -1;
#endif

// TeeStreamBuf implementation
TeeStreamBuf::TeeStreamBuf(std::streambuf* consoleBuf, const std::string& filename)
    : consoleBuf(consoleBuf) {
    fileStream.open(filename, std::ios::out | std::ios::app);
    setp(buffer, buffer + sizeof(buffer) - 1);
}

TeeStreamBuf::~TeeStreamBuf() {
    sync();
    fileStream.close();
}

int TeeStreamBuf::overflow(int c) {
    if (c != EOF) {
        *pptr() = c;
        pbump(1);
    }

    if (sync() == -1) {
        return EOF;
    }

    return c;
}

int TeeStreamBuf::sync() {
    if (pptr() > pbase()) {
        // Write to console buffer
        if (consoleBuf) {
            consoleBuf->sputn(pbase(), pptr() - pbase());
        }

        // Write to file
        fileStream.write(pbase(), pptr() - pbase());
        fileStream.flush();

        // Reset buffer
        setp(pbase(), epptr());
    }

    return 0;
}

// Helper function for fmt support
void log_message(const std::string& msg) {
    // Write to cout (which is already redirected)
    std::cout << msg;
    std::cout.flush();
}

// Initialize console for development mode
bool initialize(const std::string& logFile) {
    logFilePath = logFile;

#ifdef BINEYE_DEBUG
    // In debug mode, ensure console is visible
#ifdef _WIN32
    // Windows: Allocate a console if we're in WIN32 mode
    if (AllocConsole()) {
        // Redirect stdout and stderr to the console
        FILE* dummy;
        freopen_s(&dummy, "CONOUT$", "w", stdout);
        freopen_s(&dummy, "CONOUT$", "w", stderr);

        consoleWindow = GetConsoleWindow();
        SetConsoleTitle("Debug Console");
    }
#elif defined(__APPLE__)
    // macOS: Launch Terminal with a command to tail the log file
    terminalPid = fork();
    if (terminalPid == 0) {
        // Child process
        std::string command = "osascript -e 'tell application \"Terminal\" to do script \"echo \\\"Debug Console\\\" && tail -f \\\"" + logFile + "\\\"\"'";
        system(command.c_str());
        exit(0);
    }
#else
    // Linux: Launch a terminal with tail command
    terminalPid = fork();
    if (terminalPid == 0) {
        // Child process
        std::string command = "x-terminal-emulator -e 'bash -c \"echo Debug Console; tail -f " + logFile + "; read\"'";
        system(command.c_str());
        exit(0);
    }
#endif

    // Set up the tee stream buffers for C++ streams
    oldOutBuf = std::cout.rdbuf();
    oldErrBuf = std::cerr.rdbuf();
    outBuf = std::make_unique<TeeStreamBuf>(oldOutBuf, logFile);
    errBuf = std::make_unique<TeeStreamBuf>(oldErrBuf, logFile);
    std::cout.rdbuf(outBuf.get());
    std::cerr.rdbuf(errBuf.get());

    return true;
#else
    // In release mode, just redirect output to the log file
    oldOutBuf = std::cout.rdbuf();
    oldErrBuf = std::cerr.rdbuf();
    outBuf = std::make_unique<TeeStreamBuf>(nullptr, logFile);
    errBuf = std::make_unique<TeeStreamBuf>(nullptr, logFile);
    std::cout.rdbuf(outBuf.get());
    std::cerr.rdbuf(errBuf.get());

    return false;
#endif
}

// Clean up resources
void shutdown() {
    // Restore original stream buffers
    if (oldOutBuf) std::cout.rdbuf(oldOutBuf);
    if (oldErrBuf) std::cerr.rdbuf(oldErrBuf);

    outBuf.reset();
    errBuf.reset();

#ifdef _WIN32
    if (consoleWindow) {
        FreeConsole();
    }
#else
    // For Unix systems, try to terminate the terminal process
    if (terminalPid > 0) {
        // Add a termination message to the log file
        std::ofstream logEnd(logFilePath, std::ios::app);
        if (logEnd.is_open()) {
            logEnd << "\n--- Application terminated ---\n";
            logEnd.close();
        }

        // Give the terminal process a chance to read the last line
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

#ifdef __APPLE__
        // On macOS, we need a special approach for Terminal
        std::string closeCommand = "osascript -e 'tell application \"Terminal\" to quit'";
        system(closeCommand.c_str());
#else
        // On Linux, we need to kill the process
        // This is the process we created in initialize()
        kill(terminalPid, SIGTERM);

        // If that doesn't work, force kill after a small delay
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        kill(terminalPid, SIGKILL);
#endif
    }
#endif
}

} // namespace Console
