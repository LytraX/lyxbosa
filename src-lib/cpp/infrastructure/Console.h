#pragma once

// Console.h - Cross-platform console handling

#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <fmt/core.h>

#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__)
#include <unistd.h>
#else // Linux
#include <unistd.h>
#endif

namespace Console {
    // Stream buffer to redirect cout/cerr to a file and external console
    class TeeStreamBuf : public std::streambuf {
    private:
        std::streambuf* consoleBuf;
        std::ofstream fileStream;
        char buffer[1024];

    public:
        TeeStreamBuf(std::streambuf* consoleBuf, const std::string& filename);
        ~TeeStreamBuf();

    protected:
        virtual int overflow(int c) override;
        virtual int sync() override;
    };

    // Custom streams that tee to both console and file
    extern std::unique_ptr<TeeStreamBuf> outBuf;
    extern std::unique_ptr<TeeStreamBuf> errBuf;
    extern std::streambuf* oldOutBuf;
    extern std::streambuf* oldErrBuf;
    extern std::string logFilePath;

#ifdef _WIN32
    extern HWND consoleWindow;
#else
    // Process ID for the terminal window (on Unix systems)
    extern pid_t terminalPid;
#endif

    // Helper function for fmt support
    void log_message(const std::string& msg);

    // Initialize console for development mode
    bool initialize(const std::string& logFile);

    // Clean up resources
    void shutdown();
}

// Define fmtprint after the Console namespace
template <typename... Args>
void fmtprint(fmt::format_string<Args...> format, Args&&... args) {
    std::string msg = fmt::format(format, std::forward<Args>(args)...);
    Console::log_message(msg);
}
