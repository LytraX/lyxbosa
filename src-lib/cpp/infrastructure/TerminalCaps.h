#pragma once

// TerminalCaps.h - What the attached terminal(s) actually support, detected at
// startup.
//
// The rule this exists to enforce: stdout carries the report, stderr carries
// the human. The two streams are probed independently so that
//
//     lyxbosa scan /var/www > report.txt
//
// can animate progress on stderr without writing a single escape byte into the
// redirected report.

#include "config/Types.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace lyxbosa {

class TerminalCaps {
public:
    // Probe the standard streams. On Windows this also tries to switch the
    // console into virtual-terminal mode, so it has a side effect and should be
    // called once, early.
    static TerminalCaps detect() {
        TerminalCaps caps;

        caps.stdinTty_  = isTty(StdStream::In);
        caps.stdoutTty_ = isTty(StdStream::Out);
        caps.stderrTty_ = isTty(StdStream::Err);

        const char* term = std::getenv("TERM");
        caps.dumbTerm_ = (term != nullptr) && std::strcmp(term, "dumb") == 0;

        // no-color.org: the presence of NO_COLOR disables colour whatever its value.
        caps.noColorEnv_ = std::getenv("NO_COLOR") != nullptr;
        caps.forceColorEnv_ = std::getenv("CLICOLOR_FORCE") != nullptr;

        caps.vtOut_ = caps.stdoutTty_ && enableVirtualTerminal(StdStream::Out);
        caps.vtErr_ = caps.stderrTty_ && enableVirtualTerminal(StdStream::Err);

        return caps;
    }

    bool stdinIsTty()  const { return stdinTty_; }
    bool stdoutIsTty() const { return stdoutTty_; }
    bool stderrIsTty() const { return stderrTty_; }

    // May we write colour to this stream, given the user's --color choice?
    bool colorOnStdout(ColorWhen when) const { return colorAllowed(when, vtOut_); }
    bool colorOnStderr(ColorWhen when) const { return colorAllowed(when, vtErr_); }

    // Terminal width in columns, preferring stdout and falling back to stderr,
    // COLUMNS, and finally 80.
    size_t width() const {
#ifdef _WIN32
        for (DWORD handle : {STD_OUTPUT_HANDLE, STD_ERROR_HANDLE}) {
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            if (GetConsoleScreenBufferInfo(GetStdHandle(handle), &csbi)) {
                int cols = csbi.srWindow.Right - csbi.srWindow.Left + 1;
                if (cols > 0) {
                    return static_cast<size_t>(cols);
                }
            }
        }
#else
        for (int fd : {STDOUT_FILENO, STDERR_FILENO}) {
            struct winsize ws;
            if (::isatty(fd) && ioctl(fd, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
                return static_cast<size_t>(ws.ws_col);
            }
        }
#endif
        if (const char* columns = std::getenv("COLUMNS")) {
            int cols = std::atoi(columns);
            if (cols > 0) {
                return static_cast<size_t>(cols);
            }
        }
        return 80;
    }

private:
    enum class StdStream { In, Out, Err };

    static bool isTty(StdStream s) {
#ifdef _WIN32
        FILE* f = (s == StdStream::In) ? stdin : (s == StdStream::Out) ? stdout : stderr;
        return _isatty(_fileno(f)) != 0;
#else
        int fd = (s == StdStream::In)    ? STDIN_FILENO
                 : (s == StdStream::Out) ? STDOUT_FILENO
                                         : STDERR_FILENO;
        return ::isatty(fd) != 0;
#endif
    }

    // Older conhost does not interpret escape sequences unless asked. Returns
    // whether escape sequences can be expected to work on this stream.
    static bool enableVirtualTerminal([[maybe_unused]] StdStream s) {
#ifdef _WIN32
        HANDLE h = GetStdHandle(s == StdStream::Out ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
        if (h == INVALID_HANDLE_VALUE || h == nullptr) {
            return false;
        }
        DWORD mode = 0;
        if (!GetConsoleMode(h, &mode)) {
            return false;
        }
        if (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) {
            return true;
        }
        return SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
#else
        return true;
#endif
    }

    bool colorAllowed(ColorWhen when, bool streamSupportsVt) const {
        switch (when) {
            case ColorWhen::Never:  return false;
            case ColorWhen::Always: return true;
            case ColorWhen::Auto:   break;
        }
        if (forceColorEnv_) {
            return true;
        }
        if (noColorEnv_ || dumbTerm_) {
            return false;
        }
        return streamSupportsVt;
    }

    bool stdinTty_ = false;
    bool stdoutTty_ = false;
    bool stderrTty_ = false;
    bool vtOut_ = false;
    bool vtErr_ = false;
    bool dumbTerm_ = false;
    bool noColorEnv_ = false;
    bool forceColorEnv_ = false;
};

}  // namespace lyxbosa
