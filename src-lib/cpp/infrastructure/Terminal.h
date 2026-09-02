#pragma once

#include <cstdio>
#include <iostream>
#include <fmt/format.h>
#include <fmt/color.h>

namespace lyxbosa {

// Terminal control for ANSI sequences and colored output.
//
// stdout and stderr are tracked separately: the report goes to stdout, progress
// and diagnostics go to stderr, and either may be redirected while the other is
// still a terminal. Cursor control is gated on the target stream being a
// terminal (never write escape sequences into a redirected file); colour is
// additionally gated on the user's --color choice.
class Terminal {
public:
    struct Caps {
        bool colorOut = true;   // colour may be written to stdout
        bool colorErr = true;   // colour may be written to stderr
        bool ttyOut = true;     // stdout is a terminal (cursor control is legal)
        bool ttyErr = true;     // stderr is a terminal
    };

    enum class Target { Out, Err };

    explicit Terminal(Caps caps) : caps_(caps) {}

    // Legacy single-switch construction, used by tests and simple call sites.
    explicit Terminal(bool useAnsi = true)
        : caps_{useAnsi, useAnsi, useAnsi, useAnsi} {}

    // Cursor control -------------------------------------------------------
    // All of these are no-ops when the target stream is not a terminal.

    void hideCursor(Target t = Target::Out) const {
        if (escapesOk(t)) {
            fmt::print(stream(t), "\033[?25l");
            flush(t);
        }
    }

    void showCursor(Target t = Target::Out) const {
        if (escapesOk(t)) {
            fmt::print(stream(t), "\033[?25h");
            flush(t);
        }
    }

    void clearLine(Target t = Target::Out) const {
        if (!isTty(t)) {
            return;
        }
        if (escapesOk(t)) {
            fmt::print(stream(t), "\033[2K\r");
        } else {
            fmt::print(stream(t), "\r{:80}\r", "");
        }
    }

    // Clear from cursor to end of line (doesn't move cursor)
    void clearToEndOfLine(Target t = Target::Out) const {
        if (!isTty(t)) {
            return;
        }
        if (escapesOk(t)) {
            fmt::print(stream(t), "\033[K");
        } else {
            // Fallback: print spaces (assumes ~40 chars remaining)
            fmt::print(stream(t), "{:40}", "");
        }
    }

    void moveUp(int lines = 1, Target t = Target::Out) const {
        if (escapesOk(t)) {
            fmt::print(stream(t), "\033[{}A", lines);
        }
    }

    void moveDown(int lines = 1, Target t = Target::Out) const {
        if (escapesOk(t)) {
            fmt::print(stream(t), "\033[{}B", lines);
        }
    }

    void flush(Target t = Target::Out) const {
        if (t == Target::Out) {
            std::cout.flush();
        } else {
            std::fflush(stderr);
        }
    }

    // Output ---------------------------------------------------------------

    // Colored output to stdout
    template<typename... Args>
    void print(fmt::text_style style, fmt::format_string<Args...> fmt_str, Args&&... args) const {
        if (caps_.colorOut) {
            fmt::print(style, fmt_str, std::forward<Args>(args)...);
        } else {
            fmt::print(fmt_str, std::forward<Args>(args)...);
        }
    }

    // Colored output to stderr
    template<typename... Args>
    void printErr(fmt::text_style style, fmt::format_string<Args...> fmt_str, Args&&... args) const {
        if (caps_.colorErr) {
            fmt::print(stderr, style, fmt_str, std::forward<Args>(args)...);
        } else {
            fmt::print(stderr, fmt_str, std::forward<Args>(args)...);
        }
    }

    // Capability queries ---------------------------------------------------

    bool colorOnStdout() const { return caps_.colorOut; }
    bool colorOnStderr() const { return caps_.colorErr; }
    bool ttyOnStdout() const { return caps_.ttyOut; }
    bool ttyOnStderr() const { return caps_.ttyErr; }

    // True when colour is available on stdout. Kept for existing call sites.
    bool isAnsiEnabled() const { return caps_.colorOut; }

    // Common text styles
    static fmt::text_style critical() { return fg(fmt::color::red) | fmt::emphasis::bold; }
    static fmt::text_style high() { return fg(fmt::color::tomato); }
    static fmt::text_style medium() { return fg(fmt::color::yellow); }
    static fmt::text_style low() { return fg(fmt::color::cyan); }
    static fmt::text_style success() { return fg(fmt::color::green); }
    static fmt::text_style error() { return fg(fmt::color::red); }
    static fmt::text_style warning() { return fg(fmt::color::yellow); }
    static fmt::text_style info() { return fg(fmt::color::white) | fmt::emphasis::bold; }
    static fmt::text_style muted() { return fg(fmt::color::gray); }
    static fmt::text_style context() { return fg(fmt::color::dim_gray) | fmt::emphasis::italic; }

private:
    static std::FILE* stream(Target t) { return t == Target::Out ? stdout : stderr; }

    bool isTty(Target t) const { return t == Target::Out ? caps_.ttyOut : caps_.ttyErr; }

    // Escape sequences are written only to a terminal, and only when the user
    // has not asked for plain output.
    bool escapesOk(Target t) const {
        return isTty(t) && (t == Target::Out ? caps_.colorOut : caps_.colorErr);
    }

    Caps caps_{};
};

}  // namespace lyxbosa
