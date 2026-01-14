#pragma once

#include <iostream>
#include <fmt/core.h>
#include <fmt/color.h>

namespace lyxbosa {

// Terminal control for ANSI sequences and colored output
class Terminal {
public:
    explicit Terminal(bool useAnsi = true) : useAnsi_(useAnsi) {}

    // Cursor control
    void hideCursor() const {
        if (useAnsi_) {
            fmt::print("\033[?25l");
            std::cout.flush();
        }
    }

    void showCursor() const {
        if (useAnsi_) {
            fmt::print("\033[?25h");
            std::cout.flush();
        }
    }

    void clearLine() const {
        if (useAnsi_) {
            fmt::print("\033[2K\r");
        } else {
            fmt::print("\r{:80}\r", "");
        }
    }

    void moveUp(int lines = 1) const {
        if (useAnsi_) {
            fmt::print("\033[{}A", lines);
        }
    }

    void moveDown(int lines = 1) const {
        if (useAnsi_) {
            fmt::print("\033[{}B", lines);
        }
    }

    void flush() const {
        std::cout.flush();
    }

    // Colored output to stdout
    template<typename... Args>
    void print(fmt::text_style style, fmt::format_string<Args...> fmt_str, Args&&... args) const {
        if (useAnsi_) {
            fmt::print(style, fmt_str, std::forward<Args>(args)...);
        } else {
            fmt::print(fmt_str, std::forward<Args>(args)...);
        }
    }

    // Colored output to stderr
    template<typename... Args>
    void printErr(fmt::text_style style, fmt::format_string<Args...> fmt_str, Args&&... args) const {
        if (useAnsi_) {
            fmt::print(stderr, style, fmt_str, std::forward<Args>(args)...);
        } else {
            fmt::print(stderr, fmt_str, std::forward<Args>(args)...);
        }
    }

    // Check if ANSI is enabled
    bool isAnsiEnabled() const { return useAnsi_; }

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
    bool useAnsi_;
};

}  // namespace lyxbosa
