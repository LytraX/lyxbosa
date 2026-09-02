#pragma once

// TerminalInput.h - Consuming terminal capability replies before the shell sees them.
//
// FTXUI probes the terminal when it installs: DA1 ("\033[c"), secondary DA
// ("\033[>c") and XTVERSION ("\033[>q"). The terminal answers on *stdin*,
// asynchronously. Anything still unread when the process exits is handed to the
// shell, which is how a finished scan can end with
//
//     ^[[?61;4;6;7;14;21;22;23;24;28;32;42;52c
//
// on screen and "61;4;...c" typed at the next prompt.
//
// Timing is the whole problem: the reply can land while the UI is up (FTXUI eats
// it), between teardown and exit, or after the process is gone (nothing in-process
// can help). So the drain is called at both points it can still do something -
// when the UI stands down, and again from the atexit hook.

#include <chrono>

#ifndef _WIN32
#include <poll.h>
#include <unistd.h>
#endif

namespace lyxbosa::terminal_input {

#ifndef _WIN32
namespace detail {

// Reads the body of one escape sequence, the ESC having already been taken.
// Handles both shapes a terminal replies in: CSI (ends on a byte in @-~) and the
// string families DCS/OSC/SOS/PM/APC (end on ST or BEL). XTVERSION answers with
// DCS, not CSI.
inline bool consumeEscapeSequence(std::chrono::steady_clock::time_point deadline) {
    auto next = [&](char& out) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) {
            return false;
        }
        struct pollfd pfd { STDIN_FILENO, POLLIN, 0 };
        if (::poll(&pfd, 1, static_cast<int>(remaining)) <= 0) {
            return false;
        }
        return ::read(STDIN_FILENO, &out, 1) == 1;
    };

    char c = 0;
    if (!next(c)) {
        return false;
    }

    if (c == '[') {  // CSI - final byte is the first one in the @-~ range
        while (next(c)) {
            if (c >= '@' && c <= '~') {
                return true;
            }
        }
        return false;
    }

    if (c == 'P' || c == ']' || c == 'X' || c == '^' || c == '_') {
        bool sawEsc = false;
        while (next(c)) {
            if (c == '\a') {
                return true;
            }
            if (sawEsc) {
                return c == '\\';
            }
            sawEsc = (c == '\033');
        }
        return false;
    }

    return true;  // two-byte escape, already complete
}

}  // namespace detail
#endif

// Consume terminal report replies queued on stdin, for up to `budget`.
//
// Only sequences beginning with ESC are eaten, and the loop stops at the first
// byte that is not one, so a keystroke the user typed ahead is never swallowed:
// guessing wrong costs a stray report getting through, not lost input.
//
// Returns the number of sequences consumed.
inline size_t drainReports(std::chrono::milliseconds budget = std::chrono::milliseconds(60)) {
#ifdef _WIN32
    (void)budget;
    return 0;  // Windows consoles answer through the input record queue, not stdin
#else
    if (!::isatty(STDIN_FILENO)) {
        return 0;
    }

    size_t consumed = 0;
    const auto deadline = std::chrono::steady_clock::now() + budget;

    while (true) {
        // Poll with no timeout: a reply that has not arrived yet is not worth
        // delaying exit for, and blocking here would add the whole budget to the
        // runtime of every scan that ends with a clean input queue. The budget is
        // only spent once a sequence has actually started arriving.
        struct pollfd pfd { STDIN_FILENO, POLLIN, 0 };
        if (::poll(&pfd, 1, 0) <= 0) {
            break;  // nothing queued
        }

        char c = 0;
        if (::read(STDIN_FILENO, &c, 1) != 1) {
            break;
        }
        if (c != '\033') {
            break;  // real input, not a report - leave the rest alone
        }
        if (!detail::consumeEscapeSequence(deadline)) {
            break;
        }
        ++consumed;
    }

    return consumed;
#endif
}

}  // namespace lyxbosa::terminal_input
