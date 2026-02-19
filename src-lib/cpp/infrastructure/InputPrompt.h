#pragma once

#include "Terminal.h"
#include <string>
#include <optional>
#include <iostream>

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#include <io.h>
#include <stdio.h>
#else
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#endif

namespace lyxbosa {

// Inquirer-style interactive input prompt
// Displays: "label: <input>" with colored input that remains visible after Enter
class InputPrompt {
public:
    explicit InputPrompt(const Terminal& terminal) : terminal_(terminal) {}

    // Prompt for a directory path
    // Returns nullopt if user cancels (Ctrl+C or empty input with allowEmpty=false)
    std::optional<std::string> promptDirectory(
        const std::string& label = "Directory to scan",
        const std::string& defaultValue = "."
    ) {
        return prompt(label, defaultValue, PromptType::Directory);
    }

    // Prompt for a file path
    std::optional<std::string> promptFile(
        const std::string& label = "File to check",
        const std::string& defaultValue = ""
    ) {
        return prompt(label, defaultValue, PromptType::File);
    }

    // Generic text prompt
    std::optional<std::string> promptText(
        const std::string& label,
        const std::string& defaultValue = ""
    ) {
        return prompt(label, defaultValue, PromptType::Text);
    }

private:
    enum class PromptType { Text, Directory, File };

    // Result from readInput: input string and whether user cancelled
    struct ReadResult {
        std::string input;
        bool cancelled = false;
    };

    std::optional<std::string> prompt(
        const std::string& label,
        const std::string& defaultValue,
        PromptType type
    ) {
        // Print the label with question mark (inquirer style)
        terminal_.print(promptStyle(), "? ");
        fmt::print("{}", label);

        // Show default value hint if present
        if (!defaultValue.empty()) {
            terminal_.print(hintStyle(), " ({})", defaultValue);
        }
        fmt::print(" ");
        std::cout.flush();

        // Read input character by character for live display
        auto result = readInput();

        // Handle cancellation (ESC or Ctrl+C)
        if (result.cancelled) {
            // Clear the prompt line and show cancelled state
            fmt::print("\r");
            terminal_.clearLine();
            fmt::print("\n");
            std::cout.flush();
            return std::nullopt;
        }

        std::string input = result.input;

        // Use default if input is empty
        if (input.empty() && !defaultValue.empty()) {
            input = defaultValue;
        }

        // Move cursor back to rewrite the line with final value
        fmt::print("\r");
        terminal_.clearLine();

        // Print final state: question mark + label + final value (inquirer style)
        terminal_.print(promptStyle(), "? ");
        fmt::print("{} ", label);
        terminal_.print(valueStyle(), "{}", input);
        fmt::print("\n");
        std::cout.flush();

        if (input.empty()) {
            return std::nullopt;
        }

        return input;
    }

    ReadResult readInput() {
        ReadResult result;

#ifdef _WIN32
        // Check if stdin is a terminal
        bool isTty = _isatty(_fileno(stdin));

        if (!isTty) {
            // Non-interactive: just read a line
            std::getline(std::cin, result.input);
            terminal_.print(inputStyle(), "{}", result.input);
            return result;
        }

        // Windows: Use _getch for character-by-character input
        while (true) {
            int ch = _getch();

            if (ch == '\r' || ch == '\n') {
                break;
            } else if (ch == 27) {  // ESC
                result.cancelled = true;
                return result;
            } else if (ch == 3) {  // Ctrl+C
                result.cancelled = true;
                return result;
            } else if (ch == 8 || ch == 127) {  // Backspace
                if (!result.input.empty()) {
                    result.input.pop_back();
                    // Erase character from display
                    fmt::print("\b \b");
                    std::cout.flush();
                }
            } else if (ch >= 32 && ch < 127) {  // Printable ASCII
                result.input += static_cast<char>(ch);
                terminal_.print(inputStyle(), "{}", static_cast<char>(ch));
                std::cout.flush();
            }
        }
#else
        // Check if stdin is a terminal
        bool isTty = isatty(STDIN_FILENO);

        if (!isTty) {
            // Non-interactive: just read a line
            std::getline(std::cin, result.input);
            terminal_.print(inputStyle(), "{}", result.input);
            return result;
        }

        // Unix: Use raw terminal mode
        struct termios oldt, newt;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO | ISIG);  // Disable canonical mode, echo, and signal generation
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);

        while (true) {
            char ch;
            if (read(STDIN_FILENO, &ch, 1) != 1) {
                break;
            }

            if (ch == '\n' || ch == '\r') {
                break;
            } else if (ch == 27) {  // ESC - check for escape sequences
                // Use select() with short timeout to distinguish ESC from escape sequences
                fd_set fds;
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 50000;  // 50ms timeout
                FD_ZERO(&fds);
                FD_SET(STDIN_FILENO, &fds);

                if (select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv) > 0) {
                    // More characters available - this is an escape sequence (arrow keys, etc.)
                    char seq[3];
                    [[maybe_unused]] auto n_ = read(STDIN_FILENO, seq, sizeof(seq));  // Consume escape sequence
                    continue;  // Ignore it
                }
                // No more characters within timeout - standalone ESC key
                tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
                result.cancelled = true;
                return result;
            } else if (ch == 3) {  // Ctrl+C
                tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
                result.cancelled = true;
                return result;
            } else if (ch == 127 || ch == 8) {  // Backspace or Delete
                if (!result.input.empty()) {
                    result.input.pop_back();
                    // Erase character from display
                    fmt::print("\b \b");
                    std::cout.flush();
                }
            } else if (ch >= 32) {  // Printable characters
                result.input += ch;
                terminal_.print(inputStyle(), "{}", ch);
                std::cout.flush();
            }
        }

        // Restore terminal settings
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

        return result;
    }

    // Style definitions (inquirer-like colors)
    static fmt::text_style promptStyle() {
        return fg(fmt::color::green);
    }

    static fmt::text_style labelStyle() {
        return fg(fmt::color::white) | fmt::emphasis::bold;
    }

    static fmt::text_style hintStyle() {
        return fg(fmt::color::dim_gray);
    }

    static fmt::text_style inputStyle() {
        return fg(fmt::color::cyan);
    }

    static fmt::text_style valueStyle() {
        return fg(fmt::color::cyan);
    }

    static fmt::text_style successStyle() {
        return fg(fmt::color::green);
    }

    const Terminal& terminal_;
};

}  // namespace lyxbosa
