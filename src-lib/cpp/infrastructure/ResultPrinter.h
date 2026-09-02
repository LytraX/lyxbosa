#pragma once

#include "Terminal.h"
#include "PathUtils.h"
#include "core/ScanResult.h"
#include "config/Types.h"
#include <cctype>
#include <ostream>
#include <string>
#include <fmt/format.h>

namespace lyxbosa {

// Formats scan results as human-readable text onto an arbitrary stream.
//
// The same code serves the terminal (colour on, real terminal width) and a
// report file (colour off, fixed width), which is what lets --output-file reuse
// the text format rather than growing a second implementation of it.
class ResultPrinter {
public:
    ResultPrinter(std::ostream& out, bool color, size_t width)
        : out_(out), color_(color), width_(width) {}

    // Print a single match
    void printMatch(const FileMatch& match) const {
        plain("  ");

        // Show suppressed indicator with original severity
        if (match.suppressed) {
            styled(Terminal::muted(), "[SUPPRESSED:{}]", upper(match.originalSeverity));
        } else {
            styled(severityStyle(match.severity), "[{}]", upper(match.severity));
        }
        plain(" {} ({}:{}) - {}\n", match.ruleName, match.line, match.column, match.category);

        if (!match.context.empty()) {
            styled(Terminal::context(), "    {}\n", match.context);
        }
    }

    // Print a file result (verbose mode)
    void printFileResult(const FileResult& result) const {
        if (result.skippedSize) {
            styled(Terminal::muted(), "[-] {} (skipped - size limit)\n", pathToUtf8(result.path));
            return;
        }

        if (result.matches.empty()) {
            return;  // Don't print clean files
        }

        styled(Terminal::high(), "[!] ");
        styled(Terminal::low(), "{} ", pathToUtf8(result.path));
        styled(Terminal::medium(), "[{} match{}]\n",
               result.matches.size(), result.matches.size() == 1 ? "" : "es");

        for (const auto& match : result.matches) {
            printMatch(match);
        }

        if (result.quarantined) {
            styled(Terminal::low(), "    moved: {}\n", result.quarantinePath);
        }

        plain("\n");
    }

    // Print a file result in compact single-line format
    // Format: [!] path/to/file.php  C:2 H:5 M:3 L:1
    void printFileResultCompact(const FileResult& result) const {
        if (result.skippedSize) {
            styled(Terminal::muted(), "[-] {} (skipped)\n",
                   truncatePath(pathToUtf8(result.path), width_ > 15 ? width_ - 15 : 20));
            return;
        }

        if (result.matches.empty()) {
            return;  // Don't print clean files
        }

        // Count severities
        size_t critical = 0, high = 0, medium = 0, low = 0;
        for (const auto& match : result.matches) {
            switch (match.severity) {
                case Severity::Critical: ++critical; break;
                case Severity::High:     ++high; break;
                case Severity::Medium:   ++medium; break;
                case Severity::Low:      ++low; break;
            }
        }

        // Length of the "  C:N  H:N ..." suffix, so the path gets the rest
        size_t suffixLen = 0;
        for (size_t count : {critical, high, medium, low}) {
            if (count > 0) {
                suffixLen += 4 + std::to_string(count).length();
            }
        }

        constexpr size_t prefixLen = 4;  // "[!] "
        const size_t availableForPath =
            (width_ > prefixLen + suffixLen) ? width_ - prefixLen - suffixLen : 20;

        styled(Terminal::high(), "[!] ");
        styled(Terminal::low(), "{}", truncatePath(pathToUtf8(result.path), availableForPath));

        if (critical > 0) styled(Terminal::critical(), "  C:{}", critical);
        if (high > 0)     styled(Terminal::high(),     "  H:{}", high);
        if (medium > 0)   styled(Terminal::medium(),   "  M:{}", medium);
        if (low > 0)      styled(Terminal::low(),      "  L:{}", low);

        plain("\n");
    }

    // Print scan summary
    void printSummary(const ScanResult& result) const {
        plain("\n");
        styled(Terminal::info(), "=== Scan Summary ===\n\n");

        plain("Files scanned: {}\n", result.totalFilesScanned);
        plain("Directories parsed: {}\n", result.totalDirectoriesScanned);
        plain("Files with matches: {}\n", result.filesWithMatches);
        plain("Files skipped (size limit): {}\n", result.filesSkippedSize);

        if (result.filesQuarantined > 0) {
            plain("Files quarantined: {}\n", result.filesQuarantined);
        }

        if (result.filesWithMatches > 0) {
            plain("\nMatches by severity:\n");
            if (result.criticalCount > 0) styled(Terminal::critical(), "  Critical: {}\n", result.criticalCount);
            if (result.highCount > 0)     styled(Terminal::high(),     "  High: {}\n", result.highCount);
            if (result.mediumCount > 0)   styled(Terminal::medium(),   "  Medium: {}\n", result.mediumCount);
            if (result.lowCount > 0)      styled(Terminal::low(),      "  Low: {}\n", result.lowCount);
        } else {
            plain("\nNo matches found.\n");
        }

        auto totalMs = result.duration().count();
        auto totalSecs = totalMs / 1000;
        if (totalSecs >= 3600) {
            plain("\nScan completed in {}h {}m {}s\n",
                  totalSecs / 3600, (totalSecs % 3600) / 60, totalSecs % 60);
        } else if (totalSecs >= 60) {
            plain("\nScan completed in {}m {}s\n", totalSecs / 60, totalSecs % 60);
        } else {
            plain("\nScan completed in {:.2f} seconds\n", totalMs / 1000.0);
        }
    }

    // Truncate a path from the beginning ("...rest/of/path") without ever
    // splitting a UTF-8 codepoint.
    static std::string truncatePath(const std::string& path, size_t maxLen) {
        if (path.length() <= maxLen) {
            return path;
        }
        if (maxLen <= 3) {
            return "...";
        }
        size_t start = path.length() - (maxLen - 3);
        while (start < path.length() &&
               (static_cast<unsigned char>(path[start]) & 0xC0) == 0x80) {
            ++start;
        }
        return "..." + path.substr(start);
    }

private:
    template<typename... Args>
    void plain(fmt::format_string<Args...> fmt_str, Args&&... args) const {
        out_ << fmt::format(fmt_str, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void styled(fmt::text_style style, fmt::format_string<Args...> fmt_str, Args&&... args) const {
        if (color_) {
            out_ << fmt::format(style, fmt_str, std::forward<Args>(args)...);
        } else {
            out_ << fmt::format(fmt_str, std::forward<Args>(args)...);
        }
    }

    static fmt::text_style severityStyle(Severity s) {
        switch (s) {
            case Severity::Critical: return Terminal::critical();
            case Severity::High:     return Terminal::high();
            case Severity::Medium:   return Terminal::medium();
            case Severity::Low:      return Terminal::low();
        }
        return Terminal::medium();
    }

    static std::string upper(Severity s) {
        std::string out(severityToString(s));
        for (char& c : out) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        return out;
    }

    std::ostream& out_;
    bool color_;
    size_t width_;
};

}  // namespace lyxbosa
