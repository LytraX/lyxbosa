#pragma once

#include "Terminal.h"
#include "PathUtils.h"
#include "core/ScanResult.h"
#include "config/Types.h"
#include <fmt/core.h>

namespace lyxbosa {

// Formats and prints scan results in various formats
class ResultPrinter {
public:
    explicit ResultPrinter(const Terminal& terminal) : terminal_(terminal) {}

    // Print a single match
    void printMatch(const FileMatch& match) const {
        fmt::print("  ");

        // Show suppressed indicator with original severity
        if (match.suppressed) {
            terminal_.print(Terminal::muted(), "[SUPPRESSED:");
            switch (match.originalSeverity) {
                case Severity::Critical: terminal_.print(Terminal::muted(), "CRITICAL"); break;
                case Severity::High:     terminal_.print(Terminal::muted(), "HIGH"); break;
                case Severity::Medium:   terminal_.print(Terminal::muted(), "MEDIUM"); break;
                case Severity::Low:      terminal_.print(Terminal::muted(), "LOW"); break;
            }
            terminal_.print(Terminal::muted(), "]");
        } else {
            switch (match.severity) {
                case Severity::Critical:
                    terminal_.print(Terminal::critical(), "[CRITICAL]");
                    break;
                case Severity::High:
                    terminal_.print(Terminal::high(), "[HIGH]");
                    break;
                case Severity::Medium:
                    terminal_.print(Terminal::medium(), "[MEDIUM]");
                    break;
                case Severity::Low:
                    terminal_.print(Terminal::low(), "[LOW]");
                    break;
            }
        }
        fmt::print(" {} ({}:{}) - {}\n", match.ruleName, match.line, match.column, match.category);

        if (!match.context.empty()) {
            terminal_.print(Terminal::context(), "    {}\n", match.context);
        }
    }

    // Print a file result (verbose mode)
    void printFileResult(const FileResult& result) const {
        if (result.skippedSize) {
            terminal_.print(Terminal::muted(), "[-] {} (skipped - size limit)\n", pathToUtf8(result.path));
            return;
        }

        if (result.matches.empty()) {
            return;  // Don't print clean files
        }

        // Format: {red}[!] {cyan}filepath {yellow}[N matches]
        terminal_.print(Terminal::high(), "[!] ");
        terminal_.print(Terminal::low(), "{} ", pathToUtf8(result.path));
        terminal_.print(Terminal::medium(), "[{} match{}]\n", result.matches.size(), result.matches.size() == 1 ? "" : "es");

        for (const auto& match : result.matches) {
            printMatch(match);
        }

        if (result.quarantined) {
            terminal_.print(Terminal::low(), "    moved: {}\n", result.quarantinePath);
        }

        fmt::print("\n");
    }

    // Print a file result in compact single-line format
    // Format: [!] path/to/file.php  C:2 H:5 M:3 L:1
    void printFileResultCompact(const FileResult& result, size_t termWidth) const {
        if (result.skippedSize) {
            terminal_.print(Terminal::muted(), "[-] {} (skipped)\n", truncatePath(pathToUtf8(result.path), termWidth - 15));
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

        // Build severity suffix string to calculate its display length
        // Format: "  C:N H:N M:N L:N" (only non-zero counts)
        std::string severitySuffix;
        size_t suffixLen = 0;
        if (critical > 0) { severitySuffix += fmt::format("  C:{}", critical); suffixLen += 4 + std::to_string(critical).length(); }
        if (high > 0)     { severitySuffix += fmt::format("  H:{}", high);     suffixLen += 4 + std::to_string(high).length(); }
        if (medium > 0)   { severitySuffix += fmt::format("  M:{}", medium);   suffixLen += 4 + std::to_string(medium).length(); }
        if (low > 0)      { severitySuffix += fmt::format("  L:{}", low);      suffixLen += 4 + std::to_string(low).length(); }

        // Calculate available space for path: termWidth - "[!] " (4) - suffix length
        size_t prefixLen = 4;  // "[!] "
        size_t availableForPath = (termWidth > prefixLen + suffixLen) ? termWidth - prefixLen - suffixLen : 20;

        std::string pathStr = truncatePath(pathToUtf8(result.path), availableForPath);

        // Print the line
        terminal_.print(Terminal::high(), "[!] ");
        terminal_.print(Terminal::low(), "{}", pathStr);

        // Print severity counts with colors
        if (critical > 0) {
            terminal_.print(Terminal::critical(), "  C:{}", critical);
        }
        if (high > 0) {
            terminal_.print(Terminal::high(), "  H:{}", high);
        }
        if (medium > 0) {
            terminal_.print(Terminal::medium(), "  M:{}", medium);
        }
        if (low > 0) {
            terminal_.print(Terminal::low(), "  L:{}", low);
        }

        fmt::print("\n");
    }

    // Print scan summary
    void printSummary(const ScanResult& result) const {
        fmt::print("\n");
        terminal_.print(Terminal::info(), "=== Scan Summary ===\n\n");

        fmt::print("Files scanned: {}\n", result.totalFilesScanned);
        fmt::print("Directories parsed: {}\n", result.totalDirectoriesScanned);
        fmt::print("Files with matches: {}\n", result.filesWithMatches);
        fmt::print("Files skipped (size limit): {}\n", result.filesSkippedSize);

        if (result.filesQuarantined > 0) {
            fmt::print("Files quarantined: {}\n", result.filesQuarantined);
        }

        if (result.filesWithMatches > 0) {
            fmt::print("\nMatches by severity:\n");
            if (result.criticalCount > 0) {
                terminal_.print(Terminal::critical(), "  Critical: {}\n", result.criticalCount);
            }
            if (result.highCount > 0) {
                terminal_.print(Terminal::high(), "  High: {}\n", result.highCount);
            }
            if (result.mediumCount > 0) {
                terminal_.print(Terminal::medium(), "  Medium: {}\n", result.mediumCount);
            }
            if (result.lowCount > 0) {
                terminal_.print(Terminal::low(), "  Low: {}\n", result.lowCount);
            }
        } else {
            fmt::print("\nNo matches found.\n");
        }

        auto totalMs = result.duration().count();
        auto totalSecs = totalMs / 1000;
        if (totalSecs >= 3600) {
            auto h = totalSecs / 3600;
            auto m = (totalSecs % 3600) / 60;
            auto s = totalSecs % 60;
            fmt::print("\nScan completed in {}h {}m {}s\n", h, m, s);
        } else if (totalSecs >= 60) {
            auto m = totalSecs / 60;
            auto s = totalSecs % 60;
            fmt::print("\nScan completed in {}m {}s\n", m, s);
        } else {
            fmt::print("\nScan completed in {:.2f} seconds\n", totalMs / 1000.0);
        }
    }

    // Print results as JSON
    void printJson(const ScanResult& result) const {
        fmt::print("{{\n");
        fmt::print("  \"totalFilesScanned\": {},\n", result.totalFilesScanned);
        fmt::print("  \"totalDirectoriesScanned\": {},\n", result.totalDirectoriesScanned);
        fmt::print("  \"filesWithMatches\": {},\n", result.filesWithMatches);
        fmt::print("  \"filesQuarantined\": {},\n", result.filesQuarantined);
        fmt::print("  \"durationMs\": {},\n", result.duration().count());
        fmt::print("  \"files\": [\n");

        bool firstFile = true;
        for (const auto& file : result.files) {
            if (file.matches.empty() && !file.skippedSize) continue;

            if (!firstFile) fmt::print(",\n");
            firstFile = false;

            fmt::print("    {{\n");
            fmt::print("      \"path\": \"{}\",\n", pathToUtf8(file.path));
            fmt::print("      \"skipped\": {},\n", file.skippedSize ? "true" : "false");
            fmt::print("      \"quarantined\": {},\n", file.quarantined ? "true" : "false");
            fmt::print("      \"matches\": [\n");

            bool firstMatch = true;
            for (const auto& match : file.matches) {
                if (!firstMatch) fmt::print(",\n");
                firstMatch = false;

                fmt::print("        {{\n");
                fmt::print("          \"rule\": \"{}\",\n", match.ruleName);
                fmt::print("          \"severity\": \"{}\",\n", severityToString(match.severity));
                if (match.suppressed) {
                    fmt::print("          \"originalSeverity\": \"{}\",\n", severityToString(match.originalSeverity));
                    fmt::print("          \"suppressed\": true,\n");
                }
                fmt::print("          \"category\": \"{}\",\n", match.category);
                fmt::print("          \"line\": {},\n", match.line);
                fmt::print("          \"column\": {}\n", match.column);
                fmt::print("        }}");
            }

            fmt::print("\n      ]\n");
            fmt::print("    }}");
        }

        fmt::print("\n  ]\n");
        fmt::print("}}\n");
    }

    // Print results as CSV
    void printCsv(const ScanResult& result) const {
        fmt::print("file,rule,severity,original_severity,suppressed,category,line,column,quarantined\n");

        for (const auto& file : result.files) {
            for (const auto& match : file.matches) {
                fmt::print("{},{},{},{},{},{},{},{},{}\n",
                           pathToUtf8(file.path),
                           match.ruleName,
                           severityToString(match.severity),
                           match.suppressed ? severityToString(match.originalSeverity) : "",
                           match.suppressed ? "true" : "false",
                           match.category,
                           match.line,
                           match.column,
                           file.quarantined ? "true" : "false");
            }
        }
    }

    // Print all results based on format
    void printResults(const ScanResult& result, ReportFormat format) const {
        switch (format) {
            case ReportFormat::Text:
                for (const auto& file : result.files) {
                    printFileResult(file);
                }
                printSummary(result);
                break;

            case ReportFormat::Json:
                printJson(result);
                break;

            case ReportFormat::Csv:
                printCsv(result);
                break;
        }
    }

private:
    // Truncate path from the beginning if too long: "...rest/of/path"
    static std::string truncatePath(const std::string& path, size_t maxLen) {
        if (path.length() <= maxLen) {
            return path;
        }
        if (maxLen <= 3) {
            return "...";
        }
        size_t keep = maxLen - 3;  // Reserve space for "..."
        return "..." + path.substr(path.length() - keep);
    }

    const Terminal& terminal_;
};

}  // namespace lyxbosa
