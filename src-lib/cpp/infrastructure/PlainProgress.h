#pragma once

// PlainProgress.h - A single throttled status line on stderr.
//
// Used whenever we must not take over stdout: the report is being redirected to
// a file or a pipe, the format is JSON/CSV, or the user asked for
// --progress=plain. Deliberately uses no escape sequences beyond a carriage
// return, so it behaves identically with and without --color.

#include "ProgressModel.h"
#include "TerminalCaps.h"
#include "PathUtils.h"
#include "core/Scanner.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>
#include <fmt/format.h>

namespace lyxbosa {

class PlainProgress {
public:
    explicit PlainProgress(const TerminalCaps& caps)
        : width_(caps.width()), model_(std::chrono::steady_clock::now()) {}

    void start() { render("Starting scan..."); }

    void update(const ScanProgress& progress) {
        const auto now = std::chrono::steady_clock::now();
        model_.update(progress, now);

        if (rendered_ && now - lastRender_ < kInterval) {
            return;
        }
        lastRender_ = now;
        render(compose());
    }

    // Erase the status line so something else can write to the terminal.
    void clear() {
        if (lastLen_ == 0) {
            return;
        }
        fmt::print(stderr, "\r{: <{}}\r", "", lastLen_);
        std::fflush(stderr);
        lastLen_ = 0;
    }

    void finish() {
        clear();
        rendered_ = false;
    }

private:
    static constexpr auto kInterval = std::chrono::milliseconds(100);

    std::string compose() const {
        const ScanProgress& p = model_.progress();

        // Head: percentage once the concurrent count has landed, otherwise the
        // running scanned/discovered counts.
        std::string line;
        if (model_.totalKnown()) {
            line = fmt::format("[{:3}%] {}/{}", model_.percent(), p.filesScanned, p.totalFiles);
        } else if (p.discoveredFiles > p.filesScanned) {
            line = fmt::format("[ ...] {} of {}+", p.filesScanned, p.discoveredFiles);
        } else {
            line = fmt::format("[ ...] {}", p.filesScanned);
        }

        // Optional segments, most useful first; each is added only if it fits.
        std::vector<std::string> extras;
        if (p.directoriesScanned > 0) {
            extras.push_back(fmt::format("{} dirs", p.directoriesScanned));
        }
        if (p.totalMatchCount > 0) {
            std::string chips;
            if (p.criticalCount > 0) chips += fmt::format("C:{} ", p.criticalCount);
            if (p.highCount > 0)     chips += fmt::format("H:{} ", p.highCount);
            if (p.mediumCount > 0)   chips += fmt::format("M:{} ", p.mediumCount);
            if (p.lowCount > 0)      chips += fmt::format("L:{} ", p.lowCount);
            if (!chips.empty()) {
                chips.pop_back();
                extras.push_back(chips);
            }
        }
        if (const auto eta = model_.eta()) {
            extras.push_back(fmt::format("ETA {}", formatDuration(*eta)));
        }
        const double rate = model_.filesPerSecond();
        if (rate >= 1.0) {
            extras.push_back(fmt::format("{:.0f} f/s", rate));
        }

        const size_t budget = usableWidth();
        for (const auto& extra : extras) {
            if (line.size() + extra.size() + 2 > budget) {
                break;
            }
            line += "  " + extra;
        }

        // Whatever is left of the line goes to what is being read. Inside an
        // archive that is the archive, where the scan is within it, and the
        // member - because an archive is a directory, and scanning one should
        // look like scanning a directory.
        if (line.size() + kMinPathWidth + 2 > budget) {
            return line;
        }
        const std::string current = describeCurrentFile(p, budget - line.size() - 2);
        return current.empty() ? line : line + "  " + current;
    }

    void render(const std::string& line) {
        const std::string out = clipUtf8(line, usableWidth());
        const size_t pad = lastLen_ > out.size() ? lastLen_ - out.size() : 0;
        fmt::print(stderr, "\r{}{: <{}}", out, "", pad);
        std::fflush(stderr);
        lastLen_ = out.size();
        rendered_ = true;
    }

    size_t usableWidth() const { return width_ > 1 ? width_ - 1 : 79; }

    static constexpr size_t kMinPathWidth = 20;

    // Drop any trailing partial codepoint left by a hard byte-length clip.
    static std::string clipUtf8(const std::string& s, size_t maxBytes) {
        if (s.size() <= maxBytes) {
            return s;
        }
        size_t end = maxBytes;
        while (end > 0 && isContinuation(s[end])) {
            --end;
        }
        return s.substr(0, end);
    }

    static bool isContinuation(char c) {
        return (static_cast<unsigned char>(c) & 0xC0) == 0x80;
    }

    size_t width_ = 80;
    size_t lastLen_ = 0;
    bool rendered_ = false;
    std::chrono::steady_clock::time_point lastRender_{};
    ProgressModel model_;
};

}  // namespace lyxbosa
