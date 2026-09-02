#pragma once

// PlainProgress.h - A single throttled status line on stderr.
//
// Used whenever we must not take over stdout: the report is being redirected to
// a file or a pipe, the format is JSON/CSV, or the user asked for
// --progress=plain. Deliberately uses no escape sequences beyond a carriage
// return, so it behaves identically with and without --color.

#include "TerminalCaps.h"
#include "PathUtils.h"
#include "core/Scanner.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <string>
#include <fmt/format.h>

namespace lyxbosa {

class PlainProgress {
public:
    explicit PlainProgress(const TerminalCaps& caps) : width_(caps.width()) {}

    void onCountingStart() {
        render("Counting files...");
    }

    void onCountingDone(size_t totalFiles) {
        total_ = totalFiles;
        render(compose(0, 0, ""));
    }

    void update(const ScanProgress& progress) {
        auto now = std::chrono::steady_clock::now();
        if (rendered_ && now - lastRender_ < kInterval) {
            return;
        }
        lastRender_ = now;
        total_ = progress.totalFiles;
        render(compose(progress.filesScanned,
                       progress.totalMatchCount,
                       pathToUtf8(progress.currentFile)));
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

    std::string compose(size_t scanned, size_t hits, const std::string& current) const {
        std::string head;
        if (total_ > 0) {
            const size_t percent = std::min<size_t>(100, scanned * 100 / total_);
            head = fmt::format("[{:3}%] {}/{} files", percent, scanned, total_);
        } else {
            head = fmt::format("[  --] {} files", scanned);
        }

        if (hits > 0) {
            head += fmt::format("  {} hits", hits);
        }

        if (current.empty()) {
            return head;
        }

        // Whatever is left of the line goes to the path being scanned.
        const size_t budget = usableWidth();
        if (head.size() + 2 >= budget) {
            return head;
        }
        return head + "  " + truncateTail(current, budget - head.size() - 2);
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

    // Keep the tail of a path ("...rest/of/path"), never splitting a codepoint.
    static std::string truncateTail(const std::string& s, size_t maxBytes) {
        if (s.size() <= maxBytes) {
            return s;
        }
        if (maxBytes <= 3) {
            return "...";
        }
        size_t start = s.size() - (maxBytes - 3);
        while (start < s.size() && isContinuation(s[start])) {
            ++start;
        }
        return "..." + s.substr(start);
    }

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
    size_t total_ = 0;
    size_t lastLen_ = 0;
    bool rendered_ = false;
    std::chrono::steady_clock::time_point lastRender_{};
};

}  // namespace lyxbosa
