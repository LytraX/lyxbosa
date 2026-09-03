#pragma once

#include <optional>

// TuiReporter.h - Full-screen scan UI on the alternate screen buffer.
//
// The alternate screen is the only way to keep the status block visible while
// the user scrolls back through the findings: terminal scrollback belongs to the
// emulator and an application is never told the user scrolled, so a status line
// drawn in the primary buffer scrolls away with everything else. Owning the
// viewport means owning the scrolling too, which is what the findings pane below
// implements.
//
// The debt that buys is that the alternate screen takes its contents with it on
// exit. ScanUseCase settles it by dumping the buffered report into the primary
// buffer once this reporter has stood down.

#ifdef LYXBOSA_TUI_ENABLED

#include "ProgressModel.h"
#include "PathUtils.h"
#include "core/Interrupt.h"
#include "core/ScanResult.h"
#include "core/Scanner.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include "TerminalInput.h"

#include <ftxui/component/app.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/loop.hpp>
#include <ftxui/component/mouse.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/terminal.hpp>

namespace lyxbosa {

class TuiReporter {
public:
    explicit TuiReporter(bool dryRun) : dryRun_(dryRun) {}

    ~TuiReporter() { shutdown(); }

    TuiReporter(const TuiReporter&) = delete;
    TuiReporter& operator=(const TuiReporter&) = delete;

    void begin() {
        screen_ = std::make_unique<ftxui::App>(ftxui::App::Fullscreen());
        screen_->TrackMouse(true);
        // Let our own handling of Ctrl-C win, so an interrupt unwinds the scan
        // and still produces a report rather than dropping the process.
        screen_->ForceHandleCtrlC(false);

        auto renderer = ftxui::Renderer([this] { return render(); });
        component_ = ftxui::CatchEvent(renderer, [this](ftxui::Event event) {
            return onEvent(event);
        });

        loop_ = std::make_unique<ftxui::Loop>(screen_.get(), component_);
        started_ = true;
        g_cursorHidden.store(true, std::memory_order_relaxed);
        lastFrame_ = Clock::now();
        pump(/*force=*/true);
    }

    void onProgress(const ScanProgress& progress) {
        const auto now = Clock::now();
        model_.update(progress, now);
        // Inside an archive the line reads "backup.zip -> 1203/28092  member",
        // so a 20 GB backup does not sit on one unchanging "file" for minutes.
        currentPrefix_ = archivePositionPrefix(progress);
        current_ = pathForDisplay(progress.currentFile);
        pump();
    }

    void onFinding(const FileResult& result) {
        Row row;
        row.path = pathForDisplay(result.path);
        row.skipReason = result.skipReason;
        row.quarantined = result.quarantined;
        for (const auto& match : result.matches) {
            switch (match.severity) {
                case Severity::Critical: ++row.critical; break;
                case Severity::High:     ++row.high; break;
                case Severity::Medium:   ++row.medium; break;
                case Severity::Low:      ++row.low; break;
            }
        }
        rows_.push_back(std::move(row));
        pump();
    }

    // Draw one final frame, then leave the alternate screen. Everything the user
    // needs to keep is written to the primary buffer by the caller afterwards.
    void finish() {
        if (!started_) {
            return;
        }
        finished_ = true;
        pump(/*force=*/true);
        shutdown();
    }

    // True when the user asked to stop early with q.
    bool quitRequested() const { return quit_; }

private:
    using Clock = std::chrono::steady_clock;

    // ~20fps. Redrawing per file would be wasted work at a few hundred files a
    // second, and 50ms of key latency is imperceptible.
    static constexpr auto kFrameInterval = std::chrono::milliseconds(50);

    // separator + gauge + counters + current + keys
    static constexpr int kStatusHeight = 5;

    struct Row {
        std::string path;
        size_t critical = 0;
        size_t high = 0;
        size_t medium = 0;
        size_t low = 0;
        std::optional<SkipReason> skipReason;
        bool quarantined = false;
    };

    void shutdown() {
        if (!started_) {
            return;
        }
        started_ = false;
        // Order matters: the Loop uninstalls the terminal hooks it installed,
        // and the App restores the primary screen buffer as it goes away.
        loop_.reset();
        component_ = nullptr;
        screen_.reset();
        g_cursorHidden.store(false, std::memory_order_relaxed);
        drainTerminalReports();
    }

    // FTXUI's capability probes are answered on stdin; consume what has arrived
    // by now so it is not handed to the shell. See TerminalInput.h - the reply can
    // also land after this point, which is why main() drains again at exit.
    static void drainTerminalReports() {
        terminal_input::drainReports();
    }

    void pump(bool force = false) {
        if (!started_) {
            return;
        }
        const auto now = Clock::now();
        if (force || now - lastFrame_ >= kFrameInterval) {
            lastFrame_ = now;
            // RunOnce() drains pending tasks and only repaints in response to
            // one, so a scan that produces no input events would render a single
            // frame and then sit frozen. Asking for a frame is what drives the
            // redraw here.
            screen_->RequestAnimationFrame();
            loop_->RunOnce();
        }
        // Paused: keep servicing input so p, q and scrolling still work, but
        // hand no time back to the scan until the user resumes.
        while (paused_ && !quit_ && !interrupted()) {
            loop_->RunOnceBlocking();
        }
    }

    int paneHeight() const {
        const int rows = ftxui::Terminal::Size().dimy;
        return std::max(1, rows - kStatusHeight - 1);
    }

    int maxScroll() const {
        return std::max(0, static_cast<int>(rows_.size()) - paneHeight());
    }

    void scrollBy(int delta) {
        const int limit = maxScroll();
        if (follow_) {
            scroll_ = limit;
        }
        scroll_ = std::clamp(scroll_ + delta, 0, limit);
        // Reaching the bottom re-engages following; leaving it disengages.
        follow_ = (scroll_ >= limit);
    }

    bool onEvent(ftxui::Event event) {
        using ftxui::Event;

        if (event == Event::Character('q') || event == Event::Escape ||
            event == Event::CtrlC) {
            quit_ = true;
            // Same path as Ctrl-C on the command line: unwind, report, exit 130.
            g_interrupted.store(true, std::memory_order_relaxed);
            screen_->Exit();
            return true;
        }
        if (event == Event::Character('p') || event == Event::Character(' ')) {
            paused_ = !paused_;
            return true;
        }
        if (event == Event::ArrowUp)   { scrollBy(-1); return true; }
        if (event == Event::ArrowDown) { scrollBy(1);  return true; }
        if (event == Event::PageUp)    { scrollBy(-paneHeight()); return true; }
        if (event == Event::PageDown)  { scrollBy(paneHeight());  return true; }
        if (event == Event::Home)      { follow_ = false; scroll_ = 0; return true; }
        if (event == Event::End)       { follow_ = true; scroll_ = maxScroll(); return true; }

        if (event.is_mouse()) {
            const auto button = event.mouse().button;
            if (button == ftxui::Mouse::WheelUp)   { scrollBy(-3); return true; }
            if (button == ftxui::Mouse::WheelDown) { scrollBy(3);  return true; }
        }
        return false;
    }

    struct Chip {
        std::string text;
        ftxui::Color color;
    };

    static void addChip(std::vector<Chip>& chips, const char* label, size_t count,
                        ftxui::Color color) {
        if (count > 0) {
            chips.push_back({fmt::format("  {}:{}", label, count), color});
        }
    }

    static ftxui::Elements chipElements(const std::vector<Chip>& chips) {
        ftxui::Elements out;
        out.reserve(chips.size());
        for (const auto& chip : chips) {
            out.push_back(ftxui::text(chip.text) | ftxui::color(chip.color));
        }
        return out;
    }

    static int chipsWidth(const std::vector<Chip>& chips) {
        int width = 0;
        for (const auto& chip : chips) {
            width += static_cast<int>(chip.text.size());
        }
        return width;
    }

    ftxui::Element renderRow(const Row& row, int width) const {
        using namespace ftxui;

        if (row.skipReason) {
            const std::string reason(skipReasonToString(*row.skipReason));
            return text("  - " + truncateTail(row.path, width - 16 - static_cast<int>(reason.size()))
                        + " (skipped: " + reason + ")")
                   | color(Color::GrayDark);
        }

        std::vector<Chip> chips;
        addChip(chips, "C", row.critical, Color::Red);
        addChip(chips, "H", row.high, Color::RedLight);
        addChip(chips, "M", row.medium, Color::Yellow);
        addChip(chips, "L", row.low, Color::Cyan);
        if (row.quarantined) {
            chips.push_back({"  [quarantined]", Color::Magenta});
        }

        Elements line;
        line.push_back(text("  ! ") | color(Color::RedLight));
        line.push_back(text(truncateTail(row.path,
                                         std::max(10, width - 6 - chipsWidth(chips))))
                       | color(Color::Cyan));
        for (auto& element : chipElements(chips)) {
            line.push_back(element);
        }
        return hbox(std::move(line));
    }

    ftxui::Element render() {
        using namespace ftxui;

        const auto dims = ftxui::Terminal::Size();
        const int width = std::max(20, dims.dimx);
        const int height = paneHeight();

        if (follow_) {
            scroll_ = maxScroll();
        }
        scroll_ = std::clamp(scroll_, 0, maxScroll());

        // Findings pane
        Elements visible;
        const int first = scroll_;
        const int last = std::min(static_cast<int>(rows_.size()), first + height);
        for (int i = first; i < last; ++i) {
            visible.push_back(renderRow(rows_[i], width));
        }
        if (visible.empty()) {
            visible.push_back(text("  no findings yet") | color(Color::GrayDark));
        }
        while (static_cast<int>(visible.size()) < height) {
            visible.push_back(text(""));
        }

        const ScanProgress& p = model_.progress();

        // The affordance that makes owning the scroll worth it: say so when the
        // view is pinned above newer findings.
        const int behind = static_cast<int>(rows_.size()) - (scroll_ + height);
        Element scrollHint =
            (!follow_ && behind > 0)
                ? (text(fmt::format(" jump to bottom (End) - {} more below ", behind))
                   | color(Color::Black) | bgcolor(Color::Yellow))
                : text("");

        // Status block
        Element headline;
        if (model_.totalKnown()) {
            headline = hbox({
                text(fmt::format("{:3}% ", model_.percent())) | bold,
                gauge(static_cast<float>(model_.fraction())) | flex,
                text(fmt::format(" {}/{} files", p.filesScanned, p.totalFiles)),
            });
        } else {
            headline = hbox({
                text("counting... ") | color(Color::GrayDark),
                text(fmt::format("{} of {}+ files", p.filesScanned,
                                 std::max(p.discoveredFiles, p.filesScanned))),
                filler(),
            });
        }

        std::vector<Chip> statusChips;
        addChip(statusChips, "C", p.criticalCount, Color::Red);
        addChip(statusChips, "H", p.highCount, Color::RedLight);
        addChip(statusChips, "M", p.mediumCount, Color::Yellow);
        addChip(statusChips, "L", p.lowCount, Color::Cyan);

        Elements counters;
        counters.push_back(text(fmt::format("{} dirs", p.directoriesScanned)));
        for (auto& element : chipElements(statusChips)) {
            counters.push_back(element);
        }
        counters.push_back(filler());
        counters.push_back(text(fmt::format("{:.0f} f/s  ", model_.filesPerSecond())));
        if (const auto eta = model_.eta()) {
            counters.push_back(text(fmt::format("ETA {}  ", formatDuration(*eta))));
        }
        counters.push_back(text(formatDuration(
            std::chrono::duration_cast<std::chrono::seconds>(model_.elapsed()))));

        std::string state;
        if (finished_) {
            state = "done";
        } else if (paused_) {
            state = "PAUSED";
        } else {
            state = "scanning";
        }

        Element currentLine = hbox({
            text(state + ": ") | color(paused_ ? Color::Yellow : Color::GrayDark),
            text(currentPrefix_ +
                 truncateTail(current_,
                              std::max<int>(10, width - 12 -
                                                static_cast<int>(currentPrefix_.size()))))
                | dim,
        });

        Element keys = hbox({
            text(" q quit  p pause  " ) | color(Color::GrayDark),
            text("↑↓ PgUp/PgDn scroll  Home/End  ") | color(Color::GrayDark),
            filler(),
            dryRun_ ? (text("DRY RUN ") | color(Color::Yellow)) : text(""),
        });

        return vbox({
            vbox(std::move(visible)) | flex,
            scrollHint,
            separator(),
            headline,
            hbox(std::move(counters)),
            currentLine,
            keys,
        });
    }

    // Keep the tail of a path, never splitting a UTF-8 codepoint.
    static std::string truncateTail(const std::string& path, int maxLen) {
        if (maxLen <= 3) {
            return "...";
        }
        if (path.size() <= static_cast<size_t>(maxLen)) {
            return path;
        }
        size_t start = path.size() - (static_cast<size_t>(maxLen) - 3);
        while (start < path.size() &&
               (static_cast<unsigned char>(path[start]) & 0xC0) == 0x80) {
            ++start;
        }
        return "..." + path.substr(start);
    }

    bool dryRun_ = false;
    bool started_ = false;
    bool finished_ = false;
    bool quit_ = false;
    bool paused_ = false;
    bool follow_ = true;
    int scroll_ = 0;

    std::string current_;
    std::string currentPrefix_;   // "backup.zip -> 1203/28092  ", never truncated
    std::vector<Row> rows_;
    ProgressModel model_;
    Clock::time_point lastFrame_{};

    std::unique_ptr<ftxui::App> screen_;
    ftxui::Component component_;
    std::unique_ptr<ftxui::Loop> loop_;
};

}  // namespace lyxbosa

#endif  // LYXBOSA_TUI_ENABLED
