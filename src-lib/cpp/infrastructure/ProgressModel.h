#pragma once

// ProgressModel.h - Derived progress state: percentage, throughput and ETA.
//
// Deliberately free of any terminal dependency, so the plain stderr line and the
// full-screen UI share one source of truth and the arithmetic can be unit-tested
// against a driven clock rather than a real one.

#include "core/Scanner.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <fmt/format.h>

namespace lyxbosa {

class ProgressModel {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    explicit ProgressModel(TimePoint start = Clock::now())
        : start_(start), now_(start), lastSample_(start) {}

    void update(const ScanProgress& progress, TimePoint now) {
        progress_ = progress;
        now_ = now;

        const double dt = std::chrono::duration<double>(now - lastSample_).count();
        if (dt < kSampleSeconds) {
            return;
        }

        // Exponentially weighted so the rate tracks a directory of large files
        // without the ETA jumping around on every sample.
        const double instantFiles =
            (static_cast<double>(progress.filesScanned) - static_cast<double>(sampleFiles_)) / dt;
        const double instantBytes =
            (static_cast<double>(progress.bytesScanned) - static_cast<double>(sampleBytes_)) / dt;

        filesRate_ = haveRate_ ? kAlpha * instantFiles + (1.0 - kAlpha) * filesRate_
                               : instantFiles;
        bytesRate_ = haveRate_ ? kAlpha * instantBytes + (1.0 - kAlpha) * bytesRate_
                               : instantBytes;

        haveRate_ = true;
        lastSample_ = now;
        sampleFiles_ = progress.filesScanned;
        sampleBytes_ = progress.bytesScanned;
    }

    const ScanProgress& progress() const { return progress_; }

    bool totalKnown() const { return progress_.totalFiles > 0; }

    // 0.0 to 1.0; 0.0 while the total is still being counted.
    double fraction() const {
        if (!totalKnown()) {
            return 0.0;
        }
        const double f = static_cast<double>(progress_.filesScanned) /
                         static_cast<double>(progress_.totalFiles);
        return std::clamp(f, 0.0, 1.0);
    }

    int percent() const { return static_cast<int>(fraction() * 100.0); }

    std::chrono::milliseconds elapsed() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(now_ - start_);
    }

    double filesPerSecond() const {
        if (haveRate_) {
            return filesRate_;
        }
        // Before the first sample window closes, fall back to the overall average.
        const double secs = std::chrono::duration<double>(now_ - start_).count();
        return secs > 0.0 ? static_cast<double>(progress_.filesScanned) / secs : 0.0;
    }

    double bytesPerSecond() const {
        if (haveRate_) {
            return bytesRate_;
        }
        const double secs = std::chrono::duration<double>(now_ - start_).count();
        return secs > 0.0 ? static_cast<double>(progress_.bytesScanned) / secs : 0.0;
    }

    // Absent while the total is unknown or no rate can be established yet.
    std::optional<std::chrono::seconds> eta() const {
        if (!totalKnown() || progress_.phase == ScanPhase::Finished) {
            return std::nullopt;
        }
        if (progress_.filesScanned >= progress_.totalFiles) {
            return std::chrono::seconds{0};
        }
        const double rate = filesPerSecond();
        if (rate <= 0.0) {
            return std::nullopt;
        }
        const double remaining =
            static_cast<double>(progress_.totalFiles - progress_.filesScanned) / rate;
        return std::chrono::seconds{static_cast<long long>(remaining + 0.5)};
    }

private:
    static constexpr double kSampleSeconds = 0.25;
    static constexpr double kAlpha = 0.25;

    ScanProgress progress_{};
    TimePoint start_;
    TimePoint now_;
    TimePoint lastSample_;
    size_t sampleFiles_ = 0;
    uint64_t sampleBytes_ = 0;
    double filesRate_ = 0.0;
    double bytesRate_ = 0.0;
    bool haveRate_ = false;
};

// "3s", "2m 14s", "1h 05m"
inline std::string formatDuration(std::chrono::seconds total) {
    auto secs = total.count();
    if (secs < 0) {
        secs = 0;
    }
    if (secs >= 3600) {
        return fmt::format("{}h {:02}m", secs / 3600, (secs % 3600) / 60);
    }
    if (secs >= 60) {
        return fmt::format("{}m {:02}s", secs / 60, secs % 60);
    }
    return fmt::format("{}s", secs);
}

// "512 B", "1.5 KB", "3.2 MB"
inline std::string formatBytes(uint64_t bytes) {
    constexpr const char* kUnits[] = {"B", "KB", "MB", "GB", "TB"};
    auto value = static_cast<double>(bytes);
    size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < std::size(kUnits)) {
        value /= 1024.0;
        ++unit;
    }
    if (unit == 0) {
        return fmt::format("{} {}", bytes, kUnits[unit]);
    }
    return fmt::format("{:.1f} {}", value, kUnits[unit]);
}

}  // namespace lyxbosa
