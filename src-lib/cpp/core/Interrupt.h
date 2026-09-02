#pragma once

#include <atomic>

namespace lyxbosa {

// Set by the signal handler and polled by every long-running loop (directory
// counting, directory walking, the scan itself) so that an interrupted run can
// unwind normally and still report what it found. The handler must do nothing
// beyond setting this flag; tearing the process down from inside it would skip
// the partial report and leave the terminal in whatever state the UI left it.
inline std::atomic<bool> g_interrupted{false};

inline bool interrupted() {
    return g_interrupted.load(std::memory_order_relaxed);
}

}  // namespace lyxbosa
