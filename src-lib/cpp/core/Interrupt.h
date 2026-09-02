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

// Set while a full-screen UI owns the terminal. Nothing else hides the cursor,
// so the exit and signal paths use this to avoid writing a restore sequence to
// a terminal whose cursor was never touched - which would otherwise be the only
// thing a --silent run ever emitted.
inline std::atomic<bool> g_cursorHidden{false};

}  // namespace lyxbosa
