#pragma once

// StdoutRedirect.h - Standard output pointed at a destination for the length of one command.
//
// The destinations the delivery cases need, spelled once for both platforms: a descriptor that
// refuses every byte (opened for reading only), a pipe whose reader has already gone, and
// gtest's own capture, which takes everything. /dev/full is found by
// test::whyCannotFailAWrite() in PlatformSkips.h.

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string>

#include <fcntl.h>

#ifdef _WIN32
#include <io.h>
#else
#include <csignal>
#include <unistd.h>
#endif

namespace lyxbosa::test::stdout_redirect {

namespace fs = std::filesystem;

// The descriptor calls, spelled once for both platforms.
namespace sys {
#ifdef _WIN32
constexpr int kStdout = 1;
inline int dup(int fd) { return ::_dup(fd); }
inline int dup2(int from, int to) { return ::_dup2(from, to); }
inline int close(int fd) { return ::_close(fd); }
inline int openForWriting(const fs::path& path) { return ::_wopen(path.c_str(), _O_WRONLY); }
inline int openForReadingOnly(const fs::path& path) {
    return ::_wopen(path.c_str(), _O_RDONLY | _O_TEXT);
}
inline bool pipe(int fds[2]) { return ::_pipe(fds, 4096, _O_TEXT) == 0; }
#else
constexpr int kStdout = STDOUT_FILENO;
inline int dup(int fd) { return ::dup(fd); }
inline int dup2(int from, int to) { return ::dup2(from, to); }
inline int close(int fd) { return ::close(fd); }
inline int openForWriting(const fs::path& path) { return ::open(path.c_str(), O_WRONLY); }
inline int openForReadingOnly(const fs::path& path) { return ::open(path.c_str(), O_RDONLY); }
inline bool pipe(int fds[2]) { return ::pipe(fds) == 0; }
#endif
}  // namespace sys

// Standard output on `destination` while this lives. What the refused destination did not
// take is flushed at it and dropped before the real standard output comes back, and the
// stream's error indicator with it, so the next case starts clean.
class StdoutAt {
public:
    explicit StdoutAt(int destination) {
        std::cout.flush();
        std::fflush(stdout);
        saved_ = sys::dup(sys::kStdout);
        sys::dup2(destination, sys::kStdout);
    }
    ~StdoutAt() {
        std::fflush(stdout);
        std::clearerr(stdout);
        sys::dup2(saved_, sys::kStdout);
        sys::close(saved_);
        std::cout.clear();
    }
    StdoutAt(const StdoutAt&) = delete;
    StdoutAt& operator=(const StdoutAt&) = delete;

private:
    int saved_ = -1;
};

// The write end of a pipe whose read end is already closed.
class ClosedPipe {
public:
    ClosedPipe() {
        int fds[2] = {-1, -1};
        if (sys::pipe(fds)) {
            sys::close(fds[0]);
            writeEnd_ = fds[1];
        }
    }
    ~ClosedPipe() {
        if (writeEnd_ >= 0) sys::close(writeEnd_);
    }
    ClosedPipe(const ClosedPipe&) = delete;
    ClosedPipe& operator=(const ClosedPipe&) = delete;

    int fd() const { return writeEnd_; }

private:
    int writeEnd_ = -1;
};

// SIGPIPE ignored while this lives, the way a parent that ignores it hands it to a child.
// Windows has no SIGPIPE, and a write to a pipe with no reader fails there without it.
class SigpipeIgnored {
public:
#ifdef _WIN32
    SigpipeIgnored() = default;
#else
    SigpipeIgnored() {
        struct sigaction ignore = {};
        ignore.sa_handler = SIG_IGN;
        sigemptyset(&ignore.sa_mask);
        sigaction(SIGPIPE, &ignore, &previous_);
    }
    ~SigpipeIgnored() { sigaction(SIGPIPE, &previous_, nullptr); }

private:
    struct sigaction previous_ = {};
#endif
};

// A descriptor that owns itself.
class Descriptor {
public:
    explicit Descriptor(int fd) : fd_(fd) {}
    ~Descriptor() {
        if (fd_ >= 0) sys::close(fd_);
    }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    int fd() const { return fd_; }

private:
    int fd_;
};

struct CommandRun {
    int code = 0;
    std::string out;
    std::string err;
};

// `command` with standard output on `destination` and standard error captured.
template <typename Command>
inline CommandRun withStdoutAt(int destination, Command&& command) {
    CommandRun run;
    testing::internal::CaptureStderr();
    try {
        StdoutAt redirected(destination);
        run.code = command();
    } catch (...) {
        run.err = testing::internal::GetCapturedStderr();
        throw;
    }
    run.err = testing::internal::GetCapturedStderr();
    return run;
}

// `command` with both streams captured: a destination that takes every byte.
template <typename Command>
inline CommandRun delivered(Command&& command) {
    CommandRun run;
    testing::internal::CaptureStdout();
    testing::internal::CaptureStderr();
    try {
        run.code = command();
    } catch (...) {
        run.err = testing::internal::GetCapturedStderr();
        run.out = testing::internal::GetCapturedStdout();
        throw;
    }
    run.err = testing::internal::GetCapturedStderr();
    run.out = testing::internal::GetCapturedStdout();
    return run;
}

}  // namespace lyxbosa::test::stdout_redirect
