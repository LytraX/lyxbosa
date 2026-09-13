#pragma once

// Delivery.h - Whether what a command wrote reached the place it was written to.
//
// A command whose answer is text - the report `scan` writes to a file or to standard output,
// what `check` prints, the configuration `init-config` prints - has not answered until those
// bytes have arrived. Asking the stream once it has been opened and never again produced the
// same lie twice: "Report written to /dev/full" with exit 0, and then, on standard output, a
// JSON report written into a full disk that exited 2 with nothing on stderr. So every
// destination such an answer goes to is written through CheckedOutput, and asked with
// deliver() after the last byte meant for it.
//
// THE FAILURE IS TAKEN AT THE WRITE THAT FAILED. A C stream keeps its error indicator and not
// the errno beside it, and a report on standard output is flushed file by file, so by the time
// the command is finished errno describes whatever ran last. Which error it was decides what
// is said, below, so it is recorded at the call that returned it and never reconstructed.
//
// A READER THAT WENT AWAY IS NOT A FAILURE. `lyxbosa scan -o json | head` is ordinary use, and
// with SIGPIPE at its default disposition it ends in the kernel: the first write after `head`
// exits kills the process, which exits 141 and prints nothing. That is what Unix tools do and
// it is not changed here. This process never ignores SIGPIPE itself - libcurl would, around
// each call, but HttpTransport.cpp sets CURLOPT_NOSIGNAL, and nothing else linked in touches
// it - but a parent can hand it over ignored: systemd does by default (IgnoreSIGPIPE=), and so
// does any shell started with it ignored. Then the same write returns EPIPE instead, and it is
// answered the way the signal would have answered it: no message, and exit 141 in place of the
// exit code that would have said the answer arrived. Windows has no SIGPIPE at all, and a
// write to a pipe whose reader has gone fails with ERROR_NO_DATA or ERROR_BROKEN_PIPE like any
// other failure would; it is the same event, so it is answered the same way, with the status
// Git for Windows and a bash on Windows use for it too. Every other refusal - a full disk, an
// I/O error, a descriptor that cannot be written, a non-blocking pipe that would block - is a
// failure: the reader is still there and is holding an incomplete answer.

#include "infrastructure/Terminal.h"

#include <fmt/color.h>
#include <fmt/format.h>

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
#include <streambuf>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#ifdef _WIN32
#include <share.h>
#include <stdlib.h>
#include <windows.h>
#endif

namespace lyxbosa {

// The exit status of a run whose reader went away before its answer arrived: 128 + SIGPIPE,
// which is what a shell reports for the same run when the signal ends it.
inline constexpr int kExitReaderGone = 128 + 13;

// The first write to a destination that did not succeed, as the system reported it then.
struct WriteFailure {
    int error = 0;              // errno
    unsigned long osError = 0;  // Windows: the system error the C runtime mapped from; 0 elsewhere

    // The reader of a pipe went away. See the top of this file for why that is not a failure.
    bool readerGone() const {
#ifdef _WIN32
        if (osError != 0) {
            return osError == ERROR_NO_DATA || osError == ERROR_BROKEN_PIPE;
        }
#endif
        return error == EPIPE;
    }

    // The system's own sentence for it.
    std::string reason() const {
#ifdef _WIN32
        if (osError != 0) {
            return windowsReason(osError);
        }
#endif
        if (error != 0) {
            return std::generic_category().message(error);
        }
        return "the system gave no reason";
    }

private:
#ifdef _WIN32
    // FormatMessageW rather than std::system_category().message(), which returns the text in
    // the ANSI code page - Greek on a Greek installation - and this line is printed as UTF-8.
    static std::string windowsReason(unsigned long code) {
        wchar_t* text = nullptr;
        const DWORD length = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, code, 0, reinterpret_cast<wchar_t*>(&text), 0, nullptr);
        std::string utf8;
        if (length != 0 && text != nullptr) {
            DWORD end = length;
            while (end > 0 && (text[end - 1] == L'\r' || text[end - 1] == L'\n' ||
                               text[end - 1] == L' ' || text[end - 1] == L'.')) {
                --end;
            }
            const int bytes = WideCharToMultiByte(CP_UTF8, 0, text, static_cast<int>(end),
                                                  nullptr, 0, nullptr, nullptr);
            utf8.resize(static_cast<size_t>(bytes));
            WideCharToMultiByte(CP_UTF8, 0, text, static_cast<int>(end), utf8.data(), bytes,
                                nullptr, nullptr);
        }
        if (text != nullptr) {
            LocalFree(text);
        }
        return fmt::format("{} (Windows error {})", utf8.empty() ? "no description" : utf8,
                           code);
    }
#endif
};

// A C stream, written so that the first write it refuses is kept.
//
// Two ways in, one record. As a std::streambuf it carries a report: every byte goes to
// fwrite, as the standard streams' own buffer sends it, so a report is the same bytes it was
// through std::cout. Through print() it carries text for a person, sent the way fmt::print
// sends it - which on a Windows console is WriteConsoleW, and is why the text commands keep
// that route rather than borrowing the other one.
//
// Once a write has been refused nothing further is attempted. A report with a hole in the
// middle is worse than one that stops, and the reader is told it stopped either way. On glibc
// the stop is also what keeps the process's memory intact: fmt writes straight into the FILE's
// own buffer there, and printing on after a flush has failed writes past the end of it -
// AddressSanitizer reports a heap-buffer-overflow for exactly that, and the 3.1.0 `check` of a
// long file into a full disk trips glibc's own heap check. So the stop is asked after every
// print, not left to the end.
class CheckedOutput : public std::streambuf {
public:
    // A stream this does not own, which is standard output. Its error indicator is cleared:
    // the only thing that can have set it is an earlier answer in this process, and that one
    // has already been asked about.
    explicit CheckedOutput(std::FILE* file) : file_(file) { std::clearerr(file_); }

    // A file this opens for writing and owns, truncating it. Null when it cannot be opened,
    // with errno as the open left it.
    static std::unique_ptr<CheckedOutput> open(const std::filesystem::path& path) {
#ifdef _WIN32
        // The call std::ofstream makes on this platform, so that a report file is opened in
        // the same text mode and sharing mode it always was.
        std::FILE* file = _wfsopen(path.c_str(), L"w", _SH_DENYNO);
#else
        std::FILE* file = std::fopen(path.c_str(), "w");
#endif
        if (file == nullptr) {
            return nullptr;
        }
        std::unique_ptr<CheckedOutput> out(new CheckedOutput(file));
        out->owned_ = true;
        return out;
    }

    ~CheckedOutput() override {
        if (owned_ && file_ != nullptr) {
            std::fclose(file_);
        }
    }

    CheckedOutput(const CheckedOutput&) = delete;
    CheckedOutput& operator=(const CheckedOutput&) = delete;

    template <typename... Args>
    void print(fmt::format_string<Args...> format, Args&&... args) {
        emit(fmt::format(format, std::forward<Args>(args)...));
    }

    template <typename... Args>
    void print(const fmt::text_style& style, fmt::format_string<Args...> format, Args&&... args) {
        emit(fmt::format(style, format, std::forward<Args>(args)...));
    }

    // Flushes, closes a file this opened, and says whether every byte arrived. Asked after the
    // last write, never before it: a short answer is still in the buffer until this flush, so
    // this is the moment it fails. Nothing is written after it.
    std::optional<WriteFailure> finish() {
        if (finished_) {
            return failure_;
        }
        finished_ = true;
        if (!failure_ && std::fflush(file_) == EOF) {
            record(errno);
        }
        if (owned_) {
            const bool closed = std::fclose(file_) == 0;
            file_ = nullptr;
            if (!closed && !failure_) {
                record(errno);
            }
        }
        return failure_;
    }

protected:
    int_type overflow(int_type ch) override {
        if (traits_type::eq_int_type(ch, traits_type::eof())) {
            return traits_type::not_eof(ch);
        }
        if (!writable()) {
            return traits_type::eof();
        }
        if (std::fputc(traits_type::to_char_type(ch), file_) == EOF) {
            record(errno);
            return traits_type::eof();
        }
        return ch;
    }

    std::streamsize xsputn(const char* s, std::streamsize n) override {
        if (!writable() || n <= 0) {
            return 0;
        }
        const size_t written = std::fwrite(s, 1, static_cast<size_t>(n), file_);
        if (written < static_cast<size_t>(n)) {
            record(errno);
        }
        return static_cast<std::streamsize>(written);
    }

    int sync() override {
        if (!writable()) {
            return failure_ ? -1 : 0;
        }
        if (std::fflush(file_) == EOF) {
            record(errno);
            return -1;
        }
        return 0;
    }

private:
    bool writable() const { return !failure_ && !finished_; }

    void emit(const std::string& text) {
        if (!writable()) {
            return;
        }
        // fmt::print reports a refused write three ways, by platform: glibc's buffer takes the
        // bytes and sets the stream's error indicator, and the fwrite that musl and Windows get
        // throws instead. Uncaught, that throw ended the process with abort() - exit 134 from
        // the musl build and 3 on Windows - for no worse a reason than a closed pipe.
        try {
            fmt::print(file_, "{}", text);
        } catch (const std::system_error& e) {
            record(e.code().value());
            return;
        }
        if (std::ferror(file_)) {
            record(errno);
        }
    }

    // Called with errno as the refused call left it, before anything else can change it.
    void record(int error) {
        if (failure_) {
            return;
        }
        WriteFailure failure;
        failure.error = error;
#ifdef _WIN32
        failure.osError = _doserrno;
#endif
        failure_ = failure;
    }

    std::FILE* file_;
    bool owned_ = false;
    bool finished_ = false;
    std::optional<WriteFailure> failure_;
};

// What became of an answer, asked once the last byte meant for it has been written.
struct Delivery {
    std::optional<std::string> stopped;     // the writer stopped, and why
    std::optional<WriteFailure> refused;    // the destination refused a write

    bool delivered() const { return !stopped && !refused; }

    // Nothing went wrong except that the reader left. A writer that stopped is a failure
    // whoever is reading, so it is never this.
    bool readerGone() const { return !stopped && refused && refused->readerGone(); }

    bool failed() const { return !delivered() && !readerGone(); }
};

inline Delivery deliver(CheckedOutput& out, std::optional<std::string> stopped = std::nullopt) {
    Delivery delivery;
    delivery.stopped = std::move(stopped);
    delivery.refused = out.finish();
    return delivery;
}

// Where an undelivered answer went, and what is left there. The destination is a path
// rendered by pathForDisplay(), or standard output.
inline constexpr std::string_view kStandardOutput = "standard output";
inline constexpr std::string_view kWhatIsOnDisk = "what is on disk there, if anything, is incomplete";
inline constexpr std::string_view kWhatReachedIt = "what reached it, if anything, is incomplete";

// The one message for an answer that did not arrive, whichever destination it was sent to and
// whichever command sent it, so that a file and standard output are never described in two
// ways. Not for a reader that went away, which is not said at all.
inline void sayUndelivered(const Terminal& terminal, const Delivery& delivery,
                           std::string_view what, std::string_view destination,
                           std::string_view whatIsLeft) {
    terminal.printErr(Terminal::error(), "\nError: {} could not be written to {}\n       {}\n",
                      what, destination, whatIsLeft);
    if (delivery.stopped) {
        terminal.printErr(Terminal::error(), "       {}\n", *delivery.stopped);
    }
    if (delivery.refused) {
        terminal.printErr(Terminal::error(), "       the write failed: {}\n",
                          delivery.refused->reason());
    }
}

// The exit code once delivery is known, for a command that reports 0 for a clean answer, 2 for
// findings, and something else for an answer that is already known to be incomplete.
//
// An undelivered answer outranks a finding, because a partial answer read as a complete one
// is the whole failure: 0 and 2 both say the answer arrived. It does not replace the codes
// that already say it is incomplete - 1, and 130 for an interrupt - since those are true and
// were decided for a reason of their own. A reader that went away takes 141 in the same place
// and for the same reason, and nowhere else.
inline int exitCodeAfterDelivery(int code, const Delivery& delivery) {
    if (delivery.delivered() || (code != 0 && code != 2)) {
        return code;
    }
    return delivery.readerGone() ? kExitReaderGone : 1;
}

// The ending of a command whose whole answer is text on standard output, written through `out`.
// Every such command ends here, so none of them can answer this question differently.
inline int finishAnswerOnStandardOutput(const Terminal& terminal, CheckedOutput& out,
                                        std::string_view what, int code) {
    const Delivery delivery = deliver(out);
    if (delivery.failed()) {
        sayUndelivered(terminal, delivery, what, kStandardOutput, kWhatReachedIt);
    }
    return exitCodeAfterDelivery(code, delivery);
}

}  // namespace lyxbosa
