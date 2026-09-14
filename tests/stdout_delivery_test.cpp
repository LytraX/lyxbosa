// An answer on standard output that did not arrive, reported as one that did.
//
// THE DEFECT THESE CASES EXIST FOR
// --------------------------------
// A report written with -O was flushed, closed and asked whether it arrived. The same report on
// standard output was asked only whether its writer had stopped: a JSON scan with a finding,
// redirected to /dev/full, exited 2 with nothing on stderr, which is what a report that reached
// its reader exits. `check` and `init-config` did the same, and on the musl build and on Windows
// they did worse - fmt throws there when a write is refused, nothing caught it, and the process
// ended in abort() for no worse a reason than a closed pipe.
//
// WHY EVERY FAILURE HERE HAS A COMPANION
// --------------------------------------
// Each assertion that an answer did not arrive is paired with one that the same answer, sent
// somewhere that takes it, still exits as its findings say - and each assertion that a failure
// is reported with one that a reader who went away is not. A command that called every write a
// failure would pass the first half and fail the second.
//
// HOW EACH DESTINATION IS MADE
// ----------------------------
// Standard output is pointed at a descriptor for the length of one command and restored after
// it. Four destinations:
//
//   /dev/full, which opens and then refuses every byte with ENOSPC - probed at run time by
//     test::whyCannotFailAWrite(), and skipped with its sentence where there is none.
//   a descriptor opened for reading only, which refuses every byte on every platform and for
//     every user, so a refusal is observed on Windows as well.
//   a pipe whose read end was closed before the command started: the reader has gone. POSIX
//     cases ignore SIGPIPE around it, which is how such a pipe reaches a process whose parent
//     ignored the signal; with the signal at its default there is a death test instead,
//     because the kernel ends the run there and that is the behaviour being kept.
//   gtest's own capture, which takes everything: the companions.
//
// The report sizes are chosen against the buffers: one that fits in any stdio buffer and so
// fails only at the last flush, and one larger than any stdio or pipe buffer, which fails part
// of the way through. Each companion measures its own output, so a size that stopped being what
// its case needs fails rather than quietly testing something else.

#include <gtest/gtest.h>

#include "config/Config.h"
#include "infrastructure/Delivery.h"
#include "system/CliArgs.h"
#include "use-cases/CheckUseCase.h"
#include "use-cases/HelpUseCase.h"
#include "use-cases/InitConfigUseCase.h"
#include "use-cases/ScanUseCase.h"
#include "use-cases/UpdateUseCase.h"
#include "use-cases/ValidateConfigUseCase.h"

#include "PlatformSkips.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <fcntl.h>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <csignal>
#include <unistd.h>
#endif

using namespace lyxbosa;

namespace {

namespace fs = std::filesystem;

// Matches rule RCE001, as in incomplete_answer_test.cpp.
const std::string kShell = "<?php eval(base64_decode($_POST['x'])); ?>\n";

// Larger than any stdio buffer and any pipe buffer on either platform.
constexpr size_t kPastEveryBuffer = 64 * 1024;
// Smaller than any stdio buffer on either platform.
constexpr size_t kInsideEveryBuffer = 1024;

constexpr ReportFormat kEveryFormat[] = {ReportFormat::Text, ReportFormat::Csv,
                                         ReportFormat::Json};

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

class TempDir {
public:
    TempDir() {
        const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = fs::temp_directory_path() / ("lyxbosa-stdout-test-" + std::to_string(tick));
        fs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    const fs::path& path() const { return path_; }

private:
    fs::path path_;
};

void writeFile(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

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
CommandRun withStdoutAt(int destination, Command&& command) {
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
CommandRun delivered(Command&& command) {
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

// `lyxbosa scan ROOT -o FORMAT --force --no-quarantine --no-precount [--quiet]`.
CliArgs scanArgs(const fs::path& root, ReportFormat format, bool quiet = true) {
    CliArgs args;
    args.directories = {root.string()};
    args.force = true;
    args.quarantine = false;
    args.quiet = quiet;
    args.noPreCount = true;
    args.outputFormat = format;
    args.outputFormatExplicit = true;
    return args;
}

int scan(CliArgs args) {
    const Terminal terminal(/*useAnsi=*/false);
    const TerminalCaps caps = TerminalCaps::detect();
    return ScanUseCase(terminal, caps).execute(args);
}

int check(const fs::path& file) {
    CliArgs args;
    args.checkFile = file.string();
    const Terminal terminal(/*useAnsi=*/false);
    const TerminalCaps caps = TerminalCaps::detect();
    return CheckUseCase(terminal, caps).execute(args);
}

int initConfig() {
    const Terminal terminal(/*useAnsi=*/false);
    return InitConfigUseCase(terminal).execute();
}

// What a destination that refused the answer has to say, spelled out rather than built from
// the constants the code uses, so that a change to the wording fails here.
std::string toStandardOutput(std::string_view what, std::string_view reason) {
    return "\nError: " + std::string(what) + " could not be written to standard output\n"
           "       what reached it, if anything, is incomplete\n"
           "       the write failed: " + std::string(reason) + "\n";
}

std::string noSpace() { return std::generic_category().message(ENOSPC); }

std::string formatName(ReportFormat format) { return std::string(reportFormatToString(format)); }

size_t occurrences(const std::string& haystack, std::string_view needle) {
    size_t count = 0;
    for (size_t at = haystack.find(needle); at != std::string::npos;
         at = haystack.find(needle, at + needle.size())) {
        ++count;
    }
    return count;
}

// The trees every case scans, written once for the suite: a webshell alone, a clean page, a
// thousand webshells, and one file of three thousand webshell lines for `check`.
class StdoutDeliveryTest : public testing::Test {
protected:
    static void SetUpTestSuite() {
        dir_ = std::make_unique<TempDir>();
        writeFile(dirty() / "shell.php", kShell);
        writeFile(clean() / "page.php", "<?php echo 1;\n");
        for (int i = 0; i < 1000; ++i) {
            writeFile(many() / ("shell-" + std::to_string(i) + ".php"), kShell);
        }
        std::string lines;
        for (int i = 0; i < 3000; ++i) {
            lines += kShell;
        }
        writeFile(longFile(), lines);
        longFileBytes_ = lines;
    }
    static void TearDownTestSuite() { dir_.reset(); }

    // A resident antivirus takes webshell fixtures out of the temporary directory; see
    // PlatformSkips.h. Every case asks before it scans one.
    void SetUp() override {
        for (const auto& [path, bytes] :
             {std::pair{dirty() / "shell.php", kShell},
              std::pair{many() / "shell-999.php", kShell}}) {
            if (const auto why = test::whyTheFixtureIsNotOnDisk(path, bytes)) {
                GTEST_SKIP() << *why;
            }
        }
        if (const auto why = test::whyTheFixtureIsNotOnDisk(longFile(), longFileBytes_)) {
            GTEST_SKIP() << *why;
        }
    }

    static fs::path dirty() { return dir_->path() / "dirty"; }
    static fs::path clean() { return dir_->path() / "clean"; }
    static fs::path many() { return dir_->path() / "many"; }
    static fs::path longFile() { return dir_->path() / "long" / "lines.php"; }

    // /dev/full opened for writing, or skip with the sentence saying why there is none.
    static std::optional<Descriptor> full(std::string& why) {
        std::string sink;
        if (const auto cannot = test::whyCannotFailAWrite(sink)) {
            why = *cannot;
            return std::nullopt;
        }
        return std::optional<Descriptor>(std::in_place, sys::openForWriting(sink));
    }

private:
    static inline std::unique_ptr<TempDir> dir_;
    static inline std::string longFileBytes_;
};

}  // namespace

// ===========================================================================
// scan
// ===========================================================================

// The reproduction: a report with a finding, into a destination that refuses it, exited 2 with
// nothing on stderr. Now 1 and the sentence, in every format, and --quiet does not reach it.
TEST_F(StdoutDeliveryTest, AReportOnAFullStandardOutputExitsOneInEveryFormat) {
    std::string why;
    auto sink = full(why);
    if (!sink) GTEST_SKIP() << why;

    for (const ReportFormat format : kEveryFormat) {
        SCOPED_TRACE(formatName(format));
        const CommandRun quiet = withStdoutAt(sink->fd(), [&] { return scan(scanArgs(dirty(), format)); });
        EXPECT_EQ(quiet.code, 1);
        EXPECT_EQ(quiet.err, toStandardOutput("the report", noSpace()))
            << "--quiet suppresses progress and the summary, never a lost report";

        const CommandRun loud = withStdoutAt(sink->fd(), [&] {
            return scan(scanArgs(dirty(), format, /*quiet=*/false));
        });
        EXPECT_EQ(loud.code, 1);
        EXPECT_EQ(occurrences(loud.err, toStandardOutput("the report", noSpace())), 1u) << loud.err;
    }
}

// A report short enough to sit whole in the buffer until the writer's last flush, from a tree
// with nothing in it. It used to exit 0 - the code that says the tree is clean and the report
// says so. CSV and text only: the JSON writer flushes every piece it writes, so its refusal is
// its first flush, which the cases above already reach.
TEST_F(StdoutDeliveryTest, AReportThatFailsOnlyAtItsLastFlushDoesNotExitZero) {
    std::string why;
    auto sink = full(why);
    if (!sink) GTEST_SKIP() << why;

    for (const ReportFormat format : {ReportFormat::Csv, ReportFormat::Text}) {
        SCOPED_TRACE(formatName(format));
        // The text report of a clean tree is its summary, which --quiet removes, and an empty
        // report arrives trivially.
        const CliArgs args = scanArgs(clean(), format, /*quiet=*/format != ReportFormat::Text);

        const CommandRun arrived = delivered([&] { return scan(args); });
        EXPECT_EQ(arrived.code, 0) << arrived.err;
        EXPECT_GT(arrived.out.size(), 0u);
        EXPECT_LT(arrived.out.size(), kInsideEveryBuffer) << "the report no longer fits a buffer";

        const CommandRun refused = withStdoutAt(sink->fd(), [&] { return scan(args); });
        EXPECT_EQ(refused.code, 1);
        EXPECT_EQ(occurrences(refused.err, toStandardOutput("the report", noSpace())), 1u)
            << refused.err;
    }
}

// A report that cannot fit in any buffer, so the refusal comes part of the way through it.
TEST_F(StdoutDeliveryTest, AReportLargerThanAnyBufferFailsPartWayAndSaysSo) {
    std::string why;
    auto sink = full(why);
    if (!sink) GTEST_SKIP() << why;

    for (const ReportFormat format : kEveryFormat) {
        SCOPED_TRACE(formatName(format));
        const CommandRun arrived = delivered([&] { return scan(scanArgs(many(), format)); });
        EXPECT_EQ(arrived.code, 2) << arrived.err;
        EXPECT_GT(arrived.out.size(), kPastEveryBuffer) << "the report fits in a buffer now";

        const CommandRun refused = withStdoutAt(sink->fd(), [&] { return scan(scanArgs(many(), format)); });
        EXPECT_EQ(refused.code, 1);
        EXPECT_EQ(refused.err, toStandardOutput("the report", noSpace()));
    }
}

// A refusal observed on every platform, Windows included: a descriptor opened for reading.
TEST_F(StdoutDeliveryTest, ADestinationThatRefusesEveryByteFailsOnEveryPlatform) {
    const fs::path readable = many().parent_path() / "read-only-destination";
    writeFile(readable, "");
    Descriptor readOnly(sys::openForReadingOnly(readable));
    ASSERT_GE(readOnly.fd(), 0);

    for (const ReportFormat format : kEveryFormat) {
        SCOPED_TRACE(formatName(format));
        const CommandRun refused = withStdoutAt(readOnly.fd(), [&] { return scan(scanArgs(dirty(), format)); });
        EXPECT_EQ(refused.code, 1);
        EXPECT_EQ(refused.err.rfind("\nError: the report could not be written to standard output\n"
                                    "       what reached it, if anything, is incomplete\n"
                                    "       the write failed: ", 0),
                  0u)
            << refused.err;
        EXPECT_EQ(occurrences(refused.err, "Error:"), 1u) << refused.err;
    }

    // `check` and `init-config` through the same descriptor. The long file's answer overflows
    // the buffer, which on Windows is the write fmt throws from: this is where that platform
    // observes the throw being caught rather than ending the process with exit 3.
    const auto refusedWith = [](const CommandRun& run, std::string_view what) {
        return run.err.rfind("\nError: " + std::string(what) +
                                 " could not be written to standard output\n"
                                 "       what reached it, if anything, is incomplete\n"
                                 "       the write failed: ",
                             0) == 0;
    };
    for (const fs::path& file : {dirty() / "shell.php", clean() / "page.php", longFile()}) {
        SCOPED_TRACE(file.filename().string());
        const CommandRun refused = withStdoutAt(readOnly.fd(), [&] { return check(file); });
        EXPECT_EQ(refused.code, 1);
        EXPECT_TRUE(refusedWith(refused, "the report")) << refused.err;
    }
    const CommandRun config = withStdoutAt(readOnly.fd(), [] { return initConfig(); });
    EXPECT_EQ(config.code, 1);
    EXPECT_TRUE(refusedWith(config, "the configuration")) << config.err;

    EXPECT_EQ(fs::file_size(readable), 0u);
}

// The other direction. A reader that went away is not a failure: nothing is printed, and 141 -
// what a shell reports when SIGPIPE ends the same run - takes the place of the 2 that would say
// the report arrived. Small reports and large ones, every format, and on Windows too.
TEST_F(StdoutDeliveryTest, AReaderThatHasGoneIsNotAFailure) {
    [[maybe_unused]] const SigpipeIgnored ignored;
    for (const fs::path& root : {dirty(), many()}) {
        for (const ReportFormat format : kEveryFormat) {
            SCOPED_TRACE(root.filename().string() + " " + formatName(format));
            const ClosedPipe pipe;
            ASSERT_GE(pipe.fd(), 0);
            const CommandRun gone = withStdoutAt(pipe.fd(), [&] {
                return scan(scanArgs(root, format, /*quiet=*/false));
            });
            EXPECT_EQ(gone.code, kExitReaderGone);
            EXPECT_EQ(gone.code, 141);
            EXPECT_EQ(gone.err, "") << "a closed pipe is ordinary use, not an error";
        }
    }
}

// And with SIGPIPE at its default, which is how `lyxbosa scan -o json | head` runs: the kernel
// ends the process at the first refused write, and nothing is printed. Nothing here may change
// that disposition - a scan that ignored SIGPIPE would exit 141 by itself, and fail this.
TEST_F(StdoutDeliveryTest, WithSigpipeAtItsDefaultAClosedPipeEndsTheRunSilently) {
#ifdef _WIN32
    GTEST_SKIP() << "Windows has no SIGPIPE, so a closed pipe never ends the process; the "
                    "case above observes what happens there instead";
#else
    // The default "fast" style forks, so the child scans the tree this process already wrote.
    // "threadsafe" re-executes the binary instead, and a child that rebuilds the suite's
    // thousand-file tree and is then killed by the signal leaves the tree behind on every run.
    EXPECT_EXIT(
        {
            struct sigaction dfl = {};
            dfl.sa_handler = SIG_DFL;
            sigemptyset(&dfl.sa_mask);
            sigaction(SIGPIPE, &dfl, nullptr);
            const ClosedPipe pipe;
            const StdoutAt redirected(pipe.fd());
            scan(scanArgs(many(), ReportFormat::Json, /*quiet=*/false));
            std::_Exit(99);
        },
        testing::KilledBySignal(SIGPIPE), "^$");
#endif
}

// The companion to all of the above: a report sent where it is taken exits by its findings.
TEST_F(StdoutDeliveryTest, AReportThatArrivesStillExitsByWhatItFound) {
    if (const auto why = test::whyTheTemporaryDirectoryWillNotHold(kShell)) {
        GTEST_SKIP() << *why;
    }
    for (const ReportFormat format : kEveryFormat) {
        SCOPED_TRACE(formatName(format));
        const CommandRun found = delivered([&] { return scan(scanArgs(dirty(), format)); });
        EXPECT_EQ(found.code, 2);
        EXPECT_EQ(found.err, "");
        EXPECT_TRUE(found.out.find("shell.php") != std::string::npos) << found.out;

        const CommandRun nothing = delivered([&] { return scan(scanArgs(clean(), format)); });
        EXPECT_EQ(nothing.code, 0);
        EXPECT_EQ(nothing.err, "");
    }
}

// A file and standard output are two destinations of one report, and a refusal of either is
// described in one shape: the same sentence with the destination swapped, the same account of
// what is left, and the system's reason on both. Under --silent the file's refusal still exits 1
// and says nothing.
TEST_F(StdoutDeliveryTest, AFileAndStandardOutputAreDescribedInOneShape) {
    std::string sink;
    if (const auto why = test::whyCannotFailAWrite(sink)) {
        GTEST_SKIP() << *why;
    }
    Descriptor fullOut(sys::openForWriting(sink));

    CliArgs toFile = scanArgs(dirty(), ReportFormat::Json);
    toFile.outputFile = sink;
    const CommandRun file = delivered([&] { return scan(toFile); });
    EXPECT_EQ(file.code, 1);
    EXPECT_EQ(file.err, "\nError: the report could not be written to " +
                            pathForDisplay(fs::path(sink)) + "\n"
                            "       what is on disk there, if anything, is incomplete\n"
                            "       the write failed: " + noSpace() + "\n");

    const CommandRun out = withStdoutAt(fullOut.fd(), [&] { return scan(scanArgs(dirty(), ReportFormat::Json)); });
    EXPECT_EQ(out.code, 1);
    EXPECT_EQ(out.err, toStandardOutput("the report", noSpace()));

    toFile.silent = true;
    const CommandRun silent = delivered([&] { return scan(toFile); });
    EXPECT_EQ(silent.code, 1) << "--silent holds back the sentence, never the exit code";
    EXPECT_EQ(silent.err, "");
    EXPECT_EQ(silent.out, "");
}

// ===========================================================================
// check and init-config
// ===========================================================================

// With -O the report is the file, and standard output carries only the readable view of it -
// which the scan prints only when standard output is a terminal. When that terminal goes away
// mid-run the report on disk is complete, so the run exits by its findings: an action that
// failed beside a complete answer does not outrank a finding (AGENTS.md). The view's failure is
// still said, as a warning. The terminal is a pseudo-terminal whose other side is already
// closed, so isatty() says yes and every write to it fails with EIO.
TEST_F(StdoutDeliveryTest, AScanWithAReportFileExitsByItsFindingsWhenItsTerminalGoesAway) {
#ifdef _WIN32
    GTEST_SKIP() << "Windows has no pseudo-terminal this process can put on its own standard "
                    "output, so a terminal that goes away mid-run cannot be set up here";
#else
    const int master = ::posix_openpt(O_RDWR | O_NOCTTY);
    const char* slaveName =
        (master >= 0 && ::grantpt(master) == 0 && ::unlockpt(master) == 0) ? ::ptsname(master)
                                                                           : nullptr;
    const int slave = slaveName ? ::open(slaveName, O_RDWR | O_NOCTTY) : -1;
    if (slave < 0) {
        const int why = errno;
        if (master >= 0) ::close(master);
        GTEST_SKIP() << "this host could not open a pseudo-terminal (" << std::strerror(why)
                     << "), so a terminal that goes away mid-run cannot be observed";
    }
    Descriptor terminal(slave);

    TempDir out;
    const fs::path report = out.path() / "report.json";
    CliArgs args = scanArgs(dirty(), ReportFormat::Json, /*quiet=*/false);
    args.outputFile = report.string();
    args.progress = ProgressWhen::None;

    bool sawATerminal = false;
    const CommandRun run = withStdoutAt(terminal.fd(), [&] {
        const Terminal quiet(/*useAnsi=*/false);
        // Standard output is a terminal when the scan decides what to print...
        const TerminalCaps caps = TerminalCaps::detect();
        sawATerminal = caps.stdoutIsTty();
        // ...and has gone by the time it prints: every write to the slave now fails with EIO.
        ::close(master);
        return ScanUseCase(quiet, caps).execute(args);
    });
    ASSERT_TRUE(sawATerminal) << "the case needs standard output to be a terminal at the start";

    EXPECT_EQ(run.code, 2) << "the report file is complete, so the findings decide\n" << run.err;
    EXPECT_EQ(run.err.find("Error:"), std::string::npos) << run.err;
    EXPECT_NE(run.err.find("Warning: what this scan printed to standard output did not all "
                           "arrive"),
              std::string::npos)
        << run.err;
    EXPECT_NE(run.err.find("Report written to"), std::string::npos) << run.err;

    std::ifstream in(report, std::ios::binary);
    const std::string written((std::istreambuf_iterator<char>(in)), {});
    EXPECT_NE(written.find("shell.php"), std::string::npos) << written;
    EXPECT_NE(written.find("\"filesWithMatches\":1"), std::string::npos) << written;
#endif
}

// `check` printed its answer into a destination that refused it and exited 2 for the shell, 0
// for the clean page - whose answer fits in the buffer and fails only when the command flushes
// it - and 2 for the long file, whose answer fails part of the way through.
TEST_F(StdoutDeliveryTest, CheckOnAFullStandardOutputDoesNotExitAsIfItArrived) {
    std::string why;
    auto sink = full(why);
    if (!sink) GTEST_SKIP() << why;

    for (const fs::path& file : {dirty() / "shell.php", clean() / "page.php", longFile()}) {
        SCOPED_TRACE(file.filename().string());
        const CommandRun refused = withStdoutAt(sink->fd(), [&] { return check(file); });
        EXPECT_EQ(refused.code, 1);
        EXPECT_EQ(refused.err, toStandardOutput("the report", noSpace()));
    }
}

// The route fmt takes on musl and on Windows, observed here: when the C library does not buffer
// the stream, fmt writes with fwrite and throws on a short write. Uncaught, that was abort() -
// exit 134 from the musl build for `check` into a full disk. An unbuffered stdout makes glibc
// take the same route, so the catch is observed on this platform rather than argued.
TEST_F(StdoutDeliveryTest, AWriteThatThrowsIsAnsweredLikeAnyOtherRefusal) {
    std::string why;
    auto sink = full(why);
    if (!sink) GTEST_SKIP() << why;

    class Unbuffered {
    public:
        Unbuffered() {
            std::fflush(stdout);
            std::setvbuf(stdout, nullptr, _IONBF, 0);
        }
        ~Unbuffered() {
            std::fflush(stdout);
            std::setvbuf(stdout, nullptr, _IOFBF, BUFSIZ);
        }
    };

    for (const fs::path& file : {dirty() / "shell.php", longFile()}) {
        SCOPED_TRACE(file.filename().string());
        const CommandRun refused = withStdoutAt(sink->fd(), [&] {
            const Unbuffered unbuffered;
            return check(file);
        });
        EXPECT_EQ(refused.code, 1);
        EXPECT_EQ(refused.err, toStandardOutput("the report", noSpace()));
    }
    const CommandRun config = withStdoutAt(sink->fd(), [] {
        const Unbuffered unbuffered;
        return initConfig();
    });
    EXPECT_EQ(config.code, 1);
    EXPECT_EQ(config.err, toStandardOutput("the configuration", noSpace()));
}

TEST_F(StdoutDeliveryTest, CheckWhoseReaderHasGoneIsNotAFailure) {
    [[maybe_unused]] const SigpipeIgnored ignored;
    for (const fs::path& file : {dirty() / "shell.php", clean() / "page.php", longFile()}) {
        SCOPED_TRACE(file.filename().string());
        const ClosedPipe pipe;
        ASSERT_GE(pipe.fd(), 0);
        const CommandRun gone = withStdoutAt(pipe.fd(), [&] { return check(file); });
        EXPECT_EQ(gone.code, kExitReaderGone);
        EXPECT_EQ(gone.err, "");
    }
}

// The companion, and the measurement the two cases above rest on: the short answers fit in a
// buffer and the long one does not.
TEST_F(StdoutDeliveryTest, CheckStillExitsByItsAnswerWhenTheAnswerArrives) {
    if (const auto why = test::whyTheTemporaryDirectoryWillNotHold(kShell)) {
        GTEST_SKIP() << *why;
    }
    const CommandRun shell = delivered([&] { return check(dirty() / "shell.php"); });
    EXPECT_EQ(shell.code, 2);
    EXPECT_LT(shell.out.size(), kInsideEveryBuffer);

    const CommandRun page = delivered([&] { return check(clean() / "page.php"); });
    EXPECT_EQ(page.code, 0);
    EXPECT_LT(page.out.size(), kInsideEveryBuffer);

    const CommandRun lines = delivered([&] { return check(longFile()); });
    EXPECT_EQ(lines.code, 2);
    EXPECT_GT(lines.out.size(), kPastEveryBuffer);

    for (const CommandRun* run : {&shell, &page, &lines}) {
        EXPECT_EQ(run->err, "");
    }
}

TEST_F(StdoutDeliveryTest, InitConfigOnAFullStandardOutputExitsOne) {
    std::string why;
    auto sink = full(why);
    if (!sink) GTEST_SKIP() << why;

    const CommandRun arrived = delivered([] { return initConfig(); });
    EXPECT_EQ(arrived.code, 0);
    EXPECT_EQ(arrived.out, Config::generateDefault());
    EXPECT_GT(arrived.out.size(), kInsideEveryBuffer);

    const CommandRun refused = withStdoutAt(sink->fd(), [] { return initConfig(); });
    EXPECT_EQ(refused.code, 1);
    EXPECT_EQ(refused.err, toStandardOutput("the configuration", noSpace()));
}

TEST_F(StdoutDeliveryTest, InitConfigWhoseReaderHasGoneIsNotAFailure) {
    [[maybe_unused]] const SigpipeIgnored ignored;
    const ClosedPipe pipe;
    ASSERT_GE(pipe.fd(), 0);
    const CommandRun gone = withStdoutAt(pipe.fd(), [] { return initConfig(); });
    EXPECT_EQ(gone.code, kExitReaderGone);
    EXPECT_EQ(gone.err, "");
}

// ===========================================================================
// --help, --version, validate-config and update
// ===========================================================================

namespace {

// Set for the length of a parse. A parser that calls exit() from inside it ends this process
// with whatever status it chose - argparse's was 0 - and a runner that reads only the exit code
// calls that a pass, whatever failed before it. The handler below turns such an exit into a
// failure with a sentence, in this process and in a death test's child alike.
bool g_parsing = false;

// `lyxbosa ARGS...` as the parser reads it.
CliArgs parseCommandLine(std::vector<std::string> words) {
    static const bool registered = [] {
        std::atexit([] {
            if (g_parsing) {
                std::fputs("\nthe argument parser called exit() in the middle of a parse\n",
                           stderr);
                std::fflush(stderr);
                std::_Exit(1);
            }
        });
        return true;
    }();
    (void)registered;

    words.insert(words.begin(), "lyxbosa");
    std::vector<char*> argv;
    for (std::string& word : words) {
        argv.push_back(word.data());
    }
    argv.push_back(nullptr);
    g_parsing = true;
    CliArgs args = CliArgs::parse(static_cast<int>(words.size()), argv.data());
    g_parsing = false;
    return args;
}

// Every text answer the parser gives, one per shape: the program's own help, its version from
// both spellings, and each command's help from both of its spellings.
const std::vector<std::vector<std::string>>& parserAnswers() {
    static const std::vector<std::vector<std::string>> answers = {
        {"--help"}, {"-h"}, {"--version"}, {"-v"},
        {"scan", "--help"}, {"scan", "-h"}, {"check", "--help"},
        {"validate-config", "--help"}, {"init-config", "--help"}, {"update", "--help"},
        {"update", "-h"},
    };
    return answers;
}

std::string joined(const std::vector<std::string>& words) {
    std::string out;
    for (const auto& word : words) {
        out += (out.empty() ? "" : " ") + word;
    }
    return out;
}

int answer(const std::vector<std::string>& words) {
    const Terminal terminal(/*useAnsi=*/false);
    return HelpUseCase(terminal).execute(parseCommandLine(words));
}

std::string_view whatItIs(const std::vector<std::string>& words) {
    return words.back() == "--version" || words.back() == "-v" ? "the version"
                                                               : "the help text";
}

class FixedVersionSource : public VersionSource {
public:
    explicit FixedVersionSource(std::string tag) : tag_(std::move(tag)) {}
    FetchOutcome fetchLatest(std::chrono::milliseconds, const std::atomic<bool>&) override {
        FetchOutcome out;
        out.status = FetchOutcome::Status::Ok;
        out.version = tag_;
        return out;
    }

private:
    std::string tag_;
};

// A source that must not be asked: `update` that reaches it has gone past the answer.
class NoAssets : public AssetSource {
public:
    http::Outcome fetch(std::string_view, std::string_view, const fs::path&, uint64_t) override {
        ADD_FAILURE() << "an update that is already current fetched an asset";
        http::Outcome outcome;
        outcome.status = http::Outcome::Status::HttpError;
        return outcome;
    }
};

}  // namespace

// The library's own --help and --version used to print to std::cout and call std::exit(0) from
// inside the parse, so nothing that asks whether an answer arrived could run. The parse returns
// now: a child that parses and then exits 99 exits 99, where it exited 0 before.
TEST(ParserAnswerTest, TheParserNeitherPrintsNorExits) {
    for (const auto& words : parserAnswers()) {
        SCOPED_TRACE(joined(words));
        EXPECT_EXIT(
            {
                const CliArgs args = parseCommandLine(words);
                std::_Exit(args.command == Command::Help || args.command == Command::Version
                               ? 99 : 98);
            },
            testing::ExitedWithCode(99), "^$");
    }
    ASSERT_FALSE(HasFailure()) << "the parser still exits; not parsing in this process";

    testing::internal::CaptureStdout();
    const CliArgs version = parseCommandLine({"--version"});
    const CliArgs scanHelp = parseCommandLine({"scan", "--help"});
    EXPECT_EQ(testing::internal::GetCapturedStdout(), "") << "the parser printed an answer";

    EXPECT_TRUE(version.success);
    EXPECT_EQ(version.command, Command::Version);
    EXPECT_EQ(version.answerText, versionBanner() + "\n");
    EXPECT_EQ(scanHelp.command, Command::Help);
    EXPECT_EQ(scanHelp.answerText.rfind("Usage: lyxbosa scan ", 0), 0u) << scanHelp.answerText;
    EXPECT_NE(scanHelp.answerText.find("Scan directories for malicious files"), std::string::npos);
    EXPECT_EQ(parseCommandLine({"--help"}).answerText, CliArgs::getHelpText());
}

// The parse stops at the flag, where the exit used to stop it: what follows is never read, and
// what came before is refused as it always was.
TEST(ParserAnswerTest, TheParseStopsWhereTheExitStoppedIt) {
    const CliArgs after = parseCommandLine({"scan", "--help", "--no-such-flag"});
    EXPECT_TRUE(after.success) << after.errorMessage;
    EXPECT_EQ(after.command, Command::Help);

    const CliArgs before = parseCommandLine({"scan", "--no-such-flag", "--help"});
    EXPECT_FALSE(before.success);
    EXPECT_EQ(before.errorMessage, "Unknown argument: --no-such-flag");

    const CliArgs version = parseCommandLine({"--version", "no-such-command"});
    EXPECT_TRUE(version.success) << version.errorMessage;
    EXPECT_EQ(version.command, Command::Version);

    // --no-ansi before the flag still reaches the colour of an error about the answer.
    EXPECT_EQ(parseCommandLine({"--no-ansi", "scan", "--help"}).color, ColorWhen::Never);
    EXPECT_EQ(parseCommandLine({"check", "--color", "never", "--help"}).color, ColorWhen::Never);
    EXPECT_EQ(parseCommandLine({"scan", "--help"}).color, ColorWhen::Auto);
}

// `lyxbosa scan --help > /dev/full` exited 0, and so did every other text the parser gave. The
// refusal is a descriptor opened for reading on every platform, and /dev/full as well where
// there is one, so that Windows observes it too.
TEST_F(StdoutDeliveryTest, AHelpTextOrAVersionThatIsRefusedExitsOne) {
    const fs::path readable = dirty().parent_path() / "read-only-for-help";
    writeFile(readable, "");
    Descriptor readOnly(sys::openForReadingOnly(readable));
    ASSERT_GE(readOnly.fd(), 0);
    std::string why;
    auto sink = full(why);

    for (const auto& words : parserAnswers()) {
        SCOPED_TRACE(joined(words));
        const CommandRun arrived = delivered([&] { return answer(words); });
        EXPECT_EQ(arrived.code, 0);
        EXPECT_EQ(arrived.err, "");
        EXPECT_EQ(arrived.out, parseCommandLine(words).answerText);
        EXPECT_FALSE(arrived.out.empty());

        const CommandRun refused = withStdoutAt(readOnly.fd(), [&] { return answer(words); });
        EXPECT_EQ(refused.code, 1);
        EXPECT_EQ(refused.err.rfind("\nError: " + std::string(whatItIs(words)) +
                                        " could not be written to standard output\n"
                                        "       what reached it, if anything, is incomplete\n"
                                        "       the write failed: ",
                                    0),
                  0u)
            << refused.err;

        if (sink) {
            const CommandRun onFull = withStdoutAt(sink->fd(), [&] { return answer(words); });
            EXPECT_EQ(onFull.code, 1);
            EXPECT_EQ(onFull.err, toStandardOutput(whatItIs(words), noSpace()));
        }
    }
    EXPECT_EQ(fs::file_size(readable), 0u) << why;
}

TEST_F(StdoutDeliveryTest, AHelpTextOrAVersionWhoseReaderHasGoneIsNotAFailure) {
    [[maybe_unused]] const SigpipeIgnored ignored;
    for (const auto& words : parserAnswers()) {
        SCOPED_TRACE(joined(words));
        const ClosedPipe pipe;
        ASSERT_GE(pipe.fd(), 0);
        const CommandRun gone = withStdoutAt(pipe.fd(), [&] { return answer(words); });
        EXPECT_EQ(gone.code, kExitReaderGone);
        EXPECT_EQ(gone.err, "");
    }
}

// validate-config and update: every answer each of them writes to standard output, through a
// destination that refuses it, a pipe with no reader, and one that takes it. The refusal uses a
// descriptor opened for reading, so Windows observes it too.
TEST_F(StdoutDeliveryTest, ValidateConfigAndUpdateAnswerLikeEveryOtherCommand) {
    const fs::path configFile = dirty().parent_path() / "validate.yaml";
    writeFile(configFile, Config::generateDefault());
    const fs::path target = dirty().parent_path() / "installed-binary";
    writeFile(target, "not a real binary");
    const fs::path state = dirty().parent_path() / "update-state";

    const auto validate = [&] {
        CliArgs args;
        args.validateConfigFile = configFile.string();
        const Terminal terminal(/*useAnsi=*/false);
        return ValidateConfigUseCase(terminal).execute(args);
    };
    const auto update = [&](std::string tag, bool checkOnly) {
        return [&, tag, checkOnly] {
            CliArgs args;
            args.updateCheckOnly = checkOnly;
            args.assumeYes = true;
            UpdateUseCase::Seams seams;
            seams.running = parseVersion("3.2.0");
            seams.statePath = state;
            seams.target = target;
            const Terminal terminal(/*useAnsi=*/false);
            const TerminalCaps caps = TerminalCaps::detect();
            return UpdateUseCase(terminal, caps, std::make_shared<FixedVersionSource>(tag),
                                 std::make_shared<NoAssets>(), seams)
                .execute(args);
        };
    };

    struct Case {
        std::string name;
        std::function<int()> run;
        int code;
        std::string_view what;
        std::string_view out;
    };
    const std::vector<Case> cases = {
        {"validate-config", validate, 0, "the validation result", "Configuration is valid.\n"},
        {"update --check, newer", update("v3.3.0", true), 2, "the update result",
         "A newer release is available: 3.3.0 (this is 3.2.0).\n"},
        {"update --check, current", update("v3.2.0", true), 0, "the update result",
         "Up to date (3.2.0).\n"},
        {"update --check, older published", update("v3.1.0", true), 0, "the update result",
         "Up to date (3.2.0).\nThe newest published release is 3.1.0.\n"},
        {"update, current", update("v3.2.0", false), 0, "the update result", "Up to date ("},
    };

    const fs::path readable = dirty().parent_path() / "read-only-for-update";
    writeFile(readable, "");
    Descriptor readOnly(sys::openForReadingOnly(readable));
    ASSERT_GE(readOnly.fd(), 0);
    std::string why;
    auto sink = full(why);

    for (const Case& c : cases) {
        SCOPED_TRACE(c.name);
        const CommandRun arrived = delivered(c.run);
        EXPECT_EQ(arrived.code, c.code) << arrived.err;
        EXPECT_EQ(arrived.out.rfind(std::string(c.out), 0), 0u) << arrived.out;
        EXPECT_EQ(arrived.err.find("Error:"), std::string::npos) << arrived.err;

        const CommandRun refused = withStdoutAt(readOnly.fd(), c.run);
        EXPECT_EQ(refused.code, 1);
        const std::string sentence = "\nError: " + std::string(c.what) +
                                     " could not be written to standard output\n"
                                     "       what reached it, if anything, is incomplete\n"
                                     "       the write failed: ";
        EXPECT_NE(refused.err.find(sentence), std::string::npos) << refused.err;
        EXPECT_EQ(occurrences(refused.err, "Error:"), 1u) << refused.err;

        if (sink) {
            const CommandRun onFull = withStdoutAt(sink->fd(), c.run);
            EXPECT_EQ(onFull.code, 1);
            EXPECT_NE(onFull.err.find(toStandardOutput(c.what, noSpace())), std::string::npos)
                << onFull.err;
        }

        [[maybe_unused]] const SigpipeIgnored ignored;
        const ClosedPipe pipe;
        ASSERT_GE(pipe.fd(), 0);
        const CommandRun gone = withStdoutAt(pipe.fd(), c.run);
        EXPECT_EQ(gone.code, kExitReaderGone);
        EXPECT_EQ(gone.err.find("Error:"), std::string::npos) << gone.err;
    }
    // Where there is no /dev/full the read-only descriptor above is the refusal, as it is for
    // every other command on Windows; `why` says which this host is.
    EXPECT_EQ(fs::file_size(readable), 0u) << why;
}

// ===========================================================================
// The two decisions, directly
// ===========================================================================

// Only a pipe whose reader has gone is not a failure. Everything else the system can say about a
// refused write is one - including a pipe that would block, whose reader is still there.
TEST(DeliveryDecisionTest, OnlyAReaderThatHasGoneIsNotAFailure) {
    const auto posix = [](int error) {
        WriteFailure failure;
        failure.error = error;
        return failure;
    };
    EXPECT_TRUE(posix(EPIPE).readerGone());
    for (const int error : {ENOSPC, EIO, EBADF, EAGAIN, EINVAL}) {
        SCOPED_TRACE(error);
        EXPECT_FALSE(posix(error).readerGone());
        EXPECT_FALSE(posix(error).reason().empty());
    }
#ifdef _WIN32
    // The C runtime maps what it knows to errno and leaves the rest EINVAL, so the system's own
    // code is the one asked.
    const auto windows = [](unsigned long code) {
        WriteFailure failure;
        failure.error = EINVAL;
        failure.osError = code;
        return failure;
    };
    EXPECT_TRUE(windows(ERROR_NO_DATA).readerGone());
    EXPECT_TRUE(windows(ERROR_BROKEN_PIPE).readerGone());
    for (const unsigned long code : {static_cast<unsigned long>(ERROR_DISK_FULL),
                                     static_cast<unsigned long>(ERROR_ACCESS_DENIED),
                                     static_cast<unsigned long>(ERROR_INVALID_HANDLE)}) {
        SCOPED_TRACE(code);
        EXPECT_FALSE(windows(code).readerGone());
        EXPECT_NE(windows(code).reason().find("(Windows error " + std::to_string(code) + ")"),
                  std::string::npos)
            << windows(code).reason();
    }
#endif
}

// An undelivered answer takes the exit codes that say an answer arrived, 0 and 2, and no other.
TEST(DeliveryDecisionTest, AnUndeliveredAnswerReplacesOnlyTheCodesThatSayItArrived) {
    Delivery arrived;
    Delivery refused;
    refused.refused = WriteFailure{ENOSPC, 0};
    Delivery gone;
    gone.refused = WriteFailure{EPIPE, 0};
    Delivery stoppedAndGone = gone;
    stoppedAndGone.stopped = "the record could not be written";

    EXPECT_TRUE(arrived.delivered());
    EXPECT_TRUE(refused.failed());
    EXPECT_TRUE(gone.readerGone());
    EXPECT_TRUE(stoppedAndGone.failed()) << "a writer that stopped is a failure whoever reads it";

    for (const int code : {0, 1, 2, 130}) {
        SCOPED_TRACE(code);
        EXPECT_EQ(exitCodeAfterDelivery(code, arrived), code);
        const bool saysArrived = code == 0 || code == 2;
        EXPECT_EQ(exitCodeAfterDelivery(code, refused), saysArrived ? 1 : code);
        EXPECT_EQ(exitCodeAfterDelivery(code, gone), saysArrived ? 141 : code);
        EXPECT_EQ(exitCodeAfterDelivery(code, stoppedAndGone), saysArrived ? 1 : code);
    }
}
