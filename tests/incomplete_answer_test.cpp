// An operation that did not happen, reported as one that did.
//
// THE DEFECT THESE CASES EXIST FOR
// --------------------------------
// Three places said a thing had been done when it had not, and they are one defect
// rather than three:
//
//   `check` printed "No matches found" for a truncated gzip and exited 0 - the same
//     two things a genuinely clean file produces. archive::Stats lived on ScanResult
//     and scanFile() returns a FileResult, so what a container did not cover had
//     nowhere to travel and was dropped.
//   a report written to a full disk printed "Report written to ..." and exited 0. The
//     stream was checked when it was opened and never afterwards.
//   a quarantine that failed was `if (quarantineFile(...))` with no else: no counter,
//     no warning, no report field, so a webshell still in the web root read exactly
//     like one quarantine was never enabled for.
//
// WHY EVERY CASE HERE HAS A COMPANION
// -----------------------------------
// Each of the three is easy to "fix" by refusing everything, and a case that only
// asserts the new refusal would pass against that. So every assertion that the tool now
// says an operation did not happen is paired with one that it still says the other
// thing: a clean file still exits 0, a report that writes still says so, a quarantine
// that succeeds is still counted exactly once and is not counted as a failure.
//
// HOW EACH FAILURE IS MADE, AND WHERE IT CAN BE OBSERVED
// -----------------------------------------------------
// A quarantine that cannot complete needs a destination the process genuinely cannot
// write, because a name collision is handled now and would prove nothing. The one used
// here is a quarantine directory whose parent is a regular file: create_directories()
// fails with ENOTDIR on POSIX and the equivalent on Windows, for every user including
// root, so it needs no permission bits and no skip.
//
// A write that fails after a successful open has no such portable form. It is
// /dev/full here, probed at run time by test::whyCannotFailAWrite() and skipped with a
// sentence where the platform has no equivalent - which is Windows. The companion that
// runs everywhere is the report path that cannot be *opened*, which guards the ordering
// of the two branches.

#include <gtest/gtest.h>

#include "archive/ArchiveTypes.h"
#include "config/Config.h"
#include "core/Interrupt.h"
#include "core/Scanner.h"
#include "infrastructure/ResultPrinter.h"
#include "infrastructure/report/CsvReportWriter.h"
#include "infrastructure/report/JsonReportWriter.h"
#include "system/CliArgs.h"
#include "use-cases/CheckUseCase.h"
#include "use-cases/ScanUseCase.h"

#include "PlatformSkips.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <thread>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <zip.h>
#include <zlib.h>

using namespace lyxbosa;

namespace {

namespace fs = std::filesystem;

// Same shape as the one in archive_test.cpp and quarantine_test.cpp, named from a
// steady_clock tick for the same reason: two test binaries can be running at once and
// ::getpid() is POSIX-only.
class TempDir {
public:
    TempDir() {
        const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = fs::temp_directory_path() /
                ("lyxbosa-incomplete-test-" + std::to_string(tick) + "-" +
                 std::to_string(counter_++));
        fs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    const fs::path& path() const { return path_; }
    fs::path file(const std::string& name) const { return path_ / name; }

private:
    fs::path path_;
    static inline int counter_ = 0;
};

void writeFile(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

// Matches rule RCE001. Spelled here rather than in a fixture file so a case about exit
// code 2 can be read without going to look for what makes it 2.
const std::string kShell = "<?php eval(base64_decode($_POST['x'])); ?>\n";

std::string gzipCompress(const std::string& input) {
    z_stream stream{};
    // 15 window bits + 16: write a gzip header rather than a zlib one.
    EXPECT_EQ(deflateInit2(&stream, Z_BEST_SPEED, Z_DEFLATED, 15 + 16, 8,
                           Z_DEFAULT_STRATEGY),
              Z_OK);

    std::string out;
    out.resize(deflateBound(&stream, input.size()) + 64);

    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
    stream.avail_in = static_cast<uInt>(input.size());
    stream.next_out = reinterpret_cast<Bytef*>(out.data());
    stream.avail_out = static_cast<uInt>(out.size());

    EXPECT_EQ(deflate(&stream, Z_FINISH), Z_STREAM_END);
    out.resize(stream.total_out);
    deflateEnd(&stream);
    return out;
}

void writeZip(const fs::path& path,
              const std::vector<std::pair<std::string, std::string>>& members) {
    fs::create_directories(path.parent_path());
    int err = 0;
    zip_t* za = zip_open(path.string().c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    ASSERT_NE(za, nullptr);

    for (const auto& [name, body] : members) {
        zip_source_t* source = zip_source_buffer(za, body.data(), body.size(), 0);
        ASSERT_NE(source, nullptr);
        ASSERT_GE(zip_file_add(za, name.c_str(), source, ZIP_FL_OVERWRITE), 0);
    }

    ASSERT_EQ(zip_close(za), 0);
}

// A member body deflate genuinely compresses, so the literal the rules match does not
// survive into the container's own bytes.
std::string compressibleShell() {
    std::string body = kShell;
    for (int i = 0; i < 400; ++i) {
        body += "// padding padding padding padding padding padding\n";
    }
    return body;
}

// What `lyxbosa check FILE` exits, and what it printed. Both, because an exit code on
// its own cannot tell a refusal that names the reason from one that does not, and the
// reason is the half an operator acts on.
struct CheckRun {
    int code = 0;
    std::string text;
};

CheckRun check(const fs::path& file, const std::optional<fs::path>& config = std::nullopt) {
    CliArgs args;
    args.checkFile = file.string();
    if (config) {
        args.configFile = config->string();
    }

    const Terminal terminal(/*useAnsi=*/false);
    const TerminalCaps caps = TerminalCaps::detect();

    CheckRun run;
    testing::internal::CaptureStdout();
    run.code = CheckUseCase(terminal, caps).execute(args);
    run.text = testing::internal::GetCapturedStdout();
    return run;
}

// The exit code `lyxbosa scan` would return for these arguments, with every field that
// would make the command wait for a human pinned. Shaped after the helper in
// scan_root_test.cpp, with the report destination left to the caller because that is
// what half of these cases are about.
int scanExitCode(const std::vector<fs::path>& directories, const std::string& report,
                 const std::optional<fs::path>& config = std::nullopt) {
    CliArgs args;
    for (const auto& directory : directories) {
        args.directories.push_back(directory.string());
    }
    args.force = true;          // no confirmation prompt, and no update check
    args.quarantine = false;    // never move a file out of a test's temp directory
    args.silent = true;         // the report is the file below and nothing else
    args.outputFile = report;
    args.noPreCount = true;
    if (config) {
        args.configFile = config->string();
    }

    const Terminal terminal(/*useAnsi=*/false);
    const TerminalCaps caps = TerminalCaps::detect();
    return ScanUseCase(terminal, caps).execute(args);
}

// What `lyxbosa scan` wrote to stderr, which is where the diagnostics an operator has to
// act on go. `--quiet` is on deliberately: a failure the operator must know about is not
// progress chatter, and the case is that --quiet does not reach it.
struct ScanRun {
    int code = 0;
    std::string diagnostics;
};

ScanRun scanQuietly(const fs::path& config, const fs::path& report) {
    CliArgs args;
    args.configFile = config.string();
    args.force = true;
    args.quarantine = true;
    args.quiet = true;
    args.outputFile = report.string();
    args.noPreCount = true;

    const Terminal terminal(/*useAnsi=*/false);
    const TerminalCaps caps = TerminalCaps::detect();

    ScanRun run;
    testing::internal::CaptureStderr();
    run.code = ScanUseCase(terminal, caps).execute(args);
    run.diagnostics = testing::internal::GetCapturedStderr();
    return run;
}

// A configuration file, because the command reads one and the quarantine destination is
// what these cases are about.
void writeQuarantineConfig(const fs::path& path, const fs::path& root,
                           const fs::path& quarantineDir) {
    writeFile(path, "scan:\n  directories:\n    - " + root.string() +
                        "\nactions:\n  quarantine:\n    enabled: true\n    directory: " +
                        quarantineDir.string() + "\n");
}

AppConfig quarantineConfig(const fs::path& root, const fs::path& quarantineDir) {
    AppConfig config = Config::loadFromString(Config::generateDefault());
    config.scan.directories = {root.string()};
    config.scan.recursive = true;
    config.actions.quarantine.enabled = true;
    config.actions.quarantine.directory = quarantineDir.string();
    return config;
}

ScanResult runScan(const AppConfig& config) {
    Scanner scanner(config);
    scanner.setPreCount(false);
    return scanner.scan();
}

bool contains(const std::string& haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

// The nth comma-separated field of a CSV line, counting from zero. Enough for the cases
// here, whose fields never carry a comma of their own - a quoted field would need the
// real parser and none of these produce one.
std::string fieldAt(const std::string& line, size_t index) {
    size_t start = 0;
    for (size_t seen = 0; seen < index; ++seen) {
        start = line.find(',', start);
        if (start == std::string::npos) return {};
        ++start;
    }
    const size_t end = line.find(',', start);
    return line.substr(start, end == std::string::npos ? end : end - start);
}

}  // namespace

// ===========================================================================
// `check`: an archive whose contents were not examined
// ===========================================================================

// The reproduction. An intact gzip of a webshell exits 2; truncate it and the member
// cannot be inflated, which used to print "No matches found" and exit 0.
TEST(CheckCoverageTest, ATruncatedArchiveIsNotReportedAsClean) {
    TempDir dir;
    const std::string gz = gzipCompress(kShell);
    ASSERT_GT(gz.size(), 8u);
    writeFile(dir.file("shell.php.gz"), gz.substr(0, gz.size() / 2));

    const CheckRun run = check(dir.file("shell.php.gz"));

    EXPECT_EQ(run.code, 1);
    EXPECT_TRUE(contains(run.text, "Not fully examined")) << run.text;
    EXPECT_TRUE(contains(run.text, "Members not scanned: 1 (1 corrupt)")) << run.text;
    EXPECT_FALSE(contains(run.text, "No matches found")) << run.text;
}

// The companion that makes the case above mean something: a `check` that refused every
// archive would pass it and fail this.
TEST(CheckCoverageTest, TheSameArchiveIntactStillReportsTheShellAndExitsTwo) {
    TempDir dir;
    writeFile(dir.file("shell.php.gz"), gzipCompress(kShell));

    const CheckRun run = check(dir.file("shell.php.gz"));

    EXPECT_EQ(run.code, 2);
    EXPECT_TRUE(contains(run.text, "CRITICAL")) << run.text;
    EXPECT_FALSE(contains(run.text, "Not fully examined")) << run.text;
}

// The second way the same lie was told. A member past the per-member cap is never
// inflated, so nothing can be said about its bytes - and "No matches found" said
// something about them anyway.
TEST(CheckCoverageTest, AMemberPastTheSizeLimitIsNotReportedAsClean) {
    TempDir dir;
    writeFile(dir.file("small.yaml"), "archives:\n  max_member_size: 16\n");
    writeFile(dir.file("shell.php.gz"), gzipCompress(kShell));

    const CheckRun run = check(dir.file("shell.php.gz"), dir.file("small.yaml"));

    EXPECT_EQ(run.code, 1);
    EXPECT_TRUE(contains(run.text, "Not fully examined")) << run.text;
    EXPECT_TRUE(contains(run.text, "over size limit")) << run.text;
}

// A loose file that was read and matched nothing. Without this every case above would
// pass against a `check` that had simply stopped saying anything was clean.
TEST(CheckCoverageTest, ACleanFileStillExitsZeroAndSaysSoPlainly) {
    TempDir dir;
    writeFile(dir.file("page.php"), "<?php echo 1;\n");

    const CheckRun run = check(dir.file("page.php"));

    EXPECT_EQ(run.code, 0);
    EXPECT_TRUE(contains(run.text, "No matches found in:")) << run.text;
}

// And the same for a container: every member it selected was inflated and read, so the
// unqualified verdict is the correct one.
TEST(CheckCoverageTest, ACleanArchiveWhoseMembersWereAllReadStillExitsZero) {
    TempDir dir;
    writeFile(dir.file("page.php.gz"), gzipCompress("<?php echo 1;\n"));

    const CheckRun run = check(dir.file("page.php.gz"));

    EXPECT_EQ(run.code, 0);
    EXPECT_TRUE(contains(run.text, "No matches found in:")) << run.text;
    EXPECT_FALSE(contains(run.text, "what was scanned")) << run.text;
}

// The line the whole exit code turns on. A member the selection policy did not pick -
// here an image, outside exhaustive mode - is the container-level counterpart of an
// excluded loose file: counted, named, and no reason to call the command failed. What
// it does change is the verdict's wording, because the container was not read whole.
TEST(CheckCoverageTest, MembersThePolicyDidNotSelectAreNamedAndStillExitZero) {
    TempDir dir;
    writeZip(dir.file("assets.zip"), {{"logo.jpg", std::string(2048, 'A')},
                                      {"page.php", "<?php echo 1;\n"}});

    const CheckRun run = check(dir.file("assets.zip"));

    EXPECT_EQ(run.code, 0);
    EXPECT_TRUE(contains(run.text, "No matches found in what was scanned of:")) << run.text;
    EXPECT_TRUE(contains(run.text, "not code")) << run.text;
}

// Findings and incomplete coverage at once. The findings are printed - losing them
// would be a worse defect than the one being fixed - and the exit code still says the
// answer is partial, which is what `scan` already does for a root that was gone.
TEST(CheckCoverageTest, AnIncompleteAnswerTakesTheExitCodeAndStillPrintsWhatWasFound) {
    TempDir dir;
    // A cap the shell member fits under and the other does not, so exactly one member
    // goes unread and the finding in the other is still there to be printed.
    writeFile(dir.file("small.yaml"), "archives:\n  max_member_size: 32KB\n");
    const std::string shell = compressibleShell();
    ASSERT_LT(shell.size(), 32u * 1024u);
    writeZip(dir.file("mixed.zip"),
             {{"shell.php", shell},
              {"huge.php", "<?php\n" + std::string(64 * 1024, 'x') + "\n"}});

    const CheckRun run = check(dir.file("mixed.zip"), dir.file("small.yaml"));

    EXPECT_EQ(run.code, 1);
    EXPECT_TRUE(contains(run.text, "CRITICAL")) << run.text;
    EXPECT_TRUE(contains(run.text, "Not fully examined")) << run.text;
    EXPECT_TRUE(contains(run.text, "Members not scanned: 1 (1 over size limit)")) << run.text;
}

// The disagreement Scanner.cpp names as the thing that makes an operator stop trusting
// the tool. `check` on a file and `scan` on the directory holding it must describe that
// file the same way; the sentence is built once, in archive::membersNotScannedLine().
TEST(CheckCoverageTest, CheckAndScanDescribeTheSameArchiveInTheSameWords) {
    TempDir dir;
    const fs::path tree = dir.path() / "tree";
    const std::string gz = gzipCompress(kShell);
    writeFile(tree / "shell.php.gz", gz.substr(0, gz.size() / 2));

    const CheckRun run = check(tree / "shell.php.gz");

    AppConfig config = Config::loadFromString(Config::generateDefault());
    config.scan.directories = {tree.string()};
    const ScanResult result = runScan(config);

    const std::string sentence = archive::membersNotScannedLine(result.archives);
    EXPECT_EQ(sentence, "Members not scanned: 1 (1 corrupt)");
    EXPECT_TRUE(contains(run.text, sentence))
        << "check said:\n" << run.text << "\nscan's summary says: " << sentence;
}

// An oversize container is not a skipped file: the walk reads its index and scans its
// members, and `check` used to disagree by leaving a size skip on the result. The two
// answers are compared directly rather than by their text.
TEST(CheckCoverageTest, AnOversizeContainerIsNotCalledASkippedFileByEitherCommand) {
    TempDir dir;
    writeFile(dir.file("small.yaml"), "scan:\n  max_file_size: 64\n");

    AppConfig config = Config::loadFromFile(dir.file("small.yaml").string());
    writeZip(dir.file("backup.zip"), {{"shell.php", compressibleShell()}});
    ASSERT_GT(fs::file_size(dir.file("backup.zip")), 64u);

    Scanner scanner(config);
    const FileResult result = scanner.scanFile(dir.file("backup.zip"));

    EXPECT_FALSE(result.skipped())
        << "a container past the file cap still had its members read, so it is not a "
           "file the scan skipped";
    ASSERT_TRUE(result.archive.has_value());
    EXPECT_EQ(result.archive->membersScanned, 1u);
    EXPECT_FALSE(archive::coverageIncomplete(*result.archive));
}

// ===========================================================================
// The coverage predicate itself
// ===========================================================================

// Policy is the one reason that is not a member going unread, and the whole exit code
// rests on that. Asserted directly so the distinction cannot drift without a failure.
TEST(ArchiveCoverageTest, PolicyIsCountedAndIsNotAMemberThatWentUnread) {
    archive::Stats stats;
    stats.skip(SkipReason::Policy, 874);

    EXPECT_EQ(stats.totalSkipped(), 874u);
    EXPECT_EQ(archive::membersUnexamined(stats), 0u);
    EXPECT_FALSE(archive::coverageIncomplete(stats));
    EXPECT_EQ(archive::membersNotScannedLine(stats), "Members not scanned: 874 (874 not code)");
}

TEST(ArchiveCoverageTest, EveryOtherReasonIsAMemberThatWentUnread) {
    for (const SkipReason reason : {SkipReason::Size, SkipReason::Budget, SkipReason::Ratio,
                                    SkipReason::Depth, SkipReason::Corrupt}) {
        archive::Stats stats;
        stats.skip(reason);
        EXPECT_TRUE(archive::coverageIncomplete(stats))
            << "reason: " << skipReasonToString(reason);
    }
}

TEST(ArchiveCoverageTest, AContainerThatWouldNotOpenOrStoppedEarlyIsIncompleteWithNoSkips) {
    archive::Stats unreadable;
    unreadable.archivesUnreadable = 1;
    EXPECT_TRUE(archive::coverageIncomplete(unreadable));
    EXPECT_EQ(archive::membersNotScannedLine(unreadable), "");

    archive::Stats stopped;
    stopped.archivesTruncated = 1;
    EXPECT_TRUE(archive::coverageIncomplete(stopped));
}

// The companion for the three above: an archive that was read whole says so.
TEST(ArchiveCoverageTest, AnArchiveReadWholeIsComplete) {
    archive::Stats stats;
    stats.archivesOpened = 1;
    stats.membersScanned = 12;

    EXPECT_FALSE(archive::coverageIncomplete(stats));
    EXPECT_EQ(archive::membersNotScannedLine(stats), "");
}

// ===========================================================================
// Delivering the report
// ===========================================================================

// The reproduction: `-O /dev/full` printed "Report written to /dev/full" and exited 0,
// which is what a clean scan whose report reached the disk prints.
TEST(ReportDeliveryTest, AReportThatCouldNotBeWrittenDoesNotExitZero) {
    std::string sink;
    if (const auto why = test::whyCannotFailAWrite(sink)) {
        GTEST_SKIP() << *why;
    }

    TempDir dir;
    writeFile(dir.path() / "tree" / "page.php", "<?php echo 1;\n");

    EXPECT_EQ(scanExitCode({dir.path() / "tree"}, sink), 1);
}

// And it outranks the findings, for the same reason a missing root does: with `-O` the
// report is the answer, so exiting 2 would send an unattended caller to read a file
// that is truncated or empty.
TEST(ReportDeliveryTest, AReportThatCouldNotBeWrittenOutranksTheFindings) {
    std::string sink;
    if (const auto why = test::whyCannotFailAWrite(sink)) {
        GTEST_SKIP() << *why;
    }

    TempDir dir;
    writeFile(dir.path() / "tree" / "shell.php", kShell);

    EXPECT_EQ(scanExitCode({dir.path() / "tree"}, sink), 1);
}

// The companion. A scan whose report reached the disk still exits by what it found, and
// the report is there afterwards - without this the two cases above would pass against
// a command that had learned to call every write a failure.
TEST(ReportDeliveryTest, AReportThatWritesStillExitsAsTheFindingsSay) {
    TempDir dir;
    writeFile(dir.path() / "clean" / "page.php", "<?php echo 1;\n");
    writeFile(dir.path() / "dirty" / "shell.php", kShell);

    const fs::path cleanReport = dir.file("clean.txt");
    EXPECT_EQ(scanExitCode({dir.path() / "clean"}, cleanReport.string()), 0);
    EXPECT_TRUE(fs::exists(cleanReport));
    EXPECT_GT(fs::file_size(cleanReport), 0u);

    const fs::path dirtyReport = dir.file("dirty.txt");
    EXPECT_EQ(scanExitCode({dir.path() / "dirty"}, dirtyReport.string()), 2);
    EXPECT_TRUE(fs::exists(dirtyReport));
}

// The half of the branch that runs on every platform, including the one where
// /dev/full has no equivalent. A report path that cannot be opened at all was already
// refused before this round; the case is here so that the ordering of the two
// refusals - open, then write - stays observed wherever the suite runs.
TEST(ReportDeliveryTest, AReportPathThatCannotBeOpenedIsStillRefusedBeforeTheScan) {
    TempDir dir;
    writeFile(dir.path() / "tree" / "shell.php", kShell);
    writeFile(dir.file("not-a-directory"), "x");

    const fs::path impossible = dir.file("not-a-directory") / "report.txt";
    EXPECT_EQ(scanExitCode({dir.path() / "tree"}, impossible.string()), 1);
}

// ===========================================================================
// A quarantine that could not complete
// ===========================================================================

// The reproduction. Scanner.cpp had `if (quarantineFile(...))` with no else, so the
// webshell below stayed in the tree and every count in the report read exactly as it
// would have if quarantine had never been switched on.
//
// The destination is a directory under a regular file. That needs no permission bits,
// so it fails for root as well, and it is not a name collision - collisions are
// stepped past now and would prove nothing about a move that cannot happen.
TEST(QuarantineFailureTest, AQuarantineThatCannotCompleteIsCountedAndTheFileIsNamed) {
    TempDir dir;
    const fs::path root = dir.path() / "site";
    const fs::path shell = root / "wp" / "shell.php";
    writeFile(shell, kShell);
    writeFile(dir.file("blocker"), "a regular file, so nothing can be made under it");

    const ScanResult result =
        runScan(quarantineConfig(root, dir.file("blocker") / "quarantine"));

    EXPECT_EQ(result.filesQuarantined, 0u);
    EXPECT_EQ(result.filesQuarantineFailed, 1u);
    EXPECT_TRUE(fs::exists(shell)) << "the file is still where it was found";

    bool named = false;
    for (const auto& file : result.files) {
        if (file.path == shell) {
            named = true;
            EXPECT_TRUE(file.quarantineFailed);
            EXPECT_FALSE(file.quarantined);
        }
    }
    EXPECT_TRUE(named) << "a file that could not be contained has to reach the report";
}

// The companion. Without it the case above would pass against a scanner that had
// stopped quarantining anything at all.
TEST(QuarantineFailureTest, AQuarantineThatSucceedsIsCountedOnceAndNotAsAFailure) {
    TempDir dir;
    TempDir quarantine;
    const fs::path root = dir.path() / "site";
    const fs::path shell = root / "wp" / "shell.php";
    writeFile(shell, kShell);

    const ScanResult result = runScan(quarantineConfig(root, quarantine.path()));

    EXPECT_EQ(result.filesQuarantined, 1u);
    EXPECT_EQ(result.filesQuarantineFailed, 0u);
    EXPECT_FALSE(fs::exists(shell));

    for (const auto& file : result.files) {
        EXPECT_FALSE(file.quarantineFailed) << file.path.string();
    }
}

// A container is moved for what is inside it and carries no matches of its own, so a
// failed move leaves it with neither matches nor a destination. It used to be dropped
// from the report on exactly that test, which would have lost the only row naming a
// zip still sitting in the web root.
TEST(QuarantineFailureTest, AContainerThatCouldNotBeMovedStillReachesTheReport) {
    TempDir dir;
    const fs::path root = dir.path() / "site";
    writeZip(root / "backup.zip", {{"shell.php", compressibleShell()}});
    writeFile(dir.file("blocker"), "a regular file");

    const ScanResult result =
        runScan(quarantineConfig(root, dir.file("blocker") / "quarantine"));

    EXPECT_EQ(result.filesQuarantineFailed, 1u);
    EXPECT_TRUE(fs::exists(root / "backup.zip"));

    bool named = false;
    for (const auto& file : result.files) {
        if (file.path == root / "backup.zip") {
            named = true;
            EXPECT_TRUE(file.quarantineFailed);
        }
    }
    EXPECT_TRUE(named) << "the container has no matches of its own; it is in the report "
                          "for its quarantine outcome alone";
}

// The diagnostic an operator reads, and the two decisions in it that were deliberate:
// --quiet does not suppress it, and the list of paths is capped so a quarantine
// directory on a read-only mount cannot bury its own explanation under a thousand lines.
TEST(QuarantineFailureTest, TheDiagnosticSurvivesQuietAndCapsItsList) {
    TempDir dir;
    const fs::path root = dir.path() / "site";
    for (int i = 1; i <= 12; ++i) {
        writeFile(root / ("shell" + std::to_string(i) + ".php"), kShell);
    }
    writeFile(dir.file("blocker"), "a regular file");
    writeQuarantineConfig(dir.file("scan.yaml"), root, dir.file("blocker") / "quarantine");

    const ScanRun run = scanQuietly(dir.file("scan.yaml"), dir.file("report.txt"));

    EXPECT_EQ(run.code, 2) << "a failed move does not outrank the finding that caused it";
    EXPECT_TRUE(contains(run.diagnostics, "12 files could not be moved")) << run.diagnostics;
    EXPECT_TRUE(contains(run.diagnostics, "... and 2 more, all in the report"))
        << run.diagnostics;
}

// The companion. Without it the case above would pass against a command that had learned
// to print that sentence whatever happened.
TEST(QuarantineFailureTest, TheDiagnosticIsAbsentWhenEveryMoveSucceeded) {
    TempDir dir;
    TempDir quarantine;
    const fs::path root = dir.path() / "site";
    writeFile(root / "shell.php", kShell);
    writeQuarantineConfig(dir.file("scan.yaml"), root, quarantine.path());

    const ScanRun run = scanQuietly(dir.file("scan.yaml"), dir.file("report.txt"));

    EXPECT_EQ(run.code, 2);
    EXPECT_FALSE(contains(run.diagnostics, "could not be moved")) << run.diagnostics;
}

// The same hole in the readable report. A container has no match of its own, so both
// printers returned on the match count alone and printed no line for it at all - the
// quarantine outcome was the only thing to say about that file and nothing said it.
TEST(QuarantineFailureTest, TheReadableReportNamesAContainerWithNoMatchOfItsOwn) {
    FileResult container;
    container.path = "/var/www/html/backup.zip";
    container.quarantineFailed = true;

    FileResult moved = container;
    moved.quarantineFailed = false;
    moved.quarantined = true;
    moved.quarantinePath = "/var/quarantine/var/www/html/backup.zip";

    FileResult clean;
    clean.path = "/var/www/html/index.php";

    for (const bool verbose : {false, true}) {
        std::ostringstream out;
        ResultPrinter printer(out, /*color=*/false, /*width=*/100);
        for (const FileResult& file : {container, moved, clean}) {
            if (verbose) {
                printer.printFileResult(file);
            } else {
                printer.printFileResultCompact(file);
            }
        }

        EXPECT_TRUE(contains(out.str(), "backup.zip")) << out.str();
        EXPECT_TRUE(contains(out.str(), "NOT quarantined")) << out.str();
        // The companion inside the companion: a clean file is still not printed, so
        // this cannot be passing because every file now gets a line.
        EXPECT_FALSE(contains(out.str(), "index.php")) << out.str();
    }
}

// ===========================================================================
// What the machine-readable reports say
// ===========================================================================

namespace {

FileResult unmovedFinding(const std::string& path) {
    FileResult result;
    result.path = path;
    result.quarantineFailed = true;
    FileMatch match;
    match.ruleName = "eval base64 decode";
    match.category = "RCE001";
    match.severity = Severity::Critical;
    result.matches.push_back(match);
    return result;
}

}  // namespace

TEST(UnquarantinedReportTest, JsonCarriesTheFileAndTheCount) {
    ScanResult result;
    result.filesQuarantineFailed = 1;
    result.files.push_back(unmovedFinding("/var/www/shell.php"));

    std::ostringstream out;
    JsonReportWriter writer(out);
    writer.begin();
    writer.onFile(result.files.front());
    writer.end(result, /*interrupted=*/false);

    EXPECT_TRUE(contains(out.str(), "\"quarantineFailed\": true")) << out.str();
    EXPECT_TRUE(contains(out.str(), "\"filesQuarantineFailed\": 1")) << out.str();
}

// The companion, and the reason the per-file key is written only when it is true: a run
// where every move succeeded produces the report it always produced.
TEST(UnquarantinedReportTest, JsonSaysNothingPerFileWhenNothingFailed) {
    ScanResult result;
    FileResult moved;
    moved.path = "/var/www/shell.php";
    moved.quarantined = true;
    moved.quarantinePath = "/var/quarantine/var/www/shell.php";
    result.filesQuarantined = 1;
    result.files.push_back(moved);

    std::ostringstream out;
    JsonReportWriter writer(out);
    writer.begin();
    writer.onFile(result.files.front());
    writer.end(result, /*interrupted=*/false);

    EXPECT_FALSE(contains(out.str(), "quarantineFailed\": true")) << out.str();
    EXPECT_TRUE(contains(out.str(), "\"filesQuarantineFailed\": 0")) << out.str();
    EXPECT_TRUE(contains(out.str(), "/var/www/shell.php"))
        << "a container moved for what was inside it has no matches of its own and "
           "still belongs in the report";
}

TEST(UnquarantinedReportTest, CsvCarriesTheColumnAndKeepsEveryOtherIndex) {
    ScanResult result;
    result.files.push_back(unmovedFinding("/var/www/shell.php"));

    std::ostringstream out;
    CsvReportWriter writer(out);
    writer.begin();
    writer.onFile(result.files.front());
    writer.end(result, /*interrupted=*/false);

    std::istringstream lines(out.str());
    std::string header;
    std::string row;
    ASSERT_TRUE(std::getline(lines, header));
    ASSERT_TRUE(std::getline(lines, row));

    EXPECT_TRUE(header.starts_with(
        "file,rule,severity,original_severity,suppressed,category,line,column,"
        "quarantined,skipped,skip_reason,quarantine_failed"))
        << "the new column is appended so every existing column keeps its index: " << header;

    // The rule this case exists for is that a column is appended and the ones before it
    // keep their index - not that `quarantine_failed` is last for ever. Two more columns
    // have since been appended under the same rule, so the assertion is on the index of
    // this one rather than on its position at the end of the line.
    EXPECT_EQ(fieldAt(header, 11), "quarantine_failed") << header;
    EXPECT_EQ(fieldAt(row, 11), "true") << row;
}

// ===========================================================================
// A finding inside a container that was moved
// ===========================================================================
//
// Three defects sharing one reproduction: a webshell in a zip that genuinely
// compresses, under a scan root, with quarantine enabled. The container is moved,
// correctly, because a hostile member quarantines its container. What the report then
// said about the member was wrong in three separate ways.
//
// The member row was addressed `archive.zip!wp-content/uploads/shell.php` using the
// container's path AT THE TIME IT WAS SCANNED, and the container is not there any more.
// An operator following that path finds nothing and so does a tool. That is an ordering
// property rather than a mistake in one writer: the row was published by the archive
// finding callback and the quarantine decision was taken afterwards, so the row was
// always written before there was anything true to write. The repair is to publish the
// row after the decision - NOT to correct the retained row, which would have been worse
// than the defect, because fileResultCallback_ drives every streaming writer and the
// full-screen view, and each had already seen the stale value.
//
// The member row said `quarantined: false`, which is equally what an exposure finding,
// a run with quarantine switched off and a failed move look like - the absence that
// `quarantineFailed` was added to stop carrying a fact, made again one level in. A
// member is not a file that was moved, so it does not claim `quarantined`; it carries
// what happened to the container it is inside, and it carries it as a value that is
// absent when nothing was attempted rather than false.
//
// And the destination was known to the scanner and read by exactly one consumer, the
// `moved:` line of the verbose text view. A machine was told a file had been
// quarantined and never told where to.
//
// Every case below is paired with the other direction, because each of the three is
// easy to "fix" by asserting the fact unconditionally: a container that was not moved,
// one whose move failed, an exposure-only container and a run with quarantine off must
// each produce a visibly different row.

namespace {

// The member of an archive really is addressable at the `container!member` address the
// row gives. Reading the row is not enough: the whole defect was a row whose address
// named a file that was no longer there.
bool memberIsInArchive(const fs::path& archive, const std::string& member) {
    int err = 0;
    zip_t* za = zip_open(archive.string().c_str(), ZIP_RDONLY, &err);
    if (!za) {
        return false;
    }
    const bool found = zip_name_locate(za, member.c_str(), 0) >= 0;
    zip_close(za);
    return found;
}

// A scan that keeps the rows as the streaming writers received them, beside the rows an
// in-process caller reads at the end.
//
// The two are not the same thing and one case below turns entirely on the difference:
// `result.files` is what a caller holding the whole ScanResult sees, and the callback is
// what the report file, the terminal and the full-screen view are built from while the
// scan runs. A repair that corrected only the first would leave every report the tool
// actually writes carrying the value from before the move.
struct StreamedScan {
    ScanResult result;
    std::vector<FileResult> streamed;
};

StreamedScan runScanStreaming(const AppConfig& config) {
    StreamedScan out;
    Scanner scanner(config);
    scanner.setPreCount(false);
    scanner.setFileResultCallback(
        [&out](const FileResult& file) { out.streamed.push_back(file); });
    out.result = scanner.scan();
    return out;
}

// The row whose path ends in `suffix`. Suffix rather than substring, because
// `backup.zip` is a prefix of `backup.zip!shell.php` and a substring search would hand
// back the container when asked for the member.
const FileResult* rowEndingIn(const std::vector<FileResult>& files,
                              std::string_view suffix) {
    for (const auto& file : files) {
        if (file.path.string().ends_with(suffix)) {
            return &file;
        }
    }
    return nullptr;
}

const std::string kMemberName = "wp-content/uploads/shell.php";
const std::string kMemberSuffix = "backup.zip!wp-content/uploads/shell.php";

// The reproduction, built once: a zip whose member deflate genuinely compresses, so the
// literal the rules match is not sitting in the container's own bytes and the container
// can only be moved on the strength of what was found inside it.
fs::path writeContainerWithAShellInside(const fs::path& root) {
    const fs::path container = root / "backup.zip";
    writeZip(container, {{kMemberName, compressibleShell()}});
    return container;
}

}  // namespace

// The first defect. The row still names where the file was found - that is what the
// operator's own notes say and what every earlier report says - and it now carries
// where the bytes went, in the same `container!member` form, which really does resolve.
TEST(ContainedMemberTest, TheMemberRowSaysWhereItWasFoundAndWhereItsBytesNowAre) {
    TempDir dir;
    TempDir quarantine;
    const fs::path root = dir.path() / "site";
    const fs::path container = writeContainerWithAShellInside(root);

    const ScanResult result = runScan(quarantineConfig(root, quarantine.path()));

    const FileResult* containerRow = rowEndingIn(result.files, "backup.zip");
    const FileResult* memberRow = rowEndingIn(result.files, kMemberSuffix);
    ASSERT_NE(containerRow, nullptr);
    ASSERT_NE(memberRow, nullptr);

    ASSERT_TRUE(containerRow->quarantined);
    EXPECT_FALSE(fs::exists(container)) << "the container was moved, so the address the "
                                           "member row used to give resolves to nothing";

    EXPECT_EQ(memberRow->path.string(), pathToUtf8(container) + "!" + kMemberName)
        << "the found-at address is not rewritten by the move";

    EXPECT_EQ(memberRow->quarantinePath.string(),
              pathToUtf8(containerRow->quarantinePath) + "!" + kMemberName)
        << "the member's bytes are addressed under the container's destination";

    // And the address is not merely well-formed. The bytes are there.
    EXPECT_TRUE(fs::exists(containerRow->quarantinePath));
    EXPECT_TRUE(memberIsInArchive(containerRow->quarantinePath, kMemberName))
        << "a reader must be able to get from the row to the bytes";
}

// The second defect. The member carries what happened to its container, and does not
// claim to have been quarantined itself - which would make the rows disagree with
// filesQuarantined, the count of files that were moved.
TEST(ContainedMemberTest, TheMemberCarriesTheContainersOutcomeAndNotItsOwn) {
    TempDir dir;
    TempDir quarantine;
    const fs::path root = dir.path() / "site";
    writeContainerWithAShellInside(root);

    const ScanResult result = runScan(quarantineConfig(root, quarantine.path()));

    const FileResult* memberRow = rowEndingIn(result.files, kMemberSuffix);
    ASSERT_NE(memberRow, nullptr);

    ASSERT_TRUE(memberRow->containerQuarantine.has_value());
    EXPECT_EQ(*memberRow->containerQuarantine, ContainerQuarantine::Moved);
    EXPECT_FALSE(memberRow->quarantined)
        << "a member is not a file that was moved; the container went as a unit";
    EXPECT_FALSE(memberRow->quarantineFailed);

    EXPECT_EQ(result.filesQuarantined, 1u)
        << "one file was moved, and exactly one row may say it was";
    size_t rowsClaimingAMove = 0;
    for (const auto& file : result.files) {
        if (file.quarantined) ++rowsClaimingAMove;
    }
    EXPECT_EQ(rowsClaimingAMove, result.filesQuarantined);
}

// The control that matters most, and the one a repair is most likely to fail. A member
// whose container could NOT be moved is a webshell still under the web root, reachable
// at the same URL as before - the opposite operational answer from the case above, and
// it must not be reachable by reading `quarantined: false` on either of them.
TEST(ContainedMemberTest, AMemberOfAContainerThatCouldNotBeMovedIsSaidToBeStillInPlace) {
    TempDir dir;
    const fs::path root = dir.path() / "site";
    const fs::path container = writeContainerWithAShellInside(root);
    writeFile(dir.file("blocker"), "a regular file, so nothing can be made under it");

    const ScanResult result =
        runScan(quarantineConfig(root, dir.file("blocker") / "quarantine"));

    const FileResult* memberRow = rowEndingIn(result.files, kMemberSuffix);
    ASSERT_NE(memberRow, nullptr);

    ASSERT_TRUE(memberRow->containerQuarantine.has_value());
    EXPECT_EQ(*memberRow->containerQuarantine, ContainerQuarantine::MoveFailed);
    EXPECT_TRUE(memberRow->quarantinePath.empty())
        << "nothing moved, so there is nowhere else to point a reader";

    EXPECT_TRUE(fs::exists(container));
    EXPECT_TRUE(memberIsInArchive(container, kMemberName))
        << "the shell is still where it was found, which is what the row has to say";
    EXPECT_EQ(result.filesQuarantineFailed, 1u);
}

// A run with quarantine switched off. Nothing was attempted, so the member row carries
// no outcome at all rather than a negative one - the distinction the whole enum exists
// for. Without this case every assertion above would pass against a scanner that
// stamped `MoveFailed` on every member it ever reported.
TEST(ContainedMemberTest, WithQuarantineOffNoRowCarriesAContainerOutcome) {
    TempDir dir;
    const fs::path root = dir.path() / "site";
    const fs::path container = writeContainerWithAShellInside(root);

    AppConfig config = quarantineConfig(root, dir.file("unused-quarantine"));
    config.actions.quarantine.enabled = false;

    const ScanResult result = runScan(config);

    const FileResult* memberRow = rowEndingIn(result.files, kMemberSuffix);
    ASSERT_NE(memberRow, nullptr);
    EXPECT_FALSE(memberRow->containerQuarantine.has_value())
        << "nothing was attempted, and that is not the same answer as a move that failed";
    EXPECT_TRUE(memberRow->quarantinePath.empty());
    EXPECT_TRUE(fs::exists(container));
    EXPECT_EQ(result.filesQuarantined, 0u);
    EXPECT_EQ(result.filesQuarantineFailed, 0u);
}

// The same ruling for --dry-run, which is a different branch reaching the same
// decision: the operator asked what WOULD happen, and a row claiming a container had
// been moved would be the report telling them it had.
TEST(ContainedMemberTest, ADryRunReportsTheMemberAndClaimsNoContainment) {
    TempDir dir;
    TempDir quarantine;
    const fs::path root = dir.path() / "site";
    const fs::path container = writeContainerWithAShellInside(root);

    Scanner scanner(quarantineConfig(root, quarantine.path()));
    scanner.setPreCount(false);
    scanner.setDryRun(true);
    const ScanResult result = scanner.scan();

    const FileResult* memberRow = rowEndingIn(result.files, kMemberSuffix);
    ASSERT_NE(memberRow, nullptr);
    EXPECT_FALSE(memberRow->containerQuarantine.has_value());
    EXPECT_TRUE(fs::exists(container)) << "a dry run moves nothing";
}

// An exposure finding says a file is in the wrong place, not that it is hostile, so it
// never moves anything - and no row may claim otherwise. A member row never carries an
// exposure finding of its own, because an exposure finding is raised about a container
// and a nested container's entries fold into the outer one's summary; so the case is
// put at the level where it exists, which is the container.
TEST(ContainedMemberTest, AnExposureOnlyContainerMovesNothingAndNoRowClaimsItDid) {
    TempDir dir;
    TempDir quarantine;
    const fs::path root = dir.path() / "site";
    const fs::path backup = root / "site-backup.zip";
    writeZip(backup, {{"wp-config.php", "<?php define('DB_PASSWORD', 'x');\n"},
                      {"wp-load.php", "<?php require 'wp-config.php';\n"}});

    const ScanResult result = runScan(quarantineConfig(root, quarantine.path()));

    const FileResult* containerRow = rowEndingIn(result.files, "site-backup.zip");
    ASSERT_NE(containerRow, nullptr);
    ASSERT_FALSE(hasHostileContent(*containerRow))
        << "this case is only about an exposure finding, and this container has more";

    EXPECT_EQ(result.filesQuarantined, 0u);
    EXPECT_TRUE(fs::exists(backup)) << "the operator's own data is not moved for them";
    for (const auto& file : result.files) {
        EXPECT_FALSE(file.quarantined) << file.path.string();
        EXPECT_FALSE(file.containerQuarantine.has_value()) << file.path.string();
    }
}

// The trap, pinned. fileResultCallback_ fires as each row is published, and it is what
// the report file, the console report and the full-screen view are all built from. A
// repair that published the row first and corrected it afterwards would leave every one
// of them holding the stale address while `result.files` - which only an in-process
// caller reads - looked right.
//
// So the streamed row is compared against the final row field by field, and the member
// row's outcome is asserted on the STREAMED copy: it can only be there if the row was
// published after the container's fate was decided.
TEST(ContainedMemberTest, TheRowEveryWriterSeesIsTheRowTheResultKeeps) {
    TempDir dir;
    TempDir quarantine;
    const fs::path root = dir.path() / "site";
    writeContainerWithAShellInside(root);

    const StreamedScan scan = runScanStreaming(quarantineConfig(root, quarantine.path()));

    const FileResult* streamedMember = rowEndingIn(scan.streamed, kMemberSuffix);
    const FileResult* finalMember = rowEndingIn(scan.result.files, kMemberSuffix);
    ASSERT_NE(streamedMember, nullptr);
    ASSERT_NE(finalMember, nullptr);

    ASSERT_TRUE(streamedMember->containerQuarantine.has_value())
        << "the row reached its writers before the container's fate was known";
    EXPECT_EQ(*streamedMember->containerQuarantine, ContainerQuarantine::Moved);
    EXPECT_FALSE(streamedMember->quarantinePath.empty());

    EXPECT_EQ(streamedMember->path, finalMember->path);
    EXPECT_EQ(streamedMember->quarantinePath, finalMember->quarantinePath);
    EXPECT_EQ(streamedMember->containerQuarantine, finalMember->containerQuarantine);
    EXPECT_EQ(streamedMember->quarantined, finalMember->quarantined);

    // And the order a report has always shown these in is unchanged: the members of a
    // container, then the container itself.
    std::vector<std::string> order;
    for (const auto& file : scan.streamed) {
        order.push_back(file.path.string());
    }
    ASSERT_EQ(order.size(), 2u) << "one member row and one container row";
    EXPECT_TRUE(order[0].ends_with(kMemberSuffix)) << order[0];
    EXPECT_TRUE(order[1].ends_with("backup.zip")) << order[1];
}

// ===========================================================================
// What the reports say about a member that was contained
// ===========================================================================

namespace {

FileResult containedMember() {
    FileResult member;
    member.path = "/var/www/html/backup.zip!wp-content/uploads/shell.php";
    member.containerQuarantine = ContainerQuarantine::Moved;
    member.quarantinePath =
        "/var/quarantine/var/www/html/backup.zip!wp-content/uploads/shell.php";
    FileMatch match;
    match.ruleName = "eval base64 decode";
    match.category = "RCE001";
    match.severity = Severity::Critical;
    member.matches.push_back(match);
    return member;
}

std::string jsonFor(const FileResult& file) {
    ScanResult result;
    result.files.push_back(file);
    std::ostringstream out;
    JsonReportWriter writer(out);
    writer.begin();
    writer.onFile(result.files.front());
    writer.end(result, /*interrupted=*/false);
    return out.str();
}

}  // namespace

// The third defect. The scanner has always known the destination and exactly one
// consumer read it - the verbose text view - so a pipeline was told a file had been
// quarantined and never told where to.
TEST(ContainedMemberReportTest, JsonCarriesTheDestinationOfAFileThatMoved) {
    FileResult moved;
    moved.path = "/var/www/html/backup.zip";
    moved.quarantined = true;
    moved.quarantinePath = "/var/quarantine/var/www/html/backup.zip";

    const std::string json = jsonFor(moved);
    EXPECT_TRUE(contains(json, "\"quarantined\": true")) << json;
    EXPECT_TRUE(contains(json,
                         "\"quarantinePath\": \"/var/quarantine/var/www/html/backup.zip\""))
        << json;
}

TEST(ContainedMemberReportTest, JsonCarriesTheContainerOutcomeAndTheMembersAddress) {
    const std::string json = jsonFor(containedMember());

    EXPECT_TRUE(contains(json, "\"containerQuarantine\": \"moved\"")) << json;
    EXPECT_TRUE(contains(json, "\"quarantinePath\": \"/var/quarantine/var/www/html/"
                               "backup.zip!wp-content/uploads/shell.php\""))
        << json;
    EXPECT_TRUE(contains(json, "\"quarantined\": false"))
        << "the member itself was not moved, and the row still says so: " << json;
}

// The companion, and the reason both keys are written only when they have something to
// say: a member of a container whose move failed is still under the web root, and a
// report from a run where nothing was attempted is the report it always was.
TEST(ContainedMemberReportTest, JsonSaysMoveFailedAndOffersNoDestination) {
    FileResult member = containedMember();
    member.containerQuarantine = ContainerQuarantine::MoveFailed;
    member.quarantinePath.clear();

    const std::string json = jsonFor(member);
    EXPECT_TRUE(contains(json, "\"containerQuarantine\": \"moveFailed\"")) << json;
    EXPECT_FALSE(contains(json, "quarantinePath")) << json;
}

TEST(ContainedMemberReportTest, JsonSaysNeitherWhenNoDecisionWasTaken) {
    FileResult member = containedMember();
    member.containerQuarantine.reset();
    member.quarantinePath.clear();

    const std::string json = jsonFor(member);
    EXPECT_FALSE(contains(json, "containerQuarantine"))
        << "an absent key is how a report says nothing was attempted: " << json;
    EXPECT_FALSE(contains(json, "quarantinePath")) << json;
    EXPECT_TRUE(contains(json, "\"quarantined\": false")) << json;
}

// One CSV line, split on commas. Enough for these cases: none of the fields they look at
// is quoted, and a field's INDEX is what they are about - the columns of this format are
// consumed by position, which is the whole reason a new one is appended rather than put
// where it reads best.
std::vector<std::string> csvFields(const std::string& line) {
    std::vector<std::string> fields;
    std::string current;
    for (char c : line) {
        if (c == ',') {
            fields.push_back(current);
            current.clear();
        } else {
            current += c;
        }
    }
    fields.push_back(current);
    return fields;
}

TEST(ContainedMemberReportTest, CsvCarriesBothAndKeepsEveryOtherIndex) {
    ScanResult result;
    result.files.push_back(containedMember());

    std::ostringstream out;
    CsvReportWriter writer(out);
    writer.begin();
    writer.onFile(result.files.front());
    writer.end(result, /*interrupted=*/false);

    std::istringstream lines(out.str());
    std::string header;
    std::string row;
    ASSERT_TRUE(std::getline(lines, header));
    ASSERT_TRUE(std::getline(lines, row));

    EXPECT_TRUE(header.starts_with(
        "file,rule,severity,original_severity,suppressed,category,line,column,"
        "quarantined,skipped,skip_reason,quarantine_failed,"))
        << "the two new columns are appended, so every existing column keeps its "
           "index: " << header;
    // By index rather than by what the line ends with. The point of appending a column
    // is that the ones before it do not move, and a case that pins the LAST field breaks
    // the next time something is appended - saying nothing about whether the indexes it
    // was actually about were kept. These two are 12 and 13 and must stay there.
    const std::vector<std::string> columns = csvFields(header);
    const std::vector<std::string> values = csvFields(row);
    ASSERT_EQ(columns.size(), values.size()) << header << "\n" << row;
    ASSERT_GT(columns.size(), 13u) << header;

    EXPECT_EQ(columns[12], "quarantine_path");
    EXPECT_EQ(columns[13], "container_quarantine");
    EXPECT_EQ(values[12],
              "/var/quarantine/var/www/html/backup.zip!wp-content/uploads/shell.php");
    EXPECT_EQ(values[13], "moved");
}

// The companion for CSV: a row for which no decision was taken leaves both cells empty,
// which is not the same as `moveFailed` and is not the same as a destination of "".
TEST(ContainedMemberReportTest, CsvLeavesBothCellsEmptyWhenNothingWasAttempted) {
    ScanResult result;
    FileResult member = containedMember();
    member.containerQuarantine.reset();
    member.quarantinePath.clear();
    result.files.push_back(member);

    std::ostringstream out;
    CsvReportWriter writer(out);
    writer.begin();
    writer.onFile(result.files.front());
    writer.end(result, /*interrupted=*/false);

    std::istringstream lines(out.str());
    std::string header;
    std::string row;
    ASSERT_TRUE(std::getline(lines, header));
    ASSERT_TRUE(std::getline(lines, row));

    const std::vector<std::string> values = csvFields(row);
    ASSERT_GT(values.size(), 13u) << row;
    EXPECT_EQ(values[11], "false") << "quarantine_failed";
    EXPECT_EQ(values[12], "") << "quarantine_path";
    EXPECT_EQ(values[13], "") << "container_quarantine";
}

// Both readable views, from the one function that puts a quarantine outcome into words.
// The compact view is what an operator watching a `--quarantine` run actually reads and
// it said nothing at all about the one destructive thing the command does; the verbose
// view named a destination and no other output did.
TEST(ContainedMemberReportTest, BothReadableViewsNameTheDestinationAndTheOutcome) {
    const FileResult member = containedMember();

    FileResult stranded = member;
    stranded.containerQuarantine = ContainerQuarantine::MoveFailed;
    stranded.quarantinePath.clear();

    FileResult moved;
    moved.path = "/var/www/html/backup.zip";
    moved.quarantined = true;
    moved.quarantinePath = "/var/quarantine/var/www/html/backup.zip";

    FileResult clean;
    clean.path = "/var/www/html/index.php";

    for (const bool verbose : {false, true}) {
        std::ostringstream out;
        ResultPrinter printer(out, /*color=*/false, /*width=*/120);
        for (const FileResult& file : {member, stranded, moved, clean}) {
            if (verbose) {
                printer.printFileResult(file);
            } else {
                printer.printFileResultCompact(file);
            }
        }
        const std::string text = out.str();

        // Built from the label functions rather than from literals. The full-screen
        // view draws its chips from those same two functions and cannot be exercised
        // from here - it is compiled only into the CLI binary - so this is what holds
        // the two views to one vocabulary: a printer that grew a wording of its own
        // fails here, and a deliberate change to a label moves both at once.
        EXPECT_TRUE(contains(
            text, std::string(containerQuarantineLabel(ContainerQuarantine::Moved)) +
                      ": /var/quarantine/var/www/html/backup.zip!"
                      "wp-content/uploads/shell.php"))
            << text;
        EXPECT_TRUE(contains(
            text, std::string(containerQuarantineLabel(ContainerQuarantine::MoveFailed)) +
                      " - still at "))
            << text;
        EXPECT_TRUE(contains(text, "moved: /var/quarantine/var/www/html/backup.zip"))
            << "a file that moved names where it went in both views: " << text;
        // The companion inside the companion: a clean file is still not printed, so
        // none of this is passing because every file now gets a line.
        EXPECT_FALSE(contains(text, "index.php")) << text;
    }
}

// ===========================================================================
// A directory the walk refused, and a scan the operator stopped
// ===========================================================================
//
// Two more shapes of the same defect, from the fourth finding of the same review.
//
// A directory symlink pointing back up the path the walk is on used to be queued like
// any other, and the walk followed it without end. It is refused now, and the refusal
// needs somewhere to be said: it is not in totalDirectoriesScanned, because the walk did
// not enter it, and no other number moves - so absence would carry it, and absence is
// what "quarantined: false" already taught this codebase not to trust.
//
// It is deliberately NOT an error, and the pairing below is what pins that distinction:
// nothing was left uncovered, because the directory that was refused is the one already
// open above it and its contents were read there. So it appears in the summary and in
// the JSON, and the exit code does not move.
//
// The interrupt is the opposite ruling on the same page. A scan of a tree holding no
// regular file reached no file callback, which was the only thing that set the scanner's
// interrupted flag, so Ctrl+C produced a completed clean scan and exit 0. That answer
// really was partial, and 130 is what says so.

namespace {

// The interrupt flag is process-global; a case that raises it puts it back, or the next
// case in the same binary stops before it starts and passes for the wrong reason.
struct InterruptGuard {
    InterruptGuard() { g_interrupted.store(false, std::memory_order_relaxed); }
    ~InterruptGuard() { g_interrupted.store(false, std::memory_order_relaxed); }
    InterruptGuard(const InterruptGuard&) = delete;
    InterruptGuard& operator=(const InterruptGuard&) = delete;
};

// The review's reproduction as a fixture: a directory holding two symlinks to itself.
// Returns false when this host will not create one, which is a reason to skip and not a
// result - a case that built two plain directories and then watched the walk not loop
// would be observing nothing.
bool makeSelfLinkedTree(const fs::path& root) {
    fs::create_directories(root);
    std::error_code ec;
    fs::create_directory_symlink(".", root / "a", ec);
    if (ec) return false;
    fs::create_directory_symlink(".", root / "b", ec);
    return !ec;
}

// A deadline that turns "runs forever" into one failed expectation.
//
// The walker's own cases bound themselves by counting directories, which needs no clock
// and cannot flake. Nothing at this level exposes that count - Scanner owns its walker
// and ScanUseCase owns its Scanner - so the bound here is wall-clock instead. It is set
// two orders of magnitude above what these scans take, which is tens of milliseconds, so
// a loaded machine cannot reach it; what it must never be is absent, because without the
// repair these fixtures do not fail, they run until somebody kills the suite.
//
// It stops the scan through the interrupt flag, which is the other half of the same
// repair. That dependency is deliberate: a walk that could not be interrupted could not
// be bounded here either, and the case would be back to hanging.
class LoopDeadline {
public:
    explicit LoopDeadline(std::chrono::milliseconds limit)
        : thread_([this, limit] {
              std::unique_lock<std::mutex> lock(mutex_);
              if (!done_.wait_for(lock, limit, [this] { return finished_; })) {
                  fired_.store(true, std::memory_order_relaxed);
                  g_interrupted.store(true, std::memory_order_relaxed);
              }
          }) {}

    ~LoopDeadline() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            finished_ = true;
        }
        done_.notify_all();
        thread_.join();
        g_interrupted.store(false, std::memory_order_relaxed);
    }

    LoopDeadline(const LoopDeadline&) = delete;
    LoopDeadline& operator=(const LoopDeadline&) = delete;

    bool fired() const { return fired_.load(std::memory_order_relaxed); }

private:
    std::mutex mutex_;
    std::condition_variable done_;
    bool finished_ = false;
    std::atomic<bool> fired_{false};
    std::thread thread_;  // last, so everything it touches is built before it starts
};

AppConfig followingConfig(const fs::path& root) {
    AppConfig config = Config::loadFromString(Config::generateDefault());
    config.scan.directories = {root.string()};
    config.scan.recursive = true;
    config.scan.followSymlinks = true;
    return config;
}

std::string summaryOf(const ScanResult& result) {
    std::ostringstream out;
    ResultPrinter(out, /*color=*/false, /*width=*/100).printSummary(result);
    return out.str();
}

}  // namespace

TEST(LoopCoverageTest, ADirectoryRefusedAsALoopIsCountedOnTheResult) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }
    TempDir dir;
    const fs::path root = dir.path() / "site";
    writeFile(root / "index.php", "<?php echo 1; ?>\n");
    ASSERT_TRUE(makeSelfLinkedTree(root));

    InterruptGuard guard;
    LoopDeadline deadline(std::chrono::seconds(5));
    const ScanResult result = runScan(followingConfig(root));

    ASSERT_FALSE(deadline.fired())
        << "the scan was still walking a tree of one directory five seconds in";
    EXPECT_EQ(result.directoriesCycleSkipped, 2u);
    EXPECT_EQ(result.totalDirectoriesScanned, 1u)
        << "a refused directory is not one the walk entered";
    EXPECT_EQ(result.totalFilesScanned, 1u) << "read once, not once per path to it";
}

// The companion. Without it, a scanner that counted every directory as a loop would
// satisfy the case above.
TEST(LoopCoverageTest, NothingIsCountedWhenTheTreeHasNoLoop) {
    TempDir dir;
    const fs::path root = dir.path() / "site";
    writeFile(root / "index.php", "<?php echo 1; ?>\n");
    writeFile(root / "sub" / "page.php", "<?php echo 2; ?>\n");

    const ScanResult result = runScan(followingConfig(root));

    EXPECT_EQ(result.directoriesCycleSkipped, 0u);
    EXPECT_EQ(result.totalDirectoriesScanned, 2u);
}

TEST(LoopCoverageTest, TheSummarySaysItAndSaysNothingWhenThereIsNone) {
    ScanResult withLoop;
    withLoop.totalDirectoriesScanned = 1;
    withLoop.directoriesCycleSkipped = 2;

    const std::string said = summaryOf(withLoop);
    EXPECT_TRUE(contains(said, "Directories not re-entered: 2")) << said;
    EXPECT_TRUE(contains(said, "loop")) << said;

    ScanResult clean;
    clean.totalDirectoriesScanned = 1;
    const std::string quiet = summaryOf(clean);
    EXPECT_FALSE(contains(quiet, "not re-entered"))
        << "a tree with no loop in it must read exactly as it always did: " << quiet;
}

TEST(LoopCoverageTest, JsonCarriesTheCountAndCarriesZero) {
    for (const size_t skipped : {size_t{0}, size_t{2}}) {
        ScanResult result;
        result.directoriesCycleSkipped = skipped;

        std::ostringstream out;
        JsonReportWriter writer(out);
        writer.begin();
        writer.end(result, /*interrupted=*/false);

        // Unconditional: a consumer must not have to tell an old report from a
        // loop-free one by whether the key is there.
        EXPECT_TRUE(contains(out.str(), "\"directoriesCycleSkipped\": " +
                                            std::to_string(skipped)))
            << out.str();
    }
}

// The ranking, asserted rather than asserted about in a comment. A loop leaves the
// answer complete, so it moves nothing - including in the direction that would look
// conservative and is not: turning a clean scan into a 1 would hide it from a caller
// watching for 2, and turning a scan with a finding into a 1 would hide the finding.
TEST(LoopCoverageTest, ALoopDoesNotMoveTheExitCode) {
    if (const auto why = test::whyCannotCreateSymlinks()) {
        GTEST_SKIP() << *why;
    }
    TempDir dir;
    const fs::path clean = dir.path() / "clean";
    writeFile(clean / "index.php", "<?php echo 1; ?>\n");
    ASSERT_TRUE(makeSelfLinkedTree(clean));

    const fs::path hostile = dir.path() / "hostile";
    writeFile(hostile / "shell.php", kShell);
    ASSERT_TRUE(makeSelfLinkedTree(hostile));

    writeFile(dir.file("clean.yaml"),
              "scan:\n  directories:\n    - " + clean.string() + "\n  follow_symlinks: true\n");
    writeFile(dir.file("hostile.yaml"),
              "scan:\n  directories:\n    - " + hostile.string() + "\n  follow_symlinks: true\n");

    InterruptGuard guard;
    LoopDeadline deadline(std::chrono::seconds(10));

    EXPECT_EQ(scanExitCode({clean}, dir.file("clean.txt").string(), dir.file("clean.yaml")), 0)
        << "a loop is not an incomplete answer";
    EXPECT_EQ(scanExitCode({hostile}, dir.file("hostile.txt").string(), dir.file("hostile.yaml")),
              2)
        << "and it does not displace the finding either";
    EXPECT_FALSE(deadline.fired()) << "one of the two scans followed the loop";
}

TEST(InterruptedScanTest, AnInterruptedScanOfATreeWithNoFileInItDoesNotExitZero) {
    TempDir dir;
    const fs::path root = dir.path() / "site";
    for (int i = 0; i < 20; ++i) {
        fs::create_directories(root / ("d" + std::to_string(i)));
    }

    InterruptGuard guard;
    g_interrupted.store(true, std::memory_order_relaxed);
    const int code = scanExitCode({root}, dir.file("report.txt").string());

    EXPECT_EQ(code, 130) << "an interrupted scan of a tree the file callback never sees "
                            "used to report a completed clean run";
}

// The companion, and the one that would catch a scanner that had learned to call every
// run interrupted.
TEST(InterruptedScanTest, TheSameTreeUninterruptedStillExitsZero) {
    TempDir dir;
    const fs::path root = dir.path() / "site";
    for (int i = 0; i < 20; ++i) {
        fs::create_directories(root / ("d" + std::to_string(i)));
    }

    InterruptGuard guard;
    EXPECT_EQ(scanExitCode({root}, dir.file("report.txt").string()), 0);
}

// And that the ranking holds where it matters most: a scan cut short after it found a
// webshell exits 130, not 2, because a caller reading 2 would take the tree as examined.
TEST(InterruptedScanTest, AnInterruptOutranksTheFinding) {
    TempDir dir;
    const fs::path root = dir.path() / "site";
    writeFile(root / "shell.php", kShell);

    InterruptGuard guard;
    EXPECT_EQ(scanExitCode({root}, dir.file("found.txt").string()), 2)
        << "the finding, with nothing interrupting it";

    g_interrupted.store(true, std::memory_order_relaxed);
    EXPECT_EQ(scanExitCode({root}, dir.file("halted.txt").string()), 130);
}
