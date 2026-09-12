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
#include "core/Scanner.h"
#include "infrastructure/report/CsvReportWriter.h"
#include "infrastructure/report/JsonReportWriter.h"
#include "system/CliArgs.h"
#include "use-cases/CheckUseCase.h"
#include "use-cases/ScanUseCase.h"

#include "PlatformSkips.h"

#include <chrono>
#include <filesystem>
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
        "quarantined,skipped,skip_reason"))
        << "the new column is appended so every existing column keeps its index: " << header;
    EXPECT_TRUE(header.ends_with(",quarantine_failed")) << header;
    EXPECT_TRUE(row.ends_with(",true")) << row;
}
