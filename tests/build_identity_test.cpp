// What build is this, and would the other one have run here.
//
// The second question is the reason this file is long. Its three answers are not
// observable on any one machine - a developer's host can only ever demonstrate whichever
// one it happens to be - so most of what follows builds a host out of bytes and points
// the check at it. A check that has only ever said Yes, on the only host anybody ran it
// on, is not known to be able to say No.
//
// The ELF the helper writes is the smallest thing the reader accepts: a header, a section
// header table, a section-name table and a .dynstr holding version names. It is not a
// loadable object and does not need to be - nothing here runs it.

#include "update/BuildIdentity.h"
#include "update/ReleaseAssets.h"
#include "update/UpdatePolicy.h"
#include "update/UpdateState.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace lyxbosa;

namespace {

namespace fs = std::filesystem;

void put16(std::vector<char>& b, size_t at, uint16_t v) { std::memcpy(b.data() + at, &v, 2); }
void put32(std::vector<char>& b, size_t at, uint32_t v) { std::memcpy(b.data() + at, &v, 4); }
void put64(std::vector<char>& b, size_t at, uint64_t v) { std::memcpy(b.data() + at, &v, 8); }

// A 64-bit little-endian ELF whose .dynstr holds exactly `versionNames`. Three sections:
// the mandatory null one, .shstrtab and .dynstr.
void writeElfWithVersions(const fs::path& path,
                          const std::vector<std::string>& versionNames) {
    constexpr size_t kEhdr = 64;
    constexpr size_t kShdr = 64;
    constexpr size_t kSections = 3;

    // "\0.shstrtab\0.dynstr\0"
    std::string shstrtab;
    shstrtab.push_back('\0');
    const uint32_t shstrtabName = static_cast<uint32_t>(shstrtab.size());
    shstrtab += ".shstrtab";
    shstrtab.push_back('\0');
    const uint32_t dynstrName = static_cast<uint32_t>(shstrtab.size());
    shstrtab += ".dynstr";
    shstrtab.push_back('\0');

    std::string dynstr;
    dynstr.push_back('\0');
    for (const auto& name : versionNames) {
        dynstr += name;
        dynstr.push_back('\0');
    }

    const size_t sectionTableAt = kEhdr;
    const size_t shstrtabAt = sectionTableAt + kSections * kShdr;
    const size_t dynstrAt = shstrtabAt + shstrtab.size();

    std::vector<char> bytes(dynstrAt + dynstr.size(), '\0');

    std::memcpy(bytes.data(), "\x7f" "ELF", 4);
    bytes[4] = 2;  // ELFCLASS64
    bytes[5] = 1;  // ELFDATA2LSB
    bytes[6] = 1;  // EV_CURRENT
    put16(bytes, 0x10, 3);   // ET_DYN
    put64(bytes, 0x28, sectionTableAt);
    put16(bytes, 0x34, kEhdr);
    put16(bytes, 0x3A, kShdr);
    put16(bytes, 0x3C, kSections);
    put16(bytes, 0x3E, 1);   // .shstrtab is section 1

    const auto section = [&](size_t index, uint32_t name, uint64_t offset, uint64_t size) {
        const size_t at = sectionTableAt + index * kShdr;
        put32(bytes, at + 0x00, name);
        put32(bytes, at + 0x04, 3);   // SHT_STRTAB
        put64(bytes, at + 0x18, offset);
        put64(bytes, at + 0x20, size);
    };
    section(1, shstrtabName, shstrtabAt, shstrtab.size());
    section(2, dynstrName, dynstrAt, dynstr.size());

    std::memcpy(bytes.data() + shstrtabAt, shstrtab.data(), shstrtab.size());
    std::memcpy(bytes.data() + dynstrAt, dynstr.data(), dynstr.size());

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

// The version names a real glibc of that minor version declares, in the shape that
// matters: the dotted three-component ones, which are NOT version floors and must not be
// read as numbers, alongside the two-component ones that are.
std::vector<std::string> glibcVersionNames(unsigned minor) {
    std::vector<std::string> names{"GLIBC_2.2.5", "GLIBC_2.3", "GLIBC_2.3.2",
                                   "GLIBC_2.3.4", "GLIBC_PRIVATE"};
    for (unsigned m = 4; m <= minor; ++m) {
        names.push_back("GLIBC_2." + std::to_string(m));
    }
    return names;
}

class FakeHost : public ::testing::Test {
protected:
    void SetUp() override {
        // standardBuildHereAt() reads a glibc's dynamic string table through <elf.h>, so it
        // is compiled only for Linux and answers Unknown everywhere else by design. These
        // cases assert Yes and No against hosts built for the purpose, and off Linux there
        // is nothing for them to observe - the same reason the BuildIdentityTest and
        // PortableNoticeTest cases below skip rather than assert. Said here once because
        // the fixture is shared, and said as a reason rather than as a silent pass.
#if !defined(__linux__)
        GTEST_SKIP() << "the glibc probe is compiled for Linux only, so a fake host has "
                        "nothing to prove here";
#endif
        root_ = fs::temp_directory_path() /
                ("lyxbosa-host-" + std::to_string(::testing::UnitTest::GetInstance()
                                                      ->random_seed()) +
                 "-" + std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(root_);
    }
    void TearDown() override {
        std::error_code ec;
        fs::remove_all(root_, ec);
    }

    fs::path loaderThatExists() {
        const fs::path p = root_ / "ld-linux.so";
        std::ofstream(p) << "not read, only looked for";
        return p;
    }
    fs::path missingLoader() const { return root_ / "no-such-loader.so"; }

    fs::path libcDeclaring(unsigned minor) {
        const fs::path p = root_ / ("libc-2." + std::to_string(minor) + ".so.6");
        writeElfWithVersions(p, glibcVersionNames(minor));
        return p;
    }
    fs::path notAnElf() {
        const fs::path p = root_ / "libc-garbage.so.6";
        std::ofstream(p) << "#!/bin/sh\nthis is not an ELF file at all\n";
        return p;
    }
    fs::path truncatedElf() {
        const fs::path p = root_ / "libc-truncated.so.6";
        std::ofstream out(p, std::ios::binary);
        out.write("\x7f" "ELF\x02\x01\x01", 7);   // magic and class, then nothing
        return p;
    }
    fs::path missingLibc() const { return root_ / "no-such-libc.so.6"; }

    fs::path root_;
};

// Whether a string quotes a percentage, in either spelling. A named predicate rather than
// an inline expression, so that the case using it can assert it says yes as well as no: a
// check only ever run on a string that passes is not known to be able to fail, and this
// one is the whole defence against a figure coming back into a compiled-in sentence.
bool quotesAPercentage(std::string_view text) {
    return text.find('%') != std::string_view::npos ||
           text.find("percent") != std::string_view::npos;
}

}  // namespace

// ---------------------------------------------------------------------------------------
// Which build is this.
// ---------------------------------------------------------------------------------------

TEST(BuildIdentityTest, VersionNamesTheBuildAndTheAssetItWasPublishedAs) {
    const std::string identity = buildIdentity();
    ASSERT_FALSE(identity.empty())
        << "this platform publishes an asset, so --version has a build to name";

    // Whatever else it says, it says which asset this binary is - the one string that
    // turns "which build have you got" into a lookup rather than a conversation.
    EXPECT_NE(identity.find(std::string(platformAssetName())), std::string::npos)
        << identity << " does not name " << platformAssetName();

#if defined(__linux__)
    // And the word a person can act on without knowing what a C library is. Both CI
    // jobs run this, so between them both halves of the branch are asserted.
    if (isPortableBuild()) {
        EXPECT_NE(identity.find("portable build"), std::string::npos) << identity;
    } else {
        EXPECT_NE(identity.find("standard build"), std::string::npos) << identity;
    }
#endif
}

TEST(BuildIdentityTest, TheBuildFlagAgreesWithTheCLibraryActuallyLinked) {
    // The same two-independent-detections argument as the asset name's own cross-check,
    // one layer down: isPortableBuild() reads CMake's macro, __GLIBC__ comes from the
    // headers. A build where they disagree would print the wrong thing in --version and
    // would ask the wrong question about the host.
#if defined(__linux__)
#if defined(__GLIBC__)
    EXPECT_FALSE(isPortableBuild()) << "a glibc build reported itself as portable";
#else
    EXPECT_TRUE(isPortableBuild()) << "a build with no glibc reported itself as standard";
#endif
#else
    EXPECT_FALSE(isPortableBuild()) << "there is no portable build off Linux";
#endif
}

// ---------------------------------------------------------------------------------------
// Would the standard build run here. The three answers, on hosts built for the purpose.
// ---------------------------------------------------------------------------------------

TEST_F(FakeHost, NoLoaderIsProofTheStandardBuildCannotStart) {
    // The Alpine case, and every other musl-only host. The loader path is fixed by the
    // ABI and is carried inside every dynamically linked binary, so its absence is not a
    // hint - nothing dynamically linked can start at all.
    EXPECT_EQ(standardBuildHereAt(missingLoader(), {libcDeclaring(39)}),
              StandardBuildHere::No)
        << "a host with no dynamic loader was not recognised as having no alternative";
}

TEST_F(FakeHost, AGlibcOlderThanTheFloorIsProofItCannotStart) {
    // CentOS 7 is glibc 2.17 and Ubuntu 16.04 is 2.23. These are the users who must
    // never be told about a faster build, because for them there is not one.
    EXPECT_EQ(standardBuildHereAt(loaderThatExists(), {libcDeclaring(17)}),
              StandardBuildHere::No);
    EXPECT_EQ(standardBuildHereAt(loaderThatExists(), {libcDeclaring(23)}),
              StandardBuildHere::No);
}

TEST_F(FakeHost, TheFloorItselfIsEnough) {
    // 2.28 is what the standard build is linked against, so 2.28 exactly is a yes and
    // 2.27 - Ubuntu 18.04, one release below - is a no. An off-by-one here is a whole
    // distribution told the wrong thing.
    EXPECT_EQ(standardBuildHereAt(loaderThatExists(), {libcDeclaring(27)}),
              StandardBuildHere::No);
    EXPECT_EQ(standardBuildHereAt(loaderThatExists(), {libcDeclaring(28)}),
              StandardBuildHere::Yes);
}

TEST_F(FakeHost, ACurrentGlibcIsProofItWouldRun) {
    EXPECT_EQ(standardBuildHereAt(loaderThatExists(), {libcDeclaring(39)}),
              StandardBuildHere::Yes);
}

TEST_F(FakeHost, DottedVersionNamesAreNotReadAsNumbers) {
    // A real glibc declares GLIBC_2.2.5 and GLIBC_2.3.4 beside the plain ones. Read as
    // numbers by a sloppier parse, "2.5" or "3.4" would be nonsense, and a libc whose
    // highest plain version is 2.17 could come out above the floor. Here the dotted
    // names are the ONLY ones present, so any answer but Unknown means one was parsed.
    const fs::path p = root_ / "libc-dotted-only.so.6";
    writeElfWithVersions(p, {"GLIBC_2.2.5", "GLIBC_2.3.2", "GLIBC_2.3.4", "GLIBC_PRIVATE"});
    EXPECT_EQ(standardBuildHereAt(loaderThatExists(), {p}), StandardBuildHere::Unknown)
        << "a dotted version name was parsed as a number";
}

TEST_F(FakeHost, AFileThatIsNotAnElfIsNotAnAnswer) {
    EXPECT_EQ(standardBuildHereAt(loaderThatExists(), {notAnElf()}),
              StandardBuildHere::Unknown);
    EXPECT_EQ(standardBuildHereAt(loaderThatExists(), {truncatedElf()}),
              StandardBuildHere::Unknown);
}

TEST_F(FakeHost, ALoaderWithNoLibcAnywhereIsNotAnAnswer) {
    EXPECT_EQ(standardBuildHereAt(loaderThatExists(), {missingLibc()}),
              StandardBuildHere::Unknown);
    EXPECT_EQ(standardBuildHereAt(loaderThatExists(), {}), StandardBuildHere::Unknown);
}

TEST_F(FakeHost, TheSearchContinuesPastAPathThatIsNotThere) {
    // The real list is four paths because distributions disagree about where libc lives.
    // A search that stopped at the first miss would answer Unknown on Debian or on
    // Red Hat depending on which order the list happened to be in.
    EXPECT_EQ(standardBuildHereAt(loaderThatExists(),
                                  {missingLibc(), notAnElf(), libcDeclaring(31)}),
              StandardBuildHere::Yes);
}

TEST(BuildIdentityTest, TheRealHostAnswersYesWhenThisProcessIsItselfTheProof) {
    // The one assertion about the actual machine, and it is only made where it cannot
    // be wrong: if these tests are running against a glibc at or above the floor, then a
    // glibc at or above the floor demonstrably exists here, loader included - this
    // process is using it. Anywhere else this asserts nothing rather than guessing.
#if defined(__linux__) && defined(__GLIBC__)
    if (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 28) {
        EXPECT_EQ(standardBuildHere(), StandardBuildHere::Yes)
            << "this process is running on glibc 2." << __GLIBC_MINOR__
            << " and the check could not find it";
    } else {
        GTEST_SKIP() << "this host's glibc is below the floor the check tests for";
    }
#else
    GTEST_SKIP() << "this build does not prove a glibc is present";
#endif
}

// ---------------------------------------------------------------------------------------
// The notice: that it appears, and - the half that matters - that it does not.
// ---------------------------------------------------------------------------------------

namespace {

// A plausible "now", fixed rather than read off the clock, so that every interval case
// below is arithmetic on two constants and nothing sleeps.
constexpr uint64_t kNow = 1'757'600'000;

// A context that would print, so that each case below turns exactly one thing off and
// the reason a case passes is the thing it changed. Never said before, so no timestamp
// and no legacy flag.
PortableNoticeContext wouldPrint() {
    PortableNoticeContext ctx;
    ctx.callSite = UpdateCallSite::Scan;
    ctx.portableBuild = true;
    ctx.stdoutIsTty = true;
    ctx.isCI = false;
    ctx.quiet = false;
    ctx.silent = false;
    ctx.force = false;
    ctx.stateWritable = true;
    ctx.lastShownEpoch = std::nullopt;
    ctx.shownBeforeTimestamps = false;
    ctx.nowEpoch = kNow;
    ctx.standardBuild = StandardBuildHere::Yes;
    return ctx;
}

}  // namespace

TEST(PortableNoticeTest, ItIsSaidOnAPortableBuildOnAHostThatCouldRunTheOther) {
    // The positive control. Without it every case below could pass by the notice being
    // unreachable - which it was, once: the first version of the caller consulted the
    // policy before probing the host, so the answer was always "no alternative" and the
    // line could never print on any host at all.
    EXPECT_EQ(decidePortableNotice(wouldPrint()), PortableNoticeDecision::Show);
}

TEST(PortableNoticeTest, ItIsNotSaidOnAHostWithNoAlternative) {
    // The case the whole design is for. A CentOS 7 user has nothing to move to, and a
    // line telling them they are 10% slower is a line they can only turn off.
    auto ctx = wouldPrint();
    ctx.standardBuild = StandardBuildHere::No;
    EXPECT_EQ(decidePortableNotice(ctx), PortableNoticeDecision::SkipNoAlternative);
}

TEST(PortableNoticeTest, NotKnowingIsTreatedExactlyLikeNo) {
    // The other half of that, and the reason the check returns three answers rather than
    // a bool: a host it could not read must be as quiet as one it read and ruled out.
    auto ctx = wouldPrint();
    ctx.standardBuild = StandardBuildHere::Unknown;
    EXPECT_EQ(decidePortableNotice(ctx), PortableNoticeDecision::SkipNoAlternative);
}

TEST(PortableNoticeTest, TheStandardBuildNeverSaysAnything) {
    auto ctx = wouldPrint();
    ctx.portableBuild = false;
    EXPECT_EQ(decidePortableNotice(ctx), PortableNoticeDecision::SkipNotPortableBuild);
}

TEST(PortableNoticeTest, EachSuppressingFlagSuppressesIt) {
    // One case per flag rather than one case setting all three, so that a flag quietly
    // dropped from the condition fails on its own line instead of being covered by its
    // neighbours.
    for (const auto& [name, apply] :
         std::vector<std::pair<const char*, void (*)(PortableNoticeContext&)>>{
             {"--quiet", [](PortableNoticeContext& c) { c.quiet = true; }},
             {"--silent", [](PortableNoticeContext& c) { c.silent = true; }},
             {"--force", [](PortableNoticeContext& c) { c.force = true; }}}) {
        auto ctx = wouldPrint();
        apply(ctx);
        EXPECT_EQ(decidePortableNotice(ctx), PortableNoticeDecision::SkipUnattended)
            << name << " did not suppress the portable-build notice";
    }
}

TEST(PortableNoticeTest, ARedirectedRunAndACIRunSayNothing) {
    auto redirected = wouldPrint();
    redirected.stdoutIsTty = false;
    EXPECT_EQ(decidePortableNotice(redirected),
              PortableNoticeDecision::SkipNotATerminal);

    auto ci = wouldPrint();
    ci.isCI = true;
    EXPECT_EQ(decidePortableNotice(ci), PortableNoticeDecision::SkipCI);
}

TEST(PortableNoticeTest, OnlyAScanSaysIt) {
    for (const auto site : {UpdateCallSite::OtherCommand, UpdateCallSite::ExplicitRequest}) {
        auto ctx = wouldPrint();
        ctx.callSite = site;
        EXPECT_EQ(decidePortableNotice(ctx), PortableNoticeDecision::SkipNotAScan);
    }
}

TEST(PortableNoticeTest, ItIsNotRepeatedInsideTheInterval) {
    // The half of the cadence that keeps it from being noise. A scan a second after the
    // last one, one a day later, and one a second short of the interval are all silent.
    for (const uint64_t elapsed : {uint64_t{0}, uint64_t{1}, uint64_t{24 * 60 * 60},
                                   kPortableNoticeIntervalSeconds - 1}) {
        auto ctx = wouldPrint();
        ctx.lastShownEpoch = kNow - elapsed;
        EXPECT_EQ(decidePortableNotice(ctx), PortableNoticeDecision::SkipSaidRecently)
            << "repeated " << elapsed << " seconds after it was last said";
    }
}

TEST(PortableNoticeTest, ItIsSaidAgainOnceTheIntervalHasPassed) {
    // The half that the flag could not do at all, and the reason this is a timestamp:
    // exactly at the interval, and long past it, the line comes back.
    for (const uint64_t elapsed : {kPortableNoticeIntervalSeconds,
                                   kPortableNoticeIntervalSeconds + 1,
                                   10 * kPortableNoticeIntervalSeconds}) {
        auto ctx = wouldPrint();
        ctx.lastShownEpoch = kNow - elapsed;
        EXPECT_EQ(decidePortableNotice(ctx), PortableNoticeDecision::Show)
            << "still silent " << elapsed << " seconds after it was last said";
    }
}

TEST(PortableNoticeTest, TheIntervalIsAMonthAndIsNotTheUpdateInterval) {
    // Two claims, and the second is the one a future edit could quietly break. The
    // number is a month, so a change to it fails here and has to be argued for; and it
    // is this file's own constant, so an operator who lengthens updates.interval to be
    // kind to a rate-limited API does not thereby silence a line that opens no socket.
    EXPECT_EQ(kPortableNoticeIntervalSeconds, 30ull * 24 * 60 * 60);

    // The decoupling is structural and the compiler is what enforces it:
    // PortableNoticeContext has no interval field to set, so there is no path by which
    // an operator's updates.interval could reach this decision. What is asserted here is
    // that the decision is made from the constant and from nothing configurable - a run
    // exactly an interval on says the line whatever any configuration says.
    auto ctx = wouldPrint();
    ctx.lastShownEpoch = kNow - kPortableNoticeIntervalSeconds;
    EXPECT_EQ(decidePortableNotice(ctx), PortableNoticeDecision::Show);
}

TEST(PortableNoticeTest, ATimestampInTheFutureIsDueRatherThanSilent) {
    // A clock that was set forward and then corrected leaves a timestamp ahead of now.
    // decideUpdateCheck() treats that as "do not check", because there the cost avoided
    // is a request. Here the cost is one line and the run that prints it rewrites the
    // timestamp, so due is the self-repairing answer and silent is how a host falls back
    // into the once-ever state this cadence exists to leave.
    auto ctx = wouldPrint();
    ctx.lastShownEpoch = kNow + 5 * kPortableNoticeIntervalSeconds;
    EXPECT_EQ(decidePortableNotice(ctx), PortableNoticeDecision::Show)
        << "a timestamp in the future silenced the notice";
}

TEST(PortableNoticeTest, AnUpgradedStateFileStampsTheClockAndStaysQuiet) {
    // The old flag, and no timestamp. Neither obvious answer is right: printing repeats
    // a line the operator already dismissed the moment they upgrade, and skipping
    // forever leaves the host silent for good on a flag that no longer means that. So
    // the run writes a timestamp and prints nothing, and the line is due an interval
    // later - which the next case asserts rather than assumes.
    auto ctx = wouldPrint();
    ctx.shownBeforeTimestamps = true;
    ASSERT_EQ(decidePortableNotice(ctx), PortableNoticeDecision::AdoptLegacyFlag);
    EXPECT_TRUE(portableNoticeWrites(decidePortableNotice(ctx)))
        << "the upgrade outcome would not have written the state file, so it would "
           "recur on every scan";

    // An interval after the stamp, it is an ordinary due notice.
    ctx.lastShownEpoch = kNow;
    ctx.nowEpoch = kNow + kPortableNoticeIntervalSeconds;
    EXPECT_EQ(decidePortableNotice(ctx), PortableNoticeDecision::Show);
}

TEST(PortableNoticeTest, AFreshStateFileWithNoOldFlagJustSaysIt) {
    // The other direction, and the case that would pass silently if the legacy branch
    // were reached by every run: a file that never carried the flag is not migrated,
    // it is printed.
    auto ctx = wouldPrint();
    ctx.shownBeforeTimestamps = false;
    EXPECT_EQ(decidePortableNotice(ctx), PortableNoticeDecision::Show);
}

TEST(PortableNoticeTest, ATimestampOutranksTheOldFlagInBothDirections) {
    // Once a timestamp exists the flag is never consulted again, whichever way it
    // points. A file carrying both - which is what this version writes - is governed by
    // the timestamp, so the migration happens once and not on every run for ever.
    auto recent = wouldPrint();
    recent.shownBeforeTimestamps = true;
    recent.lastShownEpoch = kNow - 1;
    EXPECT_EQ(decidePortableNotice(recent), PortableNoticeDecision::SkipSaidRecently);

    auto due = wouldPrint();
    due.shownBeforeTimestamps = true;
    due.lastShownEpoch = kNow - kPortableNoticeIntervalSeconds;
    EXPECT_EQ(decidePortableNotice(due), PortableNoticeDecision::Show)
        << "the old flag was still being consulted alongside a timestamp";
}

TEST(PortableNoticeTest, EverySuppressionOutranksTheUpgradeStampToo) {
    // A cadence change is exactly the kind of edit that loosens a suppression, and the
    // upgrade stamp is a second way to reach the state file. None of the gates above it
    // may be bypassed by a state file that happens to carry the old flag - a --quiet run
    // on an upgraded host must write nothing and say nothing.
    for (const auto& [name, apply] :
         std::vector<std::pair<const char*, void (*)(PortableNoticeContext&)>>{
             {"--quiet", [](PortableNoticeContext& c) { c.quiet = true; }},
             {"--silent", [](PortableNoticeContext& c) { c.silent = true; }},
             {"--force", [](PortableNoticeContext& c) { c.force = true; }},
             {"a pipe", [](PortableNoticeContext& c) { c.stdoutIsTty = false; }},
             {"CI", [](PortableNoticeContext& c) { c.isCI = true; }},
             {"another command",
              [](PortableNoticeContext& c) { c.callSite = UpdateCallSite::OtherCommand; }},
             {"a host with no alternative",
              [](PortableNoticeContext& c) { c.standardBuild = StandardBuildHere::No; }},
             {"an unwritable state file",
              [](PortableNoticeContext& c) { c.stateWritable = false; }}}) {
        auto ctx = wouldPrint();
        ctx.shownBeforeTimestamps = true;
        apply(ctx);
        const auto decision = decidePortableNotice(ctx);
        EXPECT_NE(decision, PortableNoticeDecision::Show)
            << name << " did not suppress the notice on an upgraded state file";
        EXPECT_FALSE(portableNoticeWrites(decision))
            << name << " let an upgraded state file be written anyway: "
            << portableNoticeReason(decision);
    }
}

TEST(PortableNoticeTest, AStateFileThatCannotBeWrittenMeansSayNothing) {
    // Not a detail: a notice that cannot be recorded is a notice on every single run,
    // which is worse than never saying it.
    auto ctx = wouldPrint();
    ctx.stateWritable = false;
    EXPECT_EQ(decidePortableNotice(ctx), PortableNoticeDecision::SkipNoWritableState);
}

TEST(PortableNoticeTest, TheHostIsTheLastThingConsulted) {
    // Ordering is behaviour here, not taste. Every gate above the host check must
    // return its own reason even when the host would also have disqualified the run,
    // because that is what lets the caller skip reading the host's files entirely on a
    // run that was never going to print.
    auto ctx = wouldPrint();
    ctx.standardBuild = StandardBuildHere::No;
    ctx.quiet = true;
    EXPECT_EQ(decidePortableNotice(ctx), PortableNoticeDecision::SkipUnattended);
}

TEST(PortableNoticeTest, TheStandardBuildProducesNoNoticeWhateverTheHostIs) {
    // The function, not the policy: on the glibc build this must be empty on every host
    // in the world, and that is a claim about this binary that needs no fake host.
#if defined(__linux__) && !defined(LYXBOSA_LIBC_MUSL)
    EXPECT_TRUE(portableBuildNotice().empty())
        << "the standard build printed a portable-build notice";
#else
    GTEST_SKIP() << "this assertion is about the standard build";
#endif
}

TEST(PortableNoticeTest, TheWordingQuotesNoPercentage) {
    // The figure this sentence used to carry came from one tree on one machine and was
    // nearly four times the difference measured on the most realistic of the three
    // workloads since. A number compiled into a binary cannot be corrected without a
    // release, so this case is what stops one being written back in - and it runs in
    // every build and on every host, which the end-to-end case below cannot.
    const std::string notice = portableBuildNoticeFor("lyxbosa-linux-amd64");
    ASSERT_FALSE(notice.empty());
    EXPECT_FALSE(quotesAPercentage(notice)) << notice;

    // The positive control on the predicate itself, in both spellings. Without it a
    // find() that had been broken into always returning npos would pass this file.
    EXPECT_TRUE(quotesAPercentage("is about 10% faster on a scan"));
    EXPECT_TRUE(quotesAPercentage("is about 10 percent faster on a scan"));
}

TEST(PortableNoticeTest, TheWordingSaysFasterAndSaysItDepends) {
    // What has to survive an edit: the claim that stays true on a tree nobody has
    // measured. Faster, and by an amount that is a property of the work.
    const std::string notice = portableBuildNoticeFor("lyxbosa-linux-amd64");
    EXPECT_NE(notice.find("faster"), std::string::npos) << notice;
    EXPECT_NE(notice.find("depends"), std::string::npos) << notice;
}

TEST(PortableNoticeTest, TheWordingPromisesTheCadenceItActuallyKeeps) {
    // It said "This is said once." while being said once, which was accurate and was the
    // defect. What it may not do is promise once-ever while repeating: a sentence that
    // disagrees with the policy is worse than either behaviour on its own.
    const std::string notice = portableBuildNoticeFor("lyxbosa-linux-amd64");
    EXPECT_EQ(notice.find("This is said once"), std::string::npos)
        << "the sentence still promises once-ever: " << notice;
    EXPECT_NE(notice.find("month"), std::string::npos)
        << "the sentence does not say how often it comes back: " << notice;
}

TEST(PortableNoticeTest, TheWordingNamesTheStandardAssetAndNotThePortableOne) {
    // The same two claims the musl-only case below makes about the shipped binary, made
    // here where they are observable: every build, every host. The whole point of the
    // line is that the reader can act on it, and acting means fetching a named file.
    const std::string notice = portableBuildNoticeFor("lyxbosa-linux-arm64");
    EXPECT_NE(notice.find("lyxbosa-linux-arm64"), std::string::npos) << notice;
    EXPECT_EQ(notice.find("lyxbosa-linux-arm64-portable"), std::string::npos)
        << "the notice names the build the reader already has: " << notice;
}

TEST(PortableNoticeTest, TheSentenceNamesTheAssetToInstall) {
#if defined(__linux__) && defined(LYXBOSA_LIBC_MUSL)
    if (standardBuildHere() != StandardBuildHere::Yes) {
        GTEST_SKIP() << "this host has no standard build to name";
    }
    const std::string notice = portableBuildNotice();
    ASSERT_FALSE(notice.empty());
    // The whole point of the line is that the reader can act on it, and acting means
    // fetching a file whose name is in front of them.
    const std::string asset(platformAssetName());
    const std::string standard = asset.substr(0, asset.size() - std::strlen("-portable"));
    EXPECT_NE(notice.find(standard), std::string::npos) << notice;
    EXPECT_EQ(notice.find(asset), std::string::npos)
        << "the notice names the build the reader already has: " << notice;
#else
    GTEST_SKIP() << "only the portable build has this sentence";
#endif
}

// ---------------------------------------------------------------------------------------
// When it was last said survives a round trip through the state file.
// ---------------------------------------------------------------------------------------

TEST_F(FakeHost, TheTimeItWasSaidIsRememberedAndDoesNotDisturbTheRest) {
    const fs::path statePath = root_ / "update-check";

    UpdateState before;
    before.lastCheckEpoch = 1757500000;
    before.latestVersion = "2.4.0";
    ASSERT_TRUE(writeUpdateState(statePath, before));

    auto read = readUpdateState(statePath);
    ASSERT_TRUE(read.has_value());
    EXPECT_FALSE(read->portableNoticeEpoch.has_value())
        << "a state file that never said the line carried a time for it";
    EXPECT_FALSE(read->portableNoticeShownLegacy);

    ASSERT_TRUE(recordPortableNoticeShown(statePath, 1'757'600'000));
    read = readUpdateState(statePath);
    ASSERT_TRUE(read.has_value());
    ASSERT_TRUE(read->portableNoticeEpoch.has_value())
        << "the time it was said was not recorded, so it would be said on every scan";
    EXPECT_EQ(*read->portableNoticeEpoch, 1'757'600'000u);

    // A second run overwrites the time rather than keeping the first one, which is what
    // makes the interval run from the last saying and not from the first.
    ASSERT_TRUE(recordPortableNoticeShown(statePath, 1'760'000'000));
    read = readUpdateState(statePath);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(*read->portableNoticeEpoch, 1'760'000'000u);

    // The update check's own fields are what the notice must not damage: a scan that
    // says this line must not also forget when it last checked for a release.
    EXPECT_EQ(read->lastCheckEpoch, before.lastCheckEpoch);
    EXPECT_EQ(read->latestVersion, before.latestVersion);
}

TEST_F(FakeHost, AnUpgradedStateFileIsReadAsSaidWithNoWhen) {
    // The file an operator upgrading from a once-ever binary already has. It has to come
    // back as the legacy flag and NOT as a timestamp, because those two land on opposite
    // decisions: one stamps the clock silently, the other would be read as a time and
    // measured against the interval.
    const fs::path statePath = root_ / "upgraded";
    {
        std::ofstream out(statePath, std::ios::trunc);
        out << "last_check=1757500000\n"
            << "latest_version=2.4.0\n"
            << "portable_notice_shown=1\n";
    }
    const auto read = readUpdateState(statePath);
    ASSERT_TRUE(read.has_value());
    EXPECT_TRUE(read->portableNoticeShownLegacy);
    EXPECT_FALSE(read->portableNoticeEpoch.has_value())
        << "the old flag was read as a time, which it is not";
}

TEST_F(FakeHost, StampingAnUpgradedFileLeavesBothKeysAndBothReaders) {
    // What the upgrade run writes, and it is written for two readers. This version reads
    // the timestamp and stops consulting the flag; a binary rolled back to one that only
    // knows the flag still finds it and keeps its own once-ever contract rather than
    // re-announcing.
    const fs::path statePath = root_ / "upgraded-then-stamped";
    {
        std::ofstream out(statePath, std::ios::trunc);
        out << "last_check=1757500000\nportable_notice_shown=1\n";
    }
    ASSERT_TRUE(recordPortableNoticeShown(statePath, 1'757'600'000));

    const auto read = readUpdateState(statePath);
    ASSERT_TRUE(read.has_value());
    ASSERT_TRUE(read->portableNoticeEpoch.has_value());
    EXPECT_EQ(*read->portableNoticeEpoch, 1'757'600'000u);
    EXPECT_TRUE(read->portableNoticeShownLegacy);

    std::ifstream in(statePath);
    const std::string text{std::istreambuf_iterator<char>(in),
                           std::istreambuf_iterator<char>()};
    EXPECT_NE(text.find("portable_notice_epoch=1757600000"), std::string::npos) << text;
    EXPECT_NE(text.find("portable_notice_shown=1"), std::string::npos)
        << "an older binary reading this file would announce the line again: " << text;
}

TEST_F(FakeHost, AFreshStampWritesTheFlagAnOlderBinaryNeeds) {
    // The same thing on a file that never carried the flag: saying the line for the
    // first time still leaves the older key behind it.
    const fs::path statePath = root_ / "fresh";
    ASSERT_TRUE(recordPortableNoticeShown(statePath, 1'757'600'000));
    std::ifstream in(statePath);
    const std::string text{std::istreambuf_iterator<char>(in),
                           std::istreambuf_iterator<char>()};
    EXPECT_NE(text.find("portable_notice_shown=1"), std::string::npos) << text;
}

TEST_F(FakeHost, AnUpdateCheckDoesNotResetTheNoticesClock) {
    // The defect the cadence could not survive, and it was not in the cadence. Three
    // places recorded what an update check found by building a state from nothing and
    // writing it, which wrote their own two fields correctly and erased this timestamp -
    // so any scan, `update --check` or `update` whose check reached the network reset the
    // interval, and the line came back early. That is invisible from inside the notice:
    // every gate was right and the state it read was simply gone.
    const fs::path statePath = root_ / "update-check";
    ASSERT_TRUE(recordPortableNoticeShown(statePath, 1'757'600'000));

    ASSERT_TRUE(recordLatestVersion(statePath, 1'757'700'000, "2.4.0"));
    auto read = readUpdateState(statePath);
    ASSERT_TRUE(read.has_value());
    ASSERT_TRUE(read->portableNoticeEpoch.has_value())
        << "recording a version erased when the notice was last said";
    EXPECT_EQ(*read->portableNoticeEpoch, 1'757'600'000u)
        << "recording a version moved when the notice was last said";
    EXPECT_EQ(read->lastCheckEpoch, 1'757'700'000u);
    EXPECT_EQ(read->latestVersion, "2.4.0");

    // And the other direction, which already held and has to keep holding: saying the
    // line must not lose what the last check found.
    ASSERT_TRUE(recordPortableNoticeShown(statePath, 1'757'800'000));
    read = readUpdateState(statePath);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->lastCheckEpoch, 1'757'700'000u);
    EXPECT_EQ(read->latestVersion, "2.4.0");
    EXPECT_EQ(*read->portableNoticeEpoch, 1'757'800'000u);

    // The reservation is the third writer of the pair and was always a read-modify-write.
    // Asserted here anyway, because this case is about the file surviving every writer
    // and a green result from two of three is how the original defect went unnoticed.
    ASSERT_TRUE(reserveUpdateCheck(statePath, 1'757'900'000));
    read = readUpdateState(statePath);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(*read->portableNoticeEpoch, 1'757'800'000u);
    EXPECT_EQ(read->latestVersion, "2.4.0");
}

TEST_F(FakeHost, AnythingButTheWrittenValueMeansNotShown) {
    // The file is hand-editable and is read by older binaries too. Every way of being
    // unclear has to mean "not shown", which costs one extra line once.
    for (const char* line : {"portable_notice_shown=0", "portable_notice_shown=",
                             "portable_notice_shown=yes", "portable_notice_shown=true",
                             "portable_notice_shown"}) {
        const fs::path statePath = root_ / "hand-edited";
        {
            std::ofstream out(statePath, std::ios::trunc);
            out << "last_check=1757500000\n" << line << "\n";
        }
        const auto read = readUpdateState(statePath);
        ASSERT_TRUE(read.has_value()) << line;
        EXPECT_FALSE(read->portableNoticeShownLegacy) << line << " was read as shown";
    }
}

TEST_F(FakeHost, ATimestampThatDoesNotParseIsNoTimestamp) {
    // A truncated or hand-edited time must not come back as a number, and must not come
    // back as zero either - zero is 1970, which is an interval ago and would print. It
    // comes back absent, and a file that also carries the old flag falls through to the
    // upgrade path, which stamps a fresh time and says nothing.
    for (const char* line : {"portable_notice_epoch=", "portable_notice_epoch=soon",
                             "portable_notice_epoch=17576000x0",
                             "portable_notice_epoch=-1",
                             "portable_notice_epoch=999999999999999999999999"}) {
        const fs::path statePath = root_ / "bad-epoch";
        {
            std::ofstream out(statePath, std::ios::trunc);
            out << "last_check=1757500000\n" << line << "\nportable_notice_shown=1\n";
        }
        const auto read = readUpdateState(statePath);
        ASSERT_TRUE(read.has_value()) << line;
        EXPECT_FALSE(read->portableNoticeEpoch.has_value())
            << line << " was read as a time";
        EXPECT_TRUE(read->portableNoticeShownLegacy) << line;
    }
}
