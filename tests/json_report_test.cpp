// The JSON report: its frame, its layout and key order, its key rules, and what happens
// when a value cannot be written.
//
// WHY THE LITERAL BELOW IS WHAT IT IS
// -----------------------------------
// The report used to be written by hand, one stream insertion per quote, colon and comma,
// and is now written by nlohmann/json - streamed, because a scan can report on hundreds of
// thousands of files. The literal document in this file is what the hand-written writer at
// v3.0.0 produced for `everything()` below, captured by compiling that writer against the
// same function. It is compared as parsed data, key order included, and never as text: the
// layout is not part of what a report promises, and it changed when the indentation went.
//
// WHY THE SECOND CHECK REMOVES NEWLINES AND COMPARES
// --------------------------------------------------
// The one piece the library cannot write is the frame: the outer object and the `files`
// array, which stays open for the whole scan. The frame places each record on a line of its
// own, and those newlines are the only raw newlines in the document, because the library
// escapes every newline inside a string. So removing them must leave exactly the library's
// compact rendering of the whole document. A frame that dropped a comma fails to parse; one
// that added a space, misplaced a bracket or split a record over two lines parses and fails
// the comparison.

#include <gtest/gtest.h>

#include "infrastructure/PathUtils.h"
#include "infrastructure/report/JsonReportWriter.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <optional>

#include <sstream>
#include <string>
#include <vector>

using namespace lyxbosa;

namespace {

using Json = nlohmann::ordered_json;

// A plain finding: every key a record always carries, and none of the optional ones.
FileResult plainFinding() {
    FileResult file;
    file.path = "/var/www/site/shell.php";
    FileMatch match;
    match.ruleName = "eval base64 decode";
    match.category = "RCE001";
    match.severity = Severity::Critical;
    match.line = 3;
    match.column = 7;
    file.matches.push_back(match);
    return file;
}

// One result carrying every optional key somewhere, with counts that are not zero, so a
// key in the wrong place or a count written from the wrong field shows.
ScanResult everything() {
    ScanResult result;
    result.files.push_back(plainFinding());

    FileResult moved = plainFinding();
    moved.path = "/var/www/site/uploads/a \"quoted\" name\\x.php";
    moved.quarantined = true;
    moved.quarantinePath = "/var/quarantine/var/www/site/uploads/a \"quoted\" name\\x.php";
    FileMatch suppressed;
    suppressed.ruleName = "obfuscated eval";
    suppressed.category = "OBF003";
    suppressed.severity = Severity::Low;
    suppressed.originalSeverity = Severity::High;
    suppressed.suppressed = true;
    suppressed.line = 12;
    suppressed.column = 1;
    moved.matches.push_back(suppressed);
    result.files.push_back(moved);

    FileResult failed = plainFinding();
    failed.path = "/var/www/site/stuck.php";
    failed.quarantineFailed = true;
    result.files.push_back(failed);

    FileResult member;
    member.path = "/var/www/site/backup.zip!wp/shell.php";
    member.quarantinePath = "/var/quarantine/var/www/site/backup.zip!wp/shell.php";
    member.containerQuarantine = ContainerQuarantine::Moved;
    member.matches = plainFinding().matches;
    result.files.push_back(member);

    FileResult stuckMember;
    stuckMember.path = "/var/www/other/site.zip!shell.php";
    stuckMember.containerQuarantine = ContainerQuarantine::MoveFailed;
    stuckMember.matches = plainFinding().matches;
    result.files.push_back(stuckMember);

    FileResult skipped;
    skipped.path = "/var/www/site/huge.sql";
    skipped.skipReason = SkipReason::Size;
    result.files.push_back(skipped);

    result.totalFilesScanned = 1234;
    result.totalDirectoriesScanned = 56;
    result.filesWithMatches = 5;
    result.filesWithHostileNames = 1;
    result.skips.skip(SkipReason::Size, 2);
    result.skips.skip(SkipReason::Excluded, 3);
    result.skips.skip(SkipReason::Unreadable, 4);
    result.directoriesUnreadable = 7;
    result.entriesUnreadable = 30;
    result.directoriesCycleSkipped = 8;
    result.linksNotFollowed = 29;
    result.filesQuarantined = 2;
    result.filesQuarantineFailed = 1;
    result.rootsMissing = {"/var/www/gone", "/srv/also gone"};
    result.archives.archivesOpened = 9;
    result.archives.archivesUnreadable = 10;
    result.archives.archivesTruncated = 11;
    result.archives.membersScanned = 12;
    result.archives.bytesExpanded = 5000000000ULL;
    result.archives.skip(SkipReason::Policy, 13);
    result.archives.skip(SkipReason::Size, 14);
    result.archives.skip(SkipReason::Budget, 15);
    result.archives.skip(SkipReason::Ratio, 16);
    result.archives.skip(SkipReason::Depth, 17);
    result.archives.skip(SkipReason::Corrupt, 18);
    result.archives.skip(SkipReason::Excluded, 19);
    return result;
}

struct Streamed {
    std::string text;
    std::optional<std::string> failure;
    bool streamBad = false;
};

Streamed stream(const ScanResult& result, bool interrupted = false) {
    std::ostringstream out;
    JsonReportWriter writer(out);
    writer.begin();
    for (const auto& file : result.files) {
        writer.onFile(file);
    }
    writer.end(result, interrupted);
    return {out.str(), writer.failure(), out.bad()};
}

std::vector<std::string> keysOf(const Json& object) {
    std::vector<std::string> keys;
    for (auto it = object.begin(); it != object.end(); ++it) {
        keys.push_back(it.key());
    }
    return keys;
}

const char* const kEverything = R"JSON({
  "files": [
    {
      "path": "/var/www/site/shell.php",
      "skipped": false,
      "quarantined": false,
      "matches": [
        {
          "rule": "eval base64 decode",
          "severity": "critical",
          "category": "RCE001",
          "line": 3,
          "column": 7
        }
      ]
    },
    {
      "path": "/var/www/site/uploads/a \"quoted\" name\\x.php",
      "skipped": false,
      "quarantined": true,
      "quarantinePath": "/var/quarantine/var/www/site/uploads/a \"quoted\" name\\x.php",
      "matches": [
        {
          "rule": "eval base64 decode",
          "severity": "critical",
          "category": "RCE001",
          "line": 3,
          "column": 7
        },
        {
          "rule": "obfuscated eval",
          "severity": "low",
          "originalSeverity": "high",
          "suppressed": true,
          "category": "OBF003",
          "line": 12,
          "column": 1
        }
      ]
    },
    {
      "path": "/var/www/site/stuck.php",
      "skipped": false,
      "quarantined": false,
      "quarantineFailed": true,
      "matches": [
        {
          "rule": "eval base64 decode",
          "severity": "critical",
          "category": "RCE001",
          "line": 3,
          "column": 7
        }
      ]
    },
    {
      "path": "/var/www/site/backup.zip!wp/shell.php",
      "skipped": false,
      "quarantined": false,
      "quarantinePath": "/var/quarantine/var/www/site/backup.zip!wp/shell.php",
      "containerQuarantine": "moved",
      "matches": [
        {
          "rule": "eval base64 decode",
          "severity": "critical",
          "category": "RCE001",
          "line": 3,
          "column": 7
        }
      ]
    },
    {
      "path": "/var/www/other/site.zip!shell.php",
      "skipped": false,
      "quarantined": false,
      "containerQuarantine": "moveFailed",
      "matches": [
        {
          "rule": "eval base64 decode",
          "severity": "critical",
          "category": "RCE001",
          "line": 3,
          "column": 7
        }
      ]
    },
    {
      "path": "/var/www/site/huge.sql",
      "skipped": true,
      "skipReason": "size",
      "quarantined": false,
      "matches": []
    }
  ],
  "interrupted": false,
  "totalFilesScanned": 1234,
  "totalDirectoriesScanned": 56,
  "filesWithMatches": 5,
  "filesWithHostileNames": 1,
  "filesSkippedSize": 2,
  "filesSkipped": {
    "total": 9,
    "size": 2,
    "excluded": 3,
    "unreadable": 4
  },
  "directoriesUnreadable": 7,
  "entriesUnreadable": 30,
  "directoriesCycleSkipped": 8,
  "linksNotFollowed": 29,
  "filesQuarantined": 2,
  "filesQuarantineFailed": 1,
  "rootsMissing": [
    "/var/www/gone",
    "/srv/also gone"
  ],
  "archives": {
    "opened": 9,
    "unreadable": 10,
    "stoppedEarly": 11,
    "membersScanned": 12,
    "bytesExpanded": 5000000000,
    "membersSkipped": {
      "policy": 13,
      "size": 14,
      "budget": 15,
      "ratio": 16,
      "depth": 17,
      "corrupt": 18,
      "excluded": 19
    }
  },
  "durationMs": 0
}
)JSON";

}  // namespace

// ===========================================================================
// Layout, key order and the frame
// ===========================================================================

TEST(JsonReportTest, TheDataAndKeyOrderAreThoseOfTheWriterItReplaced) {
    const Streamed got = stream(everything());
    ASSERT_FALSE(got.failure) << *got.failure;
    // ordered_json compares objects member by member in order, so this pins key order as
    // well as every key and value - and nothing about whitespace.
    EXPECT_EQ(Json::parse(got.text), Json::parse(kEverything)) << got.text;
}

TEST(JsonReportTest, TheStreamedDocumentIsTheLibrarysOwnRendering) {
    ScanResult onlySkipped;
    FileResult skipped;
    skipped.path = "/var/www/huge.sql";
    skipped.skipReason = SkipReason::Unreadable;
    onlySkipped.files.push_back(skipped);

    ScanResult onlyMissingRoots;
    onlyMissingRoots.rootsMissing = {"/a", "/b", "/c"};

    ScanResult many;
    for (int i = 0; i < 50; ++i) {
        FileResult file = plainFinding();
        file.path = "/var/www/site/f" + std::to_string(i) + ".php";
        many.files.push_back(file);
    }

    const std::vector<std::pair<const char*, ScanResult>> cases = {
        {"no files", ScanResult{}},
        {"every optional key", everything()},
        {"one skipped file", onlySkipped},
        {"missing roots and no files", onlyMissingRoots},
        {"fifty files", many},
    };
    for (const auto& [name, result] : cases) {
        for (const bool interrupted : {false, true}) {
            const Streamed got = stream(result, interrupted);
            ASSERT_FALSE(got.failure) << name;
            ASSERT_TRUE(Json::accept(got.text)) << name << "\n" << got.text;
            const Json parsed = Json::parse(got.text);
            std::string withoutFrameNewlines = got.text;
            std::erase(withoutFrameNewlines, '\n');
            EXPECT_EQ(parsed.dump(), withoutFrameNewlines) << name;
            EXPECT_EQ(got.text.back(), '\n') << name;
            // One line to open, one per record, one to close; a single line when empty.
            const size_t records = parsed["files"].size();
            EXPECT_EQ(static_cast<size_t>(std::count(got.text.begin(), got.text.end(), '\n')),
                      records == 0 ? 1u : records + 2)
                << name << "\n" << got.text;
        }
    }
}

// Each record is on the stream, flushed, when onFile returns - not held until end(). A
// scan that reports on four hundred thousand files does not hold four hundred thousand
// records, and one that is killed leaves every record it had already found on disk.
TEST(JsonReportTest, EachRecordIsWrittenWhenItArrives) {
    std::ostringstream out;
    JsonReportWriter writer(out);
    writer.begin();
    EXPECT_EQ(out.str(), "{\"files\":[");

    FileResult first = plainFinding();
    writer.onFile(first);
    const std::string afterOne = out.str();
    EXPECT_NE(afterOne.find("\"/var/www/site/shell.php\""), std::string::npos) << afterOne;
    EXPECT_EQ(afterOne.back(), '}') << "the record is complete and nothing follows it yet";

    FileResult second = plainFinding();
    second.path = "/var/www/site/second.php";
    writer.onFile(second);
    const std::string afterTwo = out.str();
    ASSERT_EQ(afterTwo.compare(0, afterOne.size(), afterOne), 0)
        << "a record already written is never rewritten";
    EXPECT_EQ(afterTwo.substr(afterOne.size(), 2), ",\n");

    // A file with nothing to say is not a record.
    FileResult clean;
    clean.path = "/var/www/site/clean.php";
    writer.onFile(clean);
    EXPECT_EQ(out.str(), afterTwo);
}

// ===========================================================================
// The key rules
// ===========================================================================

// Absent rather than null or false when there is nothing to say, and nothing more than
// the keys every record carries.
TEST(JsonReportTest, AnOrdinaryFindingCarriesOnlyTheKeysEveryRecordCarries) {
    ScanResult result;
    result.files.push_back(plainFinding());
    const Json doc = Json::parse(stream(result).text);

    const Json& record = doc.at("files").at(0);
    EXPECT_EQ(keysOf(record),
              (std::vector<std::string>{"path", "skipped", "quarantined", "matches"}));
    EXPECT_EQ(keysOf(record.at("matches").at(0)),
              (std::vector<std::string>{"rule", "severity", "category", "line", "column"}));
}

// Every summary count is present at zero, and in this order; `archives` alone is absent
// when no archive was opened.
TEST(JsonReportTest, EverySummaryCountIsPresentAtZeroAndArchivesIsNot) {
    const Json doc = Json::parse(stream(ScanResult{}).text);
    EXPECT_EQ(keysOf(doc), (std::vector<std::string>{
                               "files", "interrupted", "totalFilesScanned",
                               "totalDirectoriesScanned", "filesWithMatches",
                               "filesWithHostileNames", "filesSkippedSize", "filesSkipped",
                               "directoriesUnreadable", "entriesUnreadable",
                               "directoriesCycleSkipped", "linksNotFollowed",
                               "filesQuarantined", "filesQuarantineFailed", "rootsMissing",
                               "durationMs"}));
    for (const auto* key : {"totalFilesScanned", "totalDirectoriesScanned", "filesWithMatches",
                            "filesWithHostileNames", "filesSkippedSize",
                            "directoriesUnreadable", "entriesUnreadable",
                            "directoriesCycleSkipped", "linksNotFollowed", "filesQuarantined",
                            "filesQuarantineFailed"}) {
        ASSERT_TRUE(doc.contains(key)) << key;
        EXPECT_TRUE(doc.at(key).is_number_unsigned()) << key;
        EXPECT_EQ(doc.at(key), 0) << key;
    }
    EXPECT_EQ(keysOf(doc.at("filesSkipped")),
              (std::vector<std::string>{"total", "size", "excluded", "unreadable"}));
    EXPECT_TRUE(doc.at("rootsMissing").is_array());
    EXPECT_TRUE(doc.at("rootsMissing").empty());
    EXPECT_TRUE(doc.at("files").is_array());

    // The companion: one archive opened, and the key is there with every count.
    ScanResult withArchive;
    withArchive.archives.archivesOpened = 1;
    const Json opened = Json::parse(stream(withArchive).text);
    ASSERT_TRUE(opened.contains("archives"));
    EXPECT_EQ(keysOf(opened.at("archives")),
              (std::vector<std::string>{"opened", "unreadable", "stoppedEarly",
                                        "membersScanned", "bytesExpanded", "membersSkipped"}));
    EXPECT_EQ(keysOf(opened.at("archives").at("membersSkipped")),
              (std::vector<std::string>{"policy", "size", "budget", "ratio", "depth",
                                        "corrupt", "excluded"}));
    for (const auto& [key, count] : opened.at("archives").at("membersSkipped").items()) {
        EXPECT_EQ(count, 0) << key;
    }
}

// Each optional key, present when and only when it has something to say, and never with a
// value that merely restates absence.
TEST(JsonReportTest, EachOptionalKeyIsPresentOnlyWhenItHasSomethingToSay) {
    const Json doc = Json::parse(stream(everything()).text);
    const Json& files = doc.at("files");

    // quarantined, with its destination
    EXPECT_EQ(files.at(1).at("quarantined"), true);
    EXPECT_TRUE(files.at(1).contains("quarantinePath"));
    EXPECT_FALSE(files.at(1).contains("quarantineFailed"));
    EXPECT_FALSE(files.at(1).contains("quarantinePathBytesHex"));

    // a failed move: `quarantineFailed` only ever true, and no destination
    EXPECT_EQ(files.at(2).at("quarantineFailed"), true);
    EXPECT_FALSE(files.at(2).contains("quarantinePath"));
    EXPECT_FALSE(files.at(0).contains("quarantineFailed"));

    // suppression: both keys together, and `suppressed` only ever true
    const Json& suppressed = files.at(1).at("matches").at(1);
    EXPECT_EQ(suppressed.at("suppressed"), true);
    EXPECT_EQ(suppressed.at("originalSeverity"), "high");
    EXPECT_FALSE(files.at(1).at("matches").at(0).contains("suppressed"));
    EXPECT_FALSE(files.at(1).at("matches").at(0).contains("originalSeverity"));

    // a container's outcome, as a string, on members only
    EXPECT_EQ(files.at(3).at("containerQuarantine"), "moved");
    EXPECT_EQ(files.at(4).at("containerQuarantine"), "moveFailed");
    EXPECT_FALSE(files.at(0).contains("containerQuarantine"));

    // a skip: `skipped` always, `skipReason` only with one, and `matches` still an array
    EXPECT_EQ(files.at(5).at("skipped"), true);
    EXPECT_EQ(files.at(5).at("skipReason"), "size");
    EXPECT_TRUE(files.at(5).at("matches").is_array());
    EXPECT_FALSE(files.at(0).contains("skipReason"));

    // exact paths carry no hex
    for (const auto& file : files) {
        EXPECT_FALSE(file.contains("pathBytesHex"));
    }
}

#ifndef _WIN32
// A name that is not valid UTF-8 is rendered with escapes and its bytes travel in hex, so
// the report is written in full. The companion to the refusal below: the refusal is for a
// value that did not go through that rendering, not for every hostile byte.
TEST(JsonReportTest, APathThatIsNotUtf8IsRenderedAndCarriedInHex) {
    ScanResult result;
    FileResult file = plainFinding();
    file.path = std::string("/var/www/a\xff\xc0\xaf" "b.php");
    file.quarantined = true;
    file.quarantinePath = std::string("/var/quarantine/var/www/a\xff\xc0\xaf" "b.php");
    result.files.push_back(file);

    const Streamed got = stream(result);
    ASSERT_FALSE(got.failure) << *got.failure;
    EXPECT_FALSE(got.streamBad);
    ASSERT_TRUE(Json::accept(got.text)) << got.text;
    const Json record = Json::parse(got.text).at("files").at(0);
    EXPECT_EQ(record.at("pathBytesHex"), pathBytesHex(file.path));
    EXPECT_EQ(record.at("quarantinePathBytesHex"), pathBytesHex(file.quarantinePath));
    EXPECT_EQ(keysOf(record), (std::vector<std::string>{
                                  "path", "pathBytesHex", "skipped", "quarantined",
                                  "quarantinePath", "quarantinePathBytesHex", "matches"}));
}
#endif

// ===========================================================================
// A value that cannot be written
// ===========================================================================

// A rule's name and category are not rendered the way a path is. The loader refuses a
// configuration whose rule is not plain text, so this is the writer's own refusal, for a rule
// set built without it - the same question every writer asks, see ReportWriter.h. The writer
// must not let that escape into the scan, must not write half a record, and must leave a
// document no parser takes for complete - while saying why, and marking the stream.
TEST(JsonReportTest, AValueThatIsNotUtf8StopsTheReportWithoutThrowing) {
    for (const bool inCategory : {false, true}) {
        std::ostringstream out;
        JsonReportWriter writer(out);
        writer.begin();
        writer.onFile(plainFinding());
        const std::string beforeRefusal = out.str();

        FileResult bad = plainFinding();
        bad.path = "/var/www/site/bad.php";
        (inCategory ? bad.matches[0].category : bad.matches[0].ruleName) = "Probe\xff";
        EXPECT_NO_THROW(writer.onFile(bad));

        EXPECT_EQ(out.str(), beforeRefusal) << "no part of the refused record is written";
        ASSERT_TRUE(writer.failure().has_value());
        EXPECT_NE(writer.failure()->find("/var/www/site/bad.php"), std::string::npos)
            << *writer.failure();
        EXPECT_NE(writer.failure()->find("is not valid UTF-8 (byte 0xff at offset 5)"),
                  std::string::npos)
            << *writer.failure();
        EXPECT_TRUE(out.bad()) << "a caller holding only the stream must see it too";

        // Nothing after it is written either - not a later good record, not the frame.
        FileResult later = plainFinding();
        later.path = "/var/www/site/later.php";
        EXPECT_NO_THROW(writer.onFile(later));
        ScanResult result;
        EXPECT_NO_THROW(writer.end(result, false));
        EXPECT_EQ(out.str(), beforeRefusal);
        EXPECT_FALSE(Json::accept(out.str()))
            << "an incomplete report must not parse as a complete one";
    }
}

// The companion: the same record with a name that is valid UTF-8 and not ASCII is written, the
// stream stays good and the document is whole. The name is Greek, spelled as bytes so that the
// compiler's reading of the source encoding cannot change it.
TEST(JsonReportTest, TheSameRecordWithAValidNameIsWrittenInFull) {
    ScanResult result;
    FileResult good = plainFinding();
    good.matches[0].ruleName = "\xce\x94\xce\xbf\xce\xba\xce\xb9\xce\xbc\xce\xae";
    good.matches[0].category = "\xce\xba\xce\xb1\xcf\x84\xce\xb7\xce\xb3\xce\xbf\xcf\x81\xce\xaf\xce\xb1";
    result.files.push_back(good);

    const Streamed got = stream(result);
    EXPECT_FALSE(got.failure);
    EXPECT_FALSE(got.streamBad);
    ASSERT_TRUE(Json::accept(got.text));
    EXPECT_EQ(Json::parse(got.text).at("files").at(0).at("matches").at(0).at("rule"), "\xce\x94\xce\xbf\xce\xba\xce\xb9\xce\xbc\xce\xae");
}
