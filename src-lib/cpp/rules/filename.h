#pragma once

// filename.h - Rules about a file's name rather than its bytes.
//
// Every other rule in this directory answers "what is inside this file". These seven
// answer "what is this file called", and that is a different question with its own
// evidence: on a compromised host the name is sometimes the attack. A file called
// `x$(sleep 20)y.mdb` is evidence whatever is inside it - somebody uploaded a command
// substitution hoping that something downstream would pass the name to a shell.
//
// Where the line is, and how it was drawn. These rules were not designed against
// imagination. 22,728 files an automated vulnerability scanner left in an upload
// directory on a production server were measured by name. A character set containing
// double quote, dollar, backtick, semicolon, pipe, backslash, any byte below 0x20, a
// leading dash, a dot-dot, a literal percent-zero-zero and the fullwidth solidus fires
// on 83 of those files, and every one of the 83 is the scanner's: precision 100%.
// Adding the apostrophe and the ampersand takes it to 175 files, of which 89 are
// ordinary customer uploads, and precision falls to 49%. Apostrophes and ampersands
// are what real file names contain - `O'Brien & Sons Invoice.pdf` - so they are not in
// any rule here, and a rule that wants either must require it in combination with
// something else and show the combination silent on an ordinary name.
//
// What is implemented is *tighter* than that measured set in two places, at no cost to
// recall - all 83 still fire:
//
//   - A bare `$` is not enough. FN001 wants `$(`, a backtick or `${`. `~$Quarterly
//     Report.docx` is the lock file Word and Excel write beside an open document, and
//     a rule that fires on it fires in every office document tree there is. No
//     observed name needs a bare `$` to be caught.
//   - A bare `..` is not enough. FN005 wants a dot-dot *beside a separator that is not
//     a separator*. `photo_2_final..jpg` is a doubled extension dot and is the only
//     name in 268,853 real files that a bare dot-dot rule fired on.
//
// FN007 was drawn a different way, because what it catches does its harm without a shell:
// a name that climbs out of the directory it is extracted into. Its shapes were measured
// against the extractors that write members to disk, and the rule's own comment in
// filename.cpp says which of them follow each shape.
//
// Seven rules and not one, because these are seven intentions with seven different next
// questions for an operator, and because a single rule cannot be turned off one shape
// at a time: a tree of Makefile fragments has a reason to disable FN004 and none to
// disable FN001.

#include "RuleDefinition.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace lyxbosa::rules::filename {

extern const BuiltinRule FN001;
extern const BuiltinRule FN002;
extern const BuiltinRule FN003;
extern const BuiltinRule FN004;
extern const BuiltinRule FN005;
extern const BuiltinRule FN006;
extern const BuiltinRule FN007;

inline constexpr size_t RULE_COUNT = 7;
const BuiltinRule* const* getAllRules();

// One hostile shape found in a name.
struct NameFinding {
    std::string_view code;  // "FN001" ... "FN007"

    // What fired, named by construct rather than by echoing the payload: the whole
    // name is already in the row's `path` field, and repeating it here would put the
    // attacker's bytes in a second place for no second piece of information. Already
    // escaped for output - it can carry a byte from the name (the control byte FN003
    // names, for one), and every consumer of this string prints it.
    std::string detail;
};

// The hostile shapes in one file's name. `name` is the final path component, spelled
// in UTF-8, exactly as it is on disk - see finalComponent() for how to get one.
//
// FN007 reads the same component whole, splitting it on `/` and on `\` alike. On POSIX a
// name can hold a backslash, and a file named `..\..\index.php` is, to the backup that
// copies it and the Windows extractor that unpacks that backup, a name that climbs; on
// Windows no name can hold a separator and FN007 has nothing to read.
//
// Pure, so that a test can drive it over thousands of names without a filesystem. The
// order of the result is FN001 first through FN007 last, so a report row order does
// not depend on how the name happened to be spelled.
std::vector<NameFinding> examine(std::string_view name);

// The final path component of a path already spelled in UTF-8.
//
// Splits on `/` everywhere and on `\` under _WIN32 only. That is the same rule, and
// for the same reason, as MatchEngine::filterPath(): Windows forbids a backslash
// inside a path component, so there it is always a separator and the split is exact;
// POSIX permits one, so there it is a character in a name and splitting on it would be
// a guess. The guess runs in the attacker's favour - one of the 83 observed names is
// `a\zz-<id>.php`, and a POSIX split on backslash would take the name to `zz-<id>.php`
// and hand FN002 a clean file.
std::string_view finalComponent(std::string_view pathUtf8);

// What separates the components of a stored member name, for FN001 to FN006.
enum class MemberSeparators {
    Slash,              // a tar member, and a zip entry neither reading below applies to
    SlashAndBackslash,  // a zip entry written by MS-DOS, Windows NTFS or VFAT, and every entry
                        // of a zip whose names use only backslashes (see ArchiveIndex.h)
};

// The final component of a member name as an archive stores it, split by what the WRITER of
// that entry meant - never by the platform the scan runs on.
//
// finalComponent() splits on a backslash under _WIN32 because NTFS cannot hold one in a name,
// which is a fact about the disk the scan is reading and says nothing about bytes in an
// archive. Asked of a member, it would answer the same entry two ways by platform.
//
// Two readings split on both, and nothing else does.
//
// The writer's host byte. Windows PowerShell 5.1's Compress-Archive and .NET Framework's
// ZipFile.CreateFromDirectory store `site\wp-content\index.php` under host byte 0 (MS-DOS),
// meaning a directory. Read as one name, every member below the top of a site backup made
// that way raised FN002, and a planted `-rf.htaccess` under it was not seen to start with a
// dash. So an entry whose host byte is MS-DOS (0), Windows NTFS (10) or VFAT (14) is split on
// both. What the extractors do with such an entry was measured, and it is not one answer:
// every Windows extractor - PHP's ZipArchive, PclZip, Expand-Archive, bsdtar, Python -
// splits a backslash whatever the host byte, and on Linux only Info-ZIP's unzip splits one,
// only under host byte 0 and only in a name holding no `/`. PHP's ZipArchive, PclZip, 7-Zip
// and Python keep it as a character under every host byte.
//
// The archive's own names. PHP's ZipArchive writes host byte 3 (Unix) on Windows too, and a
// PHP backup made there spells every path with backslashes, so by its host byte every member
// below the top raised FN002 and its planted leading-dash name was missed. Nothing in such an
// archive but its names says a Windows host wrote it - the fields were compared byte for byte
// against the same backup made on Linux - so the names decide: a zip whose names use a
// backslash wherever they hold a separator is split on both. ZipReader applies it, per
// archive, and ArchiveIndex.h defines it.
//
// Every other zip entry, and every tar header, gets `/` alone: a zip made on Unix holding
// `uploads/a\zz-<id>.php` beside forward-slash names is extracted on Linux as ONE file with a
// backslash in its name, which is the case FN002 exists for.
//
// Either reading is the writer's claim, as everything in an archive is. What it buys an
// attacker is the reading every Windows extractor gives the same entry, and it cannot hide a
// hostile final component - only what stands before the last backslash is set aside - nor a
// name that climbs, which FN007 reads from the whole stored name under both splits. It grants
// no suppression either: no reading of a member name makes a backslash a directory for a
// location prior or an include or exclude pattern.
std::string_view memberFinalComponent(std::string_view storedName, MemberSeparators separators);

// The hostile shapes in one member's stored name: FN001 to FN006 read its final component,
// split by `separators`, exactly as examine() reads a file's; FN007 reads the whole stored
// name, split on `/` and on `\` whatever `separators` says. A member named
// `uploads/..\..\index.php` climbs on Windows from an archive read either way, and one read as
// backslash-separated is precisely the archive in which it does.
std::vector<NameFinding> examineMember(std::string_view storedName, MemberSeparators separators);

}  // namespace lyxbosa::rules::filename
