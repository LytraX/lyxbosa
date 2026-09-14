#pragma once

// filename.h - Rules about a file's name rather than its bytes.
//
// Every other rule in this directory answers "what is inside this file". These six
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
// Six rules and not one, because these are six intentions with six different next
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

inline constexpr size_t RULE_COUNT = 6;
const BuiltinRule* const* getAllRules();

// One hostile shape found in a name.
struct NameFinding {
    std::string_view code;  // "FN001" ... "FN006"

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
// Pure, so that a test can drive it over thousands of names without a filesystem. The
// order of the result is FN001 first through FN006 last, so a report row order does
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

// What separates the components of a stored member name.
enum class MemberSeparators {
    Slash,              // a tar member, and a zip entry written by any host but the three below
    SlashAndBackslash,  // a zip entry written by MS-DOS, Windows NTFS or VFAT
};

// The final component of a member name as an archive stores it, split by what the WRITER of
// that entry meant - never by the platform the scan runs on.
//
// finalComponent() splits on a backslash under _WIN32 because NTFS cannot hold one in a name,
// which is a fact about the disk the scan is reading and says nothing about bytes in an
// archive. Asked of a member, it would answer the same entry two ways by platform.
//
// A zip records its writer per entry, in the host byte of "version made by", and that decides
// it. Windows PowerShell 5.1's Compress-Archive and .NET Framework's
// ZipFile.CreateFromDirectory store `site\wp-content\index.php` under host byte 0 (MS-DOS),
// meaning a directory. Read as one name, every member below the top of a site backup made
// that way raised FN002, and a planted `-rf.htaccess` under it was not seen to start with a
// dash. So an entry from MS-DOS, NTFS or VFAT is split on both, as Info-ZIP's unzip splits it
// when it extracts. Every other writer, and every tar header, gets `/` alone: a zip made on
// Unix holding `a\zz-<id>.php` is extracted by PHP's ZipArchive, 7-Zip and Python's zipfile on
// Linux as ONE file with a backslash in its name, which is the case FN002 exists for.
//
// The host byte is the writer's claim, as everything in an archive is. What it buys an
// attacker is the reading every Windows extractor gives the same entry, and it cannot hide a
// hostile final component: only what stands before the last backslash is set aside. Nor does
// it follow the machine an archive was made on. PHP's ZipArchive writes host byte 3 (Unix) on
// Windows too, so a PHP backup made there with backslash paths still raises FN002 on its
// nested members.
std::string_view memberFinalComponent(std::string_view storedName, MemberSeparators separators);

}  // namespace lyxbosa::rules::filename
