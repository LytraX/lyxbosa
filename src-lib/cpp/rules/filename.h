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

}  // namespace lyxbosa::rules::filename
