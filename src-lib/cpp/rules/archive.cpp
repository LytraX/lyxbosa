#include "archive.h"
#include <array>

namespace lyxbosa::rules::archive {

// The ARC rules are structural, not textual. They are raised by the archive
// scanner from an archive's entry list - no pattern can express "this file is a
// copy of the site, and the copy is downloadable" - so they carry no patterns
// and the match engine never runs them against file content. They live in the
// registry anyway so that they are named, described and disabled exactly like
// every other rule: builtin_rules.disable: [ARC001] has to mean something.

// ARC001: an archive holding credentials or a database dump.
//
// For the operator the correct output is "delete this, it is exposing your
// database password", not "here are three shells inside it". Anyone who guesses
// the URL gets the site's source and, with wp-config.php or .env, its live
// database credentials - which are usually the same credentials the site uses
// from its own network.
const BuiltinRule ARC001 {
    .code = {Category::Archive, 1},
    .name = "Exposed site backup",
    .description = "Archive in the scanned tree contains credential files or a database dump",
    .severity = Severity::Critical,
    .patterns = {},
};

// ARC002: an archive holding executable source but no credentials found.
//
// Still a source disclosure, still worth deleting, but it does not hand over the
// database, so it is not critical.
const BuiltinRule ARC002 {
    .code = {Category::Archive, 2},
    .name = "Exposed source archive",
    .description = "Archive in the scanned tree contains executable source code",
    .severity = Severity::High,
    .patterns = {},
};

// ARC003: the archive could not be read.
//
// Not a detection, an admission - but a silent one is worse. A truncated,
// encrypted or deliberately malformed archive is exactly where something would
// be hidden if the scanner were known to give up quietly on them.
const BuiltinRule ARC003 {
    .code = {Category::Archive, 3},
    .name = "Unreadable archive",
    .description = "Archive could not be parsed and its contents were not scanned",
    .severity = Severity::Low,
    .patterns = {},
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &ARC001, &ARC002, &ARC003
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::archive
