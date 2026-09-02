#pragma once

// ArchiveIndex.h - What an archive's entry list says, before anything is opened.
//
// Two questions are answered here, both from names alone:
//
//   1. Is this a site backup or a payload? (section 1 of the plan)
//      >= 20 PHP entries, any credential file, or any .sql dump means backup. A
//      .sql dump is the strongest single signal - nothing legitimate ships one
//      inside a deployment archive, and one real site backup held 110 of them.
//
//   2. Which member is worth the budget first? (section 4)
//      On a real production site of 24,351 files, the PHP living under
//      upload/cache/tmp-like paths was 5.6% of the bytes; all code was 55.7%.
//      Triaging by path recovers 94% of the work, triaging by extension 44%.
//
// Both accumulate one name at a time, because a zip hands over its whole index at
// once and a tar only ever produces the next name.

#include "ArchiveTypes.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace lyxbosa::archive {

// Priority order for spending the budget. Sequential extraction spends it on
// whatever happens to be at the front of the archive, which on a site backup is
// usually a directory of images.
enum class Bucket {
    HotScript = 0,   // executable script in a directory that is otherwise media
    Script = 1,      // any other executable script
    Markup = 2,      // js / html / css / svg
    Other = 3        // everything else - exhaustive mode only
};

// Normalise a member name for comparison: forward slashes, no "./" prefix, no
// leading slash. Display sanitising happens later and separately.
std::string normalizeMemberName(std::string_view raw);

// Entries the container carries about the other entries rather than about the
// site: the __MACOSX sidecar tree a Mac writes into every zip, its AppleDouble
// "._name" stubs, and .DS_Store. They are neither code nor content, and a
// "._index.php" is a binary resource fork wearing a PHP extension - 1,499 of
// them in one real theme's bundled plugin zips, every one of which trips the
// binary-payload rule if it is read as source.
bool isContainerMetadata(std::string_view normalizedName);

bool isScriptName(std::string_view name);
bool isMarkupName(std::string_view name);
bool isMediaName(std::string_view name);

// Path-based bucket. Knows nothing about the rest of the archive, so it is what
// a streamed tar gets; a zip refines HotScript from the whole index.
Bucket classifyMember(std::string_view normalizedName);

// Accumulated evidence about what an archive holds.
struct IndexSummary {
    size_t entries = 0;
    size_t phpEntries = 0;      // .php / .phtml / .inc, exactly as measured
    size_t sqlDumps = 0;
    std::vector<std::string> credentials;   // path-qualified hits, capped
    std::vector<std::string> platformHits;  // one per marker seen, with repeats

    void observe(std::string_view rawName);

    // Credentials or a database dump: what makes an exposed archive a takeover
    // rather than a disclosure.
    bool exposesSecrets() const { return !credentials.empty() || sqlDumps > 0; }

    // Is this a copy of a *site*?
    //
    // Section 1 said ">= 20 PHP entries, or a credential file, or a .sql dump".
    // The PHP count alone does not survive contact with a real tree: three vendor
    // plugin bundles in one WordPress theme - js_composer.zip (435 PHP),
    // revslider.zip (290), data.zip (110) - clear that threshold and expose
    // nothing at all, because they are public plugin code anyone can download.
    // A PHP count measures size, not exposure.
    //
    // What separates them from a backup is that a backup is a copy of an
    // installed site: it carries the platform's distribution files, or its
    // credentials, or its database. Every real backup measured has all three;
    // those three bundles have none.
    bool siteBackup() const {
        return exposesSecrets() ||
               (phpEntries >= kBackupPhpEntries && !platform().empty());
    }

    // "" when nothing recognisable was seen. Only ever used to word the finding -
    // an unrecognised platform still produces it.
    std::string platform() const;

    static constexpr size_t kBackupPhpEntries = 20;
    static constexpr size_t kMaxCredentialsListed = 8;
};

}  // namespace lyxbosa::archive
