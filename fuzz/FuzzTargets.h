#pragma once

// FuzzTargets.h - the bodies of the fuzz targets, in a header because two very
// different programs run them.
//
// libFuzzer runs them under clang with AddressSanitizer and UndefinedBehaviorSanitizer,
// in a container, for as long as somebody is willing to wait. tests/fuzz_replay_test.cpp
// runs them under the ordinary gcc build, over a fixed set of files, in a couple of
// seconds, every time anybody types `ctest`. If the two ran different code the regression
// would not be a regression: it would be a second harness that happens to resemble the
// first, and the input that used to crash would be replayed through something that was
// never crashing.
//
// WHAT THE TARGETS ARE AIMED AT
//
// Every byte this scanner reads was chosen by somebody who already owns the host. The
// two entry points below are where the chosen bytes meet code that parses rather than
// searches:
//
//   runArchiveTarget  - ArchiveScanner::scan() with the bytes in memory, which is libzip
//                       on a hostile central directory, zlib on a hostile deflate stream,
//                       this project's tar reader on hostile headers, and the recursion
//                       between them.
//   runContentTarget  - MatchEngine::match(), which is RE2 over the bytes plus the PHP
//                       constant folder that resolves identifiers a file assembles at
//                       run time.
//
// THE KIND IS SNIFFED, NOT SELECTED
//
// The archive target decides what the input is with archive::sniff(), exactly as
// Scanner does, rather than taking a format selector from the first byte of the input.
// That costs the fuzzer some reach - it has to keep the magic intact to stay inside a
// parser - and buys the property that matters: every crash this finds is a crash that
// can be reached by putting a file on a host and running a scan. A selector byte would
// let the fuzzer feed headerless bytes to the tar reader and report a defect nothing can
// trigger.
//
// THE GUARDS ARE AT THEIR DEFAULTS
//
// maxDepth 2, maxMemberSize 5 MB, maxExpansion 256 MB, maxRatio 100, timeBudget 60 s -
// whatever config/Rules.h says today, read from a default-constructed ArchiveConfig so
// this cannot drift from the shipped default. Turning a guard off is documented as the
// operator's to do and its consequences are theirs; a hang found with maxExpansion at 0
// is the documented consequence of asking for it, and a hang found with the guards on is
// a defect. So the harness must not quietly pick its own numbers.

#include "archive/ArchiveFormat.h"
#include "archive/ArchiveScanner.h"
#include "archive/ArchiveTypes.h"
#include "config/Rules.h"
#include "core/MatchEngine.h"
#include "core/ScanResult.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace lyxbosa::fuzz {

// The rule set, compiled once. Building it is the single most expensive thing either
// target does - every RE2 program plus the literal prefilter - and a fuzzer that paid it
// per input would spend its whole budget in the constructor.
inline const MatchEngine& engine() {
    static const MatchEngine* const instance = [] {
        auto* engine = new MatchEngine();
        engine->loadAllBuiltinRules();
        return engine;
    }();
    return *instance;
}

// The shipped defaults, held by value at namespace scope because ArchiveScanner keeps a
// reference to its config rather than a copy: a temporary here would dangle for the
// whole scan.
inline const ArchiveConfig& archiveDefaults() {
    static const ArchiveConfig config{};
    return config;
}

inline const ScanConfig& scanDefaults() {
    static const ScanConfig config{};
    return config;
}

// What the target observed, so a caller can assert on it. The fuzzer ignores it; the
// replay test uses it to prove the input actually reached the parser rather than being
// turned away by sniff() - a regression corpus that no longer enters the code under test
// passes silently, which is the failure mode this whole round exists to avoid.
struct Observation {
    archive::Kind kind = archive::Kind::None;
    bool handled = false;
    size_t membersScanned = 0;
    size_t findings = 0;
};

inline Observation runArchiveTarget(const uint8_t* data, size_t size) {
    Observation seen;
    if (data == nullptr || size == 0) {
        return seen;
    }

    const std::string_view bytes(reinterpret_cast<const char*>(data), size);

    // Exactly what Scanner does with a file it has already read: ask the bytes what they
    // are, and hand them over only if they are a container.
    seen.kind = archive::sniff(bytes);
    if (seen.kind == archive::Kind::None) {
        return seen;
    }

    archive::ArchiveScanner scanner(archiveDefaults(), scanDefaults(), engine());

    // The findings callback is wired up rather than left empty. It is not there to
    // collect results - it is there so the report side runs: the matched text and the
    // surrounding context of a finding are attacker-controlled bytes that get escaped
    // for display, and a harness with no callback never builds one.
    size_t findings = 0;
    volatile size_t sink = 0;
    scanner.setFindingCallback([&](const std::filesystem::path& display, uint64_t bytesLen,
                                   std::vector<FileMatch>&& matches) {
        findings += matches.size();
        sink += display.native().size() + static_cast<size_t>(bytesLen & 0xff);
        for (const auto& match : matches) {
            sink += match.matchedText.size() + match.context.size() + match.ruleName.size();
        }
    });

    // The member path is a container-supplied string that becomes a display path. The
    // progress callback is where it is first handled, so it is wired up too.
    scanner.setProgressCallback([&](const archive::MemberProgress& progress) {
        sink += progress.member.size() + progress.archive.size();
    });

    // The path is never opened: `scan` reads from the buffer whenever the buffer is
    // non-empty, and opens the path only when it is empty. A name is still passed
    // because gzipMemberName() derives the reported member name from it.
    const auto outcome = scanner.scan("fuzz-input.bin", seen.kind, bytes);

    seen.handled = outcome.handled;
    seen.membersScanned = outcome.stats.membersScanned;
    seen.findings = findings + outcome.archiveMatches.size();
    return seen;
}

inline Observation runContentTarget(const uint8_t* data, size_t size) {
    Observation seen;
    if (data == nullptr || size == 0) {
        return seen;
    }

    const std::string_view bytes(reinterpret_cast<const char*>(data), size);

    // A .php name rather than a neutral one: the location-aware and extension-aware
    // rules are the ones that reach the constant folder, and a name the rule set treats
    // as uninteresting would leave most of the engine unentered.
    const auto matches = engine().match(bytes, "wp-content/uploads/fuzz-input.php");

    volatile size_t sink = 0;
    for (const auto& match : matches) {
        sink += match.matchedText.size() + match.context.size() + match.offset;
    }

    seen.handled = true;
    seen.findings = matches.size();
    return seen;
}

}  // namespace lyxbosa::fuzz
