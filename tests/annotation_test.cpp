// In-file annotations: what a file may say about its own findings, and when it is believed.
//
// THE DEFECT
// ----------
// `<?php $x = "FilesMan"; echo $x; // nolint` was reported by `check` as [LOW], and the
// same line without the comment as [CRITICAL], in the release build and the debug build
// alike. MatchEngine looked for twelve markers - `// nolint`, `# noqa`, `phpcs:ignore`,
// `// eslint-disable`, `@SuppressWarnings` ... - on the matched line and the line before
// it, by plain substring, and on a hit rewrote the severity to Low. The exit code survived
// and the finding was still printed; the severity is what a quarantine threshold, an
// alerting rule or a report filter reads, and the attacker wrote the comment as surely as
// the shell. Because the marker was a substring, `$y = "// nolint";` on the line did the
// same, and so did `@SuppressWarnings` inside any string; the previous-line rule doubled
// the surface.
//
// THE DECISION, pinned here
// -------------------------
// An annotation is an instruction inside the file being judged, and whether to obey it
// turns on who wrote the file - which the bytes cannot say. A developer scanning their own
// repository wrote it beside a known false positive; an incident responder scanning a web
// root is reading the attacker's file. Only the operator knows which, so the operator says:
// `annotations.trust: true`, off by default. Without trust no marker moves any finding of
// any rule. With trust every marker works as before, for every rule, signatures included -
// a security plugin shipping a signature table is a real file a real developer annotates.
//
// WHAT EACH BLOCK CHECKS
// ----------------------
//   The marker finder as a pure function: every marker, on the line and on the line
//     before, not two lines before, not when absent; the list is as long as it was; and
//     its substring nature is stated as the trade it is.
//   The repro, dead by default: every marker, both placements, the annotated and the
//     plain shell get the SAME severity - not merely the same exit code - and nothing is
//     marked suppressed. A heuristic and a custom YAML rule are held to the same answer.
//   The feature, kept under trust: every marker, both placements, suppressed at Low with
//     the original severity beside it and still reported; the plain shell untouched; a
//     marker out of reach grants nothing; a signature, a heuristic and a custom rule alike.
//   The configuration: the generated default parses to false, an absent block is false,
//     both spellings parse and validate, `true` is warned about and `false` is not.
//   On disk through Scanner::scanFile the way `check` reads, under the default
//     configuration and under trust - loose files and members of a zip, because the
//     archive scanner shares the engine and a member is as attacker-written as a file.

#include <gtest/gtest.h>

#include "config/Config.h"
#include "core/MatchEngine.h"
#include "core/Scanner.h"
#include "rules/Registry.hpp"

#include <zip.h>

#include <cctype>
#include <filesystem>
#include <fstream>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace lyxbosa;

namespace {

namespace fs = std::filesystem;

// The repro's line, byte for byte.
constexpr std::string_view kShellLine = "$x = \"FilesMan\"; echo $x;";

// A block marker is closed so the file is a plausible annotation rather than an open
// comment; the engine reads bytes either way.
std::string annotation(std::string_view marker) {
    std::string s(marker);
    if (s.rfind("/*", 0) == 0) s += " */";
    return s;
}

std::string plainShell() { return "<?php " + std::string(kShellLine) + "\n"; }
std::string markerOnTheLine(std::string_view marker) {
    return "<?php " + std::string(kShellLine) + " " + annotation(marker) + "\n";
}
std::string markerOnTheLineBefore(std::string_view marker) {
    return "<?php " + annotation(marker) + "\n" + std::string(kShellLine) + "\n";
}
std::string markerTwoLinesAbove(std::string_view marker) {
    return "<?php " + annotation(marker) + "\n$y = 1;\n" + std::string(kShellLine) + "\n";
}

// OBF002: a heuristic, and one with no location prior at "x/y.php". Four chained chr()
// calls whose values are not an ascending run - the same fixture the location tests use.
constexpr std::string_view kChrLine = "$f = chr(112) . chr(104) . chr(112) . chr(95) . chr(117);";

// A custom YAML rule: a token nothing built in matches, at High.
RuleConfig customRule() {
    RuleConfig rc;
    rc.name = "custom token";
    rc.severity = Severity::High;
    rc.category = "custom";
    PatternConfig pc;
    pc.type = PatternType::String;
    pc.value = "qzv_custom_token";
    rc.patterns.push_back(pc);
    return rc;
}
constexpr std::string_view kCustomLine = "$t = 'qzv_custom_token';";

// A gtest-safe name for a marker.
std::string ident(std::string_view marker) {
    std::string out;
    for (size_t i = 0; i < marker.size(); ++i) {
        const char c = marker[i];
        if (std::isalnum(static_cast<unsigned char>(c))) out.push_back(c);
        else if (c == '/' && i + 1 < marker.size() && marker[i + 1] == '/') { out += "Slash"; ++i; }
        else if (c == '/' && i + 1 < marker.size() && marker[i + 1] == '*') { out += "Block"; ++i; }
        else if (c == '#') out += "Hash";
        else if (c == '@') out += "At";
        else if (c == ':') out += "_";
        else if (c == '-') out += "_";
    }
    return out;
}

std::optional<FileMatch> matchFor(const MatchEngine& engine, std::string_view rule,
                                  std::string_view content) {
    for (const auto& m : engine.match(content, "x/y.php")) {
        if (m.category == rule) return m;
    }
    return std::nullopt;
}

Severity builtinSeverity(std::string_view code) {
    const auto* rule = rules::getRuleByCode(code);
    EXPECT_NE(rule, nullptr) << code;
    return rule ? rule->severity : Severity::Low;
}

class AnnotationFixture : public ::testing::Test {
protected:
    MatchEngine engine;
    void SetUp() override {
        engine.loadAllBuiltinRules();
        engine.loadRules({customRule()});
    }
};

}  // namespace

// ===========================================================================
// The marker finder - a pure function
// ===========================================================================

class AnnotationMarkerTest : public ::testing::TestWithParam<std::string_view> {};

TEST_P(AnnotationMarkerTest, IsFoundOnTheLineAndOnTheLineBeforeAndNowhereFurther) {
    const std::string_view marker = GetParam();
    const auto offsetOf = [](const std::string& s) {
        const size_t off = s.find("FilesMan");
        EXPECT_NE(off, std::string::npos);
        return off;
    };

    const std::string same = markerOnTheLine(marker);
    ASSERT_TRUE(MatchEngine::annotationNear(same, offsetOf(same))) << marker << " on the line";
    EXPECT_EQ(*MatchEngine::annotationNear(same, offsetOf(same)), marker);

    const std::string before = markerOnTheLineBefore(marker);
    ASSERT_TRUE(MatchEngine::annotationNear(before, offsetOf(before))) << marker << " on the line before";
    EXPECT_EQ(*MatchEngine::annotationNear(before, offsetOf(before)), marker);

    const std::string above = markerTwoLinesAbove(marker);
    EXPECT_FALSE(MatchEngine::annotationNear(above, offsetOf(above)))
        << marker << " two lines above is out of reach";

    const std::string none = plainShell();
    EXPECT_FALSE(MatchEngine::annotationNear(none, offsetOf(none)));
}

INSTANTIATE_TEST_SUITE_P(EveryMarker, AnnotationMarkerTest,
                         ::testing::ValuesIn(MatchEngine::annotationMarkers().begin(),
                                             MatchEngine::annotationMarkers().end()),
                         [](const ::testing::TestParamInfo<std::string_view>& info) {
                             return ident(info.param);
                         });

TEST(AnnotationMarkerListTest, TheListIsAsLongAsItWas) {
    // Twelve markers were honoured before the default changed. A shorter list here means a
    // marker stopped being covered by every parameterised case below.
    EXPECT_EQ(MatchEngine::annotationMarkers().size(), 12u);
}

// Stated trade, not an aspiration: the finder is a substring search and does not lex
// comments. A string literal holding the bytes is found; a variable named after a marker
// whose spelling carries its delimiter is not, because the delimiter is part of the
// marker. This is acceptable only because the engine consults the finder only under
// trust, where the author of the string literal is the person being trusted.
TEST(AnnotationMarkerListTest, StatedTrade_AStringLiteralHoldingTheBytesIsFoundByTheFinder) {
    const std::string literal = "<?php $x = \"FilesMan\"; $y = \"// nolint\"; echo $x;\n";
    EXPECT_TRUE(MatchEngine::annotationNear(literal, literal.find("FilesMan")));

    const std::string bare = "<?php $x = \"FilesMan\"; $y = \"@SuppressWarnings\"; echo $x;\n";
    EXPECT_TRUE(MatchEngine::annotationNear(bare, bare.find("FilesMan")))
        << "a marker with no comment delimiter of its own is any occurrence of the word";

    const std::string variable = "<?php $x = \"FilesMan\"; $nolint = 1; echo $x;\n";
    EXPECT_FALSE(MatchEngine::annotationNear(variable, variable.find("FilesMan")))
        << "`// nolint` includes its delimiter, so a variable named nolint is not it";

    const std::string encoded = "<?php $x = \"FilesMan\"; $y = base64_decode(\"Ly8gbm9saW50\");\n";
    EXPECT_FALSE(MatchEngine::annotationNear(encoded, encoded.find("FilesMan")))
        << "the bytes have to be present; an encoding of them is not them";
}

// ===========================================================================
// The repro, dead by default
// ===========================================================================

class AnnotationDefaultTest : public AnnotationFixture,
                              public ::testing::WithParamInterface<std::string_view> {};

TEST_P(AnnotationDefaultTest, WS006_TheAnnotatedAndThePlainShellGetTheSameSeverity) {
    const std::string_view marker = GetParam();
    ASSERT_FALSE(engine.trustsAnnotations()) << "the engine's default is the decision";

    const auto plain = matchFor(engine, "WS006", plainShell());
    ASSERT_TRUE(plain);
    ASSERT_EQ(plain->severity, Severity::Critical);

    for (const std::string& content : {markerOnTheLine(marker), markerOnTheLineBefore(marker)}) {
        const auto m = matchFor(engine, "WS006", content);
        ASSERT_TRUE(m) << "the finding itself must survive: " << content;
        EXPECT_EQ(m->severity, plain->severity)
            << "a Critical signature was lowered by " << marker << " in: " << content;
        EXPECT_FALSE(m->suppressed) << marker;
        EXPECT_EQ(m->originalSeverity, Severity::Critical) << marker;
    }
}

// The rule kind is not the gate: a heuristic and a custom rule are held to the same answer.
TEST_P(AnnotationDefaultTest, AHeuristicAndACustomRuleAreNotLoweredEither) {
    const std::string_view marker = GetParam();
    const Severity chr = builtinSeverity("OBF002");

    for (const std::string& content : {
             "<?php\n" + std::string(kChrLine) + " " + annotation(marker) + "\n",
             "<?php\n" + annotation(marker) + "\n" + std::string(kChrLine) + "\n",
         }) {
        const auto m = matchFor(engine, "OBF002", content);
        ASSERT_TRUE(m) << content;
        EXPECT_EQ(m->severity, chr) << marker << " lowered OBF002 in: " << content;
        EXPECT_FALSE(m->suppressed) << marker;
    }
    for (const std::string& content : {
             "<?php\n" + std::string(kCustomLine) + " " + annotation(marker) + "\n",
             "<?php\n" + annotation(marker) + "\n" + std::string(kCustomLine) + "\n",
         }) {
        const auto m = matchFor(engine, "custom", content);
        ASSERT_TRUE(m) << content;
        EXPECT_EQ(m->severity, Severity::High) << marker << " lowered a custom rule in: " << content;
        EXPECT_FALSE(m->suppressed) << marker;
    }
}

INSTANTIATE_TEST_SUITE_P(EveryMarker, AnnotationDefaultTest,
                         ::testing::ValuesIn(MatchEngine::annotationMarkers().begin(),
                                             MatchEngine::annotationMarkers().end()),
                         [](const ::testing::TestParamInfo<std::string_view>& info) {
                             return ident(info.param);
                         });

// The string-literal and encoded shapes, without trust: nothing, whatever the finder says.
TEST_F(AnnotationFixture, WithoutTrustNoShapeOfMarkerLowersAnything) {
    for (const char* content : {
             "<?php $x = \"FilesMan\"; $y = \"// nolint\"; echo $x;\n",
             "<?php $x = \"FilesMan\"; $y = \"@SuppressWarnings\"; echo $x;\n",
             "<?php $x = \"FilesMan\"; $y = \"phpcs:ignore\"; echo $x;\n",
             "<?php // nolint\n$x = \"FilesMan\"; echo $x;\n",
         }) {
        const auto m = matchFor(engine, "WS006", content);
        ASSERT_TRUE(m) << content;
        EXPECT_EQ(m->severity, Severity::Critical) << content;
        EXPECT_FALSE(m->suppressed) << content;
    }
}

// ===========================================================================
// The feature, kept under trust
// ===========================================================================

class AnnotationTrustTest : public AnnotationFixture,
                            public ::testing::WithParamInterface<std::string_view> {
protected:
    void SetUp() override {
        AnnotationFixture::SetUp();
        engine.setTrustAnnotations(true);
    }
};

TEST_P(AnnotationTrustTest, EveryMarkerLowersASignatureOnTheLineAndTheLineBefore) {
    const std::string_view marker = GetParam();
    ASSERT_TRUE(engine.trustsAnnotations());

    for (const std::string& content : {markerOnTheLine(marker), markerOnTheLineBefore(marker)}) {
        const auto m = matchFor(engine, "WS006", content);
        ASSERT_TRUE(m) << "a suppressed finding is still a finding: " << content;
        EXPECT_TRUE(m->suppressed) << marker << " was not honoured in: " << content;
        EXPECT_EQ(m->severity, Severity::Low) << marker;
        EXPECT_EQ(m->originalSeverity, Severity::Critical)
            << marker << " - the original severity travels with the finding";
    }
}

TEST_P(AnnotationTrustTest, EveryMarkerLowersAHeuristicAndACustomRule) {
    const std::string_view marker = GetParam();
    const Severity chr = builtinSeverity("OBF002");

    for (const std::string& content : {
             "<?php\n" + std::string(kChrLine) + " " + annotation(marker) + "\n",
             "<?php\n" + annotation(marker) + "\n" + std::string(kChrLine) + "\n",
         }) {
        const auto m = matchFor(engine, "OBF002", content);
        ASSERT_TRUE(m) << content;
        EXPECT_TRUE(m->suppressed) << marker << " in: " << content;
        EXPECT_EQ(m->severity, Severity::Low) << marker;
        EXPECT_EQ(m->originalSeverity, chr) << marker;
    }
    for (const std::string& content : {
             "<?php\n" + std::string(kCustomLine) + " " + annotation(marker) + "\n",
             "<?php\n" + annotation(marker) + "\n" + std::string(kCustomLine) + "\n",
         }) {
        const auto m = matchFor(engine, "custom", content);
        ASSERT_TRUE(m) << content;
        EXPECT_TRUE(m->suppressed) << marker << " in: " << content;
        EXPECT_EQ(m->severity, Severity::Low) << marker;
        EXPECT_EQ(m->originalSeverity, Severity::High) << marker;
    }
}

TEST_P(AnnotationTrustTest, AMarkerTwoLinesAboveDoesNotReach) {
    const std::string_view marker = GetParam();
    const auto m = matchFor(engine, "WS006", markerTwoLinesAbove(marker));
    ASSERT_TRUE(m);
    EXPECT_FALSE(m->suppressed) << marker << " reached across an intervening line";
    EXPECT_EQ(m->severity, Severity::Critical);
}

INSTANTIATE_TEST_SUITE_P(EveryMarker, AnnotationTrustTest,
                         ::testing::ValuesIn(MatchEngine::annotationMarkers().begin(),
                                             MatchEngine::annotationMarkers().end()),
                         [](const ::testing::TestParamInfo<std::string_view>& info) {
                             return ident(info.param);
                         });

TEST_F(AnnotationFixture, UnderTrustTheUnannotatedShellIsUntouched) {
    engine.setTrustAnnotations(true);
    const auto m = matchFor(engine, "WS006", plainShell());
    ASSERT_TRUE(m);
    EXPECT_FALSE(m->suppressed);
    EXPECT_EQ(m->severity, Severity::Critical)
        << "trust changes what a marker may do, not what an unmarked line is";
}

// Under trust the finder's substring nature reaches the engine: the trade, pinned so a
// later tightening is a deliberate change and not a drift.
TEST_F(AnnotationFixture, StatedTrade_UnderTrustAStringLiteralHoldingAMarkerLowersTheFinding) {
    engine.setTrustAnnotations(true);
    const auto m = matchFor(engine, "WS006",
                            "<?php $x = \"FilesMan\"; $y = \"// nolint\"; echo $x;\n");
    ASSERT_TRUE(m);
    EXPECT_TRUE(m->suppressed);
    EXPECT_EQ(m->severity, Severity::Low);
}

// ===========================================================================
// The configuration
// ===========================================================================

TEST(AnnotationConfigTest, TheGeneratedDefaultSaysSoAndParsesToFalse) {
    const std::string yaml = Config::generateDefault();
    EXPECT_NE(yaml.find("\nannotations:\n"), std::string::npos)
        << "the block is in the generated file so an operator can find the switch";
    EXPECT_NE(yaml.find("  trust: false"), std::string::npos);
    EXPECT_FALSE(Config::loadFromString(yaml).annotations.trust);
}

TEST(AnnotationConfigTest, AnAbsentBlockIsFalse) {
    EXPECT_FALSE(Config::loadFromString("version: 1\n").annotations.trust)
        << "an existing configuration with no annotations: block gets the compiled-in default";
}

TEST(AnnotationConfigTest, BothSettingsParseAndValidate) {
    const auto on = Config::loadFromString("version: 1\nannotations:\n  trust: true\n");
    EXPECT_TRUE(on.annotations.trust);
    EXPECT_EQ(Config::validate(on), "");

    const auto off = Config::loadFromString("version: 1\nannotations:\n  trust: false\n");
    EXPECT_FALSE(off.annotations.trust);
    EXPECT_EQ(Config::validate(off), "");
}

TEST(AnnotationConfigTest, TrustIsWarnedAboutAndItsAbsenceIsNot) {
    const auto mentions = [](const AppConfig& config) {
        size_t n = 0;
        for (const auto& w : Config::warnings(config)) {
            if (w.find("annotations.trust") != std::string::npos) ++n;
        }
        return n;
    };
    AppConfig config = Config::loadFromString(Config::generateDefault());
    EXPECT_EQ(mentions(config), 0u) << "the default is not a warning";
    config.annotations.trust = true;
    EXPECT_EQ(mentions(config), 1u) << "a scan that trusts the files says so before it starts";
}

// ===========================================================================
// On disk, the way `check` reads
// ===========================================================================

namespace {

class AnnotationOnDiskTest : public ::testing::Test {
protected:
    fs::path root;

    void SetUp() override {
        root = fs::temp_directory_path() /
               ("lyxbosa-annotation-" + std::to_string(std::random_device{}()));
        fs::create_directories(root);
    }
    void TearDown() override {
        std::error_code ec;
        fs::remove_all(root, ec);
    }

    fs::path write(std::string_view relative, const std::string& content) {
        const fs::path file = root / std::string(relative);
        fs::create_directories(file.parent_path());
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        EXPECT_TRUE(out.good()) << "could not write " << file;
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        return file;
    }

    // Members are added from buffers `members` keeps alive: libzip does not copy them
    // until the archive is written out.
    fs::path writeZip(std::string_view relative,
                      const std::vector<std::pair<std::string, std::string>>& members) {
        const fs::path file = root / std::string(relative);
        fs::create_directories(file.parent_path());
        int err = 0;
        zip_t* za = zip_open(file.string().c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
        EXPECT_NE(za, nullptr) << "zip_open error " << err;
        for (const auto& [name, body] : members) {
            zip_source_t* source = zip_source_buffer(za, body.data(), body.size(), 0);
            EXPECT_NE(source, nullptr);
            EXPECT_GE(zip_file_add(za, name.c_str(), source, ZIP_FL_OVERWRITE), 0);
        }
        EXPECT_EQ(zip_close(za), 0);
        return file;
    }

    static AppConfig configTrusting(bool trust) {
        AppConfig config = Config::loadFromString(Config::generateDefault());
        config.actions.quarantine.enabled = false;
        config.annotations.trust = trust;
        return config;
    }

    // The WS006 match of a loose file, read through Scanner::scanFile like `check`.
    static std::optional<FileMatch> ws006(const AppConfig& config, const fs::path& file) {
        Scanner scanner(config);
        const FileResult result = scanner.scanFile(file);
        EXPECT_FALSE(result.skipped()) << file << " was not read";
        for (const auto& m : result.matches) {
            if (m.category == "WS006") return m;
        }
        return std::nullopt;
    }

    // The WS006 matches of a zip's members, by member name, collected the way `check`
    // collects them.
    static std::vector<std::pair<std::string, FileMatch>> ws006InZip(const AppConfig& config,
                                                                     const fs::path& zip) {
        std::vector<std::pair<std::string, FileMatch>> out;
        Scanner scanner(config);
        scanner.setFileResultCallback([&out](const FileResult& member) {
            for (const auto& m : member.matches) {
                if (m.category == "WS006") out.emplace_back(member.path.string(), m);
            }
        });
        scanner.scanFile(zip);
        return out;
    }
};

}  // namespace

TEST_F(AnnotationOnDiskTest, TheReproIsDeadUnderTheDefaultConfiguration) {
    const fs::path plain = write("plain.php", plainShell());
    const fs::path annotated = write("annotated.php", markerOnTheLine("// nolint"));
    const fs::path before = write("before.php", markerOnTheLineBefore("// nolint"));

    const AppConfig config = configTrusting(false);
    ASSERT_FALSE(Config::loadFromString(Config::generateDefault()).annotations.trust);

    const auto p = ws006(config, plain);
    const auto a = ws006(config, annotated);
    const auto b = ws006(config, before);
    ASSERT_TRUE(p && a && b);
    EXPECT_EQ(p->severity, Severity::Critical);
    EXPECT_EQ(a->severity, p->severity) << "the annotated shell read differently from the plain one";
    EXPECT_EQ(b->severity, p->severity) << "the shell under a marker line read differently";
    EXPECT_FALSE(a->suppressed);
    EXPECT_FALSE(b->suppressed);
}

TEST_F(AnnotationOnDiskTest, UnderTrustTheAnnotationIsHonouredAndThePlainShellIsNot) {
    const fs::path plain = write("plain.php", plainShell());
    const fs::path annotated = write("annotated.php", markerOnTheLine("phpcs:ignore"));
    const fs::path before = write("before.php", markerOnTheLineBefore("# noqa"));

    const AppConfig config = configTrusting(true);
    const auto p = ws006(config, plain);
    const auto a = ws006(config, annotated);
    const auto b = ws006(config, before);
    ASSERT_TRUE(p && a && b);
    EXPECT_EQ(p->severity, Severity::Critical);
    EXPECT_FALSE(p->suppressed);
    for (const auto& m : {a, b}) {
        EXPECT_TRUE(m->suppressed);
        EXPECT_EQ(m->severity, Severity::Low);
        EXPECT_EQ(m->originalSeverity, Severity::Critical);
    }
}

TEST_F(AnnotationOnDiskTest, AMemberOfAZipIsHeldToTheSameAnswer) {
    const fs::path zip = writeZip("site/backup.zip", {
        {"wp-content/uploads/plain.php", plainShell()},
        {"wp-content/uploads/annotated.php", markerOnTheLine("// eslint-disable")},
        {"wp-content/uploads/before.php", markerOnTheLineBefore("// NOSONAR")},
    });

    const auto byDefault = ws006InZip(configTrusting(false), zip);
    ASSERT_EQ(byDefault.size(), 3u) << "every member must be read and matched";
    for (const auto& [name, m] : byDefault) {
        EXPECT_EQ(m.severity, Severity::Critical) << name;
        EXPECT_FALSE(m.suppressed) << name;
    }

    const auto underTrust = ws006InZip(configTrusting(true), zip);
    ASSERT_EQ(underTrust.size(), 3u);
    size_t lowered = 0;
    for (const auto& [name, m] : underTrust) {
        if (name.find("plain.php") != std::string::npos) {
            EXPECT_FALSE(m.suppressed) << name;
            EXPECT_EQ(m.severity, Severity::Critical) << name;
        } else {
            EXPECT_TRUE(m.suppressed) << name;
            EXPECT_EQ(m.severity, Severity::Low) << name;
            EXPECT_EQ(m.originalSeverity, Severity::Critical) << name;
            ++lowered;
        }
    }
    EXPECT_EQ(lowered, 2u);
}
