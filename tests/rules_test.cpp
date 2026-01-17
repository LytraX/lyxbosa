#include <gtest/gtest.h>
#include "rules/Registry.hpp"
#include "config/Types.h"

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
    auto* rule = getRuleByCode("RCE003");
    ASSERT_NE(rule, nullptr);

    EXPECT_TRUE(rule->matches("$func($_POST['code']);"));
    EXPECT_TRUE(rule->matches("$handler($_GET['x']);"));
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
