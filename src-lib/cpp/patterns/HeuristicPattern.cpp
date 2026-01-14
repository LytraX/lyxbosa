#include "HeuristicPattern.h"
#include <re2/re2.h>
#include <fmt/core.h>
#include <algorithm>
#include <cctype>

namespace lyxbosa {

HeuristicPattern::HeuristicPattern(HeuristicType heuristicType,
                                   size_t minOccurrences,
                                   size_t minStringLength)
    : heuristicType_(heuristicType)
    , minOccurrences_(minOccurrences)
    , minStringLength_(minStringLength) {
}

std::string_view HeuristicPattern::pattern() const {
    if (patternDesc_.empty()) {
        patternDesc_ = std::string(heuristicTypeToString(heuristicType_));
    }
    return patternDesc_;
}

std::vector<PatternMatch> HeuristicPattern::match(std::string_view content) const {
    switch (heuristicType_) {
        case HeuristicType::MultipleBase64Concat:
            return detectMultipleBase64Concat(content);
        case HeuristicType::StrReplaceFunctionBuild:
            return detectStrReplaceFunctionBuild(content);
        case HeuristicType::VariableFunctionCall:
            return detectVariableFunctionCall(content);
        case HeuristicType::HexEncodedFunctions:
            return detectHexEncodedFunctions(content);
        case HeuristicType::GotoObfuscation:
            return detectGotoObfuscation(content);
        case HeuristicType::LongEncodedStrings:
            return detectLongEncodedStrings(content);
        case HeuristicType::EvalWithVariable:
            return detectEvalWithVariable(content);
        case HeuristicType::CreateFunctionEval:
            return detectCreateFunctionEval(content);
        case HeuristicType::ArrayIndexStringBuild:
            return detectArrayIndexStringBuild(content);
        case HeuristicType::CredentialHarvester:
            return detectCredentialHarvester(content);
    }
    return {};
}

bool HeuristicPattern::isBase64Char(char c) {
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '+' || c == '/' || c == '=';
}

bool HeuristicPattern::isHexChar(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

bool HeuristicPattern::looksLikeBase64(std::string_view s) {
    if (s.length() < 20) return false;

    size_t base64Chars = 0;
    for (char c : s) {
        if (isBase64Char(c)) ++base64Chars;
    }

    // At least 80% should be base64 characters
    return base64Chars >= s.length() * 0.8;
}

bool HeuristicPattern::looksLikeHex(std::string_view s) {
    if (s.length() < 20 || s.length() % 2 != 0) return false;

    for (char c : s) {
        if (!isHexChar(c)) return false;
    }
    return true;
}

// Check if a hex string decodes to readable ASCII (like function names)
// This helps distinguish between:
//   - '7068705f756e616d65' -> 'php_uname' (suspicious - function name)
//   - '454e8a3cffdca128c277' -> garbage (probably a hash/version)
bool HeuristicPattern::hexDecodesToReadableAscii(std::string_view hexStr) {
    if (hexStr.length() < 10 || hexStr.length() % 2 != 0) return false;

    size_t readableChars = 0;
    size_t totalChars = hexStr.length() / 2;

    for (size_t i = 0; i + 1 < hexStr.length(); i += 2) {
        // Convert two hex chars to a byte
        auto hexToByte = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return -1;
        };

        int high = hexToByte(hexStr[i]);
        int low = hexToByte(hexStr[i + 1]);
        if (high < 0 || low < 0) return false;

        unsigned char byte = static_cast<unsigned char>((high << 4) | low);

        // Check if it's a printable ASCII character (function names use a-z, A-Z, 0-9, _)
        if ((byte >= 'a' && byte <= 'z') ||
            (byte >= 'A' && byte <= 'Z') ||
            (byte >= '0' && byte <= '9') ||
            byte == '_') {
            ++readableChars;
        }
    }

    // At least 80% of decoded bytes should be readable identifier characters
    return readableChars >= totalChars * 0.8;
}

// Detect multiple variables containing base64-like strings that are concatenated
std::vector<PatternMatch> HeuristicPattern::detectMultipleBase64Concat(std::string_view content) const {
    std::vector<PatternMatch> matches;

    // Pattern: $var = "base64string"; repeated multiple times, then concatenated
    // Look for multiple assignments of long base64-like strings
    RE2 pattern(R"(\$\w+\s*=\s*["']([A-Za-z0-9+/=]{50,})["'])");

    re2::StringPiece input(content.data(), content.size());
    re2::StringPiece matchStr;
    size_t count = 0;
    size_t firstOffset = std::string::npos;

    size_t searchStart = 0;
    while (searchStart < content.size()) {
        re2::StringPiece remaining(content.data() + searchStart, content.size() - searchStart);

        if (!RE2::PartialMatch(remaining, pattern, &matchStr)) {
            break;
        }

        size_t offset = searchStart + (matchStr.data() - remaining.data());

        if (firstOffset == std::string::npos) {
            firstOffset = offset;
        }

        ++count;
        searchStart = offset + std::max(size_t(1), matchStr.size());
    }

    // If we found multiple base64 variable assignments, it's suspicious
    if (count >= minOccurrences_ && firstOffset != std::string::npos) {
        PatternMatch m;
        m.offset = firstOffset;
        auto [line, column] = computeLineColumn(content, firstOffset);
        m.line = line;
        m.column = column;
        m.matchedText = fmt::format("{} base64 variable assignments", count);
        m.context = extractContext(content, firstOffset, 50);
        matches.push_back(std::move(m));
    }

    return matches;
}

// Detect str_replace used to build function names (obfuscation)
std::vector<PatternMatch> HeuristicPattern::detectStrReplaceFunctionBuild(std::string_view content) const {
    std::vector<PatternMatch> matches;

    // Pattern: str_replace with results that look like obfuscated function names
    // e.g., str_replace("x", "", "xbxaxsxe64_decode") or str_replace("ob","","obcobreobaobtobe")
    RE2 pattern(R"(str_replace\s*\(\s*["'][^"']+["']\s*,\s*["']["']\s*,\s*["']([^"']+)["']\s*\))");

    re2::StringPiece input(content.data(), content.size());
    re2::StringPiece matchStr;
    re2::StringPiece obfuscatedStr;

    size_t searchStart = 0;
    while (searchStart < content.size()) {
        re2::StringPiece remaining(content.data() + searchStart, content.size() - searchStart);

        if (!RE2::PartialMatch(remaining, pattern, &obfuscatedStr)) {
            break;
        }

        size_t offset = searchStart + (obfuscatedStr.data() - remaining.data() - obfuscatedStr.size());

        // Check if the obfuscated string looks like it could be a function name
        std::string decoded(obfuscatedStr.data(), obfuscatedStr.size());
        // Remove alternating characters to see if it forms a recognizable pattern
        bool suspicious = decoded.length() > 15;  // Obfuscated strings are typically longer

        if (suspicious) {
            PatternMatch m;
            m.offset = offset;
            auto [line, column] = computeLineColumn(content, offset);
            m.line = line;
            m.column = column;
            m.matchedText = std::string(obfuscatedStr.data(), obfuscatedStr.size());
            m.context = extractContext(content, offset, 80);
            matches.push_back(std::move(m));
        }

        searchStart = offset + 1;
    }

    return matches;
}

// Detect variable function calls: $var() or $$var() patterns
std::vector<PatternMatch> HeuristicPattern::detectVariableFunctionCall(std::string_view content) const {
    std::vector<PatternMatch> matches;

    // Pattern: $variable() - dynamic function call
    RE2 pattern(R"(\$\$?\w+\s*\()");

    re2::StringPiece input(content.data(), content.size());
    re2::StringPiece matchStr;

    size_t searchStart = 0;
    size_t count = 0;

    while (searchStart < content.size()) {
        re2::StringPiece remaining(content.data() + searchStart, content.size() - searchStart);

        if (!RE2::PartialMatch(remaining, pattern, &matchStr)) {
            break;
        }

        size_t offset = searchStart + (matchStr.data() - remaining.data());
        ++count;

        // Only report if we find multiple instances (indicates intentional obfuscation)
        if (count >= minOccurrences_) {
            PatternMatch m;
            m.offset = offset;
            auto [line, column] = computeLineColumn(content, offset);
            m.line = line;
            m.column = column;
            m.matchedText = std::string(matchStr.data(), matchStr.size());
            m.context = extractContext(content, offset, 60);
            matches.push_back(std::move(m));
        }

        searchStart = offset + std::max(size_t(1), matchStr.size());
    }

    return matches;
}

// Detect arrays of hex-encoded function names
std::vector<PatternMatch> HeuristicPattern::detectHexEncodedFunctions(std::string_view content) const {
    std::vector<PatternMatch> matches;

    // Pattern: quoted hex strings (at least 10 hex chars = 5 bytes = function name)
    // Matches strings like '7068705f756e616d65' or "70687076657273696f6e"
    RE2 pattern(R"(["']([0-9a-fA-F]{10,})["'])");

    re2::StringPiece input(content.data(), content.size());
    re2::StringPiece hexStr;

    size_t searchStart = 0;
    size_t count = 0;
    size_t firstOffset = std::string::npos;

    while (searchStart < content.size()) {
        re2::StringPiece remaining(content.data() + searchStart, content.size() - searchStart);

        if (!RE2::PartialMatch(remaining, pattern, &hexStr)) {
            break;
        }

        size_t offset = searchStart + (hexStr.data() - remaining.data());

        // Check if it's valid hex that decodes to readable ASCII (function names)
        // This filters out random hashes/versions that happen to be hex
        std::string_view hexView(hexStr.data(), hexStr.size());
        if (looksLikeHex(hexView) && hexDecodesToReadableAscii(hexView)) {
            if (firstOffset == std::string::npos) {
                firstOffset = offset;
            }
            ++count;
        }

        searchStart = offset + std::max(size_t(1), hexStr.size());
    }

    if (count >= minOccurrences_ && firstOffset != std::string::npos) {
        PatternMatch m;
        m.offset = firstOffset;
        auto [line, column] = computeLineColumn(content, firstOffset);
        m.line = line;
        m.column = column;
        m.matchedText = fmt::format("{} hex-encoded strings in array", count);
        m.context = extractContext(content, firstOffset, 60);
        matches.push_back(std::move(m));
    }

    return matches;
}

// Detect goto-based obfuscation (common in PHP obfuscators)
std::vector<PatternMatch> HeuristicPattern::detectGotoObfuscation(std::string_view content) const {
    std::vector<PatternMatch> matches;

    // Count goto statements - excessive use indicates obfuscation
    RE2 gotoPattern(R"(goto\s+\w+\s*;)");

    re2::StringPiece input(content.data(), content.size());
    size_t searchStart = 0;
    size_t gotoCount = 0;
    size_t firstGotoOffset = std::string::npos;

    while (searchStart < content.size()) {
        re2::StringPiece remaining(content.data() + searchStart, content.size() - searchStart);
        re2::StringPiece matchStr;

        if (!RE2::PartialMatch(remaining, gotoPattern, &matchStr)) {
            break;
        }

        size_t offset = searchStart + (matchStr.data() - remaining.data());

        if (firstGotoOffset == std::string::npos) {
            firstGotoOffset = offset;
        }

        ++gotoCount;
        searchStart = offset + 1;
    }

    // More than 5 goto statements is suspicious (normal code rarely uses goto)
    if (gotoCount > 5 && firstGotoOffset != std::string::npos) {
        PatternMatch m;
        m.offset = firstGotoOffset;
        auto [line, column] = computeLineColumn(content, firstGotoOffset);
        m.line = line;
        m.column = column;
        m.matchedText = fmt::format("{} goto statements (obfuscation pattern)", gotoCount);
        m.context = extractContext(content, firstGotoOffset, 50);
        matches.push_back(std::move(m));
    }

    return matches;
}

// Detect long base64 or hex encoded strings
std::vector<PatternMatch> HeuristicPattern::detectLongEncodedStrings(std::string_view content) const {
    std::vector<PatternMatch> matches;

    // Look for very long strings (likely encoded payloads)
    RE2 pattern(R"(["']([A-Za-z0-9+/=]{100,})["'])");

    re2::StringPiece input(content.data(), content.size());
    re2::StringPiece encodedStr;

    size_t searchStart = 0;
    while (searchStart < content.size()) {
        re2::StringPiece remaining(content.data() + searchStart, content.size() - searchStart);

        if (!RE2::PartialMatch(remaining, pattern, &encodedStr)) {
            break;
        }

        size_t offset = searchStart + (encodedStr.data() - remaining.data());

        if (encodedStr.size() >= minStringLength_) {
            PatternMatch m;
            m.offset = offset;
            auto [line, column] = computeLineColumn(content, offset);
            m.line = line;
            m.column = column;
            m.matchedText = fmt::format("Long encoded string ({} chars)", encodedStr.size());
            m.context = extractContext(content, offset, 80);
            matches.push_back(std::move(m));
        }

        searchStart = offset + encodedStr.size();
    }

    return matches;
}

// Detect eval/assert with variable argument (code execution)
std::vector<PatternMatch> HeuristicPattern::detectEvalWithVariable(std::string_view content) const {
    std::vector<PatternMatch> matches;

    // Pattern 1: eval($var...) - always suspicious
    // This catches:
    //   - eval($code)
    //   - eval($x)
    //   - @eval($data)
    //   - eval($var[0](...))
    //   - eval($var[$GLOBALS[...]])
    // The key is eval( followed by $ (a variable reference)
    // Wrap in capture group to extract the match
    RE2 evalPattern(R"((@?eval\s*\(\s*\$\w+))");

    // Pattern 2: assert($var) with direct variable only (no operators/comparisons)
    // Suspicious: assert($code), assert($x ?? $y), assert($x ?: $y)
    // NOT suspicious: assert($x > 0), assert($x == $y), assert($this->method())
    // We match assert($var followed by ) or ?? or ?: but NOT followed by operators
    RE2 assertPattern(R"((assert\s*\(\s*\$\w+\s*)(\)|(\?\?|\?:)))");

    re2::StringPiece input(content.data(), content.size());
    re2::StringPiece matchStr;

    // Check for eval patterns
    size_t searchStart = 0;
    while (searchStart < content.size()) {
        re2::StringPiece remaining(content.data() + searchStart, content.size() - searchStart);

        if (!RE2::PartialMatch(remaining, evalPattern, &matchStr)) {
            break;
        }

        size_t offset = searchStart + (matchStr.data() - remaining.data());

        PatternMatch m;
        m.offset = offset;
        auto [line, column] = computeLineColumn(content, offset);
        m.line = line;
        m.column = column;
        m.matchedText = std::string(matchStr.data(), matchStr.size());
        m.context = extractContext(content, offset, 60);
        matches.push_back(std::move(m));

        searchStart = offset + std::max(size_t(1), matchStr.size());
    }

    // Check for suspicious assert patterns
    searchStart = 0;
    while (searchStart < content.size()) {
        re2::StringPiece remaining(content.data() + searchStart, content.size() - searchStart);

        if (!RE2::PartialMatch(remaining, assertPattern, &matchStr)) {
            break;
        }

        size_t offset = searchStart + (matchStr.data() - remaining.data());

        // Skip if this is a method call (preceded by "->")
        // e.g., $this->constraint->assert($token) is NOT suspicious
        bool isMethodCall = false;
        if (offset >= 2) {
            // Look for "->" immediately before "assert"
            size_t checkPos = offset;
            // Skip any whitespace before "assert"
            while (checkPos > 0 && (content[checkPos - 1] == ' ' || content[checkPos - 1] == '\t')) {
                --checkPos;
            }
            // Check for "->"
            if (checkPos >= 2 && content[checkPos - 2] == '-' && content[checkPos - 1] == '>') {
                isMethodCall = true;
            }
        }

        if (!isMethodCall) {
            PatternMatch m;
            m.offset = offset;
            auto [line, column] = computeLineColumn(content, offset);
            m.line = line;
            m.column = column;
            m.matchedText = std::string(matchStr.data(), matchStr.size());
            m.context = extractContext(content, offset, 60);
            matches.push_back(std::move(m));
        }

        searchStart = offset + std::max(size_t(1), matchStr.size());
    }

    return matches;
}

// Detect create_function used for eval-like behavior
std::vector<PatternMatch> HeuristicPattern::detectCreateFunctionEval(std::string_view content) const {
    std::vector<PatternMatch> matches;

    // Pattern: create_function('', ...) - often used for eval
    RE2 pattern(R"(create_function\s*\(\s*["']['"]\s*,)");

    re2::StringPiece input(content.data(), content.size());
    re2::StringPiece matchStr;

    size_t searchStart = 0;
    while (searchStart < content.size()) {
        re2::StringPiece remaining(content.data() + searchStart, content.size() - searchStart);

        if (!RE2::PartialMatch(remaining, pattern, &matchStr)) {
            break;
        }

        size_t offset = searchStart + (matchStr.data() - remaining.data());

        PatternMatch m;
        m.offset = offset;
        auto [line, column] = computeLineColumn(content, offset);
        m.line = line;
        m.column = column;
        m.matchedText = "create_function with empty params";
        m.context = extractContext(content, offset, 60);
        matches.push_back(std::move(m));

        searchStart = offset + std::max(size_t(1), matchStr.size());
    }

    return matches;
}

// Detect array index string building obfuscation
// Pattern: $var[N].$var[M]... OR $var{N}.$var{M}... used to build strings character by character
// This is a 100% malicious obfuscation technique - no legitimate code does this
std::vector<PatternMatch> HeuristicPattern::detectArrayIndexStringBuild(std::string_view content) const {
    std::vector<PatternMatch> matches;

    // Helper to detect concatenation chains with a specific marker
    auto detectChain = [&](std::string_view marker) {
        size_t pos = 0;
        while (pos < content.size()) {
            // Find first occurrence
            size_t start = content.find(marker, pos);
            if (start == std::string_view::npos) break;

            // Count consecutive occurrences
            size_t count = 1;
            size_t searchPos = start + marker.size();

            while (searchPos < content.size()) {
                size_t next = content.find(marker, searchPos);
                if (next == std::string_view::npos) break;

                // Check if reasonably close (within 25 chars - typical for $var_name{NN})
                if (next - searchPos > 25) break;

                ++count;
                searchPos = next + marker.size();
            }

            // If we found 5+ consecutive patterns, this is array index string building
            if (count >= minOccurrences_) {
                PatternMatch m;
                m.offset = start;
                auto [line, column] = computeLineColumn(content, start);
                m.line = line;
                m.column = column;
                m.matchedText = fmt::format("Array index string building ({} concatenations)", count);
                m.context = extractContext(content, start, 80);
                matches.push_back(std::move(m));

                // Skip past this chain
                pos = searchPos;
            } else {
                pos = start + 1;
            }
        }
    };

    // Detect both bracket styles:
    // Square brackets: $var[N].$var[M]  -> marker "].$"
    // Curly braces:    $var{N}.$var{M}  -> marker "}.$"
    detectChain("].$");
    detectChain("}.$");

    return matches;
}

// Detect credential harvesting scripts
// These combine: POST data collection (login/password fields) + mail() or file_put_contents
// This is a behavior-based heuristic that looks for the combination of indicators
std::vector<PatternMatch> HeuristicPattern::detectCredentialHarvester(std::string_view content) const {
    std::vector<PatternMatch> matches;

    // Indicator 1: POST data with credential field names
    RE2 postCredentialPattern(R"(\$_POST\s*\[\s*["'](login|user|username|email|passwd|password|pass|pwd|card|cvv|ssn|account)["']\s*\])");

    // Indicator 2: mail() function usage
    RE2 mailPattern(R"(\bmail\s*\()");

    // Indicator 3: IP collection
    RE2 ipPattern(R"(getenv\s*\(\s*["']REMOTE_ADDR["']\s*\)|\$_SERVER\s*\[\s*["']REMOTE_ADDR["']\s*\])");

    // Indicator 4: Redirect after collection (phishing pattern)
    RE2 redirectPattern(R"(header\s*\(\s*["']Location:)");

    // Indicator 5: file_put_contents for logging credentials
    RE2 fileLogPattern(R"(file_put_contents\s*\([^)]*\$_(POST|GET|REQUEST))");

    re2::StringPiece input(content.data(), content.size());

    // Count each indicator
    bool hasPostCredentials = RE2::PartialMatch(input, postCredentialPattern);
    bool hasMail = RE2::PartialMatch(input, mailPattern);
    bool hasIpCollection = RE2::PartialMatch(input, ipPattern);
    bool hasRedirect = RE2::PartialMatch(input, redirectPattern);
    bool hasFileLog = RE2::PartialMatch(input, fileLogPattern);

    // Calculate suspicion score
    int score = 0;
    if (hasPostCredentials) score += 3;  // Most important indicator
    if (hasMail) score += 2;
    if (hasIpCollection) score += 1;
    if (hasRedirect) score += 1;
    if (hasFileLog) score += 2;

    // If score >= 4 (e.g., POST credentials + mail, or POST + IP + redirect)
    // This is likely a credential harvester
    if (score >= 4) {
        // Find the first POST credential pattern for positioning
        re2::StringPiece matchStr;
        size_t offset = 0;

        if (RE2::PartialMatch(input, postCredentialPattern, &matchStr)) {
            offset = matchStr.data() - content.data();
        }

        PatternMatch m;
        m.offset = offset;
        auto [line, column] = computeLineColumn(content, offset);
        m.line = line;
        m.column = column;

        std::string indicators;
        if (hasPostCredentials) indicators += "credential fields, ";
        if (hasMail) indicators += "mail(), ";
        if (hasIpCollection) indicators += "IP logging, ";
        if (hasRedirect) indicators += "redirect, ";
        if (hasFileLog) indicators += "file logging, ";
        if (!indicators.empty()) {
            indicators = indicators.substr(0, indicators.size() - 2);  // Remove trailing ", "
        }

        m.matchedText = fmt::format("Credential harvester pattern ({})", indicators);
        m.context = extractContext(content, offset, 80);
        matches.push_back(std::move(m));
    }

    return matches;
}

}  // namespace lyxbosa
