#pragma once

#include "config/Types.h"
#include <string>
#include <string_view>
#include <optional>
#include <cstdint>
#include <array>

namespace lyxbosa::rules {

// Rule categories
enum class Category : uint8_t {
    Webshell,       // WS - Web shells
    Backdoor,       // BD - Backdoors
    Obfuscation,    // OBF - Code obfuscation
    Phishing,       // PHI - Phishing pages
    Exploit,        // EXP - Exploits/vulnerabilities
    Dropper,        // DRP - Droppers/downloaders
    CodeExec,       // RCE - Remote code execution
    CredTheft,      // CRED - Credential theft
    SeoSpam,        // SEO - SEO spam
    Tracking,       // TRK - Tracking/analytics abuse
    Defacement,     // DEFC - Site defacement
    Perl,           // PL - Perl-specific malware
    COUNT           // Number of categories
};

// Category metadata
struct CategoryInfo {
    std::string_view code;
    std::string_view name;
    std::string_view description;
};

// Get category info
constexpr CategoryInfo getCategoryInfo(Category cat) {
    constexpr std::array<CategoryInfo, static_cast<size_t>(Category::COUNT)> infos = {{
        {"WS",   "Webshell",      "Web shell backdoors"},
        {"BD",   "Backdoor",      "Persistent backdoors"},
        {"OBF",  "Obfuscation",   "Code obfuscation techniques"},
        {"PHI",  "Phishing",      "Phishing pages and forms"},
        {"EXP",  "Exploit",       "Security exploits"},
        {"DRP",  "Dropper",       "Malware droppers"},
        {"RCE",  "CodeExec",      "Remote code execution"},
        {"CRED", "CredTheft",     "Credential theft"},
        {"SEO",  "SeoSpam",       "SEO spam injection"},
        {"TRK",  "Tracking",      "Malicious tracking"},
        {"DEFC", "Defacement",    "Site defacement"},
        {"PL",   "Perl",          "Perl malware"},
    }};
    return infos[static_cast<size_t>(cat)];
}

// Parse category from code prefix
inline std::optional<Category> parseCategory(std::string_view code) {
    if (code == "WS")   return Category::Webshell;
    if (code == "BD")   return Category::Backdoor;
    if (code == "OBF")  return Category::Obfuscation;
    if (code == "PHI")  return Category::Phishing;
    if (code == "EXP")  return Category::Exploit;
    if (code == "DRP")  return Category::Dropper;
    if (code == "RCE")  return Category::CodeExec;
    if (code == "CRED") return Category::CredTheft;
    if (code == "SEO")  return Category::SeoSpam;
    if (code == "TRK")  return Category::Tracking;
    if (code == "DEFC") return Category::Defacement;
    if (code == "PL")   return Category::Perl;
    return std::nullopt;
}

// Rule code (e.g., WS001, RCE010)
struct RuleCode {
    Category category;
    uint16_t number;

    // Convert to string (e.g., "WS001")
    std::string toString() const {
        const auto& info = getCategoryInfo(category);
        char buf[16];
        snprintf(buf, sizeof(buf), "%s%03u",
                 std::string(info.code).c_str(),
                 static_cast<unsigned>(number));
        return buf;
    }

    // Parse from string (e.g., "WS001")
    static std::optional<RuleCode> parse(std::string_view str) {
        if (str.size() < 4) return std::nullopt;

        // Find where digits start
        size_t numStart = 0;
        for (size_t i = 0; i < str.size(); ++i) {
            if (str[i] >= '0' && str[i] <= '9') {
                numStart = i;
                break;
            }
        }

        if (numStart == 0) return std::nullopt;

        auto catOpt = parseCategory(str.substr(0, numStart));
        if (!catOpt) return std::nullopt;

        // Parse number
        uint16_t num = 0;
        for (size_t i = numStart; i < str.size(); ++i) {
            if (str[i] < '0' || str[i] > '9') return std::nullopt;
            num = num * 10 + (str[i] - '0');
        }

        if (num == 0) return std::nullopt;

        return RuleCode{*catOpt, num};
    }

    bool operator==(const RuleCode& other) const {
        return category == other.category && number == other.number;
    }
};

} // namespace lyxbosa::rules
