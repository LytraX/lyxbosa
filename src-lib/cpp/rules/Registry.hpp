#pragma once

#include "RuleDefinition.hpp"
#include "webshell.h"
#include "code_exec.h"
#include "obfuscation.h"
#include "backdoor.h"
#include "phishing.h"
#include "credential_theft.h"
#include "dropper.h"
#include "exploit.h"
#include "seo_spam.h"
#include "defacement.h"
#include "perl.h"
#include <vector>
#include <unordered_map>
#include <optional>

namespace lyxbosa::rules {

class Registry {
public:
    // Get singleton instance
    static Registry& instance() {
        static Registry reg;
        return reg;
    }

    // Get rule by code (e.g., "WS001")
    const BuiltinRule* getByCode(const RuleCode& code) const {
        auto it = byCode_.find(code.toString());
        return it != byCode_.end() ? it->second : nullptr;
    }

    // Get rule by code string
    const BuiltinRule* getByCode(std::string_view codeStr) const {
        auto code = RuleCode::parse(codeStr);
        if (!code) return nullptr;
        return getByCode(*code);
    }

    // Get all rules in a category
    std::vector<const BuiltinRule*> getByCategory(Category cat) const {
        std::vector<const BuiltinRule*> result;
        for (const auto* rule : allRules_) {
            if (rule->code.category == cat) {
                result.push_back(rule);
            }
        }
        return result;
    }

    // Get all rules matching a severity
    std::vector<const BuiltinRule*> getBySeverity(Severity sev) const {
        std::vector<const BuiltinRule*> result;
        for (const auto* rule : allRules_) {
            if (rule->severity == sev) {
                result.push_back(rule);
            }
        }
        return result;
    }

    // Get all rules in a category with minimum severity
    std::vector<const BuiltinRule*> getByCategory(Category cat, Severity minSev) const {
        std::vector<const BuiltinRule*> result;
        for (const auto* rule : allRules_) {
            if (rule->code.category == cat &&
                static_cast<uint8_t>(rule->severity) >= static_cast<uint8_t>(minSev)) {
                result.push_back(rule);
            }
        }
        return result;
    }

    // Get all rules
    const std::vector<const BuiltinRule*>& getAllRules() const {
        return allRules_;
    }

    // Get total rule count
    size_t ruleCount() const {
        return allRules_.size();
    }

    // Get rules count by category
    size_t ruleCount(Category cat) const {
        size_t count = 0;
        for (const auto* rule : allRules_) {
            if (rule->code.category == cat) ++count;
        }
        return count;
    }

private:
    Registry() {
        // Register webshell rules
        auto wsRules = webshell::getAllRules();
        for (size_t i = 0; i < webshell::RULE_COUNT; ++i) {
            registerRule(wsRules[i]);
        }
        // Register code_exec rules
        auto rceRules = code_exec::getAllRules();
        for (size_t i = 0; i < code_exec::RULE_COUNT; ++i) {
            registerRule(rceRules[i]);
        }
        // Register obfuscation rules
        auto obfRules = obfuscation::getAllRules();
        for (size_t i = 0; i < obfuscation::RULE_COUNT; ++i) {
            registerRule(obfRules[i]);
        }
        // Register backdoor rules
        auto bdRules = backdoor::getAllRules();
        for (size_t i = 0; i < backdoor::RULE_COUNT; ++i) {
            registerRule(bdRules[i]);
        }
        // Register phishing rules
        auto phiRules = phishing::getAllRules();
        for (size_t i = 0; i < phishing::RULE_COUNT; ++i) {
            registerRule(phiRules[i]);
        }
        // Register credential_theft rules
        auto credRules = credential_theft::getAllRules();
        for (size_t i = 0; i < credential_theft::RULE_COUNT; ++i) {
            registerRule(credRules[i]);
        }
        // Register dropper rules
        auto drpRules = dropper::getAllRules();
        for (size_t i = 0; i < dropper::RULE_COUNT; ++i) {
            registerRule(drpRules[i]);
        }
        // Register exploit rules
        auto expRules = exploit::getAllRules();
        for (size_t i = 0; i < exploit::RULE_COUNT; ++i) {
            registerRule(expRules[i]);
        }
        // Register seo_spam rules
        auto seoRules = seo_spam::getAllRules();
        for (size_t i = 0; i < seo_spam::RULE_COUNT; ++i) {
            registerRule(seoRules[i]);
        }
        // Register defacement rules
        auto defcRules = defacement::getAllRules();
        for (size_t i = 0; i < defacement::RULE_COUNT; ++i) {
            registerRule(defcRules[i]);
        }
        // Register perl rules
        auto plRules = perl::getAllRules();
        for (size_t i = 0; i < perl::RULE_COUNT; ++i) {
            registerRule(plRules[i]);
        }
    }

    void registerRule(const BuiltinRule* rule) {
        allRules_.push_back(rule);
        byCode_[rule->code.toString()] = rule;
    }

    std::vector<const BuiltinRule*> allRules_;
    std::unordered_map<std::string, const BuiltinRule*> byCode_;
};

// Convenience functions
inline const BuiltinRule* getRuleByCode(std::string_view code) {
    return Registry::instance().getByCode(code);
}

inline std::vector<const BuiltinRule*> getRulesByCategory(Category cat) {
    return Registry::instance().getByCategory(cat);
}

inline std::vector<const BuiltinRule*> getAllBuiltinRules() {
    return Registry::instance().getAllRules();
}

} // namespace lyxbosa::rules
