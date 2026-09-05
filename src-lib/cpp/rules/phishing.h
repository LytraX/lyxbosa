#pragma once

#include "RuleDefinition.hpp"

namespace lyxbosa::rules::phishing {

extern const BuiltinRule PHI001;
extern const BuiltinRule PHI002;
extern const BuiltinRule PHI003;
extern const BuiltinRule PHI004;
extern const BuiltinRule PHI005;
extern const BuiltinRule PHI006;
extern const BuiltinRule PHI007;
extern const BuiltinRule PHI008;
extern const BuiltinRule PHI009;

inline constexpr size_t RULE_COUNT = 9;
const BuiltinRule* const* getAllRules();

} // namespace lyxbosa::rules::phishing
