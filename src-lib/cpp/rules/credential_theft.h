#pragma once

#include "RuleDefinition.hpp"

namespace lyxbosa::rules::credential_theft {

extern const BuiltinRule CRED001;
extern const BuiltinRule CRED002;
extern const BuiltinRule CRED003;
extern const BuiltinRule CRED004;
extern const BuiltinRule CRED005;
extern const BuiltinRule CRED006;

inline constexpr size_t RULE_COUNT = 6;
const BuiltinRule* const* getAllRules();

} // namespace lyxbosa::rules::credential_theft
