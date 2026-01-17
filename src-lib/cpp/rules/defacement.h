#pragma once

#include "RuleDefinition.hpp"

namespace lyxbosa::rules::defacement {

extern const BuiltinRule DEFC001;
extern const BuiltinRule DEFC002;
extern const BuiltinRule DEFC003;
extern const BuiltinRule DEFC004;
extern const BuiltinRule DEFC005;
extern const BuiltinRule DEFC006;
extern const BuiltinRule DEFC007;

inline constexpr size_t RULE_COUNT = 7;
const BuiltinRule* const* getAllRules();

} // namespace lyxbosa::rules::defacement
