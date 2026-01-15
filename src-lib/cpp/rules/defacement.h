#pragma once

#include "RuleDefinition.hpp"

namespace lyxbosa::rules::defacement {

extern const BuiltinRule DEFC001;
extern const BuiltinRule DEFC002;
extern const BuiltinRule DEFC003;

inline constexpr size_t RULE_COUNT = 3;
const BuiltinRule* const* getAllRules();

} // namespace lyxbosa::rules::defacement
