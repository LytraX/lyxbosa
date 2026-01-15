#pragma once

#include "RuleDefinition.hpp"

namespace lyxbosa::rules::perl {

extern const BuiltinRule PL001;
extern const BuiltinRule PL002;
extern const BuiltinRule PL003;
extern const BuiltinRule PL004;
extern const BuiltinRule PL005;
extern const BuiltinRule PL006;
extern const BuiltinRule PL007;
extern const BuiltinRule PL008;

inline constexpr size_t RULE_COUNT = 8;
const BuiltinRule* const* getAllRules();

} // namespace lyxbosa::rules::perl
