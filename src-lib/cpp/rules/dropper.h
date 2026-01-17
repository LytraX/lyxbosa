#pragma once

#include "RuleDefinition.hpp"

namespace lyxbosa::rules::dropper {

extern const BuiltinRule DRP001;
extern const BuiltinRule DRP002;
extern const BuiltinRule DRP003;
extern const BuiltinRule DRP004;
extern const BuiltinRule DRP005;
extern const BuiltinRule DRP006;
extern const BuiltinRule DRP007;
extern const BuiltinRule DRP008;
extern const BuiltinRule DRP009;
extern const BuiltinRule DRP010;

inline constexpr size_t RULE_COUNT = 10;
const BuiltinRule* const* getAllRules();

} // namespace lyxbosa::rules::dropper
