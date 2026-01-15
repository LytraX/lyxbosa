#pragma once

#include "RuleDefinition.hpp"

namespace lyxbosa::rules::dropper {

extern const BuiltinRule DRP001;
extern const BuiltinRule DRP002;
extern const BuiltinRule DRP003;
extern const BuiltinRule DRP004;
extern const BuiltinRule DRP005;
extern const BuiltinRule DRP006;

inline constexpr size_t RULE_COUNT = 6;
const BuiltinRule* const* getAllRules();

} // namespace lyxbosa::rules::dropper
