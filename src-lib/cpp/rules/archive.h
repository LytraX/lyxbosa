#pragma once

#include "RuleDefinition.hpp"

namespace lyxbosa::rules::archive {

extern const BuiltinRule ARC001;
extern const BuiltinRule ARC002;
extern const BuiltinRule ARC003;

inline constexpr size_t RULE_COUNT = 3;
const BuiltinRule* const* getAllRules();

} // namespace lyxbosa::rules::archive
