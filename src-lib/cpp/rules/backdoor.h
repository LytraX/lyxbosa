#pragma once

#include "RuleDefinition.hpp"

namespace lyxbosa::rules::backdoor {

extern const BuiltinRule BD001;
extern const BuiltinRule BD002;
extern const BuiltinRule BD003;
extern const BuiltinRule BD004;
extern const BuiltinRule BD005;
extern const BuiltinRule BD006;
extern const BuiltinRule BD007;
extern const BuiltinRule BD008;
extern const BuiltinRule BD009;
extern const BuiltinRule BD010;
extern const BuiltinRule BD011;
extern const BuiltinRule BD012;
extern const BuiltinRule BD013;
extern const BuiltinRule BD014;
extern const BuiltinRule BD015;
extern const BuiltinRule BD016;
extern const BuiltinRule BD017;

inline constexpr size_t RULE_COUNT = 17;
const BuiltinRule* const* getAllRules();

} // namespace lyxbosa::rules::backdoor
