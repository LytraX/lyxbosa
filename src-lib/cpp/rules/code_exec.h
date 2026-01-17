#pragma once

#include "RuleDefinition.hpp"

namespace lyxbosa::rules::code_exec {

extern const BuiltinRule RCE001;
extern const BuiltinRule RCE002;
extern const BuiltinRule RCE003;
extern const BuiltinRule RCE004;
extern const BuiltinRule RCE005;
extern const BuiltinRule RCE006;
extern const BuiltinRule RCE007;
extern const BuiltinRule RCE008;
extern const BuiltinRule RCE009;
extern const BuiltinRule RCE010;
extern const BuiltinRule RCE011;
extern const BuiltinRule RCE012;
extern const BuiltinRule RCE013;

inline constexpr size_t RULE_COUNT = 13;
const BuiltinRule* const* getAllRules();

} // namespace lyxbosa::rules::code_exec
