#pragma once

#include "RuleDefinition.hpp"

namespace lyxbosa::rules::obfuscation {

extern const BuiltinRule OBF001;
extern const BuiltinRule OBF002;
extern const BuiltinRule OBF003;
extern const BuiltinRule OBF004;
extern const BuiltinRule OBF005;
extern const BuiltinRule OBF006;
extern const BuiltinRule OBF007;
extern const BuiltinRule OBF008;
extern const BuiltinRule OBF009;
extern const BuiltinRule OBF010;
extern const BuiltinRule OBF011;
extern const BuiltinRule OBF012;
extern const BuiltinRule OBF013;
extern const BuiltinRule OBF014;

inline constexpr size_t RULE_COUNT = 14;
const BuiltinRule* const* getAllRules();

} // namespace lyxbosa::rules::obfuscation
