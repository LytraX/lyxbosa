#pragma once

#include "RuleDefinition.hpp"

namespace lyxbosa::rules::webshell {

// Declarations only - definitions in webshell.cpp
extern const BuiltinRule WS001;
extern const BuiltinRule WS002;
extern const BuiltinRule WS003;
extern const BuiltinRule WS004;
extern const BuiltinRule WS005;
extern const BuiltinRule WS006;
extern const BuiltinRule WS007;
extern const BuiltinRule WS008;
extern const BuiltinRule WS009;
extern const BuiltinRule WS010;

// Array of all webshell rules
inline constexpr size_t RULE_COUNT = 10;
const BuiltinRule* const* getAllRules();

} // namespace lyxbosa::rules::webshell
