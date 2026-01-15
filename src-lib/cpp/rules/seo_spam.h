#pragma once

#include "RuleDefinition.hpp"

namespace lyxbosa::rules::seo_spam {

extern const BuiltinRule SEO001;
extern const BuiltinRule SEO002;
extern const BuiltinRule SEO003;
extern const BuiltinRule SEO004;
extern const BuiltinRule SEO005;
extern const BuiltinRule SEO006;

inline constexpr size_t RULE_COUNT = 6;
const BuiltinRule* const* getAllRules();

} // namespace lyxbosa::rules::seo_spam
