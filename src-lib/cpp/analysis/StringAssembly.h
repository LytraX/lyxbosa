#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace lyxbosa::analysis {

// A string value that the source builds up at runtime instead of writing it out.
//
// Malware hides sensitive function names from signature scanners by splitting
// them into fragments and re-joining them at runtime:
//
//   $f="ba"; $h="s"; $l="e"; $n="64";
//   $o=$f.$h.$l.$n."_d".$l."cod".$l;   // -> "base64_decode"
//
// The analyzer constant-folds those expressions, so the detection does not
// depend on how the fragments were cut - only on what they add up to.
struct AssembledString {
    size_t offset = 0;        // byte offset of the expression in the source
    size_t length = 0;        // byte length of the expression
    std::string value;        // the folded result
    size_t fragments = 0;     // atomic literals that produced the value
    size_t transforms = 0;    // decode/transform calls folded (strrev, base64_decode, ...)
    std::string variable;     // variable it was assigned to (empty for inline expressions)
    bool viaVariables = false;  // at least one piece travelled through a variable
    bool sensitive = false;   // value names a security-sensitive PHP function or superglobal
};

// Fold every resolvable string expression in `content` and return the ones that
// produce an identifier out of more than one written piece. Anything the folder
// cannot resolve (function results, parameters, interpolation) is skipped, so
// running this over non-PHP content simply yields nothing.
std::vector<AssembledString> findAssembledStrings(std::string_view content);

// True if `name` is a PHP function or superglobal that malware assembles to
// stay out of signature scanners. Case-insensitive.
bool isSensitiveIdentifier(std::string_view name);

// True if `variable` (name without the leading '$') is used as a dynamic call
// somewhere in `content`: $var(...), $$var(...), ${$var}(...) or as a callback.
bool isDynamicallyCalled(std::string_view content, std::string_view variable);

}  // namespace lyxbosa::analysis
