#pragma once

#include <string>
#include <optional>
#include "StringUtils.h"

namespace JsUtils {
    /**
     * Formats an optional string value for JavaScript injection.
     * Returns a quoted, escaped string if value is present, or "null" if empty.
     *
     * Example:
     *   formatJsValue(std::nullopt) -> "null"
     *   formatJsValue("hello") -> "'hello'"
     */
    inline std::string formatJsValue(const std::optional<std::string>& value) {
        if (value.has_value()) {
            return "'" + StringUtils::escapeForJs(*value) + "'";
        }
        return "null";
    }
}
