#pragma once

#include <string>
#include <regex>
#include <vector>
#include <sstream>

namespace StringUtils {
    inline std::string escapeForJs(const std::string& str) {
        std::string result;
        result.reserve(str.size());

        for (char c : str) {
            if (c == '\\') {
                result += "\\\\";
            } else if (c == '\'') {
                result += "\\'";
            } else {
                result += c;
            }
        }

        return result;
    }

    inline std::string join(const std::vector<std::string>& strings, const std::string& delimiter) {
        if (strings.empty()) return "";

        std::ostringstream oss;
        oss << strings[0];
        for (size_t i = 1; i < strings.size(); ++i) {
            oss << delimiter << strings[i];
        }
        return oss.str();
    }
}
