#pragma once

#include <cstdint>
#include <string>
#include <iterator>
#include <fmt/format.h>

namespace lyxbosa {

// "512 B", "1.5 KB", "3.2 MB".
//
// This lived in two places - ProgressModel.h and ResultPrinter.h - each carrying a
// comment about the other, because the report writers have no business pulling in the
// progress model and vice versa. utils/ is the direction both can depend on.
inline std::string formatBytes(uint64_t bytes) {
    constexpr const char* kUnits[] = {"B", "KB", "MB", "GB", "TB"};
    auto value = static_cast<double>(bytes);
    size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < std::size(kUnits)) {
        value /= 1024.0;
        ++unit;
    }
    if (unit == 0) {
        return fmt::format("{} {}", bytes, kUnits[unit]);
    }
    return fmt::format("{:.1f} {}", value, kUnits[unit]);
}

}  // namespace lyxbosa
