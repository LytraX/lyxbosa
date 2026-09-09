#pragma once

// Version.h - parsing and ordering release versions, and telling a release build
// from a development one.
//
// Two things this exists to get right, both of which are easy to get wrong by
// accident and impossible to notice afterwards:
//
//   2.10.0 is newer than 2.9.0. A string comparison says the opposite, and the
//   mistake is invisible until the tenth minor release - by which time the tool has
//   been quietly telling everyone they are up to date.
//
//   A build that is not from a tag reports 0.0.0 (docs/RELEASING.md: expected, and
//   LYXBOSA_VERSION_OVERRIDE is only set by CI). Compared numerically, every
//   published release is newer than 0.0.0, so a naive check tells every developer on
//   every scan that an update is available. isRelease() is what stops that, and the
//   answer for a development build is "this is not a release build", not a version.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace lyxbosa {

struct Version {
    uint32_t major = 0;
    uint32_t minor = 0;
    uint32_t patch = 0;

    // A build from a tag. 0.0.0 is what CMake uses when LYXBOSA_VERSION_OVERRIDE is
    // absent, which is every build that did not come out of the release job.
    bool isRelease() const { return major != 0 || minor != 0 || patch != 0; }

    friend bool operator==(const Version& a, const Version& b) {
        return a.major == b.major && a.minor == b.minor && a.patch == b.patch;
    }
    friend bool operator!=(const Version& a, const Version& b) { return !(a == b); }

    // Ordering is component-wise and numeric. This is the 2.10.0 > 2.9.0 line.
    friend bool operator<(const Version& a, const Version& b) {
        if (a.major != b.major) return a.major < b.major;
        if (a.minor != b.minor) return a.minor < b.minor;
        return a.patch < b.patch;
    }
    friend bool operator>(const Version& a, const Version& b) { return b < a; }
    friend bool operator<=(const Version& a, const Version& b) { return !(b < a); }
    friend bool operator>=(const Version& a, const Version& b) { return !(a < b); }
};

inline std::string toString(const Version& v) {
    return std::to_string(v.major) + '.' + std::to_string(v.minor) + '.' +
           std::to_string(v.patch);
}

// Exactly three dot-separated runs of digits, with an optional leading `v`.
//
// Deliberately strict, and the strictness is the point: this parses a string that
// arrived over the network, and everything it refuses becomes "no notice today",
// which is the safe direction. Release tags here are numeric - docs/RELEASING.md
// records that a non-numeric tag such as v0.0.1-rc1 breaks the Windows build outright
// - so a suffix is not a thing this project publishes, and accepting one would mean
// inventing an ordering for it with no releases to check the invention against.
//
// Each component is capped at six digits, which is both far more than any release
// will use and short enough that the accumulation cannot overflow.
inline std::optional<Version> parseVersion(std::string_view s) {
    if (!s.empty() && (s.front() == 'v' || s.front() == 'V')) {
        s.remove_prefix(1);
    }

    Version out;
    uint32_t* const parts[3] = {&out.major, &out.minor, &out.patch};

    size_t i = 0;
    for (int part = 0; part < 3; ++part) {
        if (part > 0) {
            if (i >= s.size() || s[i] != '.') return std::nullopt;
            ++i;
        }
        const size_t start = i;
        uint32_t value = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            value = value * 10 + static_cast<uint32_t>(s[i] - '0');
            ++i;
        }
        const size_t digits = i - start;
        if (digits == 0 || digits > 6) return std::nullopt;
        *parts[part] = value;
    }

    if (i != s.size()) return std::nullopt;  // trailing anything: -rc1, .4, junk
    return out;
}

// The version this binary was built as.
inline Version runningVersion() {
    if (const auto parsed = parseVersion(LYXBOSA_VERSION)) {
        return *parsed;
    }
    return Version{};  // unparseable is treated as a development build
}

}  // namespace lyxbosa
