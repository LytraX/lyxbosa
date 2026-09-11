#include "update/UpdateState.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string_view>
#include <system_error>

namespace lyxbosa {

namespace {

namespace fs = std::filesystem;

// A state file is a handful of short lines. Anything larger is not one, and reading
// it would be reading whatever else ended up at that path.
constexpr std::uintmax_t kMaxStateBytes = 4096;

// Long enough for any version this project will publish, short enough that a
// corrupted file cannot turn into a large allocation or a long message.
constexpr size_t kMaxVersionChars = 64;

const char* env(const char* name) {
    const char* value = std::getenv(name);
    return (value != nullptr && value[0] != '\0') ? value : nullptr;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) {
        s.remove_suffix(1);
    }
    return s;
}

// Digits only, and refuses anything that would overflow. A timestamp that does not
// parse leaves lastCheckEpoch at 0, which reads as "never checked".
std::optional<uint64_t> parseEpoch(std::string_view s) {
    if (s.empty() || s.size() > 20) return std::nullopt;
    uint64_t value = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') return std::nullopt;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (UINT64_MAX - digit) / 10) return std::nullopt;
        value = value * 10 + digit;
    }
    return value;
}

}  // namespace

std::filesystem::path defaultUpdateStatePath() {
    if (const char* explicitPath = env("LYXBOSA_UPDATE_STATE")) {
        return fs::path(explicitPath);
    }

#ifdef _WIN32
    if (const char* localAppData = env("LOCALAPPDATA")) {
        return fs::path(localAppData) / "lyxbosa" / "update-check";
    }
    if (const char* profile = env("USERPROFILE")) {
        return fs::path(profile) / "AppData" / "Local" / "lyxbosa" / "update-check";
    }
    return {};
#elif defined(__APPLE__)
    if (const char* home = env("HOME")) {
        return fs::path(home) / "Library" / "Caches" / "lyxbosa" / "update-check";
    }
    return {};
#else
    // XDG: the cache directory rather than the config or data one. Deleting this
    // file must cost nothing, and it must not be something anybody backs up.
    if (const char* xdgCache = env("XDG_CACHE_HOME")) {
        return fs::path(xdgCache) / "lyxbosa" / "update-check";
    }
    if (const char* home = env("HOME")) {
        return fs::path(home) / ".cache" / "lyxbosa" / "update-check";
    }
    return {};
#endif
}

std::optional<UpdateState> readUpdateState(const std::filesystem::path& path) {
    if (path.empty()) return std::nullopt;

    std::error_code ec;
    if (!fs::is_regular_file(path, ec) || ec) return std::nullopt;
    const auto size = fs::file_size(path, ec);
    if (ec || size > kMaxStateBytes) return std::nullopt;

    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in) return std::nullopt;

    UpdateState state;
    bool sawAnything = false;
    std::string line;
    while (std::getline(in, line)) {
        const std::string_view trimmed = trim(line);
        if (trimmed.empty() || trimmed.front() == '#') continue;

        const size_t eq = trimmed.find('=');
        if (eq == std::string_view::npos) continue;

        const std::string_view key = trim(trimmed.substr(0, eq));
        const std::string_view value = trim(trimmed.substr(eq + 1));

        if (key == "last_check") {
            if (const auto epoch = parseEpoch(value)) {
                state.lastCheckEpoch = *epoch;
                sawAnything = true;
            }
        } else if (key == "latest_version") {
            if (value.size() <= kMaxVersionChars) {
                state.latestVersion.assign(value);
                sawAnything = true;
            }
        } else if (key == "portable_notice_epoch") {
            if (const auto epoch = parseEpoch(value)) {
                state.portableNoticeEpoch = *epoch;
                sawAnything = true;
            }
        } else if (key == "portable_notice_shown") {
            // The pre-timestamp spelling of the key above. Only the exact value that
            // version wrote counts as yes: anything else - a truncated line, a
            // hand-edit, a value from some other version of this file - means "not
            // shown", which costs at most one extra line once. An unparseable
            // portable_notice_epoch therefore lands here, and the run that sees it
            // stamps a fresh timestamp rather than printing.
            state.portableNoticeShownLegacy = (value == "1");
            sawAnything = true;
        }
        // Anything else is a key from a later version of this file. Ignored, not an
        // error: a newer binary's state file must not make an older one check on
        // every run.
    }

    if (!sawAnything) return std::nullopt;
    return state;
}

bool writeUpdateState(const std::filesystem::path& path, const UpdateState& state) {
    if (path.empty()) return false;

    std::error_code ec;
    if (path.has_parent_path()) {
        fs::create_directories(path.parent_path(), ec);
        // An existing directory reports an error code on some implementations and
        // not others, so the question to ask is whether it is there now.
        if (!fs::is_directory(path.parent_path(), ec) || ec) return false;
    }

    // The temp file sits beside the target so the rename stays on one filesystem;
    // a rename across devices is not atomic and on most systems is not permitted.
    const fs::path tmp = path.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out << "# lyxbosa update check state; safe to delete\n"
            << "last_check=" << state.lastCheckEpoch << '\n';
        if (!state.latestVersion.empty() &&
            state.latestVersion.size() <= kMaxVersionChars) {
            out << "latest_version=" << state.latestVersion << '\n';
        }
        if (state.portableNoticeEpoch) {
            out << "portable_notice_epoch=" << *state.portableNoticeEpoch << '\n';
        }
        // Beside the timestamp rather than instead of it, so that a binary rolled back
        // to one that only knows this key keeps its own once-ever contract. See the
        // field's comment in the header.
        if (state.portableNoticeEpoch || state.portableNoticeShownLegacy) {
            out << "portable_notice_shown=1\n";
        }
        out.flush();
        if (!out) {
            fs::remove(tmp, ec);
            return false;
        }
    }

    fs::rename(tmp, path, ec);
    if (ec) {
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

bool reserveUpdateCheck(const std::filesystem::path& path, uint64_t nowEpoch) {
    UpdateState state;
    if (const auto existing = readUpdateState(path)) {
        state = *existing;
    }
    state.lastCheckEpoch = nowEpoch;
    return writeUpdateState(path, state);
}

bool recordLatestVersion(const std::filesystem::path& path, uint64_t nowEpoch,
                         const std::string& version) {
    UpdateState state;
    if (const auto existing = readUpdateState(path)) {
        state = *existing;
    }
    state.lastCheckEpoch = nowEpoch;
    state.latestVersion = version;
    return writeUpdateState(path, state);
}

bool recordPortableNoticeShown(const std::filesystem::path& path, uint64_t nowEpoch) {
    UpdateState state;
    if (const auto existing = readUpdateState(path)) {
        state = *existing;
    }
    state.portableNoticeEpoch = nowEpoch;
    return writeUpdateState(path, state);
}

uint64_t currentEpochSeconds() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now).count();
    return secs > 0 ? static_cast<uint64_t>(secs) : 0;
}

}  // namespace lyxbosa
