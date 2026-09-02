#pragma once

#include "utils/SafeText.h"

#include <string>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#endif

namespace lyxbosa {

// Convert a filesystem path to a UTF-8 encoded string safe for console output.
// On Windows, path::string() uses the ANSI code page which can cause crashes
// when fmt::print sends non-UTF-8 bytes to WriteConsoleW on the Windows Console.
// Path rendered for a human. A directory or file name is attacker-controlled on a
// compromised host and can carry ESC just as file *content* can, so anything headed
// for a terminal, a report or a progress line goes through here. Scanner keeps the
// raw pathToUtf8 - the context filters match on real path text.
inline std::string pathForDisplay(const std::filesystem::path& p);

inline std::string pathToUtf8(const std::filesystem::path& p) {
#ifdef _WIN32
    const auto& ws = p.native();  // Returns const wstring& on Windows
    if (ws.empty()) return "";

    int size = WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()),
                                   nullptr, 0, nullptr, nullptr);
    if (size <= 0) return p.string();  // Fallback

    std::string utf8(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()),
                        utf8.data(), size, nullptr, nullptr);
    return utf8;
#else
    return p.string();  // Already UTF-8 on Linux/macOS
#endif
}

inline std::string pathForDisplay(const std::filesystem::path& p) {
    std::string utf8 = pathToUtf8(p);
    return safe_text::needsSanitizing(utf8) ? safe_text::sanitize(utf8) : utf8;
}

}  // namespace lyxbosa
