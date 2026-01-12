#pragma once
#include <filesystem>

namespace PathUtils {

/// Returns the directory that contains your index.html in dev,
/// whether you're running a flat binary or inside a .app bundle.
inline std::filesystem::path locateDevRootDir(const std::filesystem::path& argv0) {
    namespace fs = std::filesystem;
    fs::path exe = fs::canonical(argv0);
    fs::path dir = exe.parent_path();

#ifdef __APPLE__
    if (dir.filename() == "MacOS" && dir.parent_path().filename() == "Contents") {
        return dir.parent_path().parent_path().parent_path();
    }
#endif

    // Windows/Linux: flat binary next to index.html
    return dir;
}

inline std::filesystem::path locateProdRootDir(const std::filesystem::path& argv0) {
    namespace fs = std::filesystem;
    fs::path exe = fs::canonical(argv0);
    fs::path dir = exe.parent_path();

    return dir;
}

/// Returns the full path to index.html next to your executable.
inline std::filesystem::path locateIndexHtml(const std::filesystem::path& argv0) {
#ifdef BINEYE_DEBUG
    return locateDevRootDir(argv0) / "../index.html";
#else
    return locateProdRootDir(argv0) / "index.html";
#endif
}

} // namespace PathUtils
