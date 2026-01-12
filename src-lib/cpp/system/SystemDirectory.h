/**
 * SystemDirectory - Cross-platform utility for accessing system directories
 * Supports Windows, macOS, and Linux
 */

#pragma once

#include <filesystem>
#include <string>
#include <unordered_map>
#include <stdexcept>
#include <fstream>
#include <cstdlib>

// Platform-specific includes
#ifdef _WIN32
    #include <windows.h>
#elif defined(__APPLE__)
    #include <mach-o/dyld.h>
    #include <limits.h>
#else
    #include <unistd.h>
    #include <limits.h>
#endif

namespace SystemDirectory {

// Define enum for directory types
enum class DirType {
    AppCacheDir,
    AppConfigDir,
    AppDataDir,
    AppLocalDataDir,
    AppLogDir,
    AudioDir,
    CacheDir,
    ConfigDir,
    DataDir,
    DesktopDir,
    LocalDataDir,
    DocumentDir,
    DownloadDir,
    ResourceDir,
    RuntimeDir,
    ExecutableDir,
    FontDir,
    HomeDir,
    PictureDir,
    PublicDir,
    TempDir,
    TemplateDir,
    VideoDir
};

// String to DirType conversion
static std::unordered_map<std::string, DirType> dirTypeMap = {
    {"appCacheDir", DirType::AppCacheDir},
    {"appConfigDir", DirType::AppConfigDir},
    {"appDataDir", DirType::AppDataDir},
    {"appLocalDataDir", DirType::AppLocalDataDir},
    {"appLogDir", DirType::AppLogDir},
    {"audioDir", DirType::AudioDir},
    {"cacheDir", DirType::CacheDir},
    {"configDir", DirType::ConfigDir},
    {"dataDir", DirType::DataDir},
    {"desktopDir", DirType::DesktopDir},
    {"localDataDir", DirType::LocalDataDir},
    {"documentDir", DirType::DocumentDir},
    {"downloadDir", DirType::DownloadDir},
    {"resourceDir", DirType::ResourceDir},
    {"runtimeDir", DirType::RuntimeDir},
    {"executableDir", DirType::ExecutableDir},
    {"fontDir", DirType::FontDir},
    {"homeDir", DirType::HomeDir},
    {"pictureDir", DirType::PictureDir},
    {"publicDir", DirType::PublicDir},
    {"tempDir", DirType::TempDir},
    {"templateDir", DirType::TemplateDir},
    {"videoDir", DirType::VideoDir}
};

// Application identifier for app-specific directories
static std::string appIdentifier = "my.app.identifier";

/**
 * Set the application identifier for app-specific directories
 * @param identifier The application identifier (e.g., "com.example.myapp")
 */
void setAppIdentifier(const std::string& identifier) {
    appIdentifier = identifier;
}

/**
 * Get system directory path
 * @param dirType Enum specifying which directory to retrieve
 * @return Path to the requested directory
 */
std::filesystem::path systemDir(DirType dirType) {
    namespace fs = std::filesystem;

    // Get home directory (common base for many paths)
    fs::path homePath;

#ifdef _WIN32
    // Windows
    const char* userProfile = std::getenv("USERPROFILE");
    if (userProfile) {
        homePath = userProfile;
    }

    // Get APPDATA and LOCAL_APPDATA
    const char* appData = std::getenv("APPDATA");
    fs::path appDataPath = appData ? fs::path(appData) : (homePath / "AppData" / "Roaming");

    const char* localAppData = std::getenv("LOCALAPPDATA");
    fs::path localAppDataPath = localAppData ? fs::path(localAppData) : (homePath / "AppData" / "Local");

    // For app-specific paths
    fs::path appSpecificRoaming = appDataPath / appIdentifier;
    fs::path appSpecificLocal = localAppDataPath / appIdentifier;

    switch (dirType) {
        case DirType::AppCacheDir: return appSpecificLocal;
        case DirType::AppConfigDir: return appSpecificRoaming;
        case DirType::AppDataDir: return appSpecificRoaming;
        case DirType::AppLocalDataDir: return appSpecificLocal;
        case DirType::AppLogDir: return appSpecificLocal / "logs";
        case DirType::AudioDir: return homePath / "Music";
        case DirType::CacheDir: return localAppDataPath;
        case DirType::ConfigDir: return appDataPath;
        case DirType::DataDir: return appDataPath;
        case DirType::DesktopDir: return homePath / "Desktop";
        case DirType::LocalDataDir: return localAppDataPath;
        case DirType::DocumentDir: return homePath / "Documents";
        case DirType::DownloadDir: return homePath / "Downloads";
        case DirType::ResourceDir: {
            // Best effort - this might need to be set manually
            char path[MAX_PATH] = {0};
            GetModuleFileNameA(NULL, path, MAX_PATH);
            return fs::path(path).parent_path();
        }
        case DirType::HomeDir: return homePath;
        case DirType::PictureDir: return homePath / "Pictures";
        case DirType::PublicDir: return "C:\\Users\\Public";
        case DirType::TempDir: {
            const char* temp = std::getenv("TEMP");
            return temp ? fs::path(temp) : fs::temp_directory_path();
        }
        case DirType::TemplateDir: return appDataPath / "Microsoft" / "Windows" / "Templates";
        case DirType::VideoDir: return homePath / "Videos";
        default: return fs::path();
    }

#elif defined(__APPLE__)
    // macOS
    const char* home = std::getenv("HOME");
    if (home) {
        homePath = home;
    }

    switch (dirType) {
        case DirType::AppCacheDir: return homePath / "Library" / "Caches" / appIdentifier;
        case DirType::AppConfigDir: return homePath / "Library" / "Application Support" / appIdentifier;
        case DirType::AppDataDir: return homePath / "Library" / "Application Support" / appIdentifier;
        case DirType::AppLocalDataDir: return homePath / "Library" / "Application Support" / appIdentifier;
        case DirType::AppLogDir: return homePath / "Library" / "Logs" / appIdentifier;
        case DirType::AudioDir: return homePath / "Music";
        case DirType::CacheDir: return homePath / "Library" / "Caches";
        case DirType::ConfigDir: return homePath / "Library" / "Application Support";
        case DirType::DataDir: return homePath / "Library" / "Application Support";
        case DirType::DesktopDir: return homePath / "Desktop";
        case DirType::LocalDataDir: return homePath / "Library" / "Application Support";
        case DirType::DocumentDir: return homePath / "Documents";
        case DirType::DownloadDir: return homePath / "Downloads";
        case DirType::ResourceDir: {
            // This is a best effort - might need manual setting
            char path[PATH_MAX];
            uint32_t size = sizeof(path);
            if (_NSGetExecutablePath(path, &size) == 0) {
                return fs::path(path).parent_path();
            }
            return fs::current_path();
        }
        case DirType::FontDir: return homePath / "Library" / "Fonts";
        case DirType::HomeDir: return homePath;
        case DirType::PictureDir: return homePath / "Pictures";
        case DirType::PublicDir: return "/Users/Shared";
        case DirType::TempDir: return fs::temp_directory_path();
        case DirType::TemplateDir: return homePath / "Library" / "Application Support" / "Templates";
        case DirType::VideoDir: return homePath / "Movies";
        default: return fs::path();
    }

#else
    // Linux/Unix
    const char* home = std::getenv("HOME");
    if (home) {
        homePath = home;
    }

    // XDG Base Directory spec support
    const char* xdgConfigHome = std::getenv("XDG_CONFIG_HOME");
    fs::path configHome = xdgConfigHome ? fs::path(xdgConfigHome) : (homePath / ".config");

    const char* xdgDataHome = std::getenv("XDG_DATA_HOME");
    fs::path dataHome = xdgDataHome ? fs::path(xdgDataHome) : (homePath / ".local" / "share");

    const char* xdgCacheHome = std::getenv("XDG_CACHE_HOME");
    fs::path cacheHome = xdgCacheHome ? fs::path(xdgCacheHome) : (homePath / ".cache");

    const char* xdgRuntimeDir = std::getenv("XDG_RUNTIME_DIR");
    fs::path runtimeDir = xdgRuntimeDir ? fs::path(xdgRuntimeDir) : fs::path("/tmp");

    switch (dirType) {
        case DirType::AppCacheDir: return cacheHome / appIdentifier;
        case DirType::AppConfigDir: return configHome / appIdentifier;
        case DirType::AppDataDir: return dataHome / appIdentifier;
        case DirType::AppLocalDataDir: return dataHome / appIdentifier;
        case DirType::AppLogDir: return cacheHome / appIdentifier / "logs";
        case DirType::AudioDir: return homePath / "Music";
        case DirType::CacheDir: return cacheHome;
        case DirType::ConfigDir: return configHome;
        case DirType::DataDir: return dataHome;
        case DirType::DesktopDir: return homePath / "Desktop";
        case DirType::LocalDataDir: return dataHome;
        case DirType::DocumentDir: return homePath / "Documents";
        case DirType::DownloadDir: return homePath / "Downloads";
        case DirType::ResourceDir: {
            // This is a best effort - may need to be set manually
            char result[PATH_MAX];
            ssize_t count = readlink("/proc/self/exe", result, PATH_MAX);
            if (count != -1) {
                return fs::path(std::string(result, count)).parent_path();
            }
            return fs::current_path();
        }
        case DirType::RuntimeDir: return runtimeDir;
        case DirType::FontDir: return homePath / ".local" / "share" / "fonts";
        case DirType::HomeDir: return homePath;
        case DirType::PictureDir: return homePath / "Pictures";
        case DirType::PublicDir: return "/usr/share";
        case DirType::TempDir: return fs::temp_directory_path();
        case DirType::TemplateDir: return dataHome / "templates";
        case DirType::VideoDir: return homePath / "Videos";
        default: return fs::path();
    }
#endif

    // Default fallback (should not reach here)
    return fs::path();
}

/**
 * Overloaded version that accepts a string identifier
 * @param dirTypeStr String identifier for the directory
 * @return Path to the requested directory
 */
std::filesystem::path systemDir(const std::string& dirTypeStr) {
    auto it = dirTypeMap.find(dirTypeStr);
    if (it != dirTypeMap.end()) {
        return systemDir(it->second);
    }
    throw std::invalid_argument("Unknown directory type: " + dirTypeStr);
}

/**
 * Check if a system directory exists
 * @param dirType Enum specifying which directory to check
 * @return true if the directory exists, false otherwise
 */
bool exists(DirType dirType) {
    namespace fs = std::filesystem;
    fs::path dir = systemDir(dirType);
    return !dir.empty() && fs::exists(dir);
}

/**
 * Overloaded version that accepts a string identifier
 * @param dirTypeStr String identifier for the directory
 * @return true if the directory exists, false otherwise
 */
bool exists(const std::string& dirTypeStr) {
    auto it = dirTypeMap.find(dirTypeStr);
    if (it != dirTypeMap.end()) {
        return exists(it->second);
    }
    return false;
}

/**
 * Create directory if it doesn't exist
 * @param dirType Enum specifying which directory to ensure exists
 * @return true if directory exists or was created successfully
 */
bool ensureExists(DirType dirType) {
    namespace fs = std::filesystem;
    fs::path dir = systemDir(dirType);
    if (dir.empty()) return false;

    if (fs::exists(dir)) return true;

    try {
        return fs::create_directories(dir);
    } catch (...) {
        return false;
    }
}

/**
 * Overloaded version that accepts a string identifier
 */
bool ensureExists(const std::string& dirTypeStr) {
    auto it = dirTypeMap.find(dirTypeStr);
    if (it != dirTypeMap.end()) {
        return ensureExists(it->second);
    }
    return false;
}

} // namespace SystemDirectory
