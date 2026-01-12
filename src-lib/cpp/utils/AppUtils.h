#pragma once

#include <string>
#include <optional>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <appmodel.h>
#endif

namespace AppUtils {

    /**
     * Gets the Windows MSIX/AppX package full name if the app is packaged.
     * Returns nullopt if the app is running as a traditional Win32 executable.
     *
     * Package full name format: Publisher.AppName_Version_Architecture_ResourceId_PublisherId
     * Example: "Contoso.BinEye_1.0.0.0_x64__8wekyb3d8bbwe"
     */
    inline std::optional<std::string> getMSPackageName() {
        #ifdef _WIN32
            try {
                UINT32 length = 0;
                LONG rc = GetCurrentPackageFullName(&length, nullptr);

                // Not a packaged app
                if (rc == APPMODEL_ERROR_NO_PACKAGE) {
                    return std::nullopt;
                }

                // Get the actual package name
                if (rc == ERROR_INSUFFICIENT_BUFFER && length > 0) {
                    // Allocate buffer (length is in characters, includes null terminator)
                    std::vector<wchar_t> buffer(length);
                    rc = GetCurrentPackageFullName(&length, buffer.data());

                    if (rc == ERROR_SUCCESS) {
                        // Convert wstring to UTF-8 string
                        int size_needed = WideCharToMultiByte(CP_UTF8, 0, buffer.data(), -1, nullptr, 0, nullptr, nullptr);
                        if (size_needed > 0) {
                            std::string result(size_needed - 1, '\0');
                            WideCharToMultiByte(CP_UTF8, 0, buffer.data(), -1, &result[0], size_needed, nullptr, nullptr);
                            return result;
                        }
                    }
                }
            } catch (...) {
                // Silently fail if anything goes wrong
                return std::nullopt;
            }
        #endif

        return std::nullopt;
    }
}
