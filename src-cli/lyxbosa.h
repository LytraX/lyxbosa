// For cross-platform resource handling
#ifdef _WIN32
    #include <windows.h>
#elif __APPLE__
    #include <CoreFoundation/CoreFoundation.h>
#elif __linux__
    // Linux will use external files or embedded binary data
#endif
