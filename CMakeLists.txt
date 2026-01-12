cmake_minimum_required(VERSION 3.16)

project(LyxBoSa LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set default build type if not specified
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose the type of build" FORCE)
endif()

# Define build type macros
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_definitions(LYXBOSA_DEBUG)
else()
  add_compile_definitions(LYXBOSA_RELEASE)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Find vcpkg packages
find_package(fmt CONFIG REQUIRED)
find_package(argparse CONFIG REQUIRED)
find_package(yaml-cpp CONFIG REQUIRED)
find_package(reflectcpp CONFIG REQUIRED)

# Collect library sources from src-lib
set(LIB_SOURCES
    src-lib/cpp/infrastructure/Console.cpp
)

# Create the CLI executable
add_executable(lyxbosa
    src-cli/lyxbosa.cpp
    ${LIB_SOURCES}
)

target_include_directories(lyxbosa PRIVATE
    ${CMAKE_SOURCE_DIR}/src-lib/cpp
    ${CMAKE_SOURCE_DIR}/src-cli
)

target_link_libraries(lyxbosa
  PRIVATE
    fmt::fmt
    argparse::argparse
    yaml-cpp::yaml-cpp
    reflectcpp::reflectcpp
)

# Platform-specific settings
if(WIN32)
  # Windows-specific settings if needed
elseif(APPLE)
  # macOS-specific settings if needed
elseif(UNIX)
  # Linux-specific settings if needed
endif()
