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
find_package(re2 CONFIG REQUIRED)
find_package(ctre CONFIG REQUIRED)  # Already installed via reflectcpp

# CTRE rule sources (compiled separately to avoid recompilation)
set(RULE_SOURCES
    src-lib/cpp/rules/webshell.cpp
    src-lib/cpp/rules/code_exec.cpp
    src-lib/cpp/rules/obfuscation.cpp
    src-lib/cpp/rules/backdoor.cpp
    src-lib/cpp/rules/phishing.cpp
    src-lib/cpp/rules/credential_theft.cpp
    src-lib/cpp/rules/dropper.cpp
    src-lib/cpp/rules/exploit.cpp
    src-lib/cpp/rules/seo_spam.cpp
    src-lib/cpp/rules/defacement.cpp
    src-lib/cpp/rules/perl.cpp
)

# Collect library sources from src-lib
set(LIB_SOURCES
    src-lib/cpp/infrastructure/Console.cpp
    src-lib/cpp/config/Config.cpp
    src-lib/cpp/patterns/StringPattern.cpp
    src-lib/cpp/patterns/RegexPattern.cpp
    src-lib/cpp/patterns/HeuristicPattern.cpp
    src-lib/cpp/core/Rule.cpp
    src-lib/cpp/core/FileWalker.cpp
    src-lib/cpp/core/MatchEngine.cpp
    src-lib/cpp/core/Scanner.cpp
    ${RULE_SOURCES}
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
    re2::re2
    ctre::ctre
)

# Testing
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
  enable_testing()
  find_package(GTest CONFIG REQUIRED)

  add_executable(lyxbosa_tests
    tests/rules_test.cpp
    ${LIB_SOURCES}
  )

  target_include_directories(lyxbosa_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src-lib/cpp
    ${CMAKE_SOURCE_DIR}/src-cli
  )

  target_link_libraries(lyxbosa_tests
    PRIVATE
      fmt::fmt
      argparse::argparse
      yaml-cpp::yaml-cpp
      reflectcpp::reflectcpp
      re2::re2
      ctre::ctre
      GTest::gtest
      GTest::gtest_main
  )

  include(GoogleTest)
  gtest_discover_tests(lyxbosa_tests)
endif()
