cmake_minimum_required(VERSION 3.12)
project(CppJsLibAll)

set(CMAKE_CXX_STANDARD 17)

if (DEFINED ENV{GITHUB_ACTIONS})
    message(STATUS "Building on GitHub")
endif ()

message(STATUS "Building tests")
add_subdirectory("test")