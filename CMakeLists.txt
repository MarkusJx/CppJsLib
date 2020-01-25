cmake_minimum_required(VERSION 3.12)
project(CppJsLibAll)

set(CMAKE_CXX_STANDARD 17)

option(BuildTests "BuildTests" FALSE)

if (DEFINED ENV{GITHUB_ACTIONS})
    message(STATUS "Building on GitHub")
    if(NOT WIN32)
        add_compile_definitions(CPPJSLIB_GHBUILD)
        message(STATUS "Building on Linux/MacOs on GH Actions, defining CPPJSLIB_GHBUILD")
    endif()
endif ()

if (BuildTests)
    message(STATUS "Building tests")
    add_subdirectory("src")
    add_subdirectory("test")
else ()
    message(STATUS "Just building the library")
    add_subdirectory("src")
endif ()