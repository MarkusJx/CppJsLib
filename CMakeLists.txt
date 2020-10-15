cmake_minimum_required(VERSION 3.12)
project(CppJsLibAll)

set(CMAKE_CXX_STANDARD 17)

option(BUILDDLL FALSE)
option(USE_DLL FALSE)
option(BUILD_JNI_DLL FALSE)
option(LINK_STATIC FALSE)

if (LINK_STATIC)
    message(STATUS "Creating static library")
    set(BUILDDLL TRUE)
endif ()

if (BUILD_JNI_DLL)
    set(BUILDDLL TRUE)
endif ()

if (DEFINED ENV{GITHUB_ACTIONS})
    message(STATUS "Building on GitHub")
endif ()

if (BUILDDLL)
    message(STATUS "Building dll")
    add_subdirectory("src")
else ()
    if (USE_DLL)
        message(STATUS "Building dll")
        add_subdirectory("src")
    endif()
    message(STATUS "Building tests")
    add_subdirectory("test")
endif ()