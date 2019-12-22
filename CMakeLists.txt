cmake_minimum_required(VERSION 3.15)
project(CppJsLibAll)

set(CMAKE_CXX_STANDARD 17)

option(BuildTests "BuildTests" FALSE)

if (BuildTests)
    message(STATUS "Building tests")
    add_subdirectory("src")
    add_subdirectory("test")
else ()
    message(STATUS "Just building the library")
    add_subdirectory("src")
endif ()