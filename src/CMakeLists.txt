cmake_minimum_required(VERSION 3.12)
project(CppJsLib)

set(CMAKE_CXX_STANDARD 17)

include(InitCppJsLib.cmake)

if (LINK_STATIC)
    add_library(CppJsLib STATIC)
else ()
    add_library(CppJsLib SHARED)
    add_compile_definitions(CPPJSLIB_BUILD_LIB)
endif ()

initCppJsLib(CppJsLib ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include)

