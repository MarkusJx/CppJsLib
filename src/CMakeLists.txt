cmake_minimum_required(VERSION 3.12)
project(CppJsLib)

set(CMAKE_CXX_STANDARD 17)

option(BUILD_JNI_DLL FALSE)

include(InitCppJsLib.cmake)

add_library(CppJsLib SHARED)

initCppJsLib(CppJsLib ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include TRUE TRUE FALSE ${BUILD_JNI_DLL})

add_compile_definitions(CPPJSLIB_BUILD_LIB)