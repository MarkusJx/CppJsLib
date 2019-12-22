cmake_minimum_required(VERSION 3.15)
project(CppJsLib)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

file(GLOB webInterface
        "*.cpp"
        "*.hpp"
        )

file(GLOB extern
        "../extern/*.cpp"
        "../extern/*.hpp"
        "../extern/*.h"
        )

add_compile_definitions(COMPILATION)

add_library(CppJsLib SHARED "${webInterface}" "${extern}")

target_include_directories(CppJsLib PRIVATE "../extern")

file(REMOVE_RECURSE $<TARGET_FILE_DIR:CppJsLib>/httpServerJs)

add_custom_command(TARGET CppJsLib PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/httpServerJs $<TARGET_FILE_DIR:CppJsLib>/httpServerJs)