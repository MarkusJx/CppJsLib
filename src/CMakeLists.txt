cmake_minimum_required(VERSION 3.12)
project(CppJsLib)

set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

file(GLOB webInterface
        "*.cpp"
        "*.hpp"
        )

#include_directories("C:\\Program Files\\OpenSSL-Win64\\include")
#set(ssllib "C:\\Program Files\\OpenSSL-Win64\\lib")

add_compile_definitions(COMPILATION)

add_library(CppJsLib SHARED "${webInterface}")

target_include_directories(CppJsLib PRIVATE "../extern")

#target_link_libraries(CppJsLib "${ssllib}/libssl.lib" "${ssllib}/libcrypto.lib")

file(REMOVE_RECURSE $<TARGET_FILE_DIR:CppJsLib>/CppJsLibJs)

add_custom_command(TARGET CppJsLib PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/CppJsLibJs $<TARGET_FILE_DIR:CppJsLib>/CppJsLibJs)