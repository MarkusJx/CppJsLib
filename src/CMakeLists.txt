cmake_minimum_required(VERSION 3.12)
project(CppJsLib)

set(CMAKE_CXX_STANDARD 17)

file(GLOB webInterface
        "*.cpp"
        "*.hpp"
        )

option(HTTPS "Enable https support" FALSE)
option(WinGHBuild FALSE)

if (WinGHBuild)
    message(STATUS "Building on GitHub on Windows")
endif ()

if (HTTPS)
    message(STATUS "Building with HTTPS support")
    if (NOT WinGHBuild)
        include_directories("C:\\Program Files\\OpenSSL-Win64\\include")
        set(ssllib "C:\\Program Files\\OpenSSL-Win64\\lib")
    endif ()
    add_compile_definitions(CPPJSLIB_ENABLE_HTTPS)
endif ()


add_compile_definitions(COMPILATION)

add_library(CppJsLib SHARED "${webInterface}")

target_include_directories(CppJsLib PRIVATE "../include")

if (HTTPS)
    if (WinGHBuild)
        message(STATUS "linking downloaded libssl and libcrypto")
        target_link_libraries(CppJsLib ../lib/libsslMD ../lib/libcryptoMD)
    else ()
        target_link_libraries(CppJsLib "${ssllib}/libssl.lib" "${ssllib}/libcrypto.lib")
    endif ()
endif ()

file(REMOVE_RECURSE $<TARGET_FILE_DIR:CppJsLib>/CppJsLibJs)

add_custom_command(TARGET CppJsLib PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/CppJsLibJs $<TARGET_FILE_DIR:CppJsLib>/CppJsLibJs)