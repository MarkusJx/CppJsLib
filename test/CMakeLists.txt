cmake_minimum_required(VERSION 3.12)
project(CppJsLibTests)

set(CMAKE_CXX_STANDARD 17)

option(HTTPS FALSE)
option(ENABLE_WEBSOCKET FALSE)
option(USE_DLL FALSE)

include("${CMAKE_SOURCE_DIR}/src/InitCppJsLib.cmake")

if (DEFINED ENV{GITHUB_ACTIONS})
    message(STATUS "Github Actions is for sure building this")
    add_compile_definitions(TEST_GHBUILD)
endif ()

if (ENABLE_WEBSOCKET)
    add_compile_definitions(TEST_ENABLE_WEBSOCKET)
endif ()

if (HTTPS)
    add_compile_definitions(TEST_ENABLE_HTTPS)
    message(STATUS "Building Tests with HTTPS enabled")
endif ()

add_executable(Test main.cpp)
if (USE_DLL)
    target_link_libraries(Test CppJsLib)
    add_compile_definitions(TEST_USE_DLL)
else ()
    initCppJsLib(Test "${CMAKE_SOURCE_DIR}/src" "${CMAKE_SOURCE_DIR}/include" ENABLE_WEBSOCKET HTTPS)
endif ()

target_include_directories(Test PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_include_directories(Test PRIVATE "${CMAKE_SOURCE_DIR}/include")

file(REMOVE_RECURSE $<TARGET_FILE_DIR:Test>/web)

add_custom_command(TARGET Test PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/test/web $<TARGET_FILE_DIR:Test>/web)

if (FALSE)
    if (CMAKE_SYSTEM_NAME MATCHES "CYGWIN")
        message(STATUS "Building on Cygwin")
        file(REMOVE_RECURSE $<TARGET_FILE_DIR:Test>/cygCppJsLib.dll)
        add_custom_command(TARGET Test PRE_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                $<TARGET_FILE_DIR:CppJsLib>/cygCppJsLib.dll $<TARGET_FILE_DIR:Test>/cygCppJsLib.dll)
    elseif (CMAKE_SYSTEM_NAME MATCHES "Darwin")
        message(STATUS "Building on Apple")
        file(REMOVE_RECURSE $<TARGET_FILE_DIR:Test>/libCppJsLib.dylib)
        add_custom_command(TARGET Test PRE_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                $<TARGET_FILE_DIR:CppJsLib>/libCppJsLib.dylib $<TARGET_FILE_DIR:Test>/libCppJsLib.dylib)
    elseif (CMAKE_SYSTEM_NAME MATCHES "Linux")
        message(STATUS "Building on Linux")
        set(THREADS_PREFER_PTHREAD_FLAG ON)
        find_package(Threads REQUIRED)
        target_link_libraries(Test Threads::Threads)

        file(REMOVE_RECURSE $<TARGET_FILE_DIR:Test>/libCppJsLib.so)
        add_custom_command(TARGET Test PRE_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                $<TARGET_FILE_DIR:CppJsLib>/libCppJsLib.so $<TARGET_FILE_DIR:Test>/libCppJsLib.so)
    else ()
        file(REMOVE_RECURSE $<TARGET_FILE_DIR:Test>/CppJsLib.dll)
        add_custom_command(TARGET Test PRE_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                $<TARGET_FILE_DIR:CppJsLib>/CppJsLib.dll $<TARGET_FILE_DIR:Test>/CppJsLib.dll)
    endif ()
endif ()