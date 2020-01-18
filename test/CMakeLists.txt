cmake_minimum_required(VERSION 3.12)
project(CppJsLibTests)

set(CMAKE_CXX_STANDARD 17)

option(HTTPS FALSE)

if (HTTPS)
    add_compile_definitions(TEST_ENABLE_HTTPS)
    message(STATUS "Building Tests with HTTPS enabled")
endif ()

add_executable(Test main.cpp)
target_include_directories(Test PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_include_directories(Test PRIVATE "${CMAKE_SOURCE_DIR}/include")
target_link_libraries(Test CppJsLib)

file(REMOVE_RECURSE $<TARGET_FILE_DIR:Test>/web)

add_custom_command(TARGET Test PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/test/web $<TARGET_FILE_DIR:Test>/web)

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
