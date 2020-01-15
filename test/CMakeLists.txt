cmake_minimum_required(VERSION 3.15)
project(CppJsLibTests)

set(CMAKE_CXX_STANDARD 17)

add_executable(Test main.cpp)
target_include_directories(Test PRIVATE "../src")
target_include_directories(Test PRIVATE "../extern")
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
elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
    message(STATUS "Building on Apple")
    file(REMOVE_RECURSE $<TARGET_FILE_DIR:Test>/libCppJsLib.dylib)
    add_custom_command(TARGET Test PRE_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy
            $<TARGET_FILE_DIR:CppJsLib>/libCppJsLib.dylib $<TARGET_FILE_DIR:Test>/libCppJsLib.dylib)
else ()
    file(REMOVE_RECURSE $<TARGET_FILE_DIR:Test>/CppJsLib.dll)
    add_custom_command(TARGET Test PRE_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy
            $<TARGET_FILE_DIR:CppJsLib>/CppJsLib.dll $<TARGET_FILE_DIR:Test>/CppJsLib.dll)
endif ()
