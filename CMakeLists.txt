cmake_minimum_required(VERSION 3.12)
project(CppJsLib)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

add_executable(${PROJECT_NAME} test.cpp CppJsLib.hpp)

target_precompile_headers(${PROJECT_NAME} PUBLIC CppJsLib.hpp)

option(NO_SSL FALSE)
option(NO_WEBSOCKET FALSE)

include(CppJsLib.cmake)
initCppJsLib(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/include)

if (MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /bigobj)
else ()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -pedantic)
endif ()