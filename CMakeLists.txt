cmake_minimum_required(VERSION 3.12)
project(CppJsLib)

set(CMAKE_CXX_STANDARD 17)

option(USE_CONAN FALSE)

if (USE_CONAN)
    include(${CMAKE_SOURCE_DIR}/conanbuildinfo.cmake)
    conan_basic_setup()
endif ()

include_directories(${CMAKE_SOURCE_DIR})
add_executable(${PROJECT_NAME} test/test.cpp CppJsLib.hpp)

if (USE_CONAN)
    target_precompile_headers(${PROJECT_NAME} PUBLIC CppJsLib.hpp)

    target_link_libraries(${PROJECT_NAME} ${CONAN_LIBS})

    add_compile_definitions(CPPJSLIB_ENABLE_WEBSOCKET)
    add_compile_definitions(CPPJSLIB_ENABLE_HTTPS)
else ()
    include_directories(include)

    target_precompile_headers(${PROJECT_NAME} PUBLIC CppJsLib.hpp)

    option(NO_SSL FALSE)
    option(NO_WEBSOCKET FALSE)

    include(CppJsLib.cmake)
    initCppJsLib(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/include)
endif ()

if (MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W3 /bigobj)
else ()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -pedantic)
endif ()