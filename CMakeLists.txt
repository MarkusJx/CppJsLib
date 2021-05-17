cmake_minimum_required(VERSION 3.12)
project(CppJsLib)

set(CMAKE_CXX_STANDARD 17)

option(USE_CONAN FALSE)

# Get the ExternalProject module
include(ExternalProject)

if (NOT USE_CONAN)
    # Get and build gtest
    ExternalProject_Add(gtest_proj
            URL https://github.com/google/googletest/archive/release-1.10.0.tar.gz
            PREFIX ${CMAKE_CURRENT_BINARY_DIR}/gtest
            CMAKE_ARGS -DBUILD_GMOCK=OFF -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
            )

    ExternalProject_Get_Property(gtest_proj install_dir)
    set(gtest_dir ${install_dir})
endif ()

if (USE_CONAN)
    include(${CMAKE_SOURCE_DIR}/conanbuildinfo.cmake)
    conan_basic_setup()
endif ()

include_directories(${CMAKE_SOURCE_DIR})
add_executable(${PROJECT_NAME} test/test.cpp CppJsLib.hpp)

if (NOT USE_CONAN)
    # Set link directories to gtest_dir/lib
    target_link_directories(${PROJECT_NAME} PUBLIC ${gtest_dir}/lib)
    include_directories(${gtest_dir}/include)

    # Link test against gtest
    if (WIN32)
        set(CMAKE_CXX_FLAGS_RELEASE "/MT")
        set(CMAKE_CXX_FLAGS_DEBUG "/MTd")
        target_link_libraries(${PROJECT_NAME} PUBLIC gtest_maind gtestd)
    else ()
        target_link_libraries(${PROJECT_NAME} PUBLIC gtest_main gtest pthread)
    endif ()

    # Add dependencies
    add_dependencies(${PROJECT_NAME} gtest_proj)
endif ()

if (USE_CONAN)
    target_precompile_headers(${PROJECT_NAME} PUBLIC CppJsLib.hpp)

    target_link_libraries(${PROJECT_NAME} PUBLIC ${CONAN_LIBS})

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