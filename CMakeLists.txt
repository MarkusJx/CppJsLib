cmake_minimum_required(VERSION 3.12)
project(CppJsLib)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

add_executable(${PROJECT_NAME} test.cpp CppJsLib.hpp)

target_precompile_headers(${PROJECT_NAME} PUBLIC CppJsLib.hpp)

# Use find_package to find OpenSSL
find_package(OpenSSL)
if (OPENSSL_FOUND)
    # OpenSSL was found, enable HTTPS support
    message(STATUS "OpenSSL found, building with SSL Support")
    message(STATUS "OpenSSL libaries: ${OPENSSL_INCLUDE_DIR}/../lib")
    set(OPENSSL_LIBRARY_DIR "${OPENSSL_INCLUDE_DIR}/../lib")

    include_directories(${OPENSSL_INCLUDE_DIR})
    add_compile_definitions(CPPJSLIB_ENABLE_HTTPS)
endif()

# Search for component 'system' on non-windows machines
find_package(Boost 1.65 COMPONENTS system)
if (Boost_FOUND)
    # If boost was found, enable websocket support and add link and include dirs
    message(STATUS "Boost found, building with websocket protocol support")
    message(STATUS "Boost version: ${Boost_VERSION_STRING}")
    message(STATUS "Boost library directory: ${Boost_LIBRARY_DIRS}")
    message(STATUS "Boost include directory: ${Boost_INCLUDE_DIRS}")

    add_compile_definitions(CPPJSLIB_ENABLE_WEBSOCKET)
    include_directories(${Boost_INCLUDE_DIRS})
    target_link_directories(${PROJECT_NAME} PRIVATE ${Boost_LIBRARY_DIRS})
endif ()

if (FALSE)
option(BUILDDLL FALSE)
option(USE_DLL FALSE)
option(BUILD_JNI_DLL FALSE)
option(LINK_STATIC FALSE)

if (LINK_STATIC)
    message(STATUS "Creating static library")
    set(BUILDDLL TRUE)
endif ()

if (BUILD_JNI_DLL)
    set(BUILDDLL TRUE)
endif ()

if (DEFINED ENV{GITHUB_ACTIONS})
    message(STATUS "Building on GitHub")
endif ()

if (BUILDDLL)
    message(STATUS "Building dll")
    add_subdirectory("src")
else ()
    if (USE_DLL)
        message(STATUS "Building dll")
        add_subdirectory("src")
    endif()
    message(STATUS "Building tests")
    add_subdirectory("test")
endif ()
endif ()