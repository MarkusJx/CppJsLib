cmake_minimum_required(VERSION 3.12)
project(CppJsLib)

set(CMAKE_CXX_STANDARD 17)

file(GLOB webInterface
        "*.cpp"
        "*.hpp"
        )

option(HTTPS "Enable https support" FALSE)
option(ENABLE_WEBSOCKET "Enable websocket protocol support" FALSE)

add_compile_definitions(_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS) # Silence all Boost deprecation warnings

if (ENABLE_WEBSOCKET)
    if (DEFINED ENV{GITHUB_ACTIONS})
        message(STATUS "Building with gh actions, setting BOOST_1_69 to include folder")
        set(ENV{BOOST_1_69} ${CMAKE_SOURCE_DIR}/include/boost_1_69_0)
        add_compile_definitions(CPPJSLIB_ENABLE_WEBSOCKET)
    endif()

    message(STATUS "Building with websocket protocol support")
    if (DEFINED ENV{BOOST_1_69})
        message(STATUS "Boost variable defined: $ENV{BOOST_1_69}")
        add_compile_definitions(CPPJSLIB_ENABLE_WEBSOCKET)
    else()
        message(FATAL_ERROR "BOOST_1_69 variable not defined")
    endif ()
else()
    message(STATUS "Building without websocket protocol support")
endif ()

if (HTTPS)
    message(STATUS "Building with HTTPS support")
    if (NOT DEFINED ENV{GITHUB_ACTIONS})
        include_directories("C:\\Program Files\\OpenSSL-Win64\\include")
        set(ssllib "C:\\Program Files\\OpenSSL-Win64\\lib")
    endif ()
    add_compile_definitions(CPPJSLIB_ENABLE_HTTPS)
endif ()

add_compile_definitions(COMPILATION)

add_library(CppJsLib SHARED "${webInterface}")

include_directories(${CMAKE_SOURCE_DIR}/include)

if (ENABLE_WEBSOCKET)
    target_include_directories(CppJsLib PUBLIC "$ENV{BOOST_1_69}")
    target_link_directories(CppJsLib PUBLIC "$ENV{BOOST_1_69}\\stage\\lib")
    message(STATUS "Linking to $ENV{BOOST_1_69}\\stage\\lib")

    target_compile_options(CppJsLib PRIVATE "/bigobj")
endif ()

if (HTTPS)
    if (DEFINED ENV{GITHUB_ACTIONS})
        message(STATUS "linking downloaded libssl and libcrypto")
        target_link_libraries(CppJsLib "${CMAKE_SOURCE_DIR}/lib/libsslMD.lib" "${CMAKE_SOURCE_DIR}/lib/libcryptoMD.lib")
    else ()
        target_link_libraries(CppJsLib "${ssllib}/libssl.lib" "${ssllib}/libcrypto.lib")
    endif ()
endif ()

file(REMOVE_RECURSE $<TARGET_FILE_DIR:CppJsLib>/CppJsLibJs)

add_custom_command(TARGET CppJsLib PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/CppJsLibJs $<TARGET_FILE_DIR:CppJsLib>/CppJsLibJs)