# Initialize CppJsLib
# Usage: initCppJsLib(target_name source_dir include_dir <ENABLE_WEBSOCKET> <ENABLE_HTTPS> <USE_JUTILS> <BUILD_JNI_DLL>)
function(initCppJsLib target source_dir include_dir)
    add_compile_definitions(_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS) # Silence all Boost deprecation warnings
    add_compile_definitions(COMPILATION)
    add_compile_definitions(CPPJSLIB_STATIC_DEFINE)

    find_file(HTTPLIB httplib.h HINTS ${include_dir})
    find_file(JSON json.hpp HINTS ${include_dir})

    message(STATUS "CppJsLib include folder was set to ${include_dir}")

    if (NOT WIN32)
        option(x86 FALSE)

        if (x86)
            set_target_properties(${target} PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
            message(STATUS "Building 32 bit")
            # Specify Openssl Path
            SET(CMAKE_LIBRARY_PATH "/usr/lib/i386-linux-gnu")
            include_directories(BEFORE "/usr/include/i386-linux-gnu")
        endif ()
    endif ()

    if (ARGV3)
        message(STATUS "Setting ENABLE_WEBSOCKET to ${ARGV3}")
        set(ENABLE_WEBSOCKET ${ARGV3})
    else ()
        option(ENABLE_WEBSOCKET FALSE)
        message(STATUS "Setting ENABLE_WEBSOCKET to ${ENABLE_WEBSOCKET}")
    endif ()

    if (ARGV4)
        message(STATUS "Setting HTTPS to ${ARGV4}")
        set(HTTPS ${ARGV4})
    else ()
        option(ENABLE_HTTPS FALSE)
        set(HTTPS ${ENABLE_HTTPS})
        message(STATUS "Setting HTTPS to ${ENABLE_HTTPS}")
    endif ()

    if (ARGV5)
        message(STATUS "Setting USE_JUTILS to ${ARGV5}")
        set(USE_JUTILS ${ARGV5})
    else ()
        option(USE_JUTILS FALSE)
        message(STATUS "Setting USE_JUTILS to ${USE_JUTILS}")
    endif ()

    if (ARGV6)
        message(STATUS "Setting BUILD_JNI_DLL to ${ARGV6}")
        set(BUILD_JNI_DLL ${ARGV6})
        if (${BUILD_JNI_DLL})
            message(STATUS "Building jni lib, enabling websocket and https support")
            set(HTTPS TRUE)
            set(ENABLE_WEBSOCKET TRUE)
        endif ()
    else ()
        option(BUILD_JNI_DLL FALSE)
        message(STATUS "Setting BUILD_JNI_DLL to ${BUILD_JNI_DLL}")
        if (BUILD_JNI_DLL)
            message(STATUS "Building jni lib, enabling websocket and https support")
            set(HTTPS TRUE)
            set(ENABLE_WEBSOCKET TRUE)
        endif ()
    endif ()

    if (BUILD_JNI_DLL AND NOT DEFINED JDK_INCLUDE_DIR AND NOT DEFINED ENV{JAVA_HOME})
        message(FATAL_ERROR "JDK_INCLUDE_DIR and JAVA_HOME not defined")
    else ()
        if (DEFINED JDK_INCLUDE_DIR)
            message(STATUS "JDK_INCLUDE_DIR defined: ${JDK_INCLUDE_DIR}")
        elseif (DEFINED ENV{JAVA_HOME})
            if (EXISTS $ENV{JAVA_HOME}/include)
                set(JDK_INCLUDE_DIR "$ENV{JAVA_HOME}/include")
                message(STATUS "JAVA_HOME defined, setting JDK_INCLUDE_DIR to: ${JDK_INCLUDE_DIR}")
            else ()
                message(FATAL_ERROR "$ENV{JAVA_HOME}/include does not exist, cannot continue")
            endif ()
        endif ()
    endif ()

    if (${JSON} MATCHES ${include_dir})
        message(STATUS "json.hpp found in include folder")
    else ()
        message(STATUS "json.hpp not found in include folder, downloading it")
        file(DOWNLOAD https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp ${include_dir}/json.hpp SHOW_PROGRESS STATUS JSON_DOWNLOAD)
        if (JSON_DOWNLOAD)
            message(STATUS "json.hpp download finished successfully")
        else ()
            message(FATAL_ERROR "json.hpp download failed. Cannot continue without it")
        endif ()
    endif ()

    if (${HTTPLIB} MATCHES ${include_dir})
        message(STATUS "httplib.h found in include folder")
    else ()
        message(STATUS "httplib.h not found in include folder, downloading it")
        file(DOWNLOAD https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h ${include_dir}/httplib.h SHOW_PROGRESS STATUS HTTPLIB_DOWNLOAD)
        if (HTTPLIB_DOWNLOAD)
            message(STATUS "httplib.h download finished successfully")
        else ()
            message(FATAL_ERROR "httplib.h download failed. Cannot continue without it")
        endif ()
    endif ()

    if (ENABLE_WEBSOCKET)
        find_path(WEBSOCKETPP websocketpp HINTS ${include_dir})
        if (NOT EXISTS ${WEBSOCKETPP})
            message(STATUS "Could not find webocketpp")
            find_program(GIT_PATH git)
            if (EXISTS ${GIT_PATH})
                message(STATUS "Git is installed, downloading websocketpp")
                execute_process(COMMAND "${GIT_PATH}" "clone" "https://github.com/zaphoyd/websocketpp" WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} RESULT_VARIABLE GIT_RES)
                if (${GIT_RES} STREQUAL "0" AND EXISTS "${CMAKE_SOURCE_DIR}/websocketpp/websocketpp")
                    file(COPY ${CMAKE_SOURCE_DIR}/websocketpp/websocketpp DESTINATION ${include_dir})
                else ()
                    message(STATUS "Git clone failed, retrying")
                    execute_process(COMMAND "${GIT_PATH}" "clone" "https://github.com/zaphoyd/websocketpp" WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} RESULT_VARIABLE GIT_RES)
                    if (${GIT_RES} STREQUAL "0" AND EXISTS "${CMAKE_SOURCE_DIR}/websocketpp/websocketpp")
                        file(COPY ${CMAKE_SOURCE_DIR}/websocketpp/websocketpp DESTINATION ${include_dir})
                    else ()
                        message(WARNING "Could not download websocketpp, disabling websocket")
                        set(ENABLE_WEBSOCKET FALSE)
                    endif ()
                endif ()
            else ()
                message(WARNING "Git is not installed, cannot download websocketpp, therefore, disabling websocket protocol support")
                set(ENABLE_WEBSOCKET FALSE)
            endif ()
        else ()
            message(STATUS "Websocketpp found: ${WEBSOCKETPP}/websocketpp")
        endif ()
    endif ()

    if (ENABLE_WEBSOCKET)
        if (WIN32)
            if (DEFINED ENV{BOOST_ROOT})
                message(STATUS "BOOST_ROOT defined: $ENV{BOOST_ROOT}")
                if (DEFINED ENV{GITHUB_ACTIONS})
                    message(STATUS "Building on GH Actions, adding following link dir: C:\\local\\boost_1_67_0\\lib64-msvc-14.1")
                    target_link_directories(${target} PUBLIC "C:\\local\\boost_1_67_0\\lib64-msvc-14.1")
                endif ()
                if (NOT EXISTS $ENV{BOOST_ROOT})
                    message(WARNING "$ENV{BOOST_ROOT} does not exist")
                    set(USE_BOOST FALSE)
                else ()
                    set(USE_BOOST TRUE)
                endif ()
            endif ()
        else ()
            set(USE_BOOST TRUE)
        endif ()

        if (USE_BOOST)
            set(BOOT_VERSION_LIST "1.69;1.68;1.67;1.66;1.65.1;1.65;1.64;1.63;1.62;1.61;1.60")
            message(STATUS "Searching suitable Boost version")
            foreach (BOOST_VERSION ${BOOT_VERSION_LIST})
                if (NOT WIN32)
                    find_package(Boost ${BOOST_VERSION} EXACT COMPONENTS system)
                else ()
                    find_package(Boost ${BOOST_VERSION} EXACT)
                endif ()
                if (Boost_FOUND)
                    message(STATUS "Found suitable Boost version: ${BOOST_VERSION}")
                    if (${BOOST_VERSION} STREQUAL "1.60")
                        message(STATUS "BOOST_VERSION equals 1.60, disabling BOOST_AUTO_PTR")
                        add_compile_definitions(BOOST_NO_AUTO_PTR)
                    endif ()
                    break()
                endif ()
            endforeach ()

            if (Boost_FOUND)
                message(STATUS "Boost found, building with websocket protocol support")

                add_compile_definitions(CPPJSLIB_ENABLE_WEBSOCKET)
                set(BOOST_INCLUDE_DIRS ${Boost_INCLUDE_DIRS})
                set(BOOST_LIBRARY_DIRS ${Boost_LIBRARY_DIRS})
            else ()
                message(WARNING "Boost not found, building without websocket protocol support")
                set(ENABLE_WEBSOCKET FALSE)
            endif ()
        else ()
            message(WARNING "Boost not found, building without websocket protocol support")
            set(ENABLE_WEBSOCKET FALSE)
        endif ()
    else ()
        message(STATUS "Building without websocket protocol support")
    endif ()

    if (HTTPS)
        message(STATUS "Building with HTTPS support")
        if (WIN32)
            if (DEFINED OPENSSL_PATH)
                message(STATUS "OPENSSL_PATH set to ${OPENSSL_PATH}, enabling SSL Support")
                set(OPENSSL_DIR ${OPENSSL_PATH})
            elseif (DEFINED ENV{GITHUB_ACTIONS})
                message(STATUS "Building on GH Actions, searching OpenSSL in include folder")
                set(OPENSSL_DIR ${CMAKE_SOURCE_DIR})
            else ()
                find_path(OPENSSL_DIR OpenSSL HINTS "C:")
                if (EXISTS "${OPENSSL_DIR}/OpenSSL-Win64")
                    set(OPENSSL_DIR "${OPENSSL_DIR}/OpenSSL-Win64")
                elseif (EXISTS "${OPENSSL_DIR}/OpenSSL")
                    set(OPENSSL_DIR "${OPENSSL_DIR}/OpenSSL")
                endif ()
            endif ()

            if (DEFINED OPENSSL_DIR)
                if (EXISTS ${OPENSSL_DIR})
                    set(OPENSSL_INCLUDE_DIR "${OPENSSL_DIR}/include")
                    set(OPENSSL_SSL_LIBRARY "${OPENSSL_DIR}/lib")
                    add_compile_definitions(CPPJSLIB_ENABLE_HTTPS)
                    message(STATUS "OpenSSL directory found: ${OPENSSL_DIR}, enabling SSL Support")
                else ()
                    message(WARNING "${OPENSSL_DIR} does not exist, building without SSL Support")
                    set(HTTPS FALSE)
                endif ()
            else ()
                message(WARNING "OpenSSL not found, building without SSL Support")
                set(HTTPS FALSE)
            endif ()
        else ()
            find_package(OpenSSL)
            if (OPENSSL_FOUND)
                message(STATUS "OpenSSL found, building with SSL Support")
                message(STATUS "SSL library found: ${OPENSSL_SSL_LIBRARY}")
                add_compile_definitions(CPPJSLIB_ENABLE_HTTPS)
            else ()
                find_library(CRYPTO crypto)
                find_library(SSL ssl)
                if (EXISTS ${SSL} AND EXISTS ${CRYPTO})
                    message(WARNING "find_package did not find openssl, but libssl and libcrypto were found, still disabling HTTPS Support. Sorry.")
                    set(HTTPS FALSE)
                else ()
                    set(HTTPS FALSE)
                    message(WARNING "OpenSSL was not found on this machine, building without SSL Support")
                    set(OPENSSL_INCLUDE_DIR "")
                endif ()
            endif ()
        endif ()
    endif ()

    target_include_directories(${target} PUBLIC ${include_dir} ${OPENSSL_INCLUDE_DIR} ${BOOST_INCLUDE_DIRS})
    if (DEFINED BOOST_LIBRARY_DIRS OR DEFINED OPENSSL_SSL_LIBRARY)
        target_link_directories(${target} PUBLIC ${BOOST_LIBRARY_DIRS} ${OPENSSL_SSL_LIBRARY})
    else ()
        message(STATUS "No library includes were defined, not linking anything")
    endif ()


    if (ENABLE_WEBSOCKET)
        if (WIN32)
            target_compile_options(${target} PRIVATE "/bigobj")
        else ()
            target_link_libraries(${target} boost_system)

            if ((CMAKE_CXX_COMPILER_ID STREQUAL "GNU") AND CYGWIN)
                message(STATUS "Compiler supports -Wa,-mbig-obj")
                target_compile_options(${target} PRIVATE "-Wa,-mbig-obj")
            endif ()
        endif ()
    endif ()

    if ((NOT HTTPS OR NOT ENABLE_WEBSOCKET) AND BUILD_JNI_DLL)
        message(FATAL_ERROR "BUILD_JNI_DLL is enabled but https or websocket support could not be enabled")
    endif ()

    if (HTTPS)
        if (WIN32)
            find_library(LIBCRYPTO libcrypto HINTS ${OPENSSL_SSL_LIBRARY})
            find_library(LIBSSL libssl HINTS ${OPENSSL_SSL_LIBRARY})
        else ()
            find_library(LIBCRYPTO crypto HINTS ${OPENSSL_SSL_LIBRARY})
            find_library(LIBSSL ssl HINTS ${OPENSSL_SSL_LIBRARY})
        endif ()

        if (EXISTS ${LIBSSL} AND EXISTS ${LIBCRYPTO})
            message(STATUS "Found libssl: ${LIBSSL} and libcrypto: ${LIBCRYPTO}")
            if (NOT APPLE)
                target_link_libraries(${target} ${LIBCRYPTO} ${LIBSSL})
            endif ()
        else ()
            if (DEFINED ENV{GITHUB_ACTIONS})
                target_link_libraries(${target} libcryptoMD.lib libsslMD.lib)
            else ()
                message(FATAL_ERROR "Libssl (${LIBSSL}) or libcrypto (${LIBCRYPTO}) do not exist")
            endif ()
        endif ()
    endif ()

    message(STATUS "CppJsLib subdirectory: ${source_dir}/")

    set(base_sources ${source_dir}/CppJsLib.cpp ${source_dir}/CppJsLib.hpp)

    FILE(GLOB utils
            "${source_dir}/utils/*.hpp"
            "${source_dir}/utils/*.cpp"
            )

    FILE(GLOB include
            ${source_dir}/include/*.h
            )

    if (USE_JUTILS)
        add_compile_definitions(CPPJSLIB_USE_JUTILS)
        target_link_directories(${target} PRIVATE ${source_dir}/lib)
        target_link_libraries(${target} cppJsLibJUtils)
    endif ()

    if (NOT WIN32)
        target_link_libraries(${target} pthread)
    endif ()

    if (BUILD_JNI_DLL)
        message(STATUS "Building dll for use with Java")
        FILE(GLOB jni
                ${source_dir}/jni/*.h
                ${source_dir}/jni/*.cpp
                )
        target_include_directories(${target} PRIVATE "${JDK_INCLUDE_DIR}")
        if (WIN32)
            target_include_directories(${target} PRIVATE "${JDK_INCLUDE_DIR}\\win32")
        elseif (UNIX AND NOT APPLE)
            target_include_directories(${target} PRIVATE "${JDK_INCLUDE_DIR}/linux")
        elseif (APPLE)
            target_include_directories(${target} PRIVATE "${JDK_INCLUDE_DIR}/darwin")
        endif ()
    endif ()

    target_sources(${target} PRIVATE ${base_sources} ${utils} ${include} ${jni})
    target_include_directories(${target} PRIVATE ${source_dir})
endfunction()