# Initialize CppJsLib
# Usage: initCppJsLib(target_name source_dir include_dir <ENABLE_WEBSOCKET> <ENABLE_HTTPS> <USE_JUTILS> <BUILD_JNI_DLL>)
function(initCppJsLib target source_dir include_dir)
    add_compile_definitions(_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS) # Silence all Boost deprecation warnings
    add_compile_definitions(COMPILATION)
    add_compile_definitions(CPPJSLIB_STATIC_DEFINE)

    find_file(HTTPLIB httplib.h HINTS ${include_dir})
    find_file(JSON json.hpp HINTS ${include_dir})

    message(STATUS "CppJsLib include folder was set to ${include_dir}")

    # Add x86 option for unix systems
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
        message(STATUS "Setting BUILD_JNI_LIB to ${ARGV6}")
        set(BUILD_JNI_DLL ${ARGV6})
        if (${BUILD_JNI_DLL})
            # jni lib requires websocket and HTTPS support
            message(STATUS "Building jni lib, enabling websocket and https support")
            #set(HTTPS TRUE)
            #set(ENABLE_WEBSOCKET TRUE)
        endif ()
    else ()
        option(BUILD_JNI_DLL FALSE)

        # Add BUILD_JNI_LIB option, which makes more sense than BUILD_JNI_DLL on non-win systems
        option(BUILD_JNI_LIB FALSE)
        if (BUILD_JNI_LIB)
            set(BUILD_JNI_DLL TRUE)
        endif ()

        message(STATUS "Setting BUILD_JNI_LIB to ${BUILD_JNI_DLL}")
        if (BUILD_JNI_DLL)
            message(STATUS "Building jni lib, enabling websocket and https support")
            #set(HTTPS TRUE)
            #set(ENABLE_WEBSOCKET TRUE)
        endif ()
    endif ()

    # Check if JDK_INCLUDE_DIR or JAVA_HOME is defined if jni lib is built
    if (BUILD_JNI_DLL AND NOT DEFINED JDK_INCLUDE_DIR AND NOT DEFINED ENV{JAVA_HOME})
        message(FATAL_ERROR "JDK_INCLUDE_DIR and JAVA_HOME not defined")
    else ()
        if (DEFINED JDK_INCLUDE_DIR)
            message(STATUS "JDK_INCLUDE_DIR defined: ${JDK_INCLUDE_DIR}")
        elseif (DEFINED ENV{JAVA_HOME})
            # Check if JAVA_HOME points to JDK
            if (EXISTS $ENV{JAVA_HOME}/include)
                set(JDK_INCLUDE_DIR "$ENV{JAVA_HOME}/include")
                message(STATUS "JAVA_HOME defined, setting JDK_INCLUDE_DIR to: ${JDK_INCLUDE_DIR}")
            else ()
                message(FATAL_ERROR "$ENV{JAVA_HOME}/include does not exist, cannot continue")
            endif ()
        endif ()
    endif ()

    # Check if json.hpp exists, otherwise download it
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

    # Check if httplib.h exists, otherwise download it
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
        # Check if websocketpp exists, otherwise download it
        find_path(WEBSOCKETPP websocketpp HINTS ${include_dir})
        if (NOT EXISTS ${WEBSOCKETPP})
            message(STATUS "Could not find webocketpp")

            # Check if git exists, if so, download websocketpp
            find_program(GIT_PATH git)
            if (EXISTS ${GIT_PATH})
                message(STATUS "Git is installed, downloading websocketpp")
                # Invoke git clone
                execute_process(COMMAND "${GIT_PATH}" "clone" "https://github.com/zaphoyd/websocketpp" WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} RESULT_VARIABLE GIT_RES)
                # Check if command was successful
                if (${GIT_RES} STREQUAL "0" AND EXISTS "${CMAKE_SOURCE_DIR}/websocketpp/websocketpp")
                    file(COPY ${CMAKE_SOURCE_DIR}/websocketpp/websocketpp DESTINATION ${include_dir})
                else ()
                    # Retry
                    message(STATUS "Git clone failed, retrying")
                    execute_process(COMMAND "${GIT_PATH}" "clone" "https://github.com/zaphoyd/websocketpp" WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} RESULT_VARIABLE GIT_RES)
                    # Check if command was successful
                    if (${GIT_RES} STREQUAL "0" AND EXISTS "${CMAKE_SOURCE_DIR}/websocketpp/websocketpp")
                        file(COPY ${CMAKE_SOURCE_DIR}/websocketpp/websocketpp DESTINATION ${include_dir})
                    else ()
                        message(WARNING "Could not download websocketpp, disabling websocket")
                        set(ENABLE_WEBSOCKET FALSE)
                    endif ()
                endif ()
            else ()
                # Git is not installed, cannot download websocketpp, therefore, disable websocket support
                message(WARNING "Git is not installed, cannot download websocketpp, therefore, disabling websocket protocol support")
                set(ENABLE_WEBSOCKET FALSE)
            endif ()
        else ()
            message(STATUS "Websocketpp found: ${WEBSOCKETPP}/websocketpp")
        endif ()
    endif ()

    # Check for boost
    if (ENABLE_WEBSOCKET)
        if (WIN32)
            if (DEFINED ENV{BOOST_ROOT})
                message(STATUS "BOOST_ROOT defined: $ENV{BOOST_ROOT}")
                if (DEFINED ENV{GITHUB_ACTIONS})
                    # GH Actions installs Boost via chocolatey, set appropriate link dir
                    message(STATUS "Building on GH Actions, adding following link dir: C:\\local\\boost_1_67_0\\lib64-msvc-14.1")
                    target_link_directories(${target} PUBLIC "C:\\local\\boost_1_67_0\\lib64-msvc-14.1")
                endif ()
                # BOOST_ROOT is required on windows
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
            # Search for appropriate Boost version
            message(STATUS "Searching suitable Boost version")

            if (NOT WIN32)
                # Search for component 'system' on non-windows machines
                find_package(Boost 1.65 COMPONENTS system)
            else ()
                if (DEFINED ENV{GITHUB_ACTIONS})
                    # Use Boost version 1.67 on gh actions
                    find_package(Boost 1.67 EXACT)
                else()
                    find_package(Boost 1.65)
                endif ()
            endif ()

            if (Boost_FOUND)
                # If boost was found, enable websocket support and add link and include dirs
                message(STATUS "Boost found, building with websocket protocol support")
                message(STATUS "Boost version: ${Boost_VERSION_STRING}")

                add_compile_definitions(CPPJSLIB_ENABLE_WEBSOCKET)
                set(BOOST_INCLUDE_DIRS ${Boost_INCLUDE_DIRS})
                set(BOOST_LIBRARY_DIRS ${Boost_LIBRARY_DIRS})
            else ()
                # Disable websocket support
                message(WARNING "Boost not found, building without websocket protocol support")
                set(ENABLE_WEBSOCKET FALSE)
            endif ()
        else ()
            # Disable websocket support
            message(WARNING "Boost not found, building without websocket protocol support")
            set(ENABLE_WEBSOCKET FALSE)
        endif ()
    else ()
        message(STATUS "Building without websocket protocol support")
    endif ()

    if (HTTPS)
        message(STATUS "Building with HTTPS support")
        if (WIN32)
            # Check if OPENSSL_PATH is defined, enable HTTPS support
            if (DEFINED OPENSSL_PATH)
                message(STATUS "OPENSSL_PATH set to ${OPENSSL_PATH}, enabling SSL Support")
                set(OPENSSL_DIR ${OPENSSL_PATH})
            elseif (DEFINED ENV{GITHUB_ACTIONS})
                # On GH Actions, OpenSSL will be located in the source dir
                message(STATUS "Building on GH Actions, searching OpenSSL in include folder")
                set(OPENSSL_DIR ${CMAKE_SOURCE_DIR})
            else ()
                # Find OpenSSL on windows
                find_path(OPENSSL_DIR OpenSSL HINTS "C:")
                if (EXISTS "${OPENSSL_DIR}/OpenSSL-Win64")
                    set(OPENSSL_DIR "${OPENSSL_DIR}/OpenSSL-Win64")
                elseif (EXISTS "${OPENSSL_DIR}/OpenSSL")
                    set(OPENSSL_DIR "${OPENSSL_DIR}/OpenSSL")
                endif ()
            endif ()

            if (DEFINED OPENSSL_DIR)
                if (EXISTS ${OPENSSL_DIR})
                    # Set OpenSSL include and library directories and enable HTTPS
                    set(OPENSSL_INCLUDE_DIR "${OPENSSL_DIR}/include")
                    set(OPENSSL_LIBRARY_DIR "${OPENSSL_DIR}/lib")
                    add_compile_definitions(CPPJSLIB_ENABLE_HTTPS)
                    message(STATUS "OpenSSL directory found: ${OPENSSL_DIR}, enabling SSL Support")
                else ()
                    # Disable HTTPS
                    message(WARNING "${OPENSSL_DIR} does not exist, building without SSL Support")
                    set(HTTPS FALSE)
                endif ()
            else ()
                # Disable HTTPS
                message(WARNING "OpenSSL not found, building without SSL Support")
                set(HTTPS FALSE)
            endif ()
        else ()
            # Use find_package to find OpenSSL
            find_package(OpenSSL)
            if (OPENSSL_FOUND)
                # OpenSSL was found, enable HTTPS support
                message(STATUS "OpenSSL found, building with SSL Support")
                message(STATUS "OpenSSL libaries: ${OPENSSL_INCLUDE_DIR}/../lib")
                set(OPENSSL_LIBRARY_DIR "${OPENSSL_INCLUDE_DIR}/../lib")
                add_compile_definitions(CPPJSLIB_ENABLE_HTTPS)
            else ()
                # OpenSSL was not found, disabling HTTPS support
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

    # Add Boost and OpenSSL include directories
    target_include_directories(${target} PUBLIC ${include_dir} ${OPENSSL_INCLUDE_DIR} ${BOOST_INCLUDE_DIRS})

    # Add Boost and OpenSSL link directories, if required and found
    if (DEFINED BOOST_LIBRARY_DIRS OR (DEFINED OPENSSL_SSL_LIBRARY AND DEFINED OPENSSL_CRYPTO_LIBRARY) OR DEFINED OPENSSL_LIBRARY_DIR)
        target_link_directories(${target} PUBLIC ${BOOST_LIBRARY_DIRS} ${OPENSSL_LIBRARY_DIR})
    else ()
        message(STATUS "No library includes were defined, not linking anything")
    endif ()

    if (ENABLE_WEBSOCKET)
        if (WIN32)
            # Windows: add compiler flag /bigobj to increase number of sections on .obj file
            target_compile_options(${target} PRIVATE "/bigobj")
        else ()
            # Not Windows: link against boost_system
            target_link_libraries(${target} boost_system)

            # Add compiler flags to prevent 'too many sections' error
            if ((CMAKE_CXX_COMPILER_ID STREQUAL "GNU") AND CYGWIN)
                message(STATUS "Compiler supports -Wa,-mbig-obj")
                target_compile_options(${target} PRIVATE "-Wa,-mbig-obj")
            endif ()
        endif ()
    endif ()

    # JNI lib requires Websocket and HTTPS
    #if ((NOT HTTPS OR NOT ENABLE_WEBSOCKET) AND BUILD_JNI_DLL)
    #    message(FATAL_ERROR "BUILD_JNI_DLL is enabled but https or websocket support could not be enabled")
    #endif ()

    if (HTTPS)
        if (WIN32)
            find_library(LIBCRYPTO libcrypto HINTS ${OPENSSL_LIBRARY_DIR} ${OPENSSL_CRYPTO_LIBRARY})
            find_library(LIBSSL libssl HINTS ${OPENSSL_LIBRARY_DIR} ${OPENSSL_SSL_LIBRARY})
        else ()
            find_library(LIBCRYPTO crypto HINTS ${OPENSSL_LIBRARY_DIR} ${OPENSSL_CRYPTO_LIBRARY})
            find_library(LIBSSL ssl HINTS ${OPENSSL_LIBRARY_DIR} ${OPENSSL_SSL_LIBRARY})
        endif ()

        if (EXISTS ${LIBSSL} AND EXISTS ${LIBCRYPTO})
            message(STATUS "Found libssl: ${LIBSSL} and libcrypto: ${LIBCRYPTO}")
            if (NOT APPLE)
                target_link_libraries(${target} ${LIBCRYPTO} ${LIBSSL})
            else ()
                # Darwin cannot link against *.dylib
                target_link_libraries(${target} crypto ssl)
            endif ()
        else ()
            if (DEFINED ENV{GITHUB_ACTIONS} AND WIN32)
                # Win32 on GitHub actions links against libcryptoMD and libsslMD in lib/ folder
                target_link_libraries(${target} libcryptoMD.lib libsslMD.lib)
            else ()
                message(FATAL_ERROR "Libssl (${LIBSSL}) or libcrypto (${LIBCRYPTO}) do not exist")
            endif ()
        endif ()
    endif ()

    message(STATUS "CppJsLib subdirectory: ${source_dir}/")

    # Set all sources
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

    # Not windows: link against pthread for threading support
    if (NOT WIN32)
        target_link_libraries(${target} pthread)
    endif ()

    if (BUILD_JNI_DLL)
        message(STATUS "Building dll for use with Java")
        FILE(GLOB jni
                ${source_dir}/jni/*.h
                ${source_dir}/jni/*.cpp
                )

        # Set base JDK include folder
        target_include_directories(${target} PRIVATE "${JDK_INCLUDE_DIR}")

        # Add os-specific JDK include folder
        if (WIN32)
            target_include_directories(${target} PRIVATE "${JDK_INCLUDE_DIR}\\win32")
        elseif (UNIX AND NOT APPLE)
            target_include_directories(${target} PRIVATE "${JDK_INCLUDE_DIR}/linux")
        elseif (APPLE)
            target_include_directories(${target} PRIVATE "${JDK_INCLUDE_DIR}/darwin")
        endif ()
    endif ()

    # Add all sources to the target and add CppJsLib.hpp to include path
    target_sources(${target} PRIVATE ${base_sources} ${utils} ${include} ${jni})
    target_include_directories(${target} PRIVATE ${source_dir})
endfunction()