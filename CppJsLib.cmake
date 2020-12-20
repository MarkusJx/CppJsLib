function(initCppJsLib TARGET INCLUDE_DIR)
    if (NOT EXISTS ${INCLUDE_DIR})
        message(STATUS "${INCLUDE_DIR} does not exist, creating it")
        file(MAKE_DIRECTORY ${INCLUDE_DIR})
    endif ()

    function(gitCloneRepo REPOSITORY_URL OUT_DIRECTORY)
        # Check if git exists, if so, clone repo
        find_program(GIT_PATH git)
        if (EXISTS ${GIT_PATH})
            message(STATUS "Git is installed, cloning repository")
            # Invoke git clone
            execute_process(COMMAND "${GIT_PATH}" "clone" ${REPOSITORY_URL}
                    WORKING_DIRECTORY ${OUT_DIRECTORY}
                    RESULT_VARIABLE GIT_RES)
            # Check if command was successful
            if (${GIT_RES} STREQUAL "0")
                message(STATUS "Repository successfully cloned")
            else ()
                # Retry
                message(STATUS "Git clone failed, retrying")
                execute_process(COMMAND "${GIT_PATH}" "clone" ${REPOSITORY_URL}
                        WORKING_DIRECTORY ${OUT_DIRECTORY}
                        RESULT_VARIABLE GIT_RES)
                # Check if command was successful
                if (${GIT_RES} STREQUAL "0")
                    message(STATUS "Repository successfully cloned")
                else ()
                    message(FATAL_ERROR "Could not clone repository")
                endif ()
            endif ()
        else ()
            # Git is not installed, cannot download CppJsLib
            message(FATAL_ERROR "Git is not installed, cannot clone repository")
        endif ()
    endfunction(gitCloneRepo)

    function(downloadWebsocketpp)
        set(WEBSOCKETPP_DIRECTORY ${CMAKE_SOURCE_DIR}/websocketpp)
        if (EXISTS ${WEBSOCKETPP_DIRECTORY})
            message(STATUS "websocketpp directory already exists, deleting it")
            file(REMOVE_RECURSE ${WEBSOCKETPP_DIRECTORY})
        endif ()

        message(STATUS "Cloning websocketpp...")
        gitCloneRepo("https://github.com/zaphoyd/websocketpp" "${CMAKE_SOURCE_DIR}")
        if (NOT EXISTS ${WEBSOCKETPP_DIRECTORY})
            message(FATAL_ERROR "${WEBSOCKETPP_DIRECTORY} does not exist, cannot continue")
        endif ()
    endfunction(downloadWebsocketpp)

    function(copyWebsocketpp)
        if (EXISTS ${INCLUDE_DIR}/websocketpp)
            message(STATUS "${INCLUDE_DIR}/websocketpp already exists, deleting it")
            FILE(REMOVE_RECURSE ${INCLUDE_DIR}/websocketpp)
        endif ()

        message(STATUS "Copying websocketpp into ${INCLUDE_DIR}")
        FILE(COPY "${CMAKE_SOURCE_DIR}/websocketpp/websocketpp" DESTINATION ${INCLUDE_DIR})

        if (NOT EXISTS ${INCLUDE_DIR}/websocketpp)
            message(FATAL_ERROR "${INCLUDE_DIR}/websocketpp does not exist, cannot continue")
        endif ()
    endfunction(copyWebsocketpp)

    function(deleteWebsocketGit)
        set(WEBSOCKETPP_DIRECTORY ${CMAKE_SOURCE_DIR}/websocketpp)
        if (EXISTS ${WEBSOCKETPP_DIRECTORY})
            message(STATUS "${WEBSOCKETPP_DIRECTORY} directory exists, deleting it")
            file(REMOVE_RECURSE ${WEBSOCKETPP_DIRECTORY})
        endif ()
    endfunction(deleteWebsocketGit)

    function(downloadHttpLib)
        # Check if httplib.h exists, otherwise download it
        if (EXISTS ${INCLUDE_DIR}/httplib.h)
            message(STATUS "httplib.h found in include folder")
        else ()
            message(STATUS "httplib.h not found in include folder, downloading it")
            file(DOWNLOAD https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h
                    ${INCLUDE_DIR}/httplib.h SHOW_PROGRESS STATUS HTTPLIB_DOWNLOAD)
            if (HTTPLIB_DOWNLOAD)
                message(STATUS "httplib.h download finished successfully")
            else ()
                message(FATAL_ERROR "httplib.h download failed. Cannot continue without it")
            endif ()
        endif ()
    endfunction()

    function(downloadJsonHpp)
        # Check if json.hpp exists, otherwise download it
        if (EXISTS ${INCLUDE_DIR}/json.hpp)
            message(STATUS "json.hpp found in include folder")
        else ()
            message(STATUS "json.hpp not found in include folder, downloading it")
            file(DOWNLOAD https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp
                    ${INCLUDE_DIR}/json.hpp SHOW_PROGRESS STATUS JSON_DOWNLOAD)
            if (JSON_DOWNLOAD)
                message(STATUS "json.hpp download finished successfully")
            else ()
                message(FATAL_ERROR "json.hpp download failed. Cannot continue without it")
            endif ()
        endif ()
    endfunction()

    if (NOT NO_SSL)
        # Use find_package to find OpenSSL
        find_package(OpenSSL)
        if (OPENSSL_FOUND)
            # OpenSSL was found, enable HTTPS support
            message(STATUS "OpenSSL found, building with SSL Support")
            message(STATUS "OpenSSL libaries: ${OPENSSL_INCLUDE_DIR}/../lib")
            set(OPENSSL_LIBRARY_DIR "${OPENSSL_INCLUDE_DIR}/../lib")

            include_directories(${OPENSSL_INCLUDE_DIR})
            add_compile_definitions(CPPJSLIB_ENABLE_HTTPS)
            target_link_libraries(${TARGET} PUBLIC ${OPENSSL_LIBRARIES})
        endif ()
    endif ()

    if (WIN32)
        find_package(Boost 1.65)
    else ()
        # Search for component 'system' on non-windows machines
        find_package(Boost 1.65 COMPONENTS system)
    endif ()

    if (Boost_FOUND)
        # If boost was found, enable websocket support and add link and include dirs
        message(STATUS "Boost found, building with websocket protocol support")
        message(STATUS "Boost version: ${Boost_VERSION_STRING}")
        message(STATUS "Boost library directory: ${Boost_LIBRARY_DIRS}")
        message(STATUS "Boost include directory: ${Boost_INCLUDE_DIRS}")

        add_compile_definitions(CPPJSLIB_ENABLE_WEBSOCKET)
        include_directories(${Boost_INCLUDE_DIRS})
        target_link_directories(${TARGET} PUBLIC ${Boost_LIBRARY_DIRS})

        if (NOT EXISTS ${INCLUDE_DIR}/websocketpp)
            message(STATUS "${INCLUDE_DIR}/websocketpp does not exist, downloading websocketpp")
            downloadWebsocketpp()
            copyWebsocketpp()
            deleteWebsocketGit()
        else ()
            message(STATUS "${INCLUDE_DIR}/websocketpp already exists, not downloading websocketpp")
        endif ()
    endif ()

    downloadJsonHpp()
    downloadHttpLib()

    if (NOT WIN32)
        target_link_libraries(${TARGET} PUBLIC pthread)
    endif ()

    include_directories(${INCLUDE_DIR})
endfunction()
