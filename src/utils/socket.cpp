//
// Created by markus on 05/03/2020.
//

#include "loggingfunc.hpp"
#include "../CppJsLib.hpp"

#ifndef CPPJSLIB_USE_JUTILS
#   ifdef CPPJSLIB_WINDOWS
#       ifdef _MSC_VER
#           pragma comment (lib, "Ws2_32.lib")
#       endif // _MSC_VER

#       include <winsock2.h>
#       include <ws2tcpip.h>
#       include <string>
#   elif defined(CPPJSLIB_UNIX)
#       include <unistd.h>
#       include <sys/socket.h>
#       include <netinet/in.h>
#       include <arpa/inet.h>
#   endif //CPPJSLIB_WINDOWS
#else

#   include "include/cppJsLibJUtils.h"
#   include "include/graal_isolate.h"

#endif //CPPJSLIB_USE_JUTILS

bool port_is_in_use(const char *addr, unsigned short port, int &err) {
#ifdef CPPJSLIB_USE_JUTILS
    // If available use Java for checking if the port is in use
    // That stuff is faster and cross-platform
    graal_isolate_t *isolate = nullptr;
    graal_isolatethread_t *thread = nullptr;

    if (graal_create_isolate(nullptr, &isolate, &thread) != 0) {
        errorF("[CppJsLib] graal_create_isolate error");
        return false;
    }

    bool res = portInUse(thread, (size_t) addr, port);

    if (graal_detach_thread(thread) != 0) {
        errorF("[CppJsLib] graal_detach_thread error");
    }

    return res;
#else
#   ifdef CPPJSLIB_WINDOWS
    WSADATA wsaData;
    auto ConnectSocket = INVALID_SOCKET;
    struct addrinfo *result = nullptr,
            *ptr = nullptr,
            hints{};

    // Initialize Winsock
    err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0) {
        errorF("[CppJsLib] WSAStartup failed with error: " + std::to_string(err));
        return false;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    err = getaddrinfo(addr, std::to_string(port).c_str(), &hints, &result);
    if (err != 0) {
        errorF("[CppJsLib] getaddrinfo failed with error: " + std::to_string(err));
        WSACleanup();
        return false;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
                               ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            err = WSAGetLastError();
            errorF("[CppJsLib] Socket failed with error: " + std::to_string(err));
            WSACleanup();
            return false;
        }

        // Connect to server.
        err = connect(ConnectSocket, ptr->ai_addr, (int) ptr->ai_addrlen);
        if (err == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);
    err = 0;

    if (ConnectSocket == INVALID_SOCKET) {
        loggingF("[CppJsLib] Unable to connect to server. Port is not in use");
        WSACleanup();
        return false;
    }

    // shutdown the connection since no more data will be sent
    err = shutdown(ConnectSocket, SD_SEND);
    if (err == SOCKET_ERROR) {
        err = WSAGetLastError();
        errorF("[CppJsLib] Shutdown failed with error: " + std::to_string(err));
        closesocket(ConnectSocket);
        WSACleanup();
        return false;
    }

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();

    return true;
#   else
    int sock = 0;
    struct sockaddr_in serv_addr{};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        errorF("[CppJsLib] Socket creation error");
        err = -1;
        return false;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, addr, &serv_addr.sin_addr) <= 0) {
        errorF("[CppJsLib] Invalid address/ Address not supported");
        err = -1;
        return false;
    }

    err = connect(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    if (err < 0) {
        errorF("[CppJsLib] Connection failed. Port is not in use");
        err = 0;
        return false;
    }

    close(sock);
    return true;
#   endif //CPPJSLIB_WINDOWS
#endif //CPPJSLIB_USE_JUTILS
}