/*
 * socket.hpp
 * Declares a function to check if a port is in use
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
#ifndef CPPJSLIBALL_SOCKET_HPP
#define CPPJSLIBALL_SOCKET_HPP

bool port_is_in_use(const char *addr, unsigned short port, int &err);

#endif //CPPJSLIBALL_SOCKET_HPP
