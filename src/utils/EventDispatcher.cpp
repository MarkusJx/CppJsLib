//
// Created by markus on 16/04/2020.
//

#ifndef CPPJSLIB_ENABLE_WEBSOCKET

#include "EventDispatcher.hpp"

EventDispatcher::EventDispatcher() {
    id_ = 0;
    cid_ = -1;
}

void EventDispatcher::wait_event(httplib::DataSink *sink) {
    std::unique_lock<std::mutex> lk(m_);
    int id = id_;
    cv_.wait(lk, [&] { return cid_ == id; });
    if (sink->is_writable()) {
        sink->write(message_.data(), message_.size());
    }
}

void EventDispatcher::send_event(const std::string &message) {
    std::lock_guard<std::mutex> lk(m_);
    cid_ = id_++;
    message_ = message;
    cv_.notify_all();
}

#endif
