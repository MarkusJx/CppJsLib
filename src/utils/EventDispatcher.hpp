//
// Created by markus on 16/04/2020.
//

#ifndef CPPJSLIBALL_EVENTDISPATCHER_HPP
#define CPPJSLIBALL_EVENTDISPATCHER_HPP

#include <httplib.h>

/**
 * EventDispatcher class
 * Source: https://github.com/yhirose/cpp-httplib/blob/master/example/sse.cc
 */
class EventDispatcher {
public:
    EventDispatcher();

    void wait_event(httplib::DataSink *sink);

    void send_event(const std::string &message);
private:
    std::mutex m_;
    std::condition_variable cv_;
    std::atomic_int id_;
    std::atomic_int cid_;
    std::string message_;
};

#endif //CPPJSLIBALL_EVENTDISPATCHER_HPP
