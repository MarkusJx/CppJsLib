#include "CppJsLib.hpp"
#include <chrono>
#include <thread>
#include <future>
#include <fstream>
#include <memory>
#include <gtest/gtest.h>

#define PRINTF(...)  do { testing::internal::ColoredPrintf(testing::internal::COLOR_GREEN, \
            "[          ] "); testing::internal::ColoredPrintf(testing::internal::COLOR_YELLOW, __VA_ARGS__); } while(0)

#define ERR_PRINTF(...) do { testing::internal::ColoredPrintf(testing::internal::COLOR_RED, \
            "[          ] "); testing::internal::ColoredPrintf(testing::internal::COLOR_YELLOW, __VA_ARGS__); } while(0)

// C++ stream interface
class TestCout : public std::stringstream {
public:
    ~TestCout() override {
        PRINTF("%s", str().c_str());
    }
};

class TestCerr : public std::stringstream {
public:
    ~TestCerr() override {
        ERR_PRINTF("%s", str().c_str());
    }
};

#define TEST_COUT TestCout()
#define TEST_CERR TestCerr()

class ServerStartStopTest : public ::testing::Test {
protected:
    ServerStartStopTest() : server() {
        server.setLogger([](const std::string &msg) {
            TEST_COUT << msg << std::endl;
        });

        server.setError([](const std::string &msg) {
            TEST_CERR << msg << std::endl;
        });
    }

    markusjx::cppJsLib::Server server;
};

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#define SERVER_SET_WEBSOCKET_NO_LOG() server.getWebsocketServer()->set_access_channels(websocketpp::log::alevel::none); \
                                    server.getWebsocketServer()->set_access_channels(websocketpp::log::elevel::none); \
                                    server.getWebsocketServer()->clear_access_channels(websocketpp::log::elevel::all); \
                                    server.getWebsocketServer()->clear_access_channels(websocketpp::log::alevel::all)
#else
#   define SERVER_SET_WEBSOCKET_NO_LOG()
#endif //CPPJSLIB_ENABLE_WEBSOCKET

TEST_F(ServerStartStopTest, allTest) {
    server.start(1235, markusjx::cppJsLib::localhost, 1234, false);
    SERVER_SET_WEBSOCKET_NO_LOG();
    std::promise<void> promise;
    std::future<void> future = promise.get_future();
    server.stop(promise);
    EXPECT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(5)));
}

TEST_F(ServerStartStopTest, noWebTest) {
    server.start(0, markusjx::cppJsLib::localhost, 1234, false);
    SERVER_SET_WEBSOCKET_NO_LOG();
    std::promise<void> promise;
    std::future<void> future = promise.get_future();
    server.stop(promise);
    EXPECT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(5)));
}

TEST_F(ServerStartStopTest, noWebsocketTest) {
    server.start(1235, markusjx::cppJsLib::localhost, 0, false);
    SERVER_SET_WEBSOCKET_NO_LOG();
    std::promise<void> promise;
    std::future<void> future = promise.get_future();
    server.stop(promise);
    EXPECT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(5)));
}

class ServerTest : public ::testing::Test {
protected:
    ServerTest() : client() {
        client.connect("http://localhost:12345", false);
    }

    ~ServerTest() override {
        client.stop();
    }

    markusjx::cppJsLib::Client client;

    static void SetUpTestSuite() {
        server = std::make_shared<markusjx::cppJsLib::Server>();
        server->setLogger([](const std::string &msg) {
            TEST_COUT << msg << std::endl;
        });

        server->setError([](const std::string &msg) {
            TEST_CERR << msg << std::endl;
        });

        server->import(void_void_fn);
        server->import(void_args_fn);
        server->import(int_void_fn);
        server->import(int_args_fn);

        server->expose(call_void_void_fn);
        server->expose(call_void_args_fn);
        server->expose(call_int_void_fn);
        server->expose(call_int_args_fn);

        server->start(12345, markusjx::cppJsLib::localhost, 12344, false);
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
        server->getWebsocketServer()->set_access_channels(websocketpp::log::alevel::all);
        /*server->getWebsocketServer()->set_access_channels(websocketpp::log::elevel::none);
        server->getWebsocketServer()->clear_access_channels(websocketpp::log::elevel::all);
        server->getWebsocketServer()->clear_access_channels(websocketpp::log::alevel::all);*/
#endif //CPPJSLIB_ENABLE_WEBSOCKET
    }

    static void TearDownTestSuite() {
        std::promise<void> promise;
        std::future<void> future = promise.get_future();
        server->stop(promise);
        future.wait_for(std::chrono::seconds(5));
        server.reset();
    }

    static void call_void_void_fn() {
        void_void_fn();
    }

    static void call_void_args_fn(const std::string &s, int i, const std::vector<int> &v) {
        void_args_fn(s, i, v);
    }

    static int call_int_void_fn() {
        return int_void_fn();
    }

    static int call_int_args_fn(const std::string &s, int i, const std::vector<int> &v) {
        return int_args_fn(s, i, v);
    }

    static std::shared_ptr<markusjx::cppJsLib::Server> server;
    static std::function<void()> void_void_fn;
    static std::function<void(std::string, int, std::vector<int>)> void_args_fn;
    static std::function<int()> int_void_fn;
    static std::function<int(std::string, int, std::vector<int>)> int_args_fn;
};

std::shared_ptr<markusjx::cppJsLib::Server> ServerTest::server = nullptr;
std::function<void()> ServerTest::void_void_fn = nullptr;
std::function<void(std::string, int, std::vector<int>)> ServerTest::void_args_fn = nullptr;
std::function<int()> ServerTest::int_void_fn = nullptr;
std::function<int(std::string, int, std::vector<int>)> ServerTest::int_args_fn = nullptr;

TEST_F(ServerTest, functionCallTest) {
    markusjx::cppJsLib::Client client;
    client.setLogger([](const std::string &msg) {
        TEST_COUT << msg << std::endl;
    });

    client.setError([](const std::string &msg) {
        TEST_CERR << msg << std::endl;
    });

    std::function<void(std::promise<void> &)> call_void_void_fn;
    std::function<void()> void_void_fn = [] {
        TEST_COUT << "void(void) function called" << std::endl;
    };

    client.import(call_void_void_fn);
    client.expose(void_void_fn);

    client.connect("http://localhost:12345", false);
    //std::this_thread::sleep_for(std::chrono::seconds(10));

    std::promise<void> promise;
    std::future<void> future = promise.get_future();
    call_void_void_fn(promise);

    TEST_COUT << "Waiting for result..." << std::endl;

    EXPECT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(10)));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}