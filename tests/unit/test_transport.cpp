// CurlTransport against a scripted HTTP/1.1 server on 127.0.0.1 (no network beyond loopback) that
// serves several keep-alive connections and records which connection carried each request: write
// safety (a write is never re-sent by libcurl), connection reuse for reads, and paths sent verbatim.
#include <gtest/gtest.h>
#include "fake_transport.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdlib>
#include <optional>
#include <thread>

using namespace fortiapi;
using fortiapi::testing::test_config;

namespace {

    // One request as the server read it. `connection` numbers accepted connections from 1.
    struct Seen {
        int connection = 0;
        std::string method;
        std::string target;   // the request-target exactly as sent ("/api/v2/...?...")
        std::string body;
    };

    // Answers every complete request with the handler's raw reply, or closes the connection without
    // a reply when the handler returns nullopt (a device that dropped the connection after the
    // request arrived). Replies keep the connection open (HTTP/1.1 keep-alive).
    class ScriptedServer {
    public:
        using Handler = std::function<std::optional<std::string>(const Seen&)>;

    private:
        struct Connection {
            int fd;
            int id;
            std::string in;
        };

        int listener_ = -1;
        Handler handler_;
        std::atomic<bool> stop_{false};
        mutable std::mutex mutex_;
        std::vector<Seen> seen_;
        std::thread thread_;

        static void quiet(int fd) {
#ifdef SO_NOSIGPIPE
            int one = 1;
            ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#else
            (void) fd;
#endif
        }

        static void send_all(int fd, std::string_view data) {
#ifdef MSG_NOSIGNAL
            constexpr int flags = MSG_NOSIGNAL;
#else
            constexpr int flags = 0;
#endif
            while (!data.empty()) {
                auto n = ::send(fd, data.data(), data.size(), flags);
                if (n <= 0) return;
                data.remove_prefix(static_cast<std::size_t>(n));
            }
        }

        // Consumes complete requests from the buffer; false when the connection must close.
        bool answer(Connection& connection) {
            for (;;) {
                auto head_end = connection.in.find("\r\n\r\n");
                if (head_end == std::string::npos) return true;
                std::string head = connection.in.substr(0, head_end);
                std::string lower = head;
                for (auto& c: lower) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
                std::size_t length = 0;
                if (auto at = lower.find("\r\ncontent-length:"); at != std::string::npos)
                    length = std::strtoul(head.c_str() + at + 17, nullptr, 10);
                if (connection.in.size() < head_end + 4 + length) return true;

                Seen request;
                request.connection = connection.id;
                auto first_space = head.find(' ');
                auto second_space = head.find(' ', first_space + 1);
                request.method = head.substr(0, first_space);
                request.target = head.substr(first_space + 1, second_space - first_space - 1);
                request.body = connection.in.substr(head_end + 4, length);
                connection.in.erase(0, head_end + 4 + length);
                {
                    std::lock_guard lock(mutex_);
                    seen_.push_back(request);
                }
                auto reply = handler_(request);
                if (!reply) return false;
                send_all(connection.fd, *reply);
            }
        }

        void serve() {
            std::vector<Connection> connections;
            int next_id = 0;
            while (!stop_) {
                std::vector<pollfd> fds{{listener_, POLLIN, 0}};
                for (const auto& connection: connections) fds.push_back({connection.fd, POLLIN, 0});
                if (::poll(fds.data(), fds.size(), 20) <= 0) continue;
                for (std::size_t i = 0; i < connections.size(); ++i) {
                    if (!(fds[i + 1].revents & (POLLIN | POLLHUP | POLLERR))) continue;
                    char buffer[4096];
                    auto n = ::recv(connections[i].fd, buffer, sizeof buffer, 0);
                    bool open = n > 0;
                    if (open) {
                        connections[i].in.append(buffer, static_cast<std::size_t>(n));
                        open = answer(connections[i]);
                    }
                    if (!open) {
                        ::close(connections[i].fd);
                        connections[i].fd = -1;
                    }
                }
                std::erase_if(connections, [](const Connection& connection) { return connection.fd < 0; });
                if (fds[0].revents & POLLIN) {
                    int fd = ::accept(listener_, nullptr, nullptr);
                    if (fd >= 0) {
                        quiet(fd);
                        connections.push_back({fd, ++next_id, {}});
                    }
                }
            }
            for (const auto& connection: connections) ::close(connection.fd);
        }

    public:
        unsigned short port = 0;

        explicit ScriptedServer(Handler handler) : handler_(std::move(handler)) {
            listener_ = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            socklen_t length = sizeof address;
            if (listener_ < 0 || ::bind(listener_, reinterpret_cast<sockaddr*>(&address), length) != 0 ||
                ::listen(listener_, 8) != 0 ||
                ::getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &length) != 0)
                throw std::runtime_error("scripted server: cannot listen on 127.0.0.1");
            port = ntohs(address.sin_port);
            thread_ = std::thread([this] { serve(); });
        }

        ScriptedServer(const ScriptedServer&) = delete;
        ScriptedServer& operator=(const ScriptedServer&) = delete;

        ~ScriptedServer() {
            stop_ = true;
            thread_.join();
            ::close(listener_);
        }

        [[nodiscard]] std::vector<Seen> seen() const {
            std::lock_guard lock(mutex_);
            return seen_;
        }

        [[nodiscard]] std::vector<Seen> seen(std::string_view method) const {
            std::vector<Seen> out;
            for (const auto& request: seen()) if (request.method == method) out.push_back(request);
            return out;
        }

        [[nodiscard]] std::vector<int> connections() const {
            std::vector<int> out;
            for (const auto& request: seen()) out.push_back(request.connection);
            return out;
        }

        [[nodiscard]] std::string origin() const { return std::format("http://127.0.0.1:{}", port); }
    };

    std::string ok(std::string_view body = R"({"status":"success","results":[]})") {
        return std::format("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                           body.size(), body);
    }

    // Client builds https://host:port URLs; this sends them to the loopback server over plain HTTP,
    // path and query untouched, through a real CurlTransport.
    class Loopback final : public Transport {
        CurlTransport curl_{test_config()};
        std::string origin_;

    public:
        explicit Loopback(std::string origin) : origin_(std::move(origin)) {}

        HttpResponse perform(const HttpRequest& request) override {
            HttpRequest copy = request;
            auto path = copy.url.find("/api/v2/");
            copy.url = origin_ + copy.url.substr(path);
            return curl_.perform(copy);
        }
    };

    struct CurlServer : ::testing::Test {
        void SetUp() override {
            ::setenv("no_proxy", "127.0.0.1", 1);
            ::setenv("NO_PROXY", "127.0.0.1", 1);
        }

        static Client client(const ScriptedServer& server) {
            return Client(test_config(), std::make_shared<Loopback>(server.origin()));
        }
    };

    struct DroppedWrite : CurlServer, ::testing::WithParamInterface<Method> {};

}  // namespace

// G12: the device takes the write, then the connection drops before the reply. Before the fix the
// write went out on the connection the GET had left in the pool, and libcurl, seeing "nothing
// received on a reused connection", silently sent it again on a new connection.
TEST_P(DroppedWrite, IsSentExactlyOnceAndReportedAsMaybeSent) {
    Method method = GetParam();
    ScriptedServer server([](const Seen& request) -> std::optional<std::string> {
        if (request.method == "GET") return ok();
        return std::nullopt;
    });
    auto c = client(server);
    c.get("cmdb/firewall/policy");   // leaves a kept-alive connection in the pool
    nlohmann::json body = {{"name", "forti-api-test-p"}};
    try {
        switch (method) {
            case Method::Post: c.post("cmdb/firewall/policy", body); break;
            case Method::Put: c.put("cmdb/firewall/policy/1", body); break;
            case Method::Delete: c.del("cmdb/firewall/policy/1"); break;
            case Method::Get: break;
        }
        FAIL() << "expected TransportError";
    } catch (const TransportError& error) {
        EXPECT_FALSE(error.before_send());
    }
    auto writes = server.seen(to_string(method));
    ASSERT_EQ(writes.size(), 1u) << "the server received the write " << writes.size() << " times";
    EXPECT_NE(writes[0].connection, server.seen("GET").at(0).connection);   // never on a pooled connection
}

INSTANTIATE_TEST_SUITE_P(Methods, DroppedWrite, ::testing::Values(Method::Post, Method::Put, Method::Delete),
                         [](const auto& info) { return std::string(to_string(info.param)); });

// The same through CurlTransport alone, without a GET first: a fresh connection is never retried.
TEST_F(CurlServer, DroppedWriteOnTheFirstConnectionIsSentOnce) {
    ScriptedServer server([](const Seen&) -> std::optional<std::string> { return std::nullopt; });
    CurlTransport transport(test_config());
    HttpRequest request;
    request.method = Method::Post;
    request.url = server.origin() + "/api/v2/monitor/system/external-resource/dynamic";
    request.body = "{}";
    try {
        transport.perform(request);
        FAIL() << "expected TransportError";
    } catch (const TransportError& error) {
        EXPECT_FALSE(error.before_send());
        EXPECT_TRUE(error.code() == CURLE_GOT_NOTHING || error.code() == CURLE_RECV_ERROR) << error.what();
    }
    EXPECT_EQ(server.seen("POST").size(), 1u);
}

// Reads keep using one connection; a write takes its own connection and does not return it to the
// pool, so the next read goes back to the kept-alive read connection.
TEST_F(CurlServer, ReadsReuseTheConnectionAndWritesUseTheirOwn) {
    ScriptedServer server([](const Seen&) -> std::optional<std::string> { return ok(); });
    auto c = client(server);
    nlohmann::json body = {{"name", "forti-api-test-a"}};
    c.get("cmdb/firewall/address");
    c.get("cmdb/firewall/address");
    c.post("cmdb/firewall/address", body);
    c.put("cmdb/firewall/address/forti-api-test-a", body);
    c.get("cmdb/firewall/address");
    c.del("cmdb/firewall/address/forti-api-test-a");
    c.get("cmdb/firewall/address");
    EXPECT_EQ(server.connections(), (std::vector<int>{1, 1, 2, 3, 1, 4, 1}));
}

// G13: a key "." or ".." stays one literal segment; libcurl must not resolve dot segments.
TEST_F(CurlServer, DotKeysReachTheServerVerbatim) {
    ScriptedServer server([](const Seen&) -> std::optional<std::string> { return ok(); });
    auto c = client(server);
    c.get(path("cmdb/firewall/address", "."));
    c.get(path("cmdb/firewall/address", ".."), Query().vdom("root"));
    c.del(path("cmdb/firewall/address", ".."));
    auto seen = server.seen();
    ASSERT_EQ(seen.size(), 3u);
    EXPECT_EQ(seen[0].target, "/api/v2/cmdb/firewall/address/%2E");
    EXPECT_EQ(seen[1].target, "/api/v2/cmdb/firewall/address/%2E%2E?vdom=root");
    EXPECT_EQ(seen[2].method, "DELETE");
    EXPECT_EQ(seen[2].target, "/api/v2/cmdb/firewall/address/%2E%2E");
}

// CurlTransport sends whatever path it is given, dot segments included (CURLOPT_PATH_AS_IS).
TEST_F(CurlServer, TransportSendsThePathAsIs) {
    ScriptedServer server([](const Seen&) -> std::optional<std::string> { return ok(); });
    CurlTransport transport(test_config());
    HttpRequest request;
    request.url = server.origin() + "/api/v2/cmdb/firewall/address/./x/../..";
    EXPECT_EQ(transport.perform(request).status, 200);
    ASSERT_EQ(server.seen().size(), 1u);
    EXPECT_EQ(server.seen()[0].target, "/api/v2/cmdb/firewall/address/./x/../..");
}
