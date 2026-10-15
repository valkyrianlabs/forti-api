// Client::download (raw bodies): mocked transports, and CurlTransport against a loopback HTTP server
// (no network beyond 127.0.0.1).
#include <gtest/gtest.h>
#include "fake_transport.hpp"

#include <forti_api/monitor.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <thread>

using namespace fortiapi;
using fortiapi::testing::FakeTransport;
using fortiapi::testing::test_config;

namespace {

    // Every byte value, NULs and high bytes included.
    std::string binary_body() {
        std::string body;
        for (int round = 0; round < 3; ++round)
            for (int byte = 0; byte < 256; ++byte) body += static_cast<char>(byte);
        return body;
    }

    HttpResponse file_reply(std::string body, std::string type = "application/octet-stream") {
        return {200, std::move(body), {{"content-type", std::move(type)},
                                       {"Content-Disposition", R"(attachment; filename="fw.conf")"}}};
    }

    bool has_header(const HttpRequest& request, std::string_view header) {
        return std::find(request.headers.begin(), request.headers.end(), header) != request.headers.end();
    }

    // Runs every test twice: against a transport that ignores the download fields (the client enforces
    // them after the fact) and one that honors them in chunks (as CurlTransport does).
    struct DownloadTest : ::testing::TestWithParam<std::size_t> {
        std::shared_ptr<FakeTransport> fake = std::make_shared<FakeTransport>();

        void SetUp() override { fake->chunk = GetParam(); }

        Client client(Config config = test_config()) { return Client(std::move(config), fake); }
    };

}  // namespace

INSTANTIATE_TEST_SUITE_P(Transports, DownloadTest, ::testing::Values(std::size_t{0}, std::size_t{7}),
                         [](const auto& info) { return info.param == 0 ? "Whole" : "Chunked"; });

TEST_P(DownloadTest, BinaryBodyRoundTrips) {
    fake->reply(file_reply(binary_body()));
    auto download = client().download("monitor/system/config/backup", Query().set("scope", "global"));
    EXPECT_EQ(download.http_status, 200);
    EXPECT_EQ(download.body, binary_body());
    EXPECT_EQ(download.bytes, binary_body().size());
    EXPECT_EQ(download.body[0], '\0');
    EXPECT_EQ(static_cast<unsigned char>(download.body[255]), 0xFFu);
}

TEST_P(DownloadTest, TextBodyAndHeaders) {
    std::string config = "#config-version=FGT60F-7.4.8-FW-build2795-250523:opmode=0:vdom=0\nconfig system global\nend\n";
    fake->reply(file_reply(config, "text/plain"));
    auto download = client().download("monitor/system/config/backup");
    EXPECT_EQ(download.body, config);
    EXPECT_EQ(download.content_type, "text/plain");   // header names match case-insensitively
    EXPECT_EQ(download.content_disposition, R"(attachment; filename="fw.conf")");
}

TEST_P(DownloadTest, MissingHeadersAreEmpty) {
    fake->reply(200, std::string("x"));
    auto download = client().download("monitor/x");
    EXPECT_TRUE(download.content_type.empty());
    EXPECT_TRUE(download.content_disposition.empty());
    EXPECT_EQ(download.body, "x");
}

TEST_P(DownloadTest, SendsAGetWithTheApiKeyHeaderAndAnyAccept) {
    fake->reply(200, std::string("x"));
    auto config = test_config();
    config.vdom = "root";
    client(config).download("/monitor/system/config/backup", Query().set("scope", "global"));
    ASSERT_EQ(fake->requests.size(), 1u);
    const auto& request = fake->requests[0];
    EXPECT_EQ(request.method, Method::Get);
    EXPECT_EQ(request.url, "https://fortigate.test:8443/api/v2/monitor/system/config/backup?scope=global&vdom=root");
    EXPECT_TRUE(has_header(request, "Authorization: Bearer test-key"));
    EXPECT_TRUE(has_header(request, "Accept: */*"));
    EXPECT_EQ(request.url.find("test-key"), std::string::npos);
    EXPECT_EQ(request.max_body, DownloadOptions().max_bytes);
    EXPECT_EQ(DownloadOptions().max_bytes, 64u * 1024 * 1024);
}

TEST_P(DownloadTest, HttpErrorWithJsonEnvelopeIsApiError) {
    fake->reply(400, nlohmann::json{{"status", "error"}, {"http_status", 400}, {"error", -651},
                                    {"cli_error", {"scope: invalid value"}}});
    bool sink_called = false;
    DownloadOptions options;
    options.sink = [&](std::string_view) { sink_called = true; };
    try {
        client().download("monitor/system/config/backup", {}, options);
        FAIL() << "expected ApiError";
    } catch (const ApiError& error) {
        EXPECT_EQ(error.http_status(), 400);
        EXPECT_EQ(error.fortios_error(), -651);
        EXPECT_EQ(error.method(), Method::Get);
        EXPECT_EQ(error.path(), "monitor/system/config/backup");
        EXPECT_NE(std::string(error.what()).find("scope: invalid value"), std::string::npos);
        EXPECT_EQ(std::string(error.what()).find("test-key"), std::string::npos);
    }
    EXPECT_FALSE(sink_called);   // error bodies never reach the sink
}

TEST_P(DownloadTest, HttpErrorWithNonJsonBodyKeepsTheRawBody) {
    fake->reply(403, std::string("<html>Forbidden</html>"));
    try {
        client().download("monitor/system/config/backup");
        FAIL() << "expected ApiError";
    } catch (const ApiError& error) {
        EXPECT_EQ(error.http_status(), 403);
        EXPECT_EQ(error.body()["raw"], "<html>Forbidden</html>");
        EXPECT_EQ(error.fortios_error(), 0);
    }
}

TEST_P(DownloadTest, ADeeplyNestedJsonErrorKeepsTheRawBody) {
    std::string deep = std::string(5000, '[') + std::string(5000, ']');
    fake->reply(400, deep);
    try {
        client().download("monitor/system/config/backup");
        FAIL() << "expected ApiError";
    } catch (const ApiError& error) {
        EXPECT_EQ(error.http_status(), 400);
        EXPECT_EQ(error.body()["raw"], deep);
    }
}

TEST_P(DownloadTest, AJsonErrorEnvelopeWithHttp200IsReturnedRaw) {
    fake->reply(HttpResponse{200, R"({"status":"error"})", {{"Content-Type", "application/json"}}});
    auto download = client().download("monitor/x");
    EXPECT_EQ(download.content_type, "application/json");
    EXPECT_EQ(download.body, R"({"status":"error"})");
}

TEST_P(DownloadTest, BodyOverTheLimitIsDiscardedAndNotRetried) {
    fake->reply(file_reply(std::string(100, 'a'))).reply(file_reply("ok"));
    DownloadOptions options;
    options.max_bytes = 99;
    try {
        client().download("monitor/system/config/backup", {}, options);
        FAIL() << "expected SizeLimitError";
    } catch (const SizeLimitError& error) {
        EXPECT_EQ(error.limit(), 99u);
        EXPECT_STREQ(error.what(), "GET monitor/system/config/backup: response body exceeds the limit of 99 bytes");
    }
    EXPECT_EQ(fake->requests.size(), 1u);
}

TEST_P(DownloadTest, BodyExactlyAtTheLimitIsAccepted) {
    fake->reply(file_reply(std::string(100, 'a')));
    DownloadOptions options;
    options.max_bytes = 100;
    EXPECT_EQ(client().download("monitor/x", {}, options).bytes, 100u);
}

TEST_P(DownloadTest, SinkReceivesTheBodyInsteadOfMemory) {
    fake->reply(file_reply(binary_body()));
    std::string received;
    std::size_t calls = 0;
    DownloadOptions options;
    options.sink = [&](std::string_view chunk) {
        received.append(chunk);
        ++calls;
    };
    auto download = client().download("monitor/system/config/backup", {}, options);
    EXPECT_EQ(received, binary_body());
    EXPECT_TRUE(download.body.empty());
    EXPECT_EQ(download.bytes, binary_body().size());
    EXPECT_EQ(download.content_type, "application/octet-stream");
    if (GetParam() > 0) {
        EXPECT_EQ(calls, (binary_body().size() + GetParam() - 1) / GetParam());
    }
}

TEST_P(DownloadTest, SinkModeStillEnforcesTheLimit) {
    fake->reply(file_reply(std::string(50, 'a')));
    std::size_t received = 0;
    DownloadOptions options;
    options.max_bytes = 20;
    options.sink = [&](std::string_view chunk) { received += chunk.size(); };
    EXPECT_THROW(client().download("monitor/x", {}, options), SizeLimitError);
    EXPECT_LE(received, 20u);
}

TEST_P(DownloadTest, SinkExceptionsPropagateAndAreNotRetried) {
    fake->reply(file_reply("abc")).reply(file_reply("abc"));
    DownloadOptions options;
    options.sink = [](std::string_view) { throw std::runtime_error("disk full"); };
    EXPECT_THROW(client().download("monitor/x", {}, options), std::runtime_error);
    EXPECT_EQ(fake->requests.size(), 1u);
}

// The retry policy is exchange()'s.
TEST_P(DownloadTest, GetRetriesThrottlingAndGatewayErrors) {
    fake->reply(429, std::string("")).reply(503, std::string("busy")).reply(file_reply("config"));
    auto download = client().download("monitor/system/config/backup");
    EXPECT_EQ(fake->requests.size(), 3u);
    EXPECT_EQ(download.body, "config");
}

TEST_P(DownloadTest, GetGivesUpAfterConfiguredRetries) {
    fake->reply(503, std::string("")).reply(503, std::string("")).reply(503, std::string(""));
    EXPECT_THROW(client().download("monitor/x"), ApiError);
    EXPECT_EQ(fake->requests.size(), 3u);
}

TEST_P(DownloadTest, GetRetriesTransportErrors) {
    fake->fail(CURLE_OPERATION_TIMEDOUT, false).reply(file_reply("config"));
    EXPECT_EQ(client().download("monitor/x").body, "config");
    EXPECT_EQ(fake->requests.size(), 2u);
}

TEST_P(DownloadTest, UnauthorizedIsNeverRetried) {
    fake->reply(401, std::string(""));
    EXPECT_THROW(client().download("monitor/x"), ApiError);
    EXPECT_EQ(fake->requests.size(), 1u);
}

TEST_P(DownloadTest, PostIsNotRetriedAfterAResponse) {
    fake->reply(503, std::string("")).reply(file_reply("x"));
    nlohmann::json body = {{"scope", "global"}};
    EXPECT_THROW(client().download(Method::Post, "monitor/x", {}, &body), ApiError);
    EXPECT_EQ(fake->requests.size(), 1u);
    EXPECT_EQ(fake->requests[0].body, R"({"scope":"global"})");
}

TEST_P(DownloadTest, ATransportErrorAfterTheSinkReceivedDataIsNotRetried) {
    fake->partial = "half";
    fake->fail(CURLE_RECV_ERROR, false).reply(file_reply("config"));
    std::string received;
    DownloadOptions options;
    options.sink = [&](std::string_view chunk) { received.append(chunk); };
    EXPECT_THROW(client().download("monitor/x", {}, options), TransportError);
    EXPECT_EQ(fake->requests.size(), 1u);
    EXPECT_EQ(received, "half");
}

TEST_P(DownloadTest, ExchangeRecordsNeverCarryTheDownloadedBody) {
    std::vector<Exchange> seen;
    auto config = test_config();
    config.on_exchange = [&](const Exchange& exchange) { seen.push_back(exchange); };
    fake->reply(503, std::string("busy")).reply(file_reply("secret config"));
    auto download = client(config).download("monitor/system/config/backup");
    EXPECT_EQ(download.body, "secret config");
    ASSERT_EQ(seen.size(), 2u);
    EXPECT_EQ(seen[0].response_body, "busy");    // error replies are traced as with exchange()
    EXPECT_EQ(seen[1].http_status, 200);
    EXPECT_TRUE(seen[1].response_body.empty());
    for (const auto& exchange: seen) {
        EXPECT_EQ(exchange.url.find("test-key"), std::string::npos);
        EXPECT_EQ(exchange.request_body.find("test-key"), std::string::npos);
        EXPECT_EQ(exchange.response_body.find("test-key"), std::string::npos);
    }
}

TEST_P(DownloadTest, MonitorDownloadPrefixesThePath) {
    fake->reply(file_reply("x"));
    auto c = client();
    auto download = Monitor::download("/system/config/backup", Query().set("scope", "global"), {}, c);
    EXPECT_EQ(download.body, "x");
    EXPECT_EQ(fake->requests[0].url, "https://fortigate.test:8443/api/v2/monitor/system/config/backup?scope=global");
}

// exchange() keeps its behavior: whole JSON bodies, traced, no limit.
TEST(DownloadFields, ExchangeLeavesThemUnset) {
    auto fake = std::make_shared<FakeTransport>();
    fake->reply(200, nlohmann::json{{"results", {}}});
    Client(test_config(), fake).get("monitor/system/status");
    EXPECT_EQ(fake->requests[0].max_body, std::numeric_limits<std::size_t>::max());
    EXPECT_FALSE(fake->requests[0].on_body);
    EXPECT_TRUE(has_header(fake->requests[0], "Accept: application/json"));
}

TEST(HttpResponseHeaders, LookupIsCaseInsensitiveAndFirstWins) {
    HttpResponse response{200, "", {{"Content-Type", "text/plain"}, {"content-type", "other"}}};
    EXPECT_EQ(response.header("CONTENT-TYPE"), "text/plain");
    EXPECT_EQ(response.header("Content-Typ"), "");
}

TEST(HttpResponseHeaders, HeaderLinesParseAndAStatusLineStartsOver) {
    HttpResponse response;
    EXPECT_EQ(detail::header_line(response, "HTTP/1.1 100 Continue\r\n"), 100);
    EXPECT_EQ(detail::header_line(response, "X-Interim: yes\r\n"), 0);
    EXPECT_EQ(detail::header_line(response, "HTTP/2 200\r\n"), 200);
    detail::header_line(response, "Content-Type:  text/plain; charset=utf-8 \r\n");
    detail::header_line(response, "Content-Disposition: attachment; filename=\"a:b.conf\"\r\n");
    detail::header_line(response, "\r\n");
    detail::header_line(response, ": no name\r\n");
    ASSERT_EQ(response.headers.size(), 2u);
    EXPECT_EQ(response.header("x-interim"), "");
    EXPECT_EQ(response.header("content-type"), "text/plain; charset=utf-8");
    EXPECT_EQ(response.header("content-disposition"), "attachment; filename=\"a:b.conf\"");
}

TEST(BodyWriter, RoutesSuccessToTheSinkAndErrorsToMemory) {
    std::string sunk;
    HttpRequest request;
    request.on_body = [&](std::string_view chunk) { sunk.append(chunk); };
    HttpResponse response;
    detail::BodyWriter ok(request, response);
    EXPECT_TRUE(ok.write("ab", 200));
    EXPECT_TRUE(ok.write("cd", 206));
    EXPECT_EQ(sunk, "abcd");
    EXPECT_TRUE(response.body.empty());

    detail::BodyWriter failed(request, response);
    EXPECT_TRUE(failed.write("{\"error\":-1}", 500));
    EXPECT_EQ(response.body, "{\"error\":-1}");
    EXPECT_EQ(sunk, "abcd");
}

TEST(BodyWriter, StopsPastTheLimitAndCapturesSinkExceptions) {
    HttpRequest request;
    request.max_body = 5;
    HttpResponse response;
    detail::BodyWriter writer(request, response);
    EXPECT_TRUE(writer.write("abc", 200));
    EXPECT_TRUE(writer.write("de", 200));
    EXPECT_FALSE(writer.write("f", 200));
    EXPECT_TRUE(writer.exceeded);
    EXPECT_EQ(writer.received(), 5u);

    request.max_body = std::numeric_limits<std::size_t>::max();
    request.on_body = [](std::string_view) { throw std::runtime_error("sink failed"); };
    HttpResponse other;
    detail::BodyWriter throwing(request, other);
    EXPECT_FALSE(throwing.write("x", 200));
    EXPECT_FALSE(throwing.exceeded);
    EXPECT_TRUE(throwing.error);
}

TEST(Wipe, ZeroesAndEmpties) {
    std::string secret = "password";
    detail::wipe(secret);
    EXPECT_TRUE(secret.empty());
}

// CurlTransport end to end against a one-shot HTTP server on 127.0.0.1: the libcurl header and body
// callbacks, the status seen mid-transfer, the limit abort and the sink.
namespace {

    class LoopbackServer {
        int listener_ = -1;
        std::thread thread_;
        std::string reply_;

        void serve() {
            pollfd ready{listener_, POLLIN, 0};
            if (::poll(&ready, 1, 10000) <= 0) return;
            int peer = ::accept(listener_, nullptr, nullptr);
            if (peer < 0) return;
#ifdef SO_NOSIGPIPE
            int one = 1;
            ::setsockopt(peer, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
#ifdef MSG_NOSIGNAL
            constexpr int flags = MSG_NOSIGNAL;
#else
            constexpr int flags = 0;
#endif
            std::string request;
            char buffer[4096];
            while (request.find("\r\n\r\n") == std::string::npos) {
                auto n = ::recv(peer, buffer, sizeof buffer, 0);
                if (n <= 0) break;
                request.append(buffer, static_cast<std::size_t>(n));
            }
            for (std::size_t sent = 0; sent < reply_.size();) {
                auto n = ::send(peer, reply_.data() + sent, reply_.size() - sent, flags);
                if (n <= 0) break;   // the client aborted (limit exceeded)
                sent += static_cast<std::size_t>(n);
            }
            ::close(peer);
        }

    public:
        unsigned short port = 0;

        LoopbackServer(long status, const std::string& body, const std::string& headers = "") {
            reply_ = std::format("HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n", status,
                                 body.size(), headers) + body;
            listener_ = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            socklen_t length = sizeof address;
            if (listener_ < 0 || ::bind(listener_, reinterpret_cast<sockaddr*>(&address), length) != 0 ||
                ::listen(listener_, 1) != 0 ||
                ::getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &length) != 0)
                throw std::runtime_error("loopback server: cannot listen on 127.0.0.1");
            port = ntohs(address.sin_port);
            thread_ = std::thread([this] { serve(); });
        }

        ~LoopbackServer() {
            thread_.join();
            ::close(listener_);
        }

        [[nodiscard]] HttpRequest request() const {
            HttpRequest request;
            request.url = std::format("http://127.0.0.1:{}/api/v2/monitor/system/config/backup", port);
            return request;
        }
    };

    struct CurlLoopback : ::testing::Test {
        CurlTransport transport{test_config()};

        void SetUp() override {
            ::setenv("no_proxy", "127.0.0.1", 1);
            ::setenv("NO_PROXY", "127.0.0.1", 1);
        }
    };

}  // namespace

TEST_F(CurlLoopback, BinaryBodyAndHeaders) {
    LoopbackServer server(200, binary_body(),
                          "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"fw.conf\"\r\n");
    auto response = transport.perform(server.request());
    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body, binary_body());
    EXPECT_EQ(response.header("content-type"), "application/octet-stream");
    EXPECT_EQ(response.header("Content-Disposition"), "attachment; filename=\"fw.conf\"");
}

TEST_F(CurlLoopback, AbortsPastTheLimit) {
    LoopbackServer server(200, std::string(4 << 20, 'a'));
    auto request = server.request();
    request.max_body = 1000;
    try {
        transport.perform(request);
        FAIL() << "expected SizeLimitError";
    } catch (const SizeLimitError& error) {
        EXPECT_EQ(error.limit(), 1000u);
    }
}

TEST_F(CurlLoopback, StreamsSuccessToTheSink) {
    std::string body(300000, 'b');
    LoopbackServer server(200, body);
    std::string sunk;
    auto request = server.request();
    request.on_body = [&](std::string_view chunk) { sunk.append(chunk); };
    auto response = transport.perform(request);
    EXPECT_EQ(response.status, 200);
    EXPECT_TRUE(response.body.empty());
    EXPECT_EQ(sunk, body);
}

TEST_F(CurlLoopback, KeepsErrorBodiesOutOfTheSink) {
    LoopbackServer server(500, R"({"status":"error","error":-5})", "Content-Type: application/json\r\n");
    bool sink_called = false;
    auto request = server.request();
    request.on_body = [&](std::string_view) { sink_called = true; };
    auto response = transport.perform(request);
    EXPECT_EQ(response.status, 500);
    EXPECT_EQ(response.body, R"({"status":"error","error":-5})");
    EXPECT_FALSE(sink_called);
}

TEST_F(CurlLoopback, RethrowsSinkExceptions) {
    LoopbackServer server(200, std::string(1000, 'c'));
    auto request = server.request();
    request.on_body = [](std::string_view) { throw std::invalid_argument("sink failed"); };
    EXPECT_THROW(transport.perform(request), std::invalid_argument);
}

// The full path: Client -> CurlTransport -> loopback, limit and headers through download().
TEST_F(CurlLoopback, ClientDownloadThroughCurl) {
    LoopbackServer server(200, "#config-version=test\n", "Content-Type: text/plain\r\n");
    struct Plain final : Transport {   // Client builds https URLs; rewrite to the loopback server
        CurlTransport& inner;
        std::string url;
        Plain(CurlTransport& inner, std::string url) : inner(inner), url(std::move(url)) {}
        HttpResponse perform(const HttpRequest& request) override {
            HttpRequest copy = request;
            copy.url = url;
            return inner.perform(copy);
        }
    };
    Client client(test_config(), std::make_shared<Plain>(transport, server.request().url));
    auto download = client.download("monitor/system/config/backup");
    EXPECT_EQ(download.body, "#config-version=test\n");
    EXPECT_EQ(download.content_type, "text/plain");
    EXPECT_EQ(download.bytes, download.body.size());
}
