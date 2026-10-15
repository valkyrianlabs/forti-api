#include <gtest/gtest.h>
#include "fake_transport.hpp"

using namespace fortiapi;
using fortiapi::testing::FakeTransport;
using fortiapi::testing::envelope;
using fortiapi::testing::test_config;

namespace {

    struct ClientTest : ::testing::Test {
        std::shared_ptr<FakeTransport> fake = std::make_shared<FakeTransport>();

        Client client(Config config = test_config()) { return Client(std::move(config), fake); }
    };

    // {"results":[[...]]} with `levels` levels of objects and arrays in total.
    std::string nested(std::size_t levels) {
        return R"({"results":)" + std::string(levels - 1, '[') + std::string(levels - 1, ']') + "}";
    }

}  // namespace

TEST(Encoding, KeepsUnreservedAndEscapesTheRest) {
    EXPECT_EQ(encode("abc-XYZ_0.9~"), "abc-XYZ_0.9~");
    EXPECT_EQ(encode("10.0.0.0/24"), "10.0.0.0%2F24");
    EXPECT_EQ(encode("a b#c?d&e=f%"), "a%20b%23c%3Fd%26e%3Df%25");
    EXPECT_EQ(encode("caf\xC3\xA9"), "caf%C3%A9");
}

TEST(Encoding, PathEncodesEachKeyAsOneSegment) {
    EXPECT_EQ(path("cmdb/firewall/address", "LAN 10.0.0.0/24"), "cmdb/firewall/address/LAN%2010.0.0.0%2F24");
    EXPECT_EQ(path("cmdb/firewall/policy", 42), "cmdb/firewall/policy/42");
    EXPECT_EQ(path("cmdb/system/api-user", "admin", "trusthost", 1), "cmdb/system/api-user/admin/trusthost/1");
}

// A key "." or ".." would be a dot segment (the table itself, or its parent); only whole segments are
// affected, and encode() keeps '.' everywhere.
TEST(Encoding, DotKeysAreNeverDotSegments) {
    EXPECT_EQ(path("cmdb/firewall/address", "."), "cmdb/firewall/address/%2E");
    EXPECT_EQ(path("cmdb/firewall/address", ".."), "cmdb/firewall/address/%2E%2E");
    EXPECT_EQ(path("cmdb/firewall/address", std::string("..")), "cmdb/firewall/address/%2E%2E");
    EXPECT_EQ(path("cmdb/system/api-user", "..", "trusthost", "."), "cmdb/system/api-user/%2E%2E/trusthost/%2E");
    EXPECT_EQ(path("cmdb/firewall/address", "..."), "cmdb/firewall/address/...");
    EXPECT_EQ(path("cmdb/firewall/address", ".hidden"), "cmdb/firewall/address/.hidden");
    EXPECT_EQ(path("cmdb/firewall/address", "../x"), "cmdb/firewall/address/..%2Fx");
    EXPECT_EQ(path("cmdb/firewall/address", "10.0.0.0/24"), "cmdb/firewall/address/10.0.0.0%2F24");
    EXPECT_EQ(encode("."), ".");
    EXPECT_EQ(encode(".."), "..");
}

TEST(QueryTest, EncodesParametersInOrder) {
    Query query;
    query.vdom("root").filter("name==web server").filter("status==enable").format({"name", "policyid"})
         .start(10).count(5).with_meta();
    EXPECT_EQ(query.encoded(), "vdom=root&filter=name%3D%3Dweb%20server&filter=status%3D%3Denable"
                               "&format=name%7Cpolicyid&start=10&count=5&with_meta=1");
    EXPECT_TRUE(query.has("filter"));
    EXPECT_FALSE(query.has("action"));
    EXPECT_TRUE(Query().empty());
}

TEST_F(ClientTest, BuildsUrlHeadersAndBody) {
    fake->reply(200, envelope(nlohmann::json::array()));
    auto c = client();
    nlohmann::json body = {{"name", "x"}};
    c.post("cmdb/dnsfilter/profile", body);

    ASSERT_EQ(fake->requests.size(), 1u);
    const auto& request = fake->requests[0];
    EXPECT_EQ(request.method, Method::Post);
    EXPECT_EQ(request.url, "https://fortigate.test:8443/api/v2/cmdb/dnsfilter/profile");
    EXPECT_EQ(request.body, R"({"name":"x"})");
    EXPECT_NE(std::find(request.headers.begin(), request.headers.end(), "Authorization: Bearer test-key"),
              request.headers.end());
    EXPECT_NE(std::find(request.headers.begin(), request.headers.end(), "Content-Type: application/json"),
              request.headers.end());
}

TEST_F(ClientTest, AppliesDefaultVdomUnlessTheQuerySetsOne) {
    fake->reply(200, envelope({})).reply(200, envelope({}));
    auto config = test_config();
    config.vdom = "root";
    auto c = client(config);
    c.get("/cmdb/firewall/policy");
    c.get("cmdb/firewall/policy", Query().vdom("dmz"));
    EXPECT_EQ(fake->requests[0].url, "https://fortigate.test:8443/api/v2/cmdb/firewall/policy?vdom=root");
    EXPECT_EQ(fake->requests[1].url, "https://fortigate.test:8443/api/v2/cmdb/firewall/policy?vdom=dmz");
}

TEST_F(ClientTest, ErrorEnvelopeBecomesApiError) {
    nlohmann::json body = {{"status", "error"}, {"http_status", 500}, {"error", -3},
                           {"cli_error", {"entry not found in datasource"}}};
    fake->reply(500, body);
    auto c = client();
    try {
        c.post("cmdb/dnsfilter/profile", {{"name", "x"}});
        FAIL() << "expected ApiError";
    } catch (const ApiError& error) {
        EXPECT_EQ(error.http_status(), 500);
        EXPECT_EQ(error.fortios_error(), -3);
        EXPECT_EQ(error.method(), Method::Post);
        EXPECT_FALSE(error.not_found());
        EXPECT_NE(std::string(error.what()).find("entry not found in datasource"), std::string::npos);
    }
}

TEST_F(ClientTest, ExchangeReturnsErrorsWithoutThrowing) {
    fake->reply(404, nlohmann::json{{"status", "error"}, {"http_status", 404}});
    auto result = client().exchange(Method::Get, "cmdb/firewall/policy/9");
    EXPECT_EQ(result.http_status, 404);
    EXPECT_FALSE(result.ok());
}

TEST_F(ClientTest, SuccessHttpWithErrorStatusIsNotOk) {
    fake->reply(200, nlohmann::json{{"status", "error"}});
    EXPECT_THROW(client().get("monitor/system/status"), ApiError);
}

TEST_F(ClientTest, NonJsonSuccessIsDecodeError) {
    fake->reply(200, std::string("<html>login</html>"));
    EXPECT_THROW(client().get("monitor/system/status"), DecodeError);
}

// A hostile or broken peer cannot hand back a value deep enough to overflow the stack when the caller
// copies or dumps it (nlohmann recurses per level there, not while parsing).
TEST_F(ClientTest, DeeplyNestedSuccessIsDecodeError) {
    fake->reply(200, nested(5000));
    try {
        client().get("monitor/system/status");
        FAIL() << "expected DecodeError";
    } catch (const DecodeError& error) {
        EXPECT_STREQ(error.what(), "GET monitor/system/status: HTTP 200 with JSON nested deeper than 256 levels");
    }
}

TEST_F(ClientTest, NestingUpToTheLimitIsAccepted) {
    EXPECT_EQ(Config().max_reply_depth, 256u);
    fake->reply(200, nested(256)).reply(200, nested(257));
    auto body = client().get("monitor/x");
    EXPECT_TRUE(body["results"].is_array());
    EXPECT_THROW(client().get("monitor/x"), DecodeError);
}

TEST_F(ClientTest, TheNestingLimitIsConfigurable) {
    auto config = test_config();
    config.max_reply_depth = 3;
    fake->reply(200, std::string(R"({"results":[{"name":"a"}]})"))
        .reply(200, std::string(R"({"results":[{"members":[]}]})"));
    EXPECT_EQ(client(config).get("cmdb/x")["results"][0]["name"], "a");
    EXPECT_THROW(client(config).get("cmdb/x"), DecodeError);
}

TEST_F(ClientTest, DeeplyNestedErrorKeepsTheRawBody) {
    fake->reply(500, nested(5000));
    auto result = client().exchange(Method::Post, "cmdb/firewall/address");
    EXPECT_EQ(result.http_status, 500);
    EXPECT_EQ(result.body["raw"], nested(5000));
    EXPECT_FALSE(result.ok());
}

TEST_F(ClientTest, NonJsonErrorKeepsTheRawBody) {
    fake->reply(502, std::string("Bad Gateway"));
    auto config = test_config();
    config.retries = 0;
    auto result = client(config).exchange(Method::Get, "monitor/system/status");
    EXPECT_EQ(result.http_status, 502);
    EXPECT_EQ(result.body["raw"], "Bad Gateway");
}

TEST_F(ClientTest, GetRetriesThrottlingAndGatewayErrors) {
    fake->reply(429, std::string("")).reply(503, std::string("")).reply(200, envelope({{"ok", true}}));
    auto body = client().get("monitor/system/status");
    EXPECT_EQ(fake->requests.size(), 3u);
    EXPECT_EQ(body["results"]["ok"], true);
}

TEST_F(ClientTest, GetGivesUpAfterConfiguredRetries) {
    fake->reply(503, std::string("")).reply(503, std::string("")).reply(503, std::string(""));
    EXPECT_THROW(client().get("monitor/system/status"), ApiError);
    EXPECT_EQ(fake->requests.size(), 3u);  // 1 + retries (2)
}

TEST_F(ClientTest, GetRetriesTransportErrors) {
    fake->fail(CURLE_OPERATION_TIMEDOUT, false).reply(200, envelope({}));
    client().get("monitor/system/status");
    EXPECT_EQ(fake->requests.size(), 2u);
}

TEST_F(ClientTest, UnauthorizedIsNeverRetried) {
    fake->reply(401, std::string(""));
    EXPECT_THROW(client().get("monitor/system/status"), ApiError);
    EXPECT_EQ(fake->requests.size(), 1u);
}

// Requirement: never retry a configuration mutation that may have reached the device.
TEST_F(ClientTest, MutationsAreNotRetriedAfterAResponse) {
    for (Method method: {Method::Post, Method::Put, Method::Delete}) {
        fake->requests.clear();
        fake->script.clear();
        fake->reply(503, std::string("")).reply(200, envelope({}));
        nlohmann::json body = {{"name", "x"}};
        EXPECT_THROW(client().request(method, "cmdb/dnsfilter/profile/x", {}, method == Method::Delete ? nullptr : &body),
                     ApiError) << to_string(method);
        EXPECT_EQ(fake->requests.size(), 1u) << to_string(method);
    }
}

TEST_F(ClientTest, MutationsAreNotRetriedAfterAPossibleSend) {
    fake->fail(CURLE_OPERATION_TIMEDOUT, false).reply(200, envelope({}));
    EXPECT_THROW(client().put("cmdb/dnsfilter/profile/x", {{"comment", "y"}}), TransportError);
    EXPECT_EQ(fake->requests.size(), 1u);
}

TEST_F(ClientTest, MutationsRetryOnlyWhenNothingWasSent) {
    fake->fail(CURLE_COULDNT_CONNECT, true).reply(200, envelope({}));
    client().post("cmdb/dnsfilter/profile", {{"name", "x"}});
    EXPECT_EQ(fake->requests.size(), 2u);
}

TEST_F(ClientTest, ExchangeHookNeverSeesTheApiKey) {
    std::vector<Exchange> seen;
    auto config = test_config();
    config.on_exchange = [&](const Exchange& exchange) { seen.push_back(exchange); };
    fake->reply(200, envelope({}));
    client(config).get("monitor/system/status");
    ASSERT_EQ(seen.size(), 1u);
    EXPECT_EQ(seen[0].http_status, 200);
    EXPECT_EQ(seen[0].url.find("test-key"), std::string::npos);
    EXPECT_EQ(seen[0].request_body.find("test-key"), std::string::npos);
}

TEST(ConfigTest, FromEnvironment) {
    ::setenv("FORTIGATE_HOST", "fw.example", 1);
    ::setenv("FORTIGATE_API_KEY", "k", 1);
    ::setenv("FORTIGATE_ADMIN_HTTPS_PORT", "8443", 1);
    ::setenv("FORTIGATE_RESOLVE_IP", "10.0.0.1", 1);
    ::unsetenv("FORTIGATE_VDOM");
    auto config = Config::from_env();
    EXPECT_EQ(config.host, "fw.example");
    EXPECT_EQ(config.port, 8443u);
    EXPECT_EQ(config.resolve_ip, "10.0.0.1");
    EXPECT_TRUE(config.vdom.empty());

    ::setenv("FORTIGATE_ADMIN_HTTPS_PORT", "84x3", 1);
    EXPECT_THROW(Config::from_env(), Error);
    ::setenv("FORTIGATE_ADMIN_HTTPS_PORT", "8443", 1);
    ::unsetenv("FORTIGATE_API_KEY");
    EXPECT_THROW(Config::from_env(), Error);
}
