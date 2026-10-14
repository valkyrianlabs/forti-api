#include <gtest/gtest.h>
#include "fake_transport.hpp"
#include <forti_api/gen/dnsfilter/profile.hpp>
#include <forti_api/gen/firewall/address.hpp>
#include <forti_api/gen/firewall/policy.hpp>
#include <forti_api/gen/system/global.hpp>

using namespace fortiapi;
using fortiapi::testing::FakeTransport;
using fortiapi::testing::envelope;
using fortiapi::testing::test_config;
using nlohmann::json;

namespace {

    struct EndpointTest : ::testing::Test {
        std::shared_ptr<FakeTransport> fake = std::make_shared<FakeTransport>();
        Client client{test_config(), fake};

        [[nodiscard]] std::string url(std::size_t i) const { return fake->requests.at(i).url; }
        [[nodiscard]] json body(std::size_t i) const { return json::parse(fake->requests.at(i).body); }
    };

    json write_reply(json mkey) {
        return {{"http_method", "POST"}, {"status", "success"}, {"http_status", 200}, {"revision", "abc"},
                {"mkey", std::move(mkey)}, {"vdom", "root"}};
    }

    const std::string base = "https://fortigate.test:8443/api/v2/";

}  // namespace

TEST_F(EndpointTest, ListParsesEveryResult) {
    fake->reply(200, envelope(json::array({json::object({{"name", "a"}, {"subnet", "10.0.0.0 255.255.255.0"}}), json::object({{"name", "b"}})})));
    auto addresses = firewall::Addresses::list(Query().filter("name=@a"), client);
    ASSERT_EQ(addresses.size(), 2u);
    EXPECT_EQ(*addresses[0].subnet, "10.0.0.0 255.255.255.0");
    EXPECT_FALSE(addresses[1].subnet.has_value());
    EXPECT_EQ(url(0), base + "cmdb/firewall/address?filter=name%3D%40a");
}

TEST_F(EndpointTest, GetEncodesTheKey) {
    fake->reply(200, envelope(json::array({json::object({{"name", "LAN 10.0.0.0/24"}})})));
    auto address = firewall::Addresses::get("LAN 10.0.0.0/24", {}, client);
    EXPECT_EQ(*address.name, "LAN 10.0.0.0/24");
    EXPECT_EQ(url(0), base + "cmdb/firewall/address/LAN%2010.0.0.0%2F24");
}

TEST_F(EndpointTest, FindAndContainsTreat404AsAbsent) {
    fake->reply(404, json{{"status", "error"}, {"http_status", 404}});
    EXPECT_FALSE(firewall::Addresses::find("nope", {}, client).has_value());
    fake->reply(404, json{{"status", "error"}, {"http_status", 404}});
    EXPECT_FALSE(firewall::Addresses::contains("nope", {}, client));
    fake->reply(500, json{{"status", "error"}, {"http_status", 500}});
    EXPECT_THROW(firewall::Addresses::find("x", {}, client), ApiError);
}

TEST_F(EndpointTest, GetThrowsNotFound) {
    fake->reply(404, json{{"status", "error"}, {"http_status", 404}});
    try {
        firewall::Addresses::get("nope", {}, client);
        FAIL();
    } catch (const ApiError& error) {
        EXPECT_TRUE(error.not_found());
    }
}

TEST_F(EndpointTest, AddPostsKnownFieldsAndStoresTheAssignedKey) {
    fake->reply(200, write_reply(17));
    firewall::Policy policy;
    policy.name = "forti-api-test-p";
    policy.action = std::string(firewall::Policy::Action::deny);
    auto reply = firewall::Policies::add(policy, {}, client);

    EXPECT_EQ(fake->requests[0].method, Method::Post);
    EXPECT_EQ(url(0), base + "cmdb/firewall/policy");
    EXPECT_EQ(body(0), (json{{"name", "forti-api-test-p"}, {"action", "deny"}}));
    EXPECT_EQ(reply.revision, "abc");
    EXPECT_EQ(*policy.policyid, 17u);
    EXPECT_FALSE(dirty(policy));
}

TEST_F(EndpointTest, UpdatePutsOnlyChangesToTheKeyedPath) {
    fake->reply(200, envelope(json::array({json::object({{"name", "forti-api-test-d"}, {"comment", "old"}, {"block-action", "block"}})})));
    auto profile = dnsfilter::Profiles::get("forti-api-test-d", {}, client);
    profile.comment = "new";

    fake->reply(200, write_reply("forti-api-test-d"));
    auto reply = dnsfilter::Profiles::update(profile, Query().vdom("root"), client);
    ASSERT_TRUE(reply.has_value());
    EXPECT_EQ(fake->requests[1].method, Method::Put);
    EXPECT_EQ(url(1), base + "cmdb/dnsfilter/profile/forti-api-test-d?vdom=root");
    EXPECT_EQ(body(1), (json{{"comment", "new"}}));
    EXPECT_FALSE(dirty(profile));
}

TEST_F(EndpointTest, UpdateWithoutChangesSendsNothing) {
    fake->reply(200, envelope(json::array({json::object({{"name", "forti-api-test-d"}, {"comment", "old"}})})));
    auto profile = dnsfilter::Profiles::get("forti-api-test-d", {}, client);
    EXPECT_FALSE(dnsfilter::Profiles::update(profile, {}, client).has_value());
    EXPECT_EQ(fake->requests.size(), 1u);
}

TEST_F(EndpointTest, UpdateNeedsTheKey) {
    dnsfilter::Profile profile;
    profile.comment = "x";
    EXPECT_THROW(dnsfilter::Profiles::update(profile, {}, client), Error);
    EXPECT_TRUE(fake->requests.empty());
}

TEST_F(EndpointTest, FailedWriteLeavesTheObjectDirty) {
    fake->reply(500, json{{"status", "error"}, {"http_status", 500}, {"error", -3}});
    dnsfilter::Profile profile;
    profile.name = "forti-api-test-d";
    EXPECT_THROW(dnsfilter::Profiles::add(profile, {}, client), ApiError);
    EXPECT_TRUE(dirty(profile));
    EXPECT_EQ(fake->requests.size(), 1u);
}

TEST_F(EndpointTest, DeleteUsesTheEncodedKey) {
    fake->reply(200, write_reply("a/b"));
    firewall::Addresses::del("a/b", {}, client);
    EXPECT_EQ(fake->requests[0].method, Method::Delete);
    EXPECT_EQ(url(0), base + "cmdb/firewall/address/a%2Fb");
}

TEST_F(EndpointTest, SingletonGetAndUpdate) {
    fake->reply(200, envelope(json::object({{"hostname", "fw"}, {"admin-sport", 8443}})));
    auto global = system::GlobalSettings::get({}, client);
    EXPECT_EQ(*global.hostname, "fw");
    global.hostname = "fw2";
    fake->reply(200, write_reply(nullptr));
    system::GlobalSettings::update(global, {}, client);
    EXPECT_EQ(url(1), base + "cmdb/system/global");
    EXPECT_EQ(body(1), (json{{"hostname", "fw2"}}));
}

TEST_F(EndpointTest, SchemaUsesTheSchemaAction) {
    fake->reply(200, envelope(json::object({{"name", "policy"}, {"category", "table"}})));
    auto schema = firewall::Policies::schema(client);
    EXPECT_EQ(schema["category"], "table");
    EXPECT_EQ(url(0), base + "cmdb/firewall/policy?action=schema");
}
