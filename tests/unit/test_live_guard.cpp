// The live suite's safety net is itself tested without a device.
#include <gtest/gtest.h>
#include "fake_transport.hpp"
#include "../live/guard.hpp"

using fortiapi::HttpRequest;
using fortiapi::Method;
using live::GuardTransport;
using live::GuardViolation;

namespace {
    HttpRequest req(Method method, std::string path, std::string body = "") {
        return {method, "https://fw:8443/api/v2/" + std::move(path), {}, std::move(body)};
    }
}

TEST(LiveGuard, AllowsReadsAnywhere) {
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Get, "cmdb/firewall/policy")));
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Get, "monitor/system/status?vdom=root")));
}

TEST(LiveGuard, AllowsTestObjectsInApprovedCollections) {
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Post, "cmdb/dnsfilter/profile", R"({"name":"forti-api-test-a"})")));
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Put, "cmdb/dnsfilter/profile/forti-api-test-a?vdom=root")));
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Delete, "cmdb/system/external-resource/forti-api-test-feed")));
}

TEST(LiveGuard, RefusesRealObjects) {
    EXPECT_THROW(GuardTransport::check(req(Method::Put, "cmdb/dnsfilter/profile/default")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/dnsfilter/profile/advanced")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "cmdb/dnsfilter/profile", R"({"name":"home"})")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "cmdb/dnsfilter/profile", "not json")), GuardViolation);
}

TEST(LiveGuard, RefusesUnapprovedCollections) {
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "cmdb/firewall/policy", R"({"name":"forti-api-test-p"})")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/firewall/address/forti-api-test-a")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "monitor/system/external-resource/refresh", R"({"name":"forti-api-test-x"})")), GuardViolation);
}

TEST(LiveGuard, RefusesTricksInTheKey) {
    // Child paths and whole-collection writes are not "<collection>/<test object>".
    EXPECT_THROW(GuardTransport::check(req(Method::Put, "cmdb/dnsfilter/profile")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/dnsfilter/profile/forti-api-test-a/ftgd-dns")), GuardViolation);
    // Encoded names are decoded before the prefix check.
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/dnsfilter/profile/forti%2Dapi%2Dtes")), GuardViolation);
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Delete, "cmdb/dnsfilter/profile/forti%2Dapi%2Dtest%2Dx")));
}

TEST(LiveGuard, NeverReachesTheTransportWhenRefusing) {
    auto fake = std::make_shared<fortiapi::testing::FakeTransport>();
    GuardTransport guard(fake);
    EXPECT_THROW(guard.perform(req(Method::Delete, "cmdb/firewall/policy/1")), GuardViolation);
    EXPECT_TRUE(fake->requests.empty());
}

TEST(ConfigAudit, FlagsRestChangesToNonTestObjectsSinceTheStart) {
    using fortiapi::testing::FakeTransport;
    auto fake = std::make_shared<FakeTransport>();
    fortiapi::Client client(fortiapi::testing::test_config(), fake);
    std::int64_t start_ms = 1'792'000'000'000;
    auto at = [&](std::int64_t offset_ms) { return (start_ms + offset_ms) * 1'000'000; };

    fake->reply(200, nlohmann::json{{"status", "success"}, {"now", start_ms}, {"results", nlohmann::json::array()}});
    nlohmann::json log = {{"status", "success"}, {"results", {
            {{"eventtime", at(5)}, {"ui", "RESTAPI(10.0.0.11)"}, {"user", "api_admin"}, {"action", "Edit"},
             {"cfgpath", "dnsfilter.profile"}, {"cfgobj", "default"}},
            {{"eventtime", at(4)}, {"ui", "RESTAPI(10.0.0.11)"}, {"user", "api_admin"}, {"action", "Add"},
             {"cfgpath", "dnsfilter.profile"}, {"cfgobj", "forti-api-test-x"}},
            {{"eventtime", at(3)}, {"ui", "GUI(192.168.1.10)"}, {"user", "cooper"}, {"action", "Edit"},
             {"cfgpath", "firewall.policy"}, {"cfgobj", "12"}},
            {{"eventtime", at(2)}, {"ui", "RESTAPI(10.0.0.11)"}, {"logdesc", "Admin login successful"}},
            {{"eventtime", at(-10)}, {"ui", "RESTAPI(10.0.0.11)"}, {"user", "api_admin"}, {"action", "Delete"},
             {"cfgpath", "firewall.address"}, {"cfgobj", "before-the-run"}},
    }}};
    fake->reply(200, log);

    live::ConfigAudit audit;
    audit.settle = std::chrono::milliseconds(0);
    audit.poll = std::chrono::milliseconds(0);
    audit.begin(client);
    auto found = audit.violations(client);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0], "Edit dnsfilter.profile default by api_admin");
}

TEST(ConfigAudit, AttributeNamesAreTopLevelOnly) {
    EXPECT_EQ(live::attribute_names("comment[a->b]comment[b->]"), (std::vector<std::string>{"comment"}));
    EXPECT_EQ(live::attribute_names("comment[x]ftgd-dns[filters:2[category[3]]filters:1[category[2]action[block]]]"),
              (std::vector<std::string>{"comment", "ftgd-dns"}));
    EXPECT_TRUE(live::attribute_names("").empty());
}
