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
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/router/static/forti-api-test-a")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Put, "cmdb/firewall/vip/forti-api-test-v")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "monitor/system/external-resource/refresh", R"({"name":"forti-api-test-x"})")), GuardViolation);
}

TEST(LiveGuard, AllowsPushCommandsOnlyForTestFeeds) {
    auto push = [](const std::string& body) { return req(Method::Post, "monitor/system/external-resource/dynamic", body); };
    EXPECT_NO_THROW(GuardTransport::check(push(R"({"commands":[{"name":"forti-api-test-f","command":"snapshot","entries":[]}]})")));
    EXPECT_THROW(GuardTransport::check(push(R"({"commands":[{"name":"real-feed","command":"snapshot"}]})")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(push(R"({"commands":[{"name":"forti-api-test-f"},{"name":"real-feed"}]})")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(push(R"({"commands":[]})")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(push("not json")), GuardViolation);
}

TEST(LiveGuard, RefusesTricksInTheKey) {
    // Whole-collection writes, and writes to a whole child table, are not one test object or entry.
    EXPECT_THROW(GuardTransport::check(req(Method::Put, "cmdb/dnsfilter/profile")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/dnsfilter/profile/forti-api-test-a/ftgd-dns")), GuardViolation);
    // Encoded names are decoded before the prefix check.
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/dnsfilter/profile/forti%2Dapi%2Dtes")), GuardViolation);
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Delete, "cmdb/dnsfilter/profile/forti%2Dapi%2Dtest%2Dx")));
}

TEST(LiveGuard, AllowsChildEntriesOfTestObjects) {
    // Name-keyed entries (addrgrp member): the entry is forti-api-test-* too.
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Post, "cmdb/firewall/addrgrp/forti-api-test-g/member",
                                              R"({"name":"forti-api-test-a"})")));
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Put, "cmdb/firewall/addrgrp/forti-api-test-g/member/forti-api-test-a")));
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Delete, "cmdb/firewall/addrgrp/forti-api-test-g/member/forti-api-test-a?vdom=root")));
    // Numeric-id entries (access-list rule) of a test object.
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Post, "cmdb/router/access-list/forti-api-test-acl/rule", R"({"id":0,"prefix":"192.0.2.0 255.255.255.0"})")));
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Post, "cmdb/router/access-list/forti-api-test-acl/rule", R"({"id":17})")));
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Put, "cmdb/router/access-list/forti-api-test-acl/rule/17", R"({"action":"deny"})")));
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Delete, "cmdb/router/access-list/forti-api-test-acl/rule/17")));
    // Keys are decoded per segment: an encoded "/" stays inside the key.
    EXPECT_NO_THROW(GuardTransport::check(req(Method::Delete, "cmdb/firewall/addrgrp/forti%2Dapi%2Dtest%2Dg/member/forti-api-test-a%2Fb")));
}

TEST(LiveGuard, RefusesChildEntriesOfRealObjects) {
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "cmdb/firewall/addrgrp/office/member", R"({"name":"forti-api-test-a"})")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/firewall/addrgrp/office/member/forti-api-test-a")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Put, "cmdb/router/access-list/real-acl/rule/1", R"({"action":"deny"})")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/router/access-list/real-acl/rule/1")), GuardViolation);
    // An encoded "/" cannot smuggle a test prefix into the parent segment.
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/firewall/addrgrp/office%2Fforti-api-test-g/member/forti-api-test-a")), GuardViolation);
}

TEST(LiveGuard, RefusesNonTestEntriesOfTestObjects) {
    // A name-keyed entry must be forti-api-test-* as well.
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "cmdb/firewall/addrgrp/forti-api-test-g/member", R"({"name":"all"})")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/firewall/addrgrp/forti-api-test-g/member/all")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Put, "cmdb/firewall/addrgrp/forti-api-test-g/member/office-lan")), GuardViolation);
    // A POST names a test entry or a numeric id; anything else is refused.
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "cmdb/router/access-list/forti-api-test-acl/rule", R"({"prefix":"any"})")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "cmdb/router/access-list/forti-api-test-acl/rule", R"({"id":-1})")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "cmdb/router/access-list/forti-api-test-acl/rule", R"({"id":"1"})")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "cmdb/firewall/addrgrp/forti-api-test-g/member", R"({"name":7})")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "cmdb/firewall/addrgrp/forti-api-test-g/member", "not json")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "cmdb/firewall/addrgrp/forti-api-test-g/member", R"([{"name":"forti-api-test-a"}])")), GuardViolation);
    // Numbers that are not plain decimal ids.
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/router/access-list/forti-api-test-acl/rule/-1")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/router/access-list/forti-api-test-acl/rule/1%2F2")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/router/access-list/forti-api-test-acl/rule/")), GuardViolation);
}

TEST(LiveGuard, RefusesOtherChildPathShapes) {
    // A whole child table, or the parent's path with POST.
    EXPECT_THROW(GuardTransport::check(req(Method::Put, "cmdb/firewall/addrgrp/forti-api-test-g/member", R"([])")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/router/access-list/forti-api-test-acl/rule")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "cmdb/firewall/addrgrp/forti-api-test-g", R"({"name":"forti-api-test-a"})")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "cmdb/firewall/addrgrp/forti-api-test-g/member/forti-api-test-a", R"({"name":"forti-api-test-a"})")), GuardViolation);
    // Tables nested in entries, and attribute segments that are not attribute names.
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/router/route-map/forti-api-test-rm/rule/1/set-community/forti-api-test-c")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/firewall/addrgrp/forti-api-test-g/%2E%2E/forti-api-test-a")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/firewall/addrgrp/forti-api-test-g/Member/forti-api-test-a")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/firewall/addrgrp/forti-api-test-g//forti-api-test-a")), GuardViolation);
    // Child paths outside the approved collections, even of test-named objects.
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/system.dhcp/server/1/reserved-address/7")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Post, "cmdb/system.dhcp/server/forti-api-test-s/reserved-address", R"({"id":0})")), GuardViolation);
    EXPECT_THROW(GuardTransport::check(req(Method::Put, "cmdb/firewall/policy/forti-api-test-p/srcaddr/forti-api-test-a")), GuardViolation);
    // A collection whose name merely starts with an approved one.
    EXPECT_THROW(GuardTransport::check(req(Method::Delete, "cmdb/firewall/addressX/forti-api-test-a")), GuardViolation);
}

TEST(LiveGuard, NeverReachesTheTransportWhenRefusing) {
    auto fake = std::make_shared<fortiapi::testing::FakeTransport>();
    GuardTransport guard(fake);
    EXPECT_THROW(guard.perform(req(Method::Delete, "cmdb/firewall/policy/1")), GuardViolation);
    EXPECT_TRUE(fake->requests.empty());
}

TEST(LiveGuard, ReadOnlyRunsRefuseEveryWrite) {
    auto fake = std::make_shared<fortiapi::testing::FakeTransport>();
    GuardTransport guard(fake, true);
    EXPECT_THROW(guard.perform(req(Method::Post, "cmdb/dnsfilter/profile", R"({"name":"forti-api-test-a"})")), GuardViolation);
    EXPECT_THROW(guard.perform(req(Method::Delete, "cmdb/dnsfilter/profile/forti-api-test-a")), GuardViolation);
    EXPECT_TRUE(fake->requests.empty());
    fake->reply(200, std::string("{}"));
    EXPECT_NO_THROW(guard.perform(req(Method::Get, "monitor/system/status")));
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

// Child-table writes are logged against the parent object (FortiOS 7.4.8, tests/live/test_child_table.cpp),
// so a write to an entry of a test object is a test change and one to an entry of a real object is not.
TEST(ConfigAudit, AttributesChildWritesToTheParent) {
    using fortiapi::testing::FakeTransport;
    auto fake = std::make_shared<FakeTransport>();
    fortiapi::Client client(fortiapi::testing::test_config(), fake);
    std::int64_t start_ms = 1'792'000'000'000;
    auto at = [&](std::int64_t offset_ms) { return (start_ms + offset_ms) * 1'000'000; };

    fake->reply(200, nlohmann::json{{"status", "success"}, {"now", start_ms}, {"results", nlohmann::json::array()}});
    nlohmann::json log = {{"status", "success"}, {"results", {
            {{"eventtime", at(3)}, {"ui", "RESTAPI(10.0.0.11)"}, {"user", "api_admin"}, {"action", "Edit"},
             {"cfgpath", "firewall.addrgrp"}, {"cfgobj", "office"}, {"cfgattr", "member[a b->a]"}},
            {{"eventtime", at(2)}, {"ui", "RESTAPI(10.0.0.11)"}, {"user", "api_admin"}, {"action", "Edit"},
             {"cfgpath", "router.access-list"}, {"cfgobj", "forti-api-test-ct-logged"},
             {"cfgattr", "rule:7[action[deny]prefix[198.51.100.7 255.255.255.255]wildcard[]action[deny->permit]<Delete>]"}},
    }}};
    fake->reply(200, log);

    live::ConfigAudit audit;
    audit.settle = std::chrono::milliseconds(0);
    audit.poll = std::chrono::milliseconds(0);
    audit.begin(client);
    auto found = audit.violations(client);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0], "Edit firewall.addrgrp office by api_admin");
    EXPECT_EQ(live::attribute_names("rule:7[action[deny]wildcard[]<Delete>]rule:2[action[permit]]"),
              (std::vector<std::string>{"rule:7", "rule:2"}));
}
