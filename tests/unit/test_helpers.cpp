#include <gtest/gtest.h>
#include "fake_transport.hpp"
#include <forti_api/dnsfilter.hpp>
#include <forti_api/firewall.hpp>
#include <forti_api/system.hpp>
#include <forti_api/threat_feed.hpp>

using namespace fortiapi;
using nlohmann::json;

namespace {
    dnsfilter::Profile device_profile() {
        return from_json<dnsfilter::Profile>(json{
                {"name", "p"}, {"comment", "c"},
                {"ftgd-dns", {{"options", ""}, {"filters", json::array({json::object({{"id", 1}, {"category", 26}, {"action", "block"}, {"log", "enable"}})})}}}});
    }
}

TEST(DnsFilterHelpers, CategoryActions) {
    auto profile = device_profile();
    EXPECT_EQ(dnsfilter::category_action(profile, 26), "block");
    EXPECT_EQ(dnsfilter::category_action(profile, 27), std::nullopt);
    EXPECT_EQ(dnsfilter::category_action(dnsfilter::Profile{}, 26), std::nullopt);
}

TEST(DnsFilterHelpers, EditsSendOnlyTheFilterTable) {
    auto profile = device_profile();
    dnsfilter::monitor_category(profile, 30);
    dnsfilter::block_category(profile, 26);     // already blocked: unchanged entry
    EXPECT_EQ(to_json(profile, Write::update),
              (json{{"ftgd-dns", {{"filters", json::array({
                      json::object({{"id", 1}, {"category", 26}, {"action", "block"}, {"log", "enable"}}),
                      json::object({{"category", 30}, {"action", "monitor"}})})}}}}));
}

TEST(DnsFilterHelpers, AllowRemovesTheFilterAndIsANoOpOtherwise) {
    auto profile = device_profile();
    dnsfilter::allow_category(profile, 99);
    EXPECT_FALSE(dirty(profile));
    dnsfilter::allow_category(profile, 26);
    EXPECT_EQ(to_json(profile, Write::update), (json{{"ftgd-dns", {{"filters", json::array()}}}}));
}

TEST(DnsFilterHelpers, AllowEverywhereWritesOnlyListingProfiles) {
    auto fake = std::make_shared<fortiapi::testing::FakeTransport>();
    Client client(fortiapi::testing::test_config(), fake);
    auto listing = json::object({{"name", "listing"}, {"ftgd-dns", {{"filters", json::array({json::object({{"id", 1}, {"category", 200}, {"action", "block"}})})}}}});
    auto other = json::object({{"name", "other"}, {"ftgd-dns", {{"filters", json::array()}}}});
    fake->reply(200, fortiapi::testing::envelope(json::array({listing, other})));
    fake->reply(200, json{{"status", "success"}, {"mkey", "listing"}});

    auto updated = dnsfilter::allow_category_everywhere(200, {}, client);
    EXPECT_EQ(updated, std::vector<std::string>{"listing"});
    ASSERT_EQ(fake->requests.size(), 2u);
    EXPECT_EQ(fake->requests[1].method, Method::Put);
    EXPECT_EQ(fake->requests[1].url, "https://fortigate.test:8443/api/v2/cmdb/dnsfilter/profile/listing");
    EXPECT_EQ(json::parse(fake->requests[1].body), (json{{"ftgd-dns", {{"filters", json::array()}}}}));
}

TEST(FirewallHelpers, DaysUseFortiOsNames) {
    using firewall::Weekday;
    EXPECT_EQ(firewall::days({Weekday::monday, Weekday::wednesday, Weekday::sunday}), "monday wednesday sunday");
    EXPECT_EQ(firewall::days({}), "");
}

TEST(FirewallHelpers, PortRanges) {
    EXPECT_EQ(firewall::port_ranges({{443}}), "443");
    EXPECT_EQ(firewall::port_ranges({{80}, {8000, 8080}, {53, 53}}), "80 8000-8080 53");
}

TEST(SystemHelpers, TrusthostNormalization) {
    using system::detail::ipv4_subnet;
    EXPECT_EQ(ipv4_subnet("10.0.0.0/24"), "10.0.0.0 255.255.255.0");
    EXPECT_EQ(ipv4_subnet("10.0.0.0 255.255.0.0"), "10.0.0.0 255.255.0.0");
    EXPECT_EQ(ipv4_subnet("192.168.1.10"), "192.168.1.10 255.255.255.255");
    EXPECT_EQ(ipv4_subnet("0.0.0.0/0"), "0.0.0.0 0.0.0.0");
    EXPECT_EQ(ipv4_subnet("10.0.0/24"), std::nullopt);
    EXPECT_EQ(ipv4_subnet("10.0.0.256/24"), std::nullopt);
    EXPECT_EQ(ipv4_subnet("10.0.0.0/33"), std::nullopt);
    EXPECT_EQ(ipv4_subnet("2001:db8::/32"), std::nullopt);
}

TEST(SystemHelpers, TrustAndDistrust) {
    auto user = from_json<system::ApiUser>(json{
            {"name", "api"}, {"accprofile", "x"},
            {"trusthost", json::array({json::object({{"id", 1}, {"type", "ipv4-trusthost"}, {"ipv4-trusthost", "10.0.0.0 255.255.255.0"}})})}});
    EXPECT_TRUE(system::trusts(user, "10.0.0.0/24"));
    system::trust(user, "10.0.0.0 255.255.255.0");
    EXPECT_FALSE(dirty(user));

    system::trust(user, "2001:db8::/32");
    system::trust(user, "192.168.1.0/24");
    auto body = to_json(user, Write::update);
    ASSERT_EQ(body.size(), 1u);
    EXPECT_EQ(body["trusthost"].size(), 3u);
    EXPECT_EQ(body["trusthost"][1], (json{{"type", "ipv6-trusthost"}, {"ipv6-trusthost", "2001:db8::/32"}}));
    EXPECT_EQ(body["trusthost"][2], (json{{"type", "ipv4-trusthost"}, {"ipv4-trusthost", "192.168.1.0 255.255.255.0"}}));

    system::distrust(user, "10.0.0.0/24");
    EXPECT_FALSE(system::trusts(user, "10.0.0.0/24"));
    EXPECT_THROW(system::trust(user, "not a subnet"), std::invalid_argument);
}

TEST(ThreatFeedHelpers, PushFeedObjectAndCommands) {
    auto feed = system::push_threat_feed("f", 200);
    EXPECT_EQ(to_json(feed, Write::create),
              (json{{"name", "f"}, {"type", "domain"}, {"update-method", "push"}, {"category", 200}}));

    auto fake = std::make_shared<fortiapi::testing::FakeTransport>();
    Client client(fortiapi::testing::test_config(), fake);
    fake->reply(200, json{{"status", "success"}});
    system::push_entries("f", {"a.example", "b.example"}, system::FeedCommand::remove, client);
    EXPECT_EQ(fake->requests[0].url, "https://fortigate.test:8443/api/v2/monitor/system/external-resource/dynamic");
    EXPECT_EQ(json::parse(fake->requests[0].body),
              (json{{"commands", json::array({json::object({{"name", "f"}, {"command", "remove"}, {"entries", {"a.example", "b.example"}}})})}}));
}

TEST(ThreatFeedHelpers, RejectedCommandsThrowDespiteTopLevelSuccess) {
    auto fake = std::make_shared<fortiapi::testing::FakeTransport>();
    Client client(fortiapi::testing::test_config(), fake);
    fake->reply(200, json{{"status", "success"}, {"http_status", 200},
                          {"results", json::array({json::object({{"name", "f"}, {"command", "snapshot"}, {"status", "error"},
                                                                 {"error", "External resource has not been loaded."}})})}});
    try {
        system::push_entries("f", {"a.example"}, system::FeedCommand::snapshot, client);
        FAIL() << "expected ApiError";
    } catch (const ApiError& error) {
        EXPECT_NE(std::string(error.what()).find("External resource has not been loaded."), std::string::npos);
    }
}

TEST(ThreatFeedHelpers, FeedStateDuringLoadAndAfterPush) {
    auto fake = std::make_shared<fortiapi::testing::FakeTransport>();
    Client client(fortiapi::testing::test_config(), fake);
    fake->reply(200, fortiapi::testing::envelope(json{{"status", "error"}, {"error_code", 1}, {"error", "Connect pending"}}));
    auto pending = system::feed_state("f", client);
    EXPECT_FALSE(pending.loaded);
    EXPECT_EQ(pending.error, "Connect pending");

    fake->reply(200, fortiapi::testing::envelope(json{{"status", "success"}, {"resource_file_status", "downloaded"},
                                                      {"entries", json::array({json::object({{"entry", "a.example"}, {"valid", true}})})}}));
    auto ready = system::feed_state("f", client);
    EXPECT_TRUE(ready.loaded);
    ASSERT_EQ(ready.entries.size(), 1u);
    EXPECT_TRUE(ready.entries[0].valid);
    EXPECT_EQ(fake->requests[1].url, "https://fortigate.test:8443/api/v2/monitor/system/external-resource/entry-list?mkey=f&include_notes=true");
}

TEST(ThreatFeedHelpers, FeedStatusIsOneRequestWithoutEntries) {
    auto fake = std::make_shared<fortiapi::testing::FakeTransport>();
    Client client(fortiapi::testing::test_config(), fake);
    // The shape FortiOS 7.4.8 sends for a start past the end: totals, an empty window.
    fake->reply(200, fortiapi::testing::envelope(json{
            {"status", "success"}, {"resource_file_status", "downloaded"}, {"last_content_update_time", 1792335482},
            {"overflow", false}, {"accepted_count", 5}, {"accepted_limit", 1000000}, {"entries", json::array()},
            {"matched_invalid", 0}, {"matched_valid", 0}, {"invalid_count", 1}, {"valid_count", 5}}));
    auto status = system::feed_status("f", client);
    ASSERT_EQ(fake->requests.size(), 1u);
    EXPECT_EQ(fake->requests[0].url,
              "https://fortigate.test:8443/api/v2/monitor/system/external-resource/entry-list?mkey=f&start=2147483647&count=1");
    EXPECT_TRUE(status.loaded);
    EXPECT_EQ(status.file_status, "downloaded");
    EXPECT_EQ(status.error, "");
    EXPECT_EQ(status.accepted, 5u);
    EXPECT_EQ(status.valid, 5u);
    EXPECT_EQ(status.invalid, 1u);
    EXPECT_EQ(status.limit, 1000000u);
    EXPECT_FALSE(status.overflow);
    EXPECT_EQ(status.last_update, 1792335482);
}

TEST(ThreatFeedHelpers, FeedStatusBeforeTheFeedIsLoaded) {
    auto fake = std::make_shared<fortiapi::testing::FakeTransport>();
    Client client(fortiapi::testing::test_config(), fake);
    fake->reply(200, fortiapi::testing::envelope(json{{"error", "Connect pending"}, {"error_code", 1}, {"status", "error"}}));
    auto status = system::feed_status("f", client);
    EXPECT_FALSE(status.loaded);
    EXPECT_EQ(status.error, "Connect pending");
    EXPECT_EQ(status.file_status, "");
    EXPECT_EQ(status.accepted, 0u);
    EXPECT_EQ(status.limit, 0u);
    EXPECT_EQ(status.last_update, 0);
}

TEST(ThreatFeedHelpers, FeedStatusReadsNumbersSentAsTextAndIgnoresJunk) {
    auto fake = std::make_shared<fortiapi::testing::FakeTransport>();
    Client client(fortiapi::testing::test_config(), fake);
    fake->reply(200, fortiapi::testing::envelope(json{
            {"status", "success"}, {"accepted_count", "7"}, {"valid_count", 7.0}, {"invalid_count", -1},
            {"accepted_limit", "lots"}, {"overflow", "true"}, {"last_content_update_time", "1792335482"},
            {"resource_file_status", 3}}));
    auto status = system::feed_status("f", client);
    EXPECT_TRUE(status.loaded);
    EXPECT_EQ(status.accepted, 7u);
    EXPECT_EQ(status.valid, 7u);
    EXPECT_EQ(status.invalid, 0u);   // negative: does not fit
    EXPECT_EQ(status.limit, 0u);     // not a number
    EXPECT_TRUE(status.overflow);
    EXPECT_EQ(status.last_update, 1792335482);
    EXPECT_EQ(status.file_status, "");

    fake->reply(200, fortiapi::testing::envelope(json::array()));   // not an object at all
    auto odd = system::feed_status("f", client);
    EXPECT_FALSE(odd.loaded);
    EXPECT_EQ(odd.accepted, 0u);
}

TEST(ThreatFeedHelpers, FeedEntriesRequestsOnePage) {
    auto fake = std::make_shared<fortiapi::testing::FakeTransport>();
    Client client(fortiapi::testing::test_config(), fake);
    fake->reply(200, fortiapi::testing::envelope(json{
            {"status", "success"}, {"accepted_count", 5}, {"matched_valid", 1}, {"matched_invalid", 1},
            {"entries", json::array({json::object({{"entry", "a.example"}, {"valid", true}, {"comment", ""}}),
                                     json::object({{"entry", "not a domain"}, {"valid", false}, {"comment", ""}})})}}));
    auto page = system::feed_entries("feed name", 20, 2, client);
    ASSERT_EQ(fake->requests.size(), 1u);
    EXPECT_EQ(fake->requests[0].url,
              "https://fortigate.test:8443/api/v2/monitor/system/external-resource/entry-list?mkey=feed%20name&start=20&count=2");
    ASSERT_EQ(page.size(), 2u);
    EXPECT_EQ(page[0].entry, "a.example");
    EXPECT_TRUE(page[0].valid);
    EXPECT_EQ(page[1].entry, "not a domain");
    EXPECT_FALSE(page[1].valid);

    // count=0 would make FortiOS return every entry; it sends nothing instead.
    EXPECT_TRUE(system::feed_entries("f", 0, 0, client).empty());
    EXPECT_EQ(fake->requests.size(), 1u);

    fake->reply(200, fortiapi::testing::envelope(json{{"error", "Connect pending"}, {"error_code", 1}, {"status", "error"}}));
    EXPECT_TRUE(system::feed_entries("f", 0, 10, client).empty());
}
