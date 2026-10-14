// System reads (read-only): interfaces, global settings, API users.
#include <gtest/gtest.h>
#include "live.hpp"

#include <regex>

using namespace fortiapi;

TEST(System, Wan1HasAnIpv4Address) {
    auto addresses = system::interface_addresses("wan1");
    ASSERT_FALSE(addresses.empty());
    EXPECT_TRUE(std::regex_match(addresses.front().ip, std::regex(R"(^(\d{1,3}\.){3}\d{1,3}$)"))) << addresses.front().ip;
    EXPECT_GT(addresses.front().prefix_length, 0u);
}

TEST(System, Wan1IsAPhysicalInterface) {
    auto wan1 = system::Interfaces::get("wan1");
    EXPECT_EQ(*wan1.type, system::Interface::Type::physical);
    EXPECT_EQ(*wan1.vdom, "root");
}

TEST(System, ApiUsersTrusthostsParse) {
    for (const auto& user: system::ApiUsers::list()) {
        if (!user.trusthost) continue;
        for (const auto& host: *user.trusthost) {
            ASSERT_TRUE(host.type.has_value());
            if (*host.type == system::ApiUser::TrusthostEntry::Type::ipv4_trusthost) {
                EXPECT_TRUE(system::trusts(user, *host.ipv4_trusthost)) << *host.ipv4_trusthost;
            }
        }
    }
}
