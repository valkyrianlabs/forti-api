//
// Created by Cooper Larson on 8/28/24.
//

#include <gtest/gtest.h>
#include <forti_api/dns_filter.hpp>

TEST(TestDNSFilter, TestAddRemove) {
    std::string name = "test-123";
    ASSERT_TRUE(!DNSFilter::contains(name));

    DNSFilter::add(name);
    ASSERT_TRUE(DNSFilter::contains(name));

    DNSFilter::del(name);
    ASSERT_TRUE(!DNSFilter::contains(name));
}

TEST(TestDNSFilter, TestToggleFilters) {
    std::string name = "test-456";
    DNSFilter::add(name);
    ASSERT_TRUE(DNSFilter::contains(name));

    auto profile = DNSFilter::get(name);
    auto& filter = profile.ftgd_dns;
    filter.allow(1);
    filter.block(2);
    filter.monitor(3);
    DNSFilter::update(profile);

    const auto& [match_found, index] = filter.find_category(1);
    ASSERT_FALSE(match_found);

    const auto& [match_found1, index1] = filter.find_category(2);
    ASSERT_TRUE(match_found1);
    ASSERT_TRUE(filter.filters[index1].action == "block");

    const auto& [match_found2, index2] = filter.find_category(3);
    ASSERT_TRUE(match_found2);
    ASSERT_TRUE(filter.filters[index2].action == "monitor");

    DNSFilter::del(profile.name);
    ASSERT_FALSE(DNSFilter::contains(profile.name));
}

TEST(TestDNSFilter, TestContains192) {
    ASSERT_TRUE(DNSFilter::get("advanced").ftgd_dns.contains(193));
}
