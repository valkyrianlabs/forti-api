//
// Created by Cooper Larson on 8/28/24.
//

#include <gtest/gtest.h>
#include "live.hpp"

TEST(TestDNSFilter, TestGetProfiles) {
    auto profiles = DNSFilter::get();
    ASSERT_FALSE(profiles.empty());
    for (const auto& profile : profiles) ASSERT_FALSE(profile.name.empty());
}

TEST(TestDNSFilter, TestAddRemove) {
    auto profile = live::dns_profile("dns-add-remove");
    live::Cleanup cleanup([&] { live::del_dns_profile(profile.name); });
    ASSERT_FALSE(DNSFilter::contains(profile.name));

    ASSERT_EQ(DNSFilter::add(profile).status, "success");
    ASSERT_TRUE(DNSFilter::contains(profile.name));
    ASSERT_EQ(DNSFilter::get(profile.name).comment, live::comment);

    ASSERT_EQ(DNSFilter::del(profile.name).status, "success");
    ASSERT_FALSE(DNSFilter::contains(profile.name));
}

TEST(TestDNSFilter, TestToggleFilters) {
    auto profile = live::dns_profile("dns-toggle-filters");
    live::Cleanup cleanup([&] { live::del_dns_profile(profile.name); });
    ASSERT_EQ(DNSFilter::add(profile).status, "success");

    auto created = DNSFilter::get(profile.name);
    created.ftgd_dns.block(1);
    created.ftgd_dns.block(2);
    created.ftgd_dns.monitor(3);
    created.ftgd_dns.allow(1);
    ASSERT_EQ(DNSFilter::update(created).status, "success");

    // Read back from the device, not the local copy.
    auto stored = DNSFilter::get(profile.name).ftgd_dns;
    ASSERT_FALSE(stored.contains(1));

    const auto& [blocked_found, blocked] = stored.find_category(2);
    ASSERT_TRUE(blocked_found);
    ASSERT_EQ(stored.filters[blocked].action, "block");

    const auto& [monitored_found, monitored] = stored.find_category(3);
    ASSERT_TRUE(monitored_found);
    ASSERT_EQ(stored.filters[monitored].action, "monitor");
}
