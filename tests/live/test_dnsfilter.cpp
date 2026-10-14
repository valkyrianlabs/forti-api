// DNS filter profiles and FortiGuard category helpers, on forti-api-test-* profiles only.
#include <gtest/gtest.h>
#include "live.hpp"

using namespace fortiapi;

TEST(DnsFilter, ListsTheDeviceProfiles) {
    auto profiles = dnsfilter::Profiles::list();
    ASSERT_FALSE(profiles.empty());
    for (const auto& profile: profiles) EXPECT_TRUE(profile.name.has_value());
}

TEST(DnsFilter, AddAndDelete) {
    auto profile = live::dns_profile("dns-add-delete");
    live::Cleanup cleanup([&] { live::del_dns_profile(*profile.name); });
    ASSERT_FALSE(dnsfilter::Profiles::contains(*profile.name));

    EXPECT_EQ(dnsfilter::Profiles::add(profile).status, "success");
    EXPECT_EQ(*dnsfilter::Profiles::get(*profile.name).comment, live::comment);

    dnsfilter::Profiles::del(*profile.name);
    EXPECT_FALSE(dnsfilter::Profiles::contains(*profile.name));
}

TEST(DnsFilter, CategoryActionsRoundTrip) {
    auto profile = live::dns_profile("dns-categories");
    live::Cleanup cleanup([&] { live::del_dns_profile(*profile.name); });
    dnsfilter::Profiles::add(profile);

    auto stored = dnsfilter::Profiles::get(*profile.name);
    dnsfilter::block_category(stored, 1);
    dnsfilter::block_category(stored, 2);
    dnsfilter::monitor_category(stored, 3);
    dnsfilter::allow_category(stored, 1);
    EXPECT_EQ(to_json(stored, Write::update).size(), 1u);   // only ftgd-dns
    dnsfilter::Profiles::update(stored);

    auto device = dnsfilter::Profiles::get(*profile.name);   // read back, not the local copy
    EXPECT_EQ(dnsfilter::category_action(device, 1), std::nullopt);
    EXPECT_EQ(dnsfilter::category_action(device, 2), "block");
    EXPECT_EQ(dnsfilter::category_action(device, 3), "monitor");
}

TEST(DnsFilter, AllowEverywhereWritesOnlyProfilesListingTheCategory) {
    auto category = live::free_threat_feed_category();
    auto feed = live::threat_feed("dns-sweep-feed", category);
    auto listing = live::dns_profile("dns-sweep-listing");
    auto other = live::dns_profile("dns-sweep-other");
    live::Cleanup cleanup([&] {
        live::del_dns_profile(*listing.name);
        live::del_dns_profile(*other.name);
        live::del_threat_feed(*feed.name);
    });
    system::ExternalResources::add(feed);   // a profile can only list a category some feed provides
    dnsfilter::block_category(listing, category);
    dnsfilter::Profiles::add(listing);
    dnsfilter::Profiles::add(other);

    auto updated = dnsfilter::allow_category_everywhere(category);
    EXPECT_EQ(updated, std::vector<std::string>{*listing.name});
    EXPECT_EQ(dnsfilter::category_action(dnsfilter::Profiles::get(*listing.name), category), std::nullopt);
}
