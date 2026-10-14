// Push threat feeds: entries through the monitor API, and deletion that frees the category first.
#include <gtest/gtest.h>
#include "live.hpp"

#include <algorithm>
#include <chrono>
#include <thread>

using namespace fortiapi;

namespace {
    // FortiOS loads a new feed and applies pushed entries asynchronously (measured: ~6 s each on
    // 7.4.8). Poll for the expected state instead of assuming timing.
    template<typename Predicate>
    system::FeedState wait_for(const std::string& feed, Predicate done, std::chrono::seconds patience = std::chrono::seconds(45)) {
        auto deadline = std::chrono::steady_clock::now() + patience;
        auto state = system::feed_state(feed);
        while (!done(state) && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            state = system::feed_state(feed);
        }
        return state;
    }

    std::vector<std::string> entries(const system::FeedState& state) {
        std::vector<std::string> out;
        for (const auto& e: state.entries) out.push_back(e.entry);
        std::sort(out.begin(), out.end());
        return out;
    }
}

TEST(ThreatFeed, PushEntries) {
    auto feed = live::threat_feed("feed-push", live::free_threat_feed_category());
    live::Cleanup cleanup([&] { live::del_threat_feed(*feed.name); });
    system::ExternalResources::add(feed);

    // Before FortiOS has loaded the feed, a push is rejected per command; that must surface.
    auto initial = system::feed_state(*feed.name);
    if (!initial.loaded) {
        EXPECT_THROW(system::push_entries(*feed.name, {"early.forti-api-test.invalid"}), ApiError);
    }
    ASSERT_TRUE(wait_for(*feed.name, [](const auto& s) { return s.loaded; }).loaded);

    std::vector<std::string> first{"a.forti-api-test.invalid", "b.forti-api-test.invalid"};
    system::push_entries(*feed.name, {"b.forti-api-test.invalid", "a.forti-api-test.invalid"});
    EXPECT_EQ(entries(wait_for(*feed.name, [&](const auto& s) { return entries(s) == first; })), first);

    std::vector<std::string> second{"b.forti-api-test.invalid", "c.forti-api-test.invalid"};
    system::push_entries(*feed.name, {"c.forti-api-test.invalid"}, system::FeedCommand::add);
    system::push_entries(*feed.name, {"a.forti-api-test.invalid"}, system::FeedCommand::remove);
    auto state = wait_for(*feed.name, [&](const auto& s) { return entries(s) == second; });
    EXPECT_EQ(entries(state), second);
    EXPECT_EQ(state.file_status, "downloaded");
    for (const auto& e: state.entries) EXPECT_TRUE(e.valid) << e.entry;
}

TEST(ThreatFeed, DeleteFreesTheCategoryInListingProfiles) {
    auto category = live::free_threat_feed_category();
    auto feed = live::threat_feed("feed-delete", category);
    auto profile = live::dns_profile("feed-delete-profile");
    live::Cleanup cleanup([&] {
        live::del_threat_feed(*feed.name);
        live::del_dns_profile(*profile.name);
    });
    system::ExternalResources::add(feed);
    dnsfilter::block_category(profile, category);
    dnsfilter::Profiles::add(profile);

    // FortiOS refuses to delete a feed a profile still references; delete_threat_feed handles it.
    EXPECT_THROW(system::ExternalResources::del(*feed.name), ApiError);
    system::delete_threat_feed(*feed.name);
    EXPECT_FALSE(system::ExternalResources::contains(*feed.name));
    EXPECT_EQ(dnsfilter::category_action(dnsfilter::Profiles::get(*profile.name), category), std::nullopt);
}
