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

    template<typename Predicate>
    system::FeedStatus wait_for_status(const std::string& feed, Predicate done,
                                       std::chrono::seconds patience = std::chrono::seconds(45)) {
        auto deadline = std::chrono::steady_clock::now() + patience;
        auto status = system::feed_status(feed);
        while (!done(status) && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            status = system::feed_status(feed);
        }
        return status;
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

TEST(ThreatFeed, StatusCountsAndPages) {
    auto feed = live::threat_feed("feed-status", live::free_threat_feed_category());
    live::Cleanup cleanup([&] { live::del_threat_feed(*feed.name); });
    system::ExternalResources::add(feed);

    auto loaded = wait_for_status(*feed.name, [](const auto& s) { return s.loaded; });
    ASSERT_TRUE(loaded.loaded) << loaded.error;

    // Four distinct domains, an exact duplicate (FortiOS keeps one) and an entry FortiOS keeps but
    // marks invalid. ("not a domain" would not do: FortiOS keeps only "not", a valid name.)
    system::push_entries(*feed.name, {"a.forti-api-test.invalid", "b.forti-api-test.invalid", "c.forti-api-test.invalid",
                                      "d.forti-api-test.invalid", "b.forti-api-test.invalid",
                                      "bad!char.forti-api-test.invalid"});
    auto status = wait_for_status(*feed.name, [&](const auto& s) {
        return s.last_update > loaded.last_update && s.file_status == "downloaded";
    });
    ASSERT_GT(status.last_update, loaded.last_update);
    EXPECT_EQ(status.file_status, "downloaded");
    EXPECT_EQ(status.error, "");
    EXPECT_EQ(status.accepted, 4u);
    EXPECT_EQ(status.valid, 4u);
    EXPECT_EQ(status.invalid, 1u);
    EXPECT_GT(status.limit, 0u);
    EXPECT_FALSE(status.overflow);

    // The counts cover the whole feed, so they match a full download.
    auto state = system::feed_state(*feed.name);
    auto valid = std::count_if(state.entries.begin(), state.entries.end(), [](const auto& e) { return e.valid; });
    EXPECT_EQ(static_cast<std::uint64_t>(valid), status.valid);
    EXPECT_EQ(state.entries.size() - static_cast<std::size_t>(valid), status.invalid);

    // Pages are windows of the same list, in the same order; past the end there is nothing.
    ASSERT_EQ(state.entries.size(), 5u);
    auto first = system::feed_entries(*feed.name, 0, 2);
    auto rest = system::feed_entries(*feed.name, 2, 100);
    EXPECT_EQ(first.size(), 2u);
    std::vector<system::FeedEntry> paged = first;
    paged.insert(paged.end(), rest.begin(), rest.end());
    ASSERT_EQ(paged.size(), state.entries.size());
    for (std::size_t i = 0; i < paged.size(); ++i) {
        EXPECT_EQ(paged[i].entry, state.entries[i].entry);
        EXPECT_EQ(paged[i].valid, state.entries[i].valid) << paged[i].entry;
    }
    EXPECT_TRUE(system::feed_entries(*feed.name, state.entries.size(), 10).empty());
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
