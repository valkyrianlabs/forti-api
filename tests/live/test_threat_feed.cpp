//
// Created by Cooper Larson on 8/28/24.
//

#include <gtest/gtest.h>
#include <algorithm>
#include "live.hpp"

TEST(TestThreatFeed, TestGetIncludesNewFeed) {
    auto feed = live::threat_feed("feed-get", live::free_threat_feed_category());
    live::Cleanup cleanup([&] { live::del_threat_feed(feed.name); });
    ASSERT_EQ(ThreatFeed::add(feed).status, "success");

    auto feeds = ThreatFeed::get();
    ASSERT_TRUE(std::any_of(feeds.begin(), feeds.end(), [&](const PushThreatFeed& f) { return f.name == feed.name; }));
}

TEST(TestThreatFeed, TestAddAndRemoveThreatFeed) {
    auto category = live::free_threat_feed_category();
    auto feed = live::threat_feed("feed-add-remove", category);
    live::Cleanup cleanup([&] { live::del_threat_feed(feed.name); });
    ASSERT_EQ(ThreatFeed::add(feed).status, "success");
    ASSERT_TRUE(ThreatFeed::contains(feed.name));

    auto stored = ThreatFeed::get(feed.name);
    ASSERT_EQ(stored.name, feed.name);
    ASSERT_EQ(stored.category, category);
    ASSERT_EQ(stored.update_method, "push");
    ASSERT_EQ(stored.comments, live::comment);

    ThreatFeed::del(feed.name);
    ASSERT_FALSE(ThreatFeed::contains(feed.name));
}
