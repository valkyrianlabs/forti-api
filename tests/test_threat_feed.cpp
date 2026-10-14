//
// Created by Cooper Larson on 8/28/24.
//

#include <gtest/gtest.h>
#include <forti_api/threat_feed.hpp>

TEST(TestThreatFeed, TestGetAllFeeds) {
    auto feeds = ThreatFeed::get();
    ASSERT_TRUE(!feeds.empty());
}

TEST(TestThreatFeed, TestAddAndRemoveThreatFeed) {
    std::string name = "test-feed";
    ThreatFeed::add(name, 219);
    ASSERT_TRUE(ThreatFeed::contains(name));

    auto feed = ThreatFeed::get(name);
    ASSERT_TRUE(feed.name == name);
    ASSERT_TRUE(feed.category == 219);
    ASSERT_TRUE(feed.update_method == "push") << feed.update_method;

    ThreatFeed::del(name);
    ASSERT_TRUE(!ThreatFeed::contains(name));
}
