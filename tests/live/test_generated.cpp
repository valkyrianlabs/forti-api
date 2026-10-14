// Generated endpoints against the live device: every generated type must parse what the device
// returns (read-only), and writes on approved test objects must change exactly what was set,
// verified independently in the device's config-change log.
#include <gtest/gtest.h>
#include "live.hpp"
#include <forti_api/gen/all.hpp>

using namespace fortiapi;

namespace {
    template<typename Endpoint>
    void parses_every_object() {
        auto objects = Endpoint::list();
        for (const auto& object: objects) EXPECT_FALSE(dirty(object));
    }
}

TEST(Generated, EveryTableParsesTheDevice) {
    parses_every_object<dnsfilter::Profiles>();
    parses_every_object<firewall::Addresses>();
    parses_every_object<firewall::Policies>();
    parses_every_object<firewall::Vips>();
    parses_every_object<firewall::RecurringSchedules>();
    parses_every_object<firewall::ServiceCategories>();
    parses_every_object<firewall::Services>();
    parses_every_object<system::ApiUsers>();
    parses_every_object<system::ExternalResources>();
    parses_every_object<system::Interfaces>();
}

TEST(Generated, SingletonParsesTheDevice) {
    auto global = system::GlobalSettings::get();
    EXPECT_TRUE(global.hostname.has_value());
    EXPECT_FALSE(dirty(global));
}

TEST(Generated, KeyedReadsMatchListedObjects) {
    auto policies = firewall::Policies::list(Query().format({"policyid", "name"}));
    if (policies.empty()) GTEST_SKIP() << "no firewall policies on the device";
    auto first = firewall::Policies::get(*policies.front().policyid);
    EXPECT_EQ(*first.policyid, *policies.front().policyid);
    EXPECT_FALSE(firewall::Policies::find(4294967294u).has_value());
}

TEST(Generated, UpdateChangesExactlyWhatWasSet) {
    live::ConfigAudit audit;
    audit.begin(fortiapi::default_client());

    dnsfilter::Profile profile;
    profile.name = live::name("gen-profile");
    profile.comment = std::string(live::comment);
    live::Cleanup cleanup([&] { live::del_dns_profile(*profile.name); });
    dnsfilter::Profiles::add(profile);

    auto stored = dnsfilter::Profiles::get(*profile.name);
    EXPECT_EQ(*stored.comment, live::comment);
    stored.comment = std::string(live::comment) + " Updated.";
    ASSERT_TRUE(dnsfilter::Profiles::update(stored).has_value());
    EXPECT_FALSE(dnsfilter::Profiles::update(stored).has_value());   // nothing left to send

    stored.comment.clear();
    dnsfilter::Profiles::update(stored);
    EXPECT_EQ(*dnsfilter::Profiles::get(*profile.name).comment, "");

    dnsfilter::Profiles::del(*profile.name);
    EXPECT_FALSE(dnsfilter::Profiles::contains(*profile.name));

    // Independent check against the device's log: across the object's whole life (FortiOS folds
    // edits shortly after a create into the Add record) the only attribute written was the comment.
    std::vector<std::string> written;
    bool deleted = false;
    for (const auto& change: audit.changes(fortiapi::default_client())) {
        if (change.value("cfgobj", "") != *profile.name) continue;
        if (change.value("action", "") == "Delete") deleted = true;
        for (auto& attribute: live::attribute_names(change.value("cfgattr", ""))) written.push_back(attribute);
    }
    EXPECT_TRUE(deleted);
    ASSERT_FALSE(written.empty());
    for (const auto& attribute: written) EXPECT_EQ(attribute, "comment");
}

TEST(Generated, ExternalResourceRoundTrip) {
    system::ExternalResource feed;
    feed.name = live::name("gen-feed");
    feed.type = std::string(system::external_resource::type::domain);
    feed.update_method = std::string(system::external_resource::update_method::push);
    feed.category = live::free_threat_feed_category();
    feed.comments = std::string(live::comment);
    live::Cleanup cleanup([&] { live::del_threat_feed(*feed.name); });
    system::ExternalResources::add(feed);

    auto stored = system::ExternalResources::get(*feed.name);
    EXPECT_EQ(*stored.category, *feed.category);
    EXPECT_EQ(*stored.update_method, "push");
    EXPECT_EQ(*stored.comments, live::comment);
    system::ExternalResources::del(*feed.name);
    EXPECT_FALSE(system::ExternalResources::contains(*feed.name));
}
