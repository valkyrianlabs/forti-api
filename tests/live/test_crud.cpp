// Create -> read -> update -> delete on every approved test collection (guard.hpp), with minimal
// objects that are inert unless referenced: RFC 5737 / RFC 3849 documentation addresses, port 65000,
// schedules in 2037, unattached profiles, unreferenced routing lists. Every object is forti-api-test-*.
#include <gtest/gtest.h>
#include "live.hpp"

using namespace fortiapi;

namespace {

    // Creates `object`, reads it back, changes its comment (when the table has one) and checks the
    // device kept it, then deletes it. Cleanup runs even when an assertion fails.
    template<typename Endpoint, typename Comment = std::nullptr_t>
    void roundtrip(typename Endpoint::type object, Comment comment = nullptr) {
        const std::string name = *(object.*Endpoint::key);
        ASSERT_TRUE(live::is_test_object(name));
        live::Cleanup cleanup([&] { live::del_test<Endpoint>(name); });
        if constexpr (!std::is_null_pointer_v<Comment>) object.*comment = std::string(live::comment);

        Endpoint::add(object);
        auto stored = Endpoint::get(name);
        EXPECT_EQ(*(stored.*Endpoint::key), name);
        EXPECT_FALSE(dirty(stored));

        if constexpr (!std::is_null_pointer_v<Comment>) {
            EXPECT_EQ(*(stored.*comment), live::comment);
            std::string updated = std::string(live::comment) + " Updated.";
            stored.*comment = updated;
            ASSERT_TRUE(Endpoint::update(stored).has_value());
            EXPECT_EQ(*(Endpoint::get(name).*comment), updated);
        }

        Endpoint::del(name);
        EXPECT_FALSE(Endpoint::contains(name));
    }

    template<typename T>
    T named(std::string_view suffix) {
        T object;
        object.name = live::name(suffix);
        return object;
    }

    template<typename Endpoint>
    struct Created {   // a dependency object for group tests, removed again on scope exit
        std::string name;
        explicit Created(typename Endpoint::type object) : name(*object.name) { Endpoint::add(object); }
        ~Created() { try { live::del_test<Endpoint>(name); } catch (...) {} }
    };

}  // namespace

TEST(Crud, Address) {
    auto a = named<firewall::Address>("crud-addr");
    a.subnet = "192.0.2.10 255.255.255.255";
    roundtrip<firewall::Addresses>(a, &firewall::Address::comment);
}

TEST(Crud, Address6) {
    auto a = named<firewall::Address6>("crud-addr6");
    a.ip6 = "2001:db8::10/128";
    roundtrip<firewall::Addresses6>(a, &firewall::Address6::comment);
}

TEST(Crud, AddressGroup) {
    auto member = named<firewall::Address>("crud-grp-member");
    member.subnet = "192.0.2.11 255.255.255.255";
    Created<firewall::Addresses> dependency(member);
    auto g = named<firewall::AddressGroup>("crud-addrgrp");
    g.member = std::vector<Ref>{dependency.name};
    roundtrip<firewall::AddressGroups>(g, &firewall::AddressGroup::comment);
}

TEST(Crud, AddressGroup6) {
    auto member = named<firewall::Address6>("crud-grp6-member");
    member.ip6 = "2001:db8::11/128";
    Created<firewall::Addresses6> dependency(member);
    auto g = named<firewall::AddressGroup6>("crud-addrgrp6");
    g.member = std::vector<Ref>{dependency.name};
    roundtrip<firewall::AddressGroups6>(g, &firewall::AddressGroup6::comment);
}

TEST(Crud, Service) {
    auto s = named<firewall::Service>("crud-svc");
    s.tcp_portrange = firewall::port_ranges({{65000}});
    roundtrip<firewall::Services>(s, &firewall::Service::comment);
}

TEST(Crud, ServiceGroup) {
    auto member = named<firewall::Service>("crud-svcgrp-member");
    member.udp_portrange = firewall::port_ranges({{65001}});
    Created<firewall::Services> dependency(member);
    auto g = named<firewall::ServiceGroup>("crud-svcgrp");
    g.member = std::vector<Ref>{dependency.name};
    roundtrip<firewall::ServiceGroups>(g, &firewall::ServiceGroup::comment);
}

TEST(Crud, ServiceCategory) {
    roundtrip<firewall::ServiceCategories>(named<firewall::ServiceCategory>("crud-svccat"), &firewall::ServiceCategory::comment);
}

TEST(Crud, OnetimeSchedule) {
    auto s = named<firewall::OnetimeSchedule>("crud-once");
    s.start = "00:00 2037/12/30";
    s.end = "00:00 2037/12/31";
    roundtrip<firewall::OnetimeSchedules>(s);
}

TEST(Crud, RecurringSchedule) {
    auto s = named<firewall::RecurringSchedule>("crud-recur");
    s.day = firewall::days({firewall::Weekday::sunday});
    s.start = "00:00";
    s.end = "00:01";
    roundtrip<firewall::RecurringSchedules>(s);
}

TEST(Crud, ScheduleGroup) {
    auto member = named<firewall::OnetimeSchedule>("crud-sgrp-member");
    member.start = "00:00 2037/12/30";
    member.end = "00:00 2037/12/31";
    Created<firewall::OnetimeSchedules> dependency(member);
    auto g = named<firewall::ScheduleGroup>("crud-schedgrp");
    g.member = std::vector<Ref>{dependency.name};
    roundtrip<firewall::ScheduleGroups>(g);
}

TEST(Crud, WildcardFqdn) {
    auto w = named<firewall::WildcardFqdn>("crud-wildcard");
    w.wildcard_fqdn = "*.forti-api-test.invalid";
    roundtrip<firewall::WildcardFqdns>(w, &firewall::WildcardFqdn::comment);
}

TEST(Crud, DnsFilterProfile) {
    roundtrip<dnsfilter::Profiles>(named<dnsfilter::Profile>("crud-dnsfilter"), &dnsfilter::Profile::comment);
}

TEST(Crud, WebFilterProfile) {
    roundtrip<webfilter::Profiles>(named<webfilter::Profile>("crud-webfilter"), &webfilter::Profile::comment);
}

TEST(Crud, ApplicationList) {
    roundtrip<application::Lists>(named<application::List>("crud-applist"), &application::List::comment);
}

TEST(Crud, AntivirusProfile) {
    roundtrip<antivirus::Profiles>(named<antivirus::Profile>("crud-av"), &antivirus::Profile::comment);
}

TEST(Crud, IpsSensor) {
    roundtrip<ips::Sensors>(named<ips::Sensor>("crud-ips"), &ips::Sensor::comment);
}

TEST(Crud, EmailFilterProfile) {
    roundtrip<emailfilter::Profiles>(named<emailfilter::Profile>("crud-email"), &emailfilter::Profile::comment);
}

TEST(Crud, FileFilterProfile) {
    roundtrip<file_filter::Profiles>(named<file_filter::Profile>("crud-filefilter"), &file_filter::Profile::comment);
}

TEST(Crud, AccessList) {
    roundtrip<router::AccessLists>(named<router::AccessList>("crud-acl"), &router::AccessList::comments);
}

TEST(Crud, PrefixList) {
    roundtrip<router::PrefixLists>(named<router::PrefixList>("crud-prefix"), &router::PrefixList::comments);
}

TEST(Crud, RouteMap) {
    roundtrip<router::RouteMaps>(named<router::RouteMap>("crud-routemap"), &router::RouteMap::comments);
}

TEST(Crud, AspathList) {
    roundtrip<router::AspathLists>(named<router::AspathList>("crud-aspath"));
}

TEST(Crud, CommunityList) {
    auto c = named<router::CommunityList>("crud-community");
    c.type = std::string(router::CommunityList::Type::standard);
    roundtrip<router::CommunityLists>(c);
}

TEST(Crud, ExternalResource) {
    auto feed = live::threat_feed("crud-feed", live::free_threat_feed_category());
    live::Cleanup cleanup([&] { live::del_threat_feed(*feed.name); });
    system::ExternalResources::add(feed);
    auto stored = system::ExternalResources::get(*feed.name);
    stored.comments = std::string(live::comment) + " Updated.";
    system::ExternalResources::update(stored);
    EXPECT_EQ(*system::ExternalResources::get(*feed.name).comments, std::string(live::comment) + " Updated.");
    system::delete_threat_feed(*feed.name);
    EXPECT_FALSE(system::ExternalResources::contains(*feed.name));
}
