//
// Live-FortiGate test support. The suite runs against a real firewall (AGENTS.md): it never modifies
// existing config, names everything it writes forti-api-test-*, and removes it again even when an
// assertion fails. guard.hpp enforces the first two before any request is sent.
//

#ifndef FORTI_API_TESTS_LIVE_HPP
#define FORTI_API_TESTS_LIVE_HPP

#include <forti_api/dnsfilter.hpp>
#include <forti_api/firewall.hpp>
#include <forti_api/system.hpp>
#include <forti_api/threat_feed.hpp>
#include <forti_api/gen/antivirus.hpp>
#include <forti_api/gen/application.hpp>
#include <forti_api/gen/emailfilter.hpp>
#include <forti_api/gen/file-filter.hpp>
#include <forti_api/gen/ips.hpp>
#include <forti_api/gen/router.hpp>
#include <forti_api/gen/webfilter.hpp>
#include "guard.hpp"

#include <set>
#include <string>
#include <string_view>
#include <utility>

namespace live {

    inline constexpr std::string_view comment = "Created by the forti-api test suite; safe to delete.";

    inline std::string name(std::string_view suffix) { return std::string(prefix) + std::string(suffix); }

    inline bool is_test_object(const std::string& object_name) { return object_name.starts_with(prefix); }

    // Runs on scope exit, so cleanup also happens when an ASSERT_* returns early.
    template<typename F>
    class Cleanup {
        F f;
    public:
        explicit Cleanup(F f) : f(std::move(f)) {}
        Cleanup(const Cleanup&) = delete;
        Cleanup& operator=(const Cleanup&) = delete;
        ~Cleanup() { try { f(); } catch (...) {} }
    };

    inline fortiapi::dnsfilter::Profile dns_profile(std::string_view suffix) {
        fortiapi::dnsfilter::Profile profile;
        profile.name = name(suffix);
        profile.comment = std::string(comment);
        return profile;
    }

    inline fortiapi::system::ExternalResource threat_feed(std::string_view suffix, std::uint32_t category) {
        auto feed = fortiapi::system::push_threat_feed(name(suffix), category);
        feed.comments = std::string(comment);
        return feed;
    }

    // A remote threat-feed category (192-221) that no existing feed provides and no DNS filter profile
    // lists, so category sweeps can never match a real profile.
    inline std::uint32_t free_threat_feed_category() {
        std::set<std::uint32_t> used;
        for (const auto& feed: fortiapi::system::ExternalResources::list())
            if (feed.category) used.insert(*feed.category);
        for (const auto& profile: fortiapi::dnsfilter::Profiles::list())
            if (profile.ftgd_dns && profile.ftgd_dns->filters)
                for (const auto& filter: *profile.ftgd_dns->filters)
                    if (filter.category) used.insert(*filter.category);
        for (std::uint32_t category = 221; category >= 192; --category)
            if (!used.contains(category)) return category;
        throw std::runtime_error("No unused threat feed category (192-221) available for the test suite");
    }

    // Deletes a forti-api-test-* object if it exists; anything else is left alone.
    template<typename Endpoint>
    void del_test(const std::string& object_name) {
        if (is_test_object(object_name) && Endpoint::contains(object_name)) Endpoint::del(object_name);
    }

    inline void del_dns_profile(const std::string& profile_name) { del_test<fortiapi::dnsfilter::Profiles>(profile_name); }

    inline void del_threat_feed(const std::string& feed_name) {
        if (is_test_object(feed_name) && fortiapi::system::ExternalResources::contains(feed_name))
            fortiapi::system::delete_threat_feed(feed_name);
    }

    template<typename Endpoint>
    void purge() {
        for (const auto& object: Endpoint::list(fortiapi::Query().format({"name"})))
            if (object.name) del_test<Endpoint>(*object.name);
    }

    // Removes forti-api-test-* objects an aborted earlier run left behind, in dependency order
    // (groups and route-maps before what they reference); nothing else.
    inline void purge_leftovers() {
        using namespace fortiapi;
        purge<firewall::AddressGroups>();
        purge<firewall::AddressGroups6>();
        purge<firewall::ServiceGroups>();
        purge<firewall::ScheduleGroups>();
        purge<router::RouteMaps>();
        for (const auto& feed: system::ExternalResources::list(Query().format({"name"})))
            del_threat_feed(feed.name.value_or(""));
        purge<dnsfilter::Profiles>();
        purge<webfilter::Profiles>();
        purge<application::Lists>();
        purge<antivirus::Profiles>();
        purge<ips::Sensors>();
        purge<emailfilter::Profiles>();
        purge<file_filter::Profiles>();
        purge<firewall::Addresses>();
        purge<firewall::Addresses6>();
        purge<firewall::Services>();
        purge<firewall::ServiceCategories>();
        purge<firewall::OnetimeSchedules>();
        purge<firewall::RecurringSchedules>();
        purge<firewall::WildcardFqdns>();
        purge<router::AccessLists>();
        purge<router::PrefixLists>();
        purge<router::AspathLists>();
        purge<router::CommunityLists>();
    }

}  // namespace live

#endif //FORTI_API_TESTS_LIVE_HPP
