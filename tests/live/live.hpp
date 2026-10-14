//
// Live-FortiGate test support. The suite runs against a real firewall (AGENTS.md): it never modifies
// existing config, names everything it writes forti-api-test-*, and removes it again even when an
// assertion fails. guard.hpp enforces the first two before any request is sent.
//

#ifndef FORTI_API_TESTS_LIVE_HPP
#define FORTI_API_TESTS_LIVE_HPP

#include <forti_api.hpp>
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

    inline void del_dns_profile(const std::string& profile_name) {
        if (is_test_object(profile_name) && fortiapi::dnsfilter::Profiles::contains(profile_name))
            fortiapi::dnsfilter::Profiles::del(profile_name);
    }

    inline void del_threat_feed(const std::string& feed_name) {
        if (is_test_object(feed_name) && fortiapi::system::ExternalResources::contains(feed_name))
            fortiapi::system::delete_threat_feed(feed_name);
    }

    // Removes forti-api-test-* objects an aborted earlier run left behind; nothing else.
    inline void purge_leftovers() {
        for (const auto& feed: fortiapi::system::ExternalResources::list(fortiapi::Query().format({"name"})))
            del_threat_feed(feed.name.value_or(""));
        for (const auto& profile: fortiapi::dnsfilter::Profiles::list(fortiapi::Query().format({"name"})))
            del_dns_profile(profile.name.value_or(""));
    }

}  // namespace live

#endif //FORTI_API_TESTS_LIVE_HPP
