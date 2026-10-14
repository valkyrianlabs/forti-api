//
// Live-FortiGate test support. The suite runs against a real firewall (AGENTS.md): it never modifies
// existing config, names everything it writes forti-api-test-*, and removes it again even when an
// assertion fails.
//

#ifndef FORTI_API_TESTS_LIVE_HPP
#define FORTI_API_TESTS_LIVE_HPP

#include <forti_api/dns_filter.hpp>
#include <forti_api/threat_feed.hpp>
#include <set>
#include <string>
#include <string_view>
#include <utility>

namespace live {

    inline constexpr std::string_view prefix = "forti-api-test-";
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

    inline DNSProfile dns_profile(std::string_view suffix) {
        DNSProfile profile(name(suffix));
        profile.comment = comment;
        return profile;
    }

    inline PushThreatFeed threat_feed(std::string_view suffix, unsigned int category) {
        PushThreatFeed feed(name(suffix), category);
        feed.comments = comment;
        return feed;
    }

    // A remote threat-feed category (192-221) that no existing feed provides and no DNS filter profile
    // references, so deleting a test feed can never touch a real profile.
    inline unsigned int free_threat_feed_category() {
        std::set<unsigned int> used;
        for (const auto& feed : ThreatFeed::get()) used.insert(feed.category);
        for (auto& profile : DNSFilter::get())
            for (const auto& filter : profile.ftgd_dns.filters) used.insert(filter.category);
        for (unsigned int category = 221; category >= 192; --category)
            if (!used.contains(category)) return category;
        throw std::runtime_error("No unused threat feed category (192-221) available for the test suite");
    }

    inline void del_dns_profile(const std::string& profile_name) {
        if (is_test_object(profile_name) && DNSFilter::contains(profile_name)) DNSFilter::del(profile_name);
    }

    inline void del_threat_feed(const std::string& feed_name) {
        if (is_test_object(feed_name) && ThreatFeed::contains(feed_name)) ThreatFeed::del(feed_name);
    }

    // Removes forti-api-test-* objects an aborted earlier run left behind; nothing else.
    inline void purge_leftovers() {
        for (const auto& feed : ThreatFeed::get()) del_threat_feed(feed.name);
        for (const auto& profile : DNSFilter::get()) del_dns_profile(profile.name);
    }

}  // namespace live

#endif //FORTI_API_TESTS_LIVE_HPP
