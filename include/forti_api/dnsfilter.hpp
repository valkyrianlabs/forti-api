//
// DNS filter profiles: the generated endpoint plus FortiGuard category helpers.
//
// A profile lists FortiGuard categories in ftgd-dns.filters with an action ("block" or "monitor");
// a category that is not listed is allowed. The helpers edit a Profile in memory (marking only
// ftgd-dns as changed); Profiles::update() sends it.
//

#ifndef FORTI_API_DNSFILTER_HPP
#define FORTI_API_DNSFILTER_HPP

#include "gen/dnsfilter.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

namespace fortiapi::dnsfilter {

    namespace detail {
        inline auto find(const std::vector<Profile::FtgdDns::FiltersEntry>& filters, std::uint32_t category) {
            return std::find_if(filters.begin(), filters.end(), [&](const Profile::FtgdDns::FiltersEntry& f) {
                return f.category.has_value() && *f.category == category;
            });
        }

        inline void set_action(Profile& profile, std::uint32_t category, std::string_view action) {
            auto& filters = profile.ftgd_dns.edit().filters.edit();
            auto it = std::find_if(filters.begin(), filters.end(), [&](const Profile::FtgdDns::FiltersEntry& f) {
                return f.category.has_value() && *f.category == category;
            });
            if (it != filters.end()) {
                it->action = std::string(action);
                return;
            }
            Profile::FtgdDns::FiltersEntry entry;
            entry.category = category;
            entry.action = std::string(action);
            filters.push_back(std::move(entry));
        }
    }

    // "block", "monitor", or nullopt when the category is allowed.
    inline std::optional<std::string> category_action(const Profile& profile, std::uint32_t category) {
        if (!profile.ftgd_dns || !profile.ftgd_dns->filters) return std::nullopt;
        const auto& filters = *profile.ftgd_dns->filters;
        auto it = detail::find(filters, category);
        if (it == filters.end()) return std::nullopt;
        return it->action.value_or(std::string(Profile::FtgdDns::FiltersEntry::Action::monitor));
    }

    inline void block_category(Profile& profile, std::uint32_t category) {
        detail::set_action(profile, category, Profile::FtgdDns::FiltersEntry::Action::block);
    }

    inline void monitor_category(Profile& profile, std::uint32_t category) {
        detail::set_action(profile, category, Profile::FtgdDns::FiltersEntry::Action::monitor);
    }

    // Removes the category's filter; does nothing (and marks nothing) when it is not listed.
    inline void allow_category(Profile& profile, std::uint32_t category) {
        if (!category_action(profile, category)) return;
        auto& filters = profile.ftgd_dns.edit().filters.edit();
        filters.erase(detail::find(filters, category));
    }

    // Allows the category in every profile that lists it; profiles that do not are never written.
    // Returns the names of the profiles updated.
    inline std::vector<std::string> allow_category_everywhere(std::uint32_t category, const Query& query = {},
                                                              Client& client = default_client()) {
        std::vector<std::string> updated;
        for (auto& profile: Profiles::list(query, client)) {
            if (!category_action(profile, category)) continue;
            allow_category(profile, category);
            Profiles::update(profile, query, client);
            updated.push_back(*profile.name);
        }
        return updated;
    }

}  // namespace fortiapi::dnsfilter

#endif //FORTI_API_DNSFILTER_HPP
