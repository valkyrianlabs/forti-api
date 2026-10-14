//
// Created by Cooper Larson on 8/26/24.
//

#ifndef FORTI_API_DNS_FILTER_HPP
#define FORTI_API_DNS_FILTER_HPP

#include <utility>
#include "api.hpp"
#include "types/dns/filter.h"


class DNSFilter {
    inline static std::string api_endpoint = "/cmdb/dnsfilter/profile";

public:
    static Response update(const DNSProfile& profile) {
        if (!contains(profile.name)) throw std::runtime_error("Can't update non-existent DNS Profile");
        return FortiAPI::put(std::format("{}/{}", api_endpoint, profile.name), profile);
    }

    static Response add(const DNSProfile& profile) { return FortiAPI::post(api_endpoint, profile); }

    static Response add(const std::string& name) { return add(DNSProfile(name)); }

    static Response del(const std::string& name) {
        if (!contains(name)) throw std::runtime_error("Can't delete non-existent item: " + name);
        return FortiAPI::del(std::format("{}/{}", api_endpoint, name));
    }

    static bool contains(const std::string& name) {
        return FortiAPI::get<DNSProfilesResponse>(std::format("{}/{}", api_endpoint, name)).http_status == 200;
    }

    static std::vector<DNSProfile> get() {
        auto results = FortiAPI::get<DNSProfilesResponse>(api_endpoint).results;
        for (auto& profile : results) profile.ftgd_dns.sort_filters();
        return results;
    }

    static DNSProfile get(const std::string& feed) {
        auto result = FortiAPI::get<DNSProfilesResponse>(std::format("{}/{}", api_endpoint, feed)).results[0];
        result.ftgd_dns.sort_filters();
        return result;
    }

    // Only profiles that reference the category are written; the others are left untouched.
    static void global_allow_category(unsigned int category) {
        for (auto& profile : get()) {
            if (!profile.contains_category(category)) continue;
            profile.allow_category(category);
            update(profile);
        }
    }

    static void block_category_in_profile(const std::string& profile_name, unsigned int category) {
        auto profile = get(profile_name);
        profile.block_category(category);
        update(profile);
    }

    static void block_category_in_profiles(const std::vector<std::string>& profiles, unsigned int category) {
        for (const auto& name : profiles) block_category_in_profile(name, category);
    }
};

#endif //FORTI_API_DNS_FILTER_HPP
