//
// Created by Cooper Larson on 8/26/24.
//

#ifndef FORTI_API_THREAT_FEED_HPP
#define FORTI_API_THREAT_FEED_HPP

#include "dns_filter.hpp"
#include <utility>
#include <vector>
#include "api.hpp"
#include "types/threat_feed/ext_connector.h"


class ThreatFeed {
    inline static std::string command = "snapshot";
    inline static std::string external_resource = "/cmdb/system/external-resource";
    inline static std::string external_resource_monitor = "/monitor/system/external-resource/dynamic";
    inline static std::string external_resource_entry_list =
            std::format("{}/entry-list?include_notes=true&vdom=root&mkey=", external_resource);

    static void set(const std::string& name, bool enable = true) {
        nlohmann::json j;
        j["status"] = enable ? "enable" : "disable";
        FortiAPI::post(std::format("{}/{}", external_resource, name), j);
    }

public:
    static void update_info(const std::string& name, const nlohmann::json& data) {
        FortiAPI::post(std::format("{}/{}", external_resource_monitor, name), data);
    }

    static void update_feed(const CommandsRequest& data) { FortiAPI::post(external_resource_monitor, data); }

    static std::vector<PushThreatFeed> get() {
        return FortiAPI::get<ExternalResourcesResponse>(external_resource).results;
    }

    static PushThreatFeed get(const std::string& query) {
        return FortiAPI::get<ExternalResourcesResponse>(std::format("{}/{}", external_resource, query)).results[0];
    }

    static std::vector<Entry> get_entry_list(const std::string& feed) {
        return FortiAPI::get<ExternalResourceEntryListResponse>
                (std::format("{}/{}", external_resource_entry_list, feed)).results.entries;
    }

    static bool contains(const std::string& name) {
        return FortiAPI::get<ExternalResourcesResponse>(std::format("{}/{}", external_resource, name)).http_status == 200;
    }

    static void enable(const std::string& name) { set(name, true); }

    static void disable(const std::string& name) { set(name, false); }

    static Response add(const PushThreatFeed& feed) { return FortiAPI::post(external_resource, feed); }

    static Response add(const std::string& name, unsigned int category) { return add(PushThreatFeed(name, category)); }

    // DNS filter profiles must stop referencing the feed's category before FortiOS allows the delete,
    // unless another feed still provides that category.
    static void del(const std::string& name) {
        if (contains(name)) {
            auto category = get(name).category;
            auto feeds = get();
            bool shared = std::any_of(feeds.begin(), feeds.end(), [&](const PushThreatFeed& feed) {
                return feed.name != name && feed.category == category;
            });
            if (!shared) DNSFilter::global_allow_category(category);
            FortiAPI::del(std::format("{}/{}", external_resource, name));
        } else std::cerr << "Couldn't locate threat feed for deletion: " << name << std::endl;
    }

    static void del(unsigned int category) {
        DNSFilter::global_allow_category(category);
        for (const auto& feed : get()) {
            if (feed.category == category) FortiAPI::del(std::format("{}/{}", external_resource, feed.name));
        }
    }
};

#endif //FORTI_API_THREAT_FEED_HPP
