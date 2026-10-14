//
// Threat feeds: FortiOS external resources plus the push API.
//
// A push feed (update-method "push") holds entries that clients send through
// monitor/system/external-resource/dynamic; DNS filter profiles block its category. Deleting a feed
// that a profile still references fails, so delete_threat_feed() first allows the category in the
// profiles that list it, unless another feed still provides that category.
//

#ifndef FORTI_API_THREAT_FEED_HPP
#define FORTI_API_THREAT_FEED_HPP

#include "dnsfilter.hpp"
#include "gen/system/external_resource.hpp"
#include "monitor.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace fortiapi::system {

    // A push feed of `type` (domain, address, url, ...) for a remote category (192-221). Not sent;
    // pass it to ExternalResources::add().
    inline ExternalResource push_threat_feed(std::string name, std::uint32_t category,
                                             std::string_view type = external_resource::type::domain) {
        ExternalResource feed;
        feed.name = std::move(name);
        feed.type = std::string(type);
        feed.update_method = std::string(external_resource::update_method::push);
        feed.category = category;
        return feed;
    }

    enum class FeedCommand { snapshot, add, remove };

    constexpr std::string_view to_string(FeedCommand command) {
        switch (command) {
            case FeedCommand::snapshot: return "snapshot";
            case FeedCommand::add: return "add";
            case FeedCommand::remove: return "remove";
        }
        return "snapshot";
    }

    // snapshot replaces the feed's entries; add and remove change them. A new feed accepts pushes
    // only once FortiOS has loaded it (feed_state().loaded, a few seconds after creation); a command
    // FortiOS rejects throws ApiError even though the reply as a whole reports success.
    inline nlohmann::json push_entries(std::string_view feed, const std::vector<std::string>& entries,
                                       FeedCommand command = FeedCommand::snapshot, Client& client = default_client()) {
        static constexpr std::string_view path = "system/external-resource/dynamic";
        nlohmann::json body = {{"commands", nlohmann::json::array({{{"name", feed}, {"command", to_string(command)},
                                                                    {"entries", entries}}})}};
        auto reply = Monitor::post(path, body, {}, client);
        for (const auto& result: reply.value("results", nlohmann::json::array()))
            if (result.is_object() && result.value("status", "") == "error")
                throw ApiError(Method::Post, Monitor::path(path), reply.value("http_status", 200L), result);
        return reply;
    }

    struct FeedEntry {
        std::string entry;
        bool valid = false;
    };

    struct FeedState {
        bool loaded = false;           // FortiOS has loaded the feed; pushes are accepted
        std::string file_status;       // "downloaded" once pushed entries are applied, "unavailable" before
        std::string error;             // why it is not loaded yet ("Connect pending")
        std::vector<FeedEntry> entries;
    };

    // What FortiOS currently holds for a feed. Pushed entries show up a few seconds after the push.
    inline FeedState feed_state(std::string_view feed, Client& client = default_client()) {
        auto results = Monitor::get("system/external-resource/entry-list",
                                    Query().set("mkey", std::string(feed)).set("include_notes", "true"), client);
        FeedState state;
        state.loaded = results.value("status", "") == "success";
        state.file_status = results.value("resource_file_status", "");
        state.error = results.value("error", "");
        for (const auto& item: results.value("entries", nlohmann::json::array())) {
            auto valid = item.value("valid", nlohmann::json());
            state.entries.push_back({item.value("entry", std::string()),
                                     valid.is_boolean() ? valid.get<bool>() : valid == "true"});
        }
        return state;
    }

    // Deletes a feed. DNS filter profiles that list its category are switched to allow first, unless
    // another feed provides the same category; profiles that do not list it are never written.
    inline void delete_threat_feed(const std::string& name, Client& client = default_client()) {
        auto feed = ExternalResources::get(name, {}, client);
        auto feeds = ExternalResources::list(Query().format({"name", "category"}), client);
        bool shared = std::any_of(feeds.begin(), feeds.end(), [&](const ExternalResource& other) {
            return other.name.has_value() && *other.name != name && other.category == feed.category.value_or(0);
        });
        if (feed.category && !shared) dnsfilter::allow_category_everywhere(*feed.category, {}, client);
        ExternalResources::del(name, {}, client);
    }

}  // namespace fortiapi::system

#endif //FORTI_API_THREAT_FEED_HPP
