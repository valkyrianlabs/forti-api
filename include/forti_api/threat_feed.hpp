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
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace fortiapi::system {

    // A push feed of `type` (domain, address, url, ...) for a remote category (192-221). Not sent;
    // pass it to ExternalResources::add().
    inline ExternalResource push_threat_feed(std::string name, std::uint32_t category,
                                             std::string_view type = ExternalResource::Type::domain) {
        ExternalResource feed;
        feed.name = std::move(name);
        feed.type = std::string(type);
        feed.update_method = std::string(ExternalResource::UpdateMethod::push);
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
    // only once FortiOS has loaded it (feed_status().loaded, a few seconds after creation); a command
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

    // A feed's counters, without its entries (feed_status()).
    struct FeedStatus {
        bool loaded = false;           // FortiOS has loaded the feed; pushes are accepted
        std::string file_status;       // "downloaded" once pushed entries are applied, "unavailable" before
        std::string error;             // why it is not loaded yet ("Connect pending")
        std::uint64_t accepted = 0;    // entries FortiOS uses: the valid ones
        // The entries FortiOS kept, by validity. It keeps one copy of an exact duplicate (case
        // matters: "A.example" and "a.example" are two entries) and keeps an entry it cannot use
        // ("a..b.example") as invalid.
        std::uint64_t valid = 0;
        std::uint64_t invalid = 0;
        std::uint64_t limit = 0;       // the device-wide entry cap (1000000 on a FortiGate-60F), not per feed
        bool overflow = false;         // FortiOS flags the feed as over the cap
        std::int64_t last_update = 0;  // when FortiOS last applied new content (Unix seconds); 0 if unreported
    };

    namespace detail {

        inline constexpr std::string_view entry_list = "system/external-resource/entry-list";

        // An entry-list number: a JSON number or a number sent as text. Anything else, or a value T
        // cannot hold, reads as 0.
        template<typename T>
        T feed_number(const nlohmann::json& results, std::string_view key) {
            auto it = results.find(key);
            if (it == results.end()) return 0;
            if (it->is_number_unsigned()) {
                auto value = it->get<std::uint64_t>();
                return std::in_range<T>(value) ? static_cast<T>(value) : 0;
            }
            if (it->is_number_integer()) {
                auto value = it->get<std::int64_t>();
                return std::in_range<T>(value) ? static_cast<T>(value) : 0;
            }
            if (it->is_number_float()) {
                auto value = it->get<double>();
                if (!std::isfinite(value) || value < -0x1p63 || value >= 0x1p63) return 0;
                auto whole = static_cast<std::int64_t>(value);
                return std::in_range<T>(whole) ? static_cast<T>(whole) : 0;
            }
            T value = 0;
            if (it->is_string() && fortiapi::detail::parse_number(it->get_ref<const std::string&>(), value)) return value;
            return 0;
        }

        inline std::string feed_text(const nlohmann::json& results, std::string_view key) {
            auto it = results.find(key);
            return it != results.end() && it->is_string() ? it->get<std::string>() : std::string();
        }

        inline bool feed_flag(const nlohmann::json& value) {
            if (value.is_boolean()) return value.get<bool>();
            if (value.is_number()) return value != 0;
            return value == "true" || value == "enable" || value == "1";
        }

        inline std::vector<FeedEntry> feed_entries_of(const nlohmann::json& results) {
            std::vector<FeedEntry> entries;
            if (!results.is_object()) return entries;
            for (const auto& item: results.value("entries", nlohmann::json::array()))
                if (item.is_object())
                    entries.push_back({item.value("entry", std::string()), feed_flag(item.value("valid", nlohmann::json()))});
            return entries;
        }

        inline FeedStatus feed_status_of(const nlohmann::json& results) {
            FeedStatus status;
            if (!results.is_object()) return status;
            status.loaded = results.value("status", nlohmann::json()) == "success";
            status.file_status = feed_text(results, "resource_file_status");
            status.error = feed_text(results, "error");
            status.accepted = feed_number<std::uint64_t>(results, "accepted_count");
            status.valid = feed_number<std::uint64_t>(results, "valid_count");
            status.invalid = feed_number<std::uint64_t>(results, "invalid_count");
            status.limit = feed_number<std::uint64_t>(results, "accepted_limit");
            status.overflow = feed_flag(results.value("overflow", nlohmann::json()));
            status.last_update = feed_number<std::int64_t>(results, "last_content_update_time");
            return status;
        }

    }  // namespace detail

    // What FortiOS currently holds for a feed, every entry included. Pushed entries show up a few
    // seconds after the push. For a large feed prefer feed_status() and feed_entries().
    inline FeedState feed_state(std::string_view feed, Client& client = default_client()) {
        auto results = Monitor::get(detail::entry_list, Query().set("mkey", std::string(feed)).set("include_notes", "true"), client);
        auto status = detail::feed_status_of(results);
        return {status.loaded, std::move(status.file_status), std::move(status.error), detail::feed_entries_of(results)};
    }

    // A feed's counters in one request that never transfers an entry, however large the feed. A feed
    // FortiOS has not loaded yet reports loaded == false and error ("Connect pending"); an unknown
    // feed throws ApiError (HTTP 404).
    //
    // FortiOS pages the entry list server-side, but its valid_count and invalid_count only count
    // entries up to the end of the requested window (start=0&count=1 reports at most one entry), and
    // count=0 means "all". So this asks for one entry at a start no feed reaches: the counts cover the
    // whole feed and the window is empty.
    inline FeedStatus feed_status(std::string_view feed, Client& client = default_client()) {
        static constexpr std::size_t past_any_feed = std::numeric_limits<std::int32_t>::max();
        return detail::feed_status_of(
                Monitor::get(detail::entry_list, Query().set("mkey", std::string(feed)).start(past_any_feed).count(1), client));
    }

    // Entries [start, start + count) of a feed in FortiOS order (one request; FortiOS pages
    // server-side), for verifying a sample without downloading the whole feed. Past the end, or for a
    // feed that is not loaded yet, the page is short or empty; count 0 returns nothing without a
    // request (FortiOS would read count=0 as "every entry").
    inline std::vector<FeedEntry> feed_entries(std::string_view feed, std::size_t start, std::size_t count,
                                               Client& client = default_client()) {
        if (count == 0) return {};
        return detail::feed_entries_of(
                Monitor::get(detail::entry_list, Query().set("mkey", std::string(feed)).start(start).count(count), client));
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
