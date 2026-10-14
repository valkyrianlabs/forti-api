//
// fortiapi::Monitor: the monitor API (status, statistics and actions), which has no schema. Paths
// are relative to "monitor/" ("system/status", "system/available-interfaces").
//

#ifndef FORTI_API_MONITOR_HPP
#define FORTI_API_MONITOR_HPP

#include "client.hpp"

#include <string>
#include <string_view>

namespace fortiapi {

    struct Monitor {
        static std::string path(std::string_view relative) {
            while (relative.starts_with('/')) relative.remove_prefix(1);
            return "monitor/" + std::string(relative);
        }

        // The `results` member of the reply (an object or an array, depending on the endpoint).
        static nlohmann::json get(std::string_view relative, const Query& query = {}, Client& client = default_client()) {
            auto body = client.get(path(relative), query);
            auto it = body.find("results");
            return it != body.end() ? std::move(*it) : nlohmann::json();
        }

        // Monitor actions. Returns the full reply. Like every write, never retried.
        static nlohmann::json post(std::string_view relative, const nlohmann::json& body, const Query& query = {},
                                   Client& client = default_client()) {
            return client.post(path(relative), body, query);
        }
    };

}  // namespace fortiapi

#endif //FORTI_API_MONITOR_HPP
