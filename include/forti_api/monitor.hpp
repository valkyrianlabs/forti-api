//
// fortiapi::Monitor: the monitor API (status, statistics and actions), which has no schema. Paths
// are relative to "monitor/" ("system/status", "system/available-interfaces").
//

#ifndef FORTI_API_MONITOR_HPP
#define FORTI_API_MONITOR_HPP

#include "client.hpp"
#include "field.hpp"

#include <string>
#include <string_view>
#include <vector>

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

        // A monitor reply as raw bytes, for endpoints that answer with a file instead of JSON (see
        // Client::download): Monitor::download("system/config/backup", Query().set("scope", "global")).
        static Download download(std::string_view relative, const Query& query = {}, DownloadOptions options = {},
                                 Client& client = default_client()) {
            return client.download(path(relative), query, std::move(options));
        }

        // Monitor actions. Returns the full reply. Like every write, never retried.
        static nlohmann::json post(std::string_view relative, const nlohmann::json& body, const Query& query = {},
                                   Client& client = default_client()) {
            return client.post(path(relative), body, query);
        }
    };

    // A generated read-only monitor endpoint. Spec names the result type, the path (relative to
    // monitor/) and whether `results` is a list. Result types come from response shapes recorded on
    // a real device, so every attribute is a Field<T> and unknown attributes are ignored.
    template<typename Spec>
    struct MonitorGet {
        using type = typename Spec::type;
        using result_type = std::conditional_t<Spec::list, std::vector<type>, type>;

        static constexpr std::string_view path = Spec::path;

        static result_type get(const Query& query = {}, Client& client = default_client()) {
            auto results = Monitor::get(path, query, client);
            try {
                return from_json<result_type>(results);
            } catch (const detail::DecodeFailure& failure) {
                throw DecodeError("monitor/" + std::string(path) + ": attribute " + failure.what());
            } catch (const nlohmann::json::exception& error) {
                throw DecodeError("monitor/" + std::string(path) + ": " + error.what());
            }
        }
    };

}  // namespace fortiapi

#endif //FORTI_API_MONITOR_HPP
