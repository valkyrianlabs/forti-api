//
// Created by Cooper Larson on 8/26/24.
//

#ifndef FORTI_API_API_HPP
#define FORTI_API_API_HPP

#include <string>
#include <nlohmann/json.hpp>
#include <iostream>
#include <format>
#include <algorithm>
#include <cctype>
#include <utility>
#include <cstdlib>
#include <stdexcept>
#include <regex>
#include "client.hpp"
#include "types/response.h"

inline static std::regex ipv4("(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])");
inline static std::regex ipv6("((([0-9a-fA-F]){1,4})\\:){7}([0-9a-fA-F]){1,4}");

inline static nlohmann::json convert_keys_to_hyphens(const nlohmann::json& j) {
    nlohmann::json result;

    std::array<std::string, 10> ignore_keys{
            "q_origin_key"
    };

    for (auto it = j.begin(); it != j.end(); ++it) {
        std::string key = it.key();

        // Ignore certain keys
        bool should_process = true;
        for (const auto& ignore : ignore_keys) {
            if (key == ignore) {
                should_process = false;
                break;
            }
        }
        if (!should_process) continue;

        // Replace underscores with hyphens in the key
        std::replace(key.begin(), key.end(), '_', '-');

        // Recursively process objects and arrays
        if (it->is_object()) result[key] = convert_keys_to_hyphens(*it);
        else if (it->is_array()) {
            nlohmann::json array_result = nlohmann::json::array();
            for (const auto& elem : *it) {  // Use *it instead of it.value()
                if (elem.is_object()) array_result.push_back(convert_keys_to_hyphens(elem));
                else array_result.push_back(elem);  // Directly add the element if it's not an object
            }
            result[key] = array_result;
        } else result[key] = *it;  // Directly copy the value if it's neither an object nor array
    }

    return result;
}

inline static nlohmann::json convert_keys_to_underscores(const nlohmann::json& j) {
    nlohmann::json result;

    for (auto it = j.begin(); it != j.end(); ++it) {
        std::string key = it.key();
        std::replace(key.begin(), key.end(), '-', '_');

        if (it->is_object()) result[key] = convert_keys_to_underscores(*it);
        else if (it->is_array()) {
            nlohmann::json array_result = nlohmann::json::array();
            for (const auto& elem : *it) {  // Use *it instead of it.value()
                if (elem.is_object()) array_result.push_back(convert_keys_to_underscores(elem));
                else array_result.push_back(elem);  // Directly add the element if it's not an object
            }
            result[key] = array_result;
        } else result[key] = *it;  // Directly copy the value if it's neither an object nor array
    }

    return result;
}

// Pre-generation accessors (firewall.hpp, dns_filter.hpp, threat_feed.hpp, system.hpp) talk to the
// device through these until the generated fortiapi:: endpoints replace them (buildout plan, phase 3).
class FortiAuth {
public:
    static void set_vars_from_env() {
        fortiapi::set_default_client(std::make_shared<fortiapi::Client>(fortiapi::Config::from_env()));
    }
};


class FortiAPI {
    // "/cmdb/x/y?vdom=root&mkey=z" -> path + Query (values re-encoded by Query).
    static std::pair<std::string, fortiapi::Query> split(const std::string& target) {
        auto mark = target.find('?');
        fortiapi::Query query;
        if (mark != std::string::npos) {
            std::string_view rest(target);
            rest.remove_prefix(mark + 1);
            while (!rest.empty()) {
                auto amp = rest.find('&');
                auto pair = rest.substr(0, amp);
                auto eq = pair.find('=');
                query.set(std::string(pair.substr(0, eq)), eq == std::string_view::npos ? "" : std::string(pair.substr(eq + 1)));
                if (amp == std::string_view::npos) break;
                rest.remove_prefix(amp + 1);
            }
        }
        return {target.substr(0, mark), query};
    }

    template<typename T>
    static T request(fortiapi::Method method, const std::string& target, const nlohmann::json& data = {}) {
        auto [path, query] = split(target);
        nlohmann::json body = convert_keys_to_hyphens(data);
        bool has_body = method == fortiapi::Method::Post || method == fortiapi::Method::Put;
        auto result = fortiapi::default_client().exchange(method, path, query, has_body ? &body : nullptr);
        return convert_keys_to_underscores(result.body);
    }

public:
    template<typename T>
    static T get(const std::string &path) { return request<T>(fortiapi::Method::Get, path); }

    static Response post(const std::string &path, const nlohmann::json &data) { return request<Response>(fortiapi::Method::Post, path, data); }
    static Response put(const std::string &path, const nlohmann::json &data) { return request<Response>(fortiapi::Method::Put, path, data); }
    static Response del(const std::string &path) { return request<Response>(fortiapi::Method::Delete, path); }
};

#endif //FORTI_API_API_HPP
