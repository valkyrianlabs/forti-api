//
// Live-test safeguards (AGENTS.md): a transport that refuses, before sending, every mutation outside
// the approved test resources, and an independent audit of the device's config-change log.
//

#ifndef FORTI_API_TESTS_LIVE_GUARD_HPP
#define FORTI_API_TESTS_LIVE_GUARD_HPP

#include <forti_api/client.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace live {

    inline constexpr std::string_view prefix = "forti-api-test-";

    // The only cmdb collections the live suite may write to, and only for forti-api-test-* objects.
    inline constexpr std::array<std::string_view, 2> approved_collections{
            "cmdb/dnsfilter/profile",
            "cmdb/system/external-resource",
    };

    class GuardViolation : public std::logic_error {
    public:
        using std::logic_error::logic_error;
    };

    inline std::string decode(std::string_view text) {
        auto hex = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        };
        std::string out;
        for (std::size_t i = 0; i < text.size(); ++i) {
            if (text[i] == '%' && i + 2 < text.size() && hex(text[i + 1]) >= 0 && hex(text[i + 2]) >= 0) {
                out += static_cast<char>(hex(text[i + 1]) * 16 + hex(text[i + 2]));
                i += 2;
            } else out += text[i];
        }
        return out;
    }

    // Wraps the real transport. GETs pass; a POST must create a forti-api-test-* object in an
    // approved collection; PUT/DELETE must target <approved collection>/<forti-api-test-*> exactly.
    class GuardTransport final : public fortiapi::Transport {
        std::shared_ptr<fortiapi::Transport> inner_;

        static std::string api_path(const std::string& url) {
            auto at = url.find("/api/v2/");
            if (at == std::string::npos) throw GuardViolation("live guard: not an API URL: " + url);
            auto path = url.substr(at + 8);
            return path.substr(0, path.find('?'));
        }

        static bool approved(std::string_view collection) {
            return std::find(approved_collections.begin(), approved_collections.end(), collection) !=
                   approved_collections.end();
        }

    public:
        explicit GuardTransport(std::shared_ptr<fortiapi::Transport> inner) : inner_(std::move(inner)) {}

        static void check(const fortiapi::HttpRequest& request) {
            if (request.method == fortiapi::Method::Get) return;
            auto path = api_path(request.url);
            auto method = std::string(fortiapi::to_string(request.method));

            if (request.method == fortiapi::Method::Post) {
                auto body = nlohmann::json::parse(request.body, nullptr, false);
                std::string name = body.is_object() && body.contains("name") && body["name"].is_string()
                                   ? body["name"].get<std::string>() : "";
                if (approved(path) && name.starts_with(prefix)) return;
                throw GuardViolation("live guard: refusing POST " + path + " (name '" + name + "')");
            }

            auto slash = path.rfind('/');
            auto collection = slash == std::string::npos ? "" : path.substr(0, slash);
            auto key = slash == std::string::npos ? "" : decode(path.substr(slash + 1));
            if (approved(collection) && key.starts_with(prefix)) return;
            throw GuardViolation("live guard: refusing " + method + " " + path);
        }

        fortiapi::HttpResponse perform(const fortiapi::HttpRequest& request) override {
            check(request);
            return inner_->perform(request);
        }
    };

    // A client for the live suite: environment config, every request through the guard.
    inline std::shared_ptr<fortiapi::Client> guarded_client() {
        auto config = fortiapi::Config::from_env();
        auto transport = std::make_shared<GuardTransport>(std::make_shared<fortiapi::CurlTransport>(config));
        return std::make_shared<fortiapi::Client>(config, transport);
    }

    // Independent verification: every configuration change made through the REST API since `begin()`
    // must concern a forti-api-test-* object, according to the device's own event log.
    class ConfigAudit {
        std::int64_t since_ns_ = 0;

    public:
        // Time for the last changes to reach the memory log before it is read.
        std::chrono::milliseconds settle{1000};

    private:

        static nlohmann::json events(fortiapi::Client& client, std::size_t rows) {
            return client.get("log/memory/event/system", fortiapi::Query().set("rows", std::to_string(rows)));
        }

    public:
        void begin(fortiapi::Client& client) {
            auto reply = events(client, 1);
            since_ns_ = reply.value("now", std::int64_t{0}) * 1'000'000;
            if (since_ns_ == 0) throw std::runtime_error("config audit: the event log reply has no device time");
        }

        // Returns a description of each change that touched something other than a test object.
        std::vector<std::string> violations(fortiapi::Client& client) const {
            std::this_thread::sleep_for(settle);
            std::vector<std::string> found;
            for (const auto& entry: events(client, 1000).value("results", nlohmann::json::array())) {
                if (entry.value("eventtime", std::int64_t{0}) < since_ns_) continue;
                if (!entry.value("ui", std::string()).starts_with("RESTAPI")) continue;
                if (!entry.contains("cfgpath")) continue;
                auto object = entry.value("cfgobj", std::string());
                if (object.starts_with(prefix)) continue;
                found.push_back(entry.value("action", std::string("?")) + " " + entry.value("cfgpath", std::string()) +
                                " " + object + " by " + entry.value("user", std::string("?")));
            }
            return found;
        }
    };

}  // namespace live

#endif //FORTI_API_TESTS_LIVE_GUARD_HPP
