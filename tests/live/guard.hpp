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
#include <cstdlib>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace live {

    inline constexpr std::string_view prefix = "forti-api-test-";

    // The only cmdb collections the live suite may write to, and only for forti-api-test-* objects.
    // Every entry is inert unless something references it (no policies, routes, VIPs, users or
    // admins); adding one is a reviewed change (AGENTS.md).
    inline constexpr std::array<std::string_view, 24> approved_collections{
            "cmdb/antivirus/profile",
            "cmdb/application/list",
            "cmdb/dnsfilter/profile",
            "cmdb/emailfilter/profile",
            "cmdb/file-filter/profile",
            "cmdb/firewall/address",
            "cmdb/firewall/address6",
            "cmdb/firewall/addrgrp",
            "cmdb/firewall/addrgrp6",
            "cmdb/firewall.schedule/group",
            "cmdb/firewall.schedule/onetime",
            "cmdb/firewall.schedule/recurring",
            "cmdb/firewall.service/category",
            "cmdb/firewall.service/custom",
            "cmdb/firewall.service/group",
            "cmdb/firewall.wildcard-fqdn/custom",
            "cmdb/ips/sensor",
            "cmdb/router/access-list",
            "cmdb/router/aspath-list",
            "cmdb/router/community-list",
            "cmdb/router/prefix-list",
            "cmdb/router/route-map",
            "cmdb/system/external-resource",
            "cmdb/webfilter/profile",
    };

    // Monitor actions the live suite may call, only when every command names a forti-api-test-* object.
    inline constexpr std::array<std::string_view, 1> approved_monitor_actions{
            "monitor/system/external-resource/dynamic",   // push entries into a test threat feed
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

    // FORTI_API_LIVE_READ_ONLY=1: a read-only run (for example only the read-only tests, selected
    // with --gtest_filter, while another run owns the test objects). The guard refuses every write and
    // the suite skips its leftover purge.
    inline bool read_only_requested() {
        const char* value = std::getenv("FORTI_API_LIVE_READ_ONLY");
        return value && std::string_view(value) == "1";
    }

    // A cmdb path below an approved collection, split into decoded segments:
    //   cmdb/firewall/addrgrp/forti-api-test-g/member/forti-api-test-a
    //     -> collection "cmdb/firewall/addrgrp", rest {"forti-api-test-g", "member", "forti-api-test-a"}
    // Splitting happens before decoding, so an encoded "/" (%2F) stays inside its key.
    struct ApprovedPath {
        std::string_view collection;
        std::vector<std::string> rest;
    };

    inline std::optional<ApprovedPath> approved_path(std::string_view path) {
        for (auto collection: approved_collections) {
            if (path == collection) return ApprovedPath{collection, {}};
            if (!path.starts_with(collection) || path.size() <= collection.size() || path[collection.size()] != '/')
                continue;
            ApprovedPath found{collection, {}};
            auto tail = path.substr(collection.size() + 1);
            while (true) {
                auto slash = tail.find('/');
                found.rest.push_back(decode(tail.substr(0, slash)));
                if (slash == std::string_view::npos) break;
                tail.remove_prefix(slash + 1);
            }
            return found;
        }
        return std::nullopt;
    }

    // A FortiOS attribute name as it appears in a child path ("member", "reserved-address").
    inline bool attribute_segment(std::string_view segment) {
        return !segment.empty() && std::all_of(segment.begin(), segment.end(), [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        }) && segment.front() != '-';
    }

    // A numeric entry key ("0", "17"): the id of an entry in an id-keyed child table.
    inline bool numeric_segment(std::string_view segment) {
        return !segment.empty() && segment.size() <= 10 &&
               std::all_of(segment.begin(), segment.end(), [](char c) { return c >= '0' && c <= '9'; });
    }

    // Wraps the real transport. GETs pass; every other request must stay inside a forti-api-test-*
    // object of an approved collection:
    //   POST   <collection>                              body "name" forti-api-test-*
    //   PUT    <collection>/<test object>                DELETE likewise
    //   POST   <collection>/<test object>/<attribute>    one child-table entry: body "name"
    //                                                    forti-api-test-*, or no "name" and a numeric "id"
    //   PUT    <collection>/<test object>/<attribute>/<entry>    DELETE likewise; the entry key is
    //                                                    forti-api-test-* or numeric (an id-keyed entry)
    // Everything else, including writes to a whole child table (PUT/DELETE <test object>/<attribute>)
    // and deeper paths, is refused. A read-only guard refuses everything but GET.
    class GuardTransport final : public fortiapi::Transport {
        std::shared_ptr<fortiapi::Transport> inner_;
        bool read_only_ = false;

        static std::string api_path(const std::string& url) {
            auto at = url.find("/api/v2/");
            if (at == std::string::npos) throw GuardViolation("live guard: not an API URL: " + url);
            auto path = url.substr(at + 8);
            return path.substr(0, path.find('?'));
        }

        // The body of a POST that creates one child-table entry names a test entry or a numeric id.
        static bool test_entry_body(const nlohmann::json& body) {
            if (!body.is_object()) return false;
            if (auto it = body.find("name"); it != body.end())
                return it->is_string() && it->get_ref<const std::string&>().starts_with(prefix);
            auto id = body.find("id");
            return id != body.end() && (id->is_number_unsigned() || (id->is_number_integer() && id->get<std::int64_t>() >= 0));
        }

    public:
        explicit GuardTransport(std::shared_ptr<fortiapi::Transport> inner, bool read_only = false)
                : inner_(std::move(inner)), read_only_(read_only) {}

        static void check(const fortiapi::HttpRequest& request) {
            if (request.method == fortiapi::Method::Get) return;
            auto path = api_path(request.url);
            auto method = std::string(fortiapi::to_string(request.method));

            if (request.method == fortiapi::Method::Post &&
                std::find(approved_monitor_actions.begin(), approved_monitor_actions.end(), path) != approved_monitor_actions.end()) {
                auto body = nlohmann::json::parse(request.body, nullptr, false);
                auto commands = body.is_object() ? body.value("commands", nlohmann::json()) : nlohmann::json();
                bool all_test = commands.is_array() && !commands.empty() &&
                                std::all_of(commands.begin(), commands.end(), [](const nlohmann::json& c) {
                                    return c.is_object() && c.value("name", std::string()).starts_with(prefix);
                                });
                if (all_test) return;
                throw GuardViolation("live guard: refusing POST " + path + " for non-test objects");
            }

            auto target = approved_path(path);
            const bool post = request.method == fortiapi::Method::Post;
            if (target && (post || request.method == fortiapi::Method::Put || request.method == fortiapi::Method::Delete)) {
                const auto& rest = target->rest;
                bool test_parent = !rest.empty() && rest[0].starts_with(prefix);
                if (post && rest.empty()) {
                    auto body = nlohmann::json::parse(request.body, nullptr, false);
                    std::string name = body.is_object() && body.contains("name") && body["name"].is_string()
                                       ? body["name"].get<std::string>() : "";
                    if (name.starts_with(prefix)) return;
                    throw GuardViolation("live guard: refusing POST " + path + " (name '" + name + "')");
                }
                if (!post && rest.size() == 1 && test_parent) return;
                if (post && rest.size() == 2 && test_parent && attribute_segment(rest[1])) {
                    if (test_entry_body(nlohmann::json::parse(request.body, nullptr, false))) return;
                    throw GuardViolation("live guard: refusing POST " + path + " (entry is neither forti-api-test-* nor numeric)");
                }
                if (!post && rest.size() == 3 && test_parent && attribute_segment(rest[1]) &&
                    (rest[2].starts_with(prefix) || numeric_segment(rest[2])))
                    return;
            }
            throw GuardViolation("live guard: refusing " + method + " " + path);
        }

        fortiapi::HttpResponse perform(const fortiapi::HttpRequest& request) override {
            if (read_only_ && request.method != fortiapi::Method::Get)
                throw GuardViolation("live guard: read-only run, refusing " +
                                     std::string(fortiapi::to_string(request.method)) + " " + api_path(request.url));
            check(request);
            return inner_->perform(request);
        }
    };

    // A client for the live suite: environment config, every request through the guard. Each call
    // makes a separate client with its own connection (the concurrency tests use two).
    inline std::shared_ptr<fortiapi::Client> guarded_client(std::function<void(const fortiapi::Exchange&)> on_exchange = {}) {
        auto config = fortiapi::Config::from_env();
        config.on_exchange = std::move(on_exchange);
        auto transport = std::make_shared<GuardTransport>(std::make_shared<fortiapi::CurlTransport>(config),
                                                          read_only_requested());
        return std::make_shared<fortiapi::Client>(config, transport);
    }

    // Top-level attribute names in a FortiOS cfgattr record:
    //   "comment[a->b]ftgd-dns[filters:2[category[3]]]" -> {"comment", "ftgd-dns"}
    inline std::vector<std::string> attribute_names(std::string_view cfgattr) {
        std::vector<std::string> names;
        int depth = 0;
        std::string current;
        for (char c: cfgattr) {
            if (c == '[') {
                if (depth++ == 0 && !current.empty()) {
                    if (std::find(names.begin(), names.end(), current) == names.end()) names.push_back(current);
                    current.clear();
                }
            } else if (c == ']') {
                if (depth > 0) --depth;
            } else if (depth == 0) current += c;
        }
        return names;
    }

    // Independent verification: every configuration change made through the REST API since `begin()`
    // must concern a forti-api-test-* object, according to the device's own event log.
    class ConfigAudit {
        std::int64_t since_ns_ = 0;

    public:
        // FortiOS writes config changes to the memory log several seconds late (measured: 5-8 s on
        // 7.4.8, edits shortly after a create folded into the Add record). changes() waits at least
        // `settle`, then polls until two consecutive reads agree, up to `patience`.
        std::chrono::milliseconds settle{10000};
        std::chrono::milliseconds poll{3000};
        std::chrono::milliseconds patience{45000};

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

        // Every configuration change made through the REST API since begin(), oldest first, as the
        // device logged it (action, cfgpath, cfgobj, cfgattr, user, ...).
        std::vector<nlohmann::json> changes(fortiapi::Client& client) const {
            auto read = [&] {
                std::vector<nlohmann::json> found;
                for (const auto& entry: events(client, 1000).value("results", nlohmann::json::array())) {
                    if (entry.value("eventtime", std::int64_t{0}) < since_ns_) continue;
                    if (!entry.value("ui", std::string()).starts_with("RESTAPI")) continue;
                    if (!entry.contains("cfgpath")) continue;
                    found.push_back(entry);
                }
                std::reverse(found.begin(), found.end());
                return found;
            };
            auto deadline = std::chrono::steady_clock::now() + patience;
            std::this_thread::sleep_for(settle);
            auto found = read();
            while (poll.count() > 0 && std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(poll);
                auto again = read();
                if (again == found) break;
                found = std::move(again);
            }
            return found;
        }

        // Returns a description of each change that touched something other than a test object.
        std::vector<std::string> violations(fortiapi::Client& client) const {
            std::vector<std::string> found;
            for (const auto& entry: changes(client)) {
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
