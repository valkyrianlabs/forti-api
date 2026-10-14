//
// System: the generated endpoints plus API-user trusted hosts and live interface addresses.
//

#ifndef FORTI_API_SYSTEM_HPP
#define FORTI_API_SYSTEM_HPP

#include "gen/system/api_user.hpp"
#include "gen/system/external_resource.hpp"
#include "gen/system/global.hpp"
#include "gen/system/interface.hpp"
#include "monitor.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <format>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fortiapi::system {

    namespace detail {
        // "10.0.0.0/24" or "10.0.0.0 255.255.255.0" -> "10.0.0.0 255.255.255.0"; nullopt if not IPv4.
        inline std::optional<std::string> ipv4_subnet(std::string_view text) {
            auto parse_ip = [](std::string_view ip) -> std::optional<std::array<unsigned, 4>> {
                std::array<unsigned, 4> octets{};
                for (std::size_t i = 0; i < 4; ++i) {
                    auto dot = i < 3 ? ip.find('.') : ip.size();
                    if (dot == std::string_view::npos) return std::nullopt;
                    auto part = ip.substr(0, dot);
                    auto [end, ec] = std::from_chars(part.data(), part.data() + part.size(), octets[i]);
                    if (ec != std::errc() || end != part.data() + part.size() || part.empty() || octets[i] > 255) return std::nullopt;
                    ip.remove_prefix(i < 3 ? dot + 1 : dot);
                }
                return ip.empty() ? std::optional(octets) : std::nullopt;
            };
            auto split = text.find_first_of("/ ");
            auto address = parse_ip(text.substr(0, split));
            if (!address) return std::nullopt;
            std::string mask = "255.255.255.255";
            if (split != std::string_view::npos) {
                auto rest = text.substr(split + 1);
                if (text[split] == '/') {
                    unsigned bits = 0;
                    auto [end, ec] = std::from_chars(rest.data(), rest.data() + rest.size(), bits);
                    if (ec != std::errc() || end != rest.data() + rest.size() || bits > 32) return std::nullopt;
                    std::uint32_t m = bits == 0 ? 0 : ~std::uint32_t{0} << (32 - bits);
                    mask = std::format("{}.{}.{}.{}", m >> 24, (m >> 16) & 255, (m >> 8) & 255, m & 255);
                } else if (auto parsed = parse_ip(rest)) {
                    mask = std::format("{}.{}.{}.{}", (*parsed)[0], (*parsed)[1], (*parsed)[2], (*parsed)[3]);
                } else return std::nullopt;
            }
            const auto& a = *address;
            return std::format("{}.{}.{}.{} {}", a[0], a[1], a[2], a[3], mask);
        }

        inline std::pair<std::string_view, std::string> trusthost_of(std::string_view subnet) {
            if (auto v4 = ipv4_subnet(subnet)) return {api_user::trusthost::type::ipv4_trusthost, *v4};
            if (subnet.find(':') != std::string_view::npos) {
                std::string v6(subnet);
                if (v6.find('/') == std::string::npos) v6 += "/128";
                return {api_user::trusthost::type::ipv6_trusthost, v6};
            }
            throw std::invalid_argument("fortiapi: not an IPv4 or IPv6 subnet: " + std::string(subnet));
        }

        inline bool matches(const ApiUser::TrusthostEntry& entry, std::string_view type, const std::string& value) {
            if (type == api_user::trusthost::type::ipv4_trusthost) return entry.ipv4_trusthost == value;
            return entry.ipv6_trusthost == value;
        }
    }  // namespace detail

    // Whether the API user accepts requests from `subnet` ("10.0.0.0/24", "10.0.0.0 255.255.255.0",
    // "2001:db8::/32").
    inline bool trusts(const ApiUser& user, std::string_view subnet) {
        auto [type, value] = detail::trusthost_of(subnet);
        if (!user.trusthost) return false;
        return std::any_of(user.trusthost->begin(), user.trusthost->end(),
                           [&](const ApiUser::TrusthostEntry& e) { return detail::matches(e, type, value); });
    }

    // Adds a trusted host (in memory; ApiUsers::update() sends it). No change if already trusted.
    inline void trust(ApiUser& user, std::string_view subnet) {
        if (trusts(user, subnet)) return;
        auto [type, value] = detail::trusthost_of(subnet);
        ApiUser::TrusthostEntry entry;
        entry.type = std::string(type);
        if (type == api_user::trusthost::type::ipv4_trusthost) entry.ipv4_trusthost = value;
        else entry.ipv6_trusthost = value;
        user.trusthost.edit().push_back(std::move(entry));
    }

    inline void distrust(ApiUser& user, std::string_view subnet) {
        if (!trusts(user, subnet)) return;
        auto [type, value] = detail::trusthost_of(subnet);
        auto& hosts = user.trusthost.edit();
        std::erase_if(hosts, [&](const ApiUser::TrusthostEntry& e) { return detail::matches(e, type, value); });
    }

    struct InterfaceAddress {
        std::string ip, netmask;
        unsigned prefix_length = 0;
    };

    // The IPv4 addresses an interface holds right now (DHCP included), from the monitor API.
    inline std::vector<InterfaceAddress> interface_addresses(std::string_view interface, const Query& query = {},
                                                             Client& client = default_client()) {
        std::vector<InterfaceAddress> out;
        for (const auto& item: Monitor::get("system/available-interfaces", query, client)) {
            if (item.value("name", std::string()) != interface) continue;
            for (const auto& address: item.value("ipv4_addresses", nlohmann::json::array()))
                out.push_back({address.value("ip", std::string()), address.value("netmask", std::string()),
                               address.value("cidr_netmask", 0u)});
        }
        return out;
    }

}  // namespace fortiapi::system

#endif //FORTI_API_SYSTEM_HPP
