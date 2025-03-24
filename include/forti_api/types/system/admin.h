//
// Created by Cooper Larson on 3/24/25.
//

#ifndef FORTI_API_ADMIN_H
#define FORTI_API_ADMIN_H

#include "nlohmann/json.hpp"
#include "../response.h"
#include "../../api.hpp"

struct VDomEntry {
    std::string name, q_origin_key;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(VDomEntry, name, q_origin_key)
};

enum class TrustHostType {
    IPV4,
    IPV6,
};

struct TrustHostEntry {
    unsigned int id{}, q_origin_key{};
    std::string type;

    TrustHostEntry() = default;
    explicit TrustHostEntry(std::string type) : type(std::move(type)) {}

    [[nodiscard]] virtual TrustHostType get_type() const = 0;
    [[nodiscard]] virtual std::string get_subnet() const = 0;
    virtual ~TrustHostEntry() = default;

    [[nodiscard]] bool is_ipv4() const { return get_type() == TrustHostType::IPV4; }
    [[nodiscard]] bool is_ipv6() const { return get_type() == TrustHostType::IPV6; }

    friend void to_json(nlohmann::json& j, const TrustHostEntry& host) {
        j = nlohmann::json{
                {"id", host.id},
                {"q_origin_key", host.q_origin_key},
                {"type", host.type},
                {host.is_ipv4() ? "ipv4-trusthost" : "ipv6-trusthost", host.get_subnet()}
        };
    }
};

// Derived class for IPv4 TrustHost
struct IPV4TrustHost : public TrustHostEntry {
    std::string ipv4_trusthost;

    [[nodiscard]] TrustHostType get_type() const override { return TrustHostType::IPV4; }
    [[nodiscard]] std::string get_subnet() const override { return ipv4_trusthost; }

    IPV4TrustHost() = default;
    explicit IPV4TrustHost(std::string ip_addr) : TrustHostEntry("ipv4-trusthost"), ipv4_trusthost(std::move(ip_addr)) {}

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(IPV4TrustHost, id, q_origin_key, type, ipv4_trusthost)
};

// Derived class for IPv6 TrustHost
struct IPV6TrustHost : public TrustHostEntry {
    std::string ipv6_trusthost;

    [[nodiscard]] TrustHostType get_type() const override { return TrustHostType::IPV6; }
    [[nodiscard]] std::string get_subnet() const override { return ipv6_trusthost; }

    IPV6TrustHost() = default;
    explicit IPV6TrustHost(std::string ip_addr) : TrustHostEntry("ipv4-trusthost"), ipv6_trusthost(std::move(ip_addr)) {}

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(IPV6TrustHost, id, q_origin_key, type, ipv6_trusthost)
};

struct TrustHost : public std::vector<std::shared_ptr<TrustHostEntry>> {
friend void from_json(const nlohmann::json& j, TrustHost& th) {
    for (const auto& item : j) {
        auto type = item.at("type").get<std::string>();
        if (type == "ipv4-trusthost") th.push_back(std::make_shared<IPV4TrustHost>(item));
        else th.push_back(std::make_shared<IPV6TrustHost>(item));
    }
}

friend void to_json(nlohmann::json& j, const TrustHost& th) {
    for (const auto& host : th) j.push_back(*host);
}
};

struct APIUser {
    inline static std::string api_user_endpoint = "/cmdb/system/api-user";
    std::string name, q_origin_key, comments, api_key, accprofile, schedule, cors_allow_origin,
            peer_auth, peer_group;
    TrustHost trusthost;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(APIUser, name, q_origin_key, comments, api_key, accprofile,
            schedule, cors_allow_origin, peer_auth, peer_group, trusthost)

    bool is_trusted(const std::string& subnet) {
        return std::any_of(trusthost.begin(), trusthost.end(),
                           [&subnet](const std::shared_ptr<TrustHostEntry>& host) {
                               return host->get_subnet() == subnet;
                           });
    }

    void trust(const std::string& subnet) {
        if (is_trusted(subnet)) return;
        if (std::regex_match(subnet, ipv4)) trusthost.push_back(std::make_shared<IPV4TrustHost>(subnet));
        else if (std::regex_match(subnet, ipv6)) trusthost.push_back(std::make_shared<IPV6TrustHost>(subnet));
    }

    void distrust(const std::string& subnet) {
        if (!is_trusted(subnet)) return;
        trusthost.erase(std::remove_if(trusthost.begin(), trusthost.end(),
                                       [&subnet](const std::shared_ptr<TrustHostEntry>& entry) {
                                           return entry->get_subnet() == subnet;
                                       }), trusthost.end());
    }

    void update() {
        FortiAPI::put(std::format("{}/{}", api_user_endpoint, name), *this);
    }
};

struct AllAPIUsersResponse : public Response {
    std::vector<APIUser> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(AllAPIUsersResponse, http_method, size, matched_count, next_idx,
            revision, vdom, path, name, status, http_status, serial, version,
            build, results)
};

#endif //FORTI_API_ADMIN_H
