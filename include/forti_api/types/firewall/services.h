//
// Created by Cooper Larson on 3/24/25.
//

#ifndef FORTI_API_SERVICES_H
#define FORTI_API_SERVICES_H

#include "nlohmann/json.hpp"
#include "include/forti_api/types/response.h"
#include "include/forti_api/api.hpp"

enum ServiceProtocol { TCP, UDP, SCTP };

struct ServiceCategory {
    inline static std::string endpoint = "/cmdb/firewall.service/category";
    std::string name, q_origin_key, comment, fabric_object;

    explicit ServiceCategory(std::string name, std::string comment="") : name(std::move(name)), comment(std::move(comment)) {}

    ServiceCategory() = default;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(ServiceCategory, name, q_origin_key, comment, fabric_object);

    void del() { FortiAPI::del(std::format("{}/{}", endpoint, name)); }

    void add() { FortiAPI::post(endpoint, *this); }
};

struct ServiceCategoriesResponse : public Response {
    std::vector<ServiceCategory> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(ServiceCategoriesResponse, http_method, size, matched_count, next_idx,
            revision, vdom, path, name, status, http_status, serial, version, build, results);
};

struct FirewallService {
    inline static std::string endpoint = "/cmdb/firewall.service/custom";
    std::string name, q_origin_key, uuid, proxy, category, protocol, helper, iprange, fqdn, tcp_portrange, udp_portrange,
            sctp_portrange, session_ttl, check_reset_range, comment, app_service_type, fabric_object;
    unsigned int uuid_idx{}, tcp_halfclose_timer{}, tcp_halfopen_timer{}, tcp_timewait_timer{}, tcp_rst_timer{}, udp_idle_timer{}, color{};
    std::vector<std::string> app_category, application;

    explicit FirewallService(std::string n) : name(std::move(n)) {}

    FirewallService() = default;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(FirewallService, name, q_origin_key, uuid, proxy, category, protocol,
            helper, iprange, fqdn, tcp_portrange, udp_portrange, sctp_portrange,
            session_ttl, check_reset_range, comment, app_service_type, fabric_object,
            uuid_idx, tcp_halfclose_timer, tcp_halfopen_timer, tcp_timewait_timer,
            tcp_rst_timer, udp_idle_timer, color, app_category, application);

    void update(const std::string& vdom="root") {
        FortiAPI::put(std::format("{}/{}?vdom={}", endpoint, name, vdom), *this);
    }

    void set_port(unsigned int port, const ServiceProtocol& proto=TCP) {
        std::string p = std::to_string(port);
        switch (proto) {
            case TCP:
                tcp_portrange = p;
                break;
            case UDP:
                udp_portrange = p;
                break;
            case SCTP:
                sctp_portrange = p;
                break;
        }
        update();
    }

    void set_port_range(std::pair<unsigned int, unsigned int> range, const ServiceProtocol& proto=TCP) {
        std::string port_range = std::format("{}-{}", range.first, range.second);
        switch (proto) {
            case TCP:
                tcp_portrange = port_range;
                break;
            case UDP:
                udp_portrange = port_range;
                break;
            case SCTP:
                sctp_portrange = port_range;
                break;
        }
        update();
    }

    void set_port_range(const std::vector<std::pair<unsigned int, unsigned int>>& ranges, const ServiceProtocol& proto) {
        std::string port_ranges;

        for (unsigned int i = 0; i < ranges.size(); ++i) {
            port_ranges += std::format("{}-{}", ranges[i].first, ranges[i].second);
            if (i < ranges.size() - 1) port_ranges += " ";
        }

        switch (proto) {
            case TCP:
                tcp_portrange = port_ranges;
                break;
            case UDP:
                udp_portrange = port_ranges;
                break;
            case SCTP:
                sctp_portrange = port_ranges;
                break;
        }

        update();
    }

    void set_category(const std::string& category_name) {
        auto categories = FortiAPI::get<ServiceCategoriesResponse>(ServiceCategory::endpoint).results;
        for (const auto& cat : categories) {
            if (cat.name == category_name) {
                category = category_name;
                update();
                return;
            }
        }

        throw std::runtime_error("Unable to locate category: " + category_name + ". Did you mean to create the category first?");
    }

    void set_comment(const std::string& new_comment) {
        comment = new_comment;
        update();
    }
};

struct FirewallServicesResponse : public Response {
    std::vector<FirewallService> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(FirewallServicesResponse, http_method, size, matched_count, next_idx,
            revision, vdom, path, name, status, http_status, serial, version, build, results)
};

#endif //FORTI_API_SERVICES_H
