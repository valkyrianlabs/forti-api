//
// Created by Cooper Larson on 3/24/25.
//

#ifndef FORTI_API_INTERFACE_H
#define FORTI_API_INTERFACE_H

#include "nlohmann/json.hpp"
#include "../response.h"

struct SystemResponse {
    unsigned int build{};
    std::string http_method, revision, vdom, path, name, action, status, serial, version;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(SystemResponse, build, http_method, revision, vdom, path, name, action,
            status, serial, version);
};

struct GeneralInterface {
    std::string name;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(GeneralInterface, name);
};

struct GeneralResponse : public Response {
    std::vector<GeneralInterface> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(GeneralResponse, http_method, size, matched_count, next_idx,
            revision, vdom, path, name, status, http_status, serial, version,
            build, results)
};

struct IPV4Address {
    std::string ip, netmask;
    unsigned int cidr_netmask{};

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(IPV4Address, ip, netmask, cidr_netmask);
};

struct SystemInterface {
    std::string name, type, real_interface_name, vdom, status, alias, vlan_protocol, role,
            mac_address, port_speed, media, physical_switch, link, duplex, icon;
    bool is_used{}, is_physical{}, dynamic_addressing{}, dhcp_interface{}, valid_in_policy{},
            is_ipsecable{}, is_routable{}, supports_fortilink{}, supports_dhcp{}, is_explicit_proxyable{},
            supports_device_id{}, supports_fortitelemetry{}, is_system_interface{}, monitor_bandwidth{};
    unsigned int in_bandwidth_limit{}, out_bandwidth_limit{}, dhcp4_client_count{}, dhcp6_client_count{},
            estimated_upstream_bandwidth{}, estimated_downstream_bandwidth{}, chip_id{}, speed{};
    std::vector<IPV4Address> ipv4_addresses{};
    std::vector<std::string> members{};

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(SystemInterface,
            name, type, real_interface_name, vdom, status, alias, vlan_protocol, role,
            mac_address, port_speed, media, physical_switch, link, duplex, icon,
            is_used, is_physical, dynamic_addressing, dhcp_interface, valid_in_policy,
            is_ipsecable, is_routable, supports_fortilink, supports_dhcp, is_explicit_proxyable,
            supports_device_id, supports_fortitelemetry, is_system_interface, monitor_bandwidth,
            in_bandwidth_limit, out_bandwidth_limit, dhcp4_client_count, dhcp6_client_count,
            estimated_upstream_bandwidth, estimated_downstream_bandwidth, chip_id, speed,
            ipv4_addresses
    )
};

struct VirtualWANLink {
    std::string name, vdom, status, type, link, icon;
    bool is_sdwan_zone{}, valid_in_policy{};
    std::vector<std::string> members{};

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(VirtualWANLink, name, vdom, status, type, link, icon, is_sdwan_zone,
            valid_in_policy, members);
};

struct InterfacesGeneralResponse : public SystemResponse {
    std::vector<nlohmann::json> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(InterfacesGeneralResponse, build, http_method, revision, vdom, path,
            name, action, status, serial, version, results);
};

#endif //FORTI_API_INTERFACE_H
