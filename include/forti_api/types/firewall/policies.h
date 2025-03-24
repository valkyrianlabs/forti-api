//
// Created by Cooper Larson on 3/24/25.
//

#ifndef FORTI_API_POLICIES_H
#define FORTI_API_POLICIES_H

#include "nlohmann/json.hpp"
#include "include/forti_api/types/response.h"

struct Module { std::string name, q_origin_key; };

struct Interface : public Module {
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Interface, name, q_origin_key)
};

struct Address : public Module {
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Address, name, q_origin_key)
};

struct Service : public Module {
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Service, name, q_origin_key)
};

struct FirewallPolicy {
    unsigned int policyid{}, q_origin_key{}, uuid_idx{};
    std::vector<Interface> srcintf, dstintf;
    std::vector<Address> srcaddr, dstaddr;
    std::vector<Service> service;
    std::string status, name, action, ssl_ssh_profile, av_profile, webfilter_profile, dnsfilter_profile,
            nat, inbound, outbound, natinbound, natoutbound, comments, vlan_filter;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(FirewallPolicy, policyid, q_origin_key, uuid_idx,
            srcintf, dstintf, srcaddr, dstaddr, service,
            status, name, action, ssl_ssh_profile,
            av_profile, webfilter_profile, dnsfilter_profile, nat,
            inbound, outbound, natinbound, natoutbound, comments, vlan_filter)
};

struct FirewallPoliciesResponse : public Response {
    std::vector<FirewallPolicy> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(FirewallPoliciesResponse, http_method, size, matched_count, next_idx,
            revision, vdom, path, name, status, http_status, serial, version, build, results)
};

#endif //FORTI_API_POLICIES_H
