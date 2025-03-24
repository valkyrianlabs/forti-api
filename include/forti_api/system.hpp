//
// Created by Cooper Larson on 8/28/24.
//

#ifndef FORTI_API_SYSTEM_H
#define FORTI_API_SYSTEM_H

#include "api.hpp"
#include <string>
#include <utility>
#include <algorithm>
#include "types/system/interface.h"
#include "types/system/admin.h"


namespace System {

    class Interface {
        inline static std::string available_interfaces_endpoint = "/monitor/system/available-interfaces";

        inline static std::vector<SystemInterface> physical_interfaces{},
                tunnel_interfaces{},
                hard_switch_vlan_interfaces{},
                aggregate_interfaces{};

        static void update_local_interface_data() {
            physical_interfaces.clear();
            tunnel_interfaces.clear();
            hard_switch_vlan_interfaces.clear();
            aggregate_interfaces.clear();

            auto interfaces = FortiAPI::get<InterfacesGeneralResponse>(available_interfaces_endpoint);
            for (const auto& interface : interfaces.results) {
                if (!interface.contains("type")) continue;
                auto type = interface["type"].get<std::string>();

                if (type == "physical") physical_interfaces.emplace_back(interface);
                else if (type == "tunnel") tunnel_interfaces.emplace_back(interface);
                else if (type == "hard-switch-vlan") hard_switch_vlan_interfaces.emplace_back(interface);
                else if (type == "aggregate") aggregate_interfaces.emplace_back(interface);
            }
        }

        static unsigned int count_interfaces() {
            return FortiAPI::get<GeneralResponse>(available_interfaces_endpoint).results.size();
        }

        static nlohmann::json get(const std::string& name, const std::string& vdom = "root") {
            std::string endpoint =
                    std::format("{}?vdom={}&mkey={}", available_interfaces_endpoint, vdom, name);

            return FortiAPI::get<std::vector<nlohmann::json>>(endpoint)[0];
        }

        static SystemInterface get(const std::vector<SystemInterface>& interfaces,
                                   const std::string& name, const std::string& vdom = "root") {
            if (interfaces.empty()) update_local_interface_data();
            for (const auto& interface : interfaces)
                if (interface.name == name && interface.vdom == vdom) return interface;
            throw std::runtime_error(std::format("No system interface found for: {}", name));
        }

    public:
        static SystemInterface get_physical_interface(const std::string& name, const std::string& vdom = "root") {
            return get(physical_interfaces, name, vdom);
        }

        static SystemInterface get_tunnel_interface(const std::string& name, const std::string& vdom = "root") {
            return get(tunnel_interfaces, name, vdom);
        }

        static SystemInterface get_hard_vlan_switch_interface(const std::string& name, const std::string& vdom = "root") {
            return get(hard_switch_vlan_interfaces, name, vdom);
        }

        static SystemInterface get_aggregate_interface(const std::string& name, const std::string& vdom = "root") {
            return get(aggregate_interfaces, name, vdom);
        }

        static VirtualWANLink get_virtual_wan_link(const std::string& name = "virtual-wan-link", const std::string& vdom = "root") {
            return get(name, vdom);
        }

        static std::string get_wan_ip(unsigned int wan_port = 1, const std::string& vdom = "root") {
            return get_physical_interface(std::format("wan{}", wan_port), vdom).ipv4_addresses[0].ip;
        }
    }; // System::Interface

    class Admin {
        inline static std::string admin_endpoint = "/cmdb/system/admin";
        inline static std::string admin_profiles_endpoint = "cmdb/system/accprofile";

    public:

        class API {
            inline static std::string api_user_endpoint = "/cmdb/system/api-user";

            static std::string get_trusthost_endpoint(const std::string& admin) {
                return std::format("{}/{}/trusthost", api_user_endpoint, admin);
            }

        public:
            static std::vector<APIUser> get() {
                return FortiAPI::get<AllAPIUsersResponse>(api_user_endpoint).results;
            }

            static APIUser get(const std::string& api_admin_name) {
                auto endpoint = std::format("{}/{}", api_user_endpoint, api_admin_name);
                auto response = FortiAPI::get<AllAPIUsersResponse>(endpoint);
                if (response.status == "success") return response.results[0];
                else throw std::runtime_error("API Admin user " + api_admin_name + " not found...");
            }
        };
    };

}  // namespace System



#endif //FORTI_API_SYSTEM_H
