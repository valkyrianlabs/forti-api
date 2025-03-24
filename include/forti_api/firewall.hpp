//
// Created by Cooper Larson on 8/31/24.
//

#ifndef FORTI_API_FIREWALL_HPP
#define FORTI_API_FIREWALL_HPP

#include <utility>

#include "api.hpp"
#include "types/firewall/policies.h"
#include "types/firewall/services.h"
#include "types/firewall/schedules.h"


namespace FortiGate {

    class Policies {
        inline static std::string endpoint = "/cmdb/firewall/policy";

    public:
        static std::vector<FirewallPolicy> get() { return FortiAPI::get<FirewallPoliciesResponse>(endpoint).results; }

        static FirewallPolicy get(const std::string& name) {
            auto policies = get();
            for (const auto& policy : policies) if (policy.name == name) return policy;
            throw std::runtime_error("Unable to locate firewall policy: " + name);
        }

        static void update(const FirewallPolicy& policy) {
            FortiAPI::put(std::format("{}/{}", endpoint, policy.policyid), policy);
        }
    };


    class Services {
    public:
        static std::vector<FirewallService> get() {
            return FortiAPI::get<FirewallServicesResponse>(FirewallService::endpoint).results;
        }

        static FirewallService get(const std::string& name, const std::string& vdom="root") {
            auto results = FortiAPI::get<FirewallServicesResponse>(std::format("{}/{}?vdom={}", FirewallService::endpoint, name, vdom)).results;
            if (results.empty()) throw std::runtime_error("Unable to locate firewall service: " + name);
            else if (results.size() > 1) throw std::runtime_error("Get of firewall service " + name + " returned multiple results");
            return results[0];
        }

        static void update(const FirewallService& service, const std::string& vdom="root") {
            FortiAPI::put(std::format("{}/{}?vdom={}", FirewallService::endpoint, service.name, vdom), service);
        }

        static void add(const FirewallService& service, const std::string& vdom="root") {
            FortiAPI::post(std::format("{}?vdom={}", FirewallService::endpoint, vdom), service);
        }

        static std::vector<ServiceCategory> get_categories() {
            return FortiAPI::get<ServiceCategoriesResponse>(ServiceCategory::endpoint).results;
        }

        static void add_category(ServiceCategory category) { category.add(); }

        static void add_category(const std::string& name, const std::string& comment="") {
            ServiceCategory{name, comment}.add();
        }

        static void delete_category(ServiceCategory category) { category.del(); }

        static void delete_category(const std::string& name) {
            for (auto category : get_categories()) {
                if (category.name == name) category.del();
                return;
            }
            throw std::runtime_error("Unable to locate category for deletion: " + name);
        }
    };

    class Schedules {
    public:
        static std::vector<FirewallSchedule> get(const std::string& vdom="root") {
            return FortiAPI::get<FirewallSchedulesResponse>(std::format("{}?vdom={}", FirewallSchedule::endpoint, vdom)).results;
        }

        static FirewallSchedule get(const std::string& name, const std::string& vdom="root") {
            auto endpoint = std::format("{}/{}?vdom={}", FirewallSchedule::endpoint, name, vdom);
            auto results = FortiAPI::get<FirewallSchedulesResponse>(endpoint).results;
            if (results.empty()) throw std::runtime_error("Unable to locate firewall schedule: " + name);
            else if (results.size() > 1) throw std::runtime_error("Get of firewall schedule " + name + " returned multiple results");
            return results[0];
        }
    };

}


#endif //FORTI_API_FIREWALL_HPP
