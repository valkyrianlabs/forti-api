// Read-only tour of a FortiGate: firmware, interfaces, policies and addresses.
//
//   set -a; . ./.env; set +a; ./build/inventory
//
// Configuration comes from the environment (fortiapi::Config::from_env(), see .env.example).

#include <forti_api.hpp>
#include <iostream>

using namespace fortiapi;

int main() try {
    auto status = Monitor::get("system/status");
    std::cout << status.value("model_name", "FortiGate") << " " << status.value("hostname", "?") << "\n";

    for (const auto& address: system::interface_addresses("wan1"))
        std::cout << "wan1: " << address.ip << "/" << address.prefix_length << "\n";

    for (const auto& policy: firewall::Policies::list(Query().format({"policyid", "name", "action", "status"})))
        std::cout << "policy " << policy.policyid.value_or(0u) << " " << policy.name.value_or("") << ": "
                  << policy.action.value_or("?") << (policy.status == std::string("disable") ? " (disabled)" : "") << "\n";

    std::cout << firewall::Addresses::list(Query().format({"name"})).size() << " addresses\n";
    return 0;
} catch (const fortiapi::Error& error) {
    std::cerr << "error: " << error.what() << "\n";
    return 1;
}
