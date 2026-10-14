// Built by CI against the *installed* forti-api (pkg-config --cflags --libs forti-api) to prove
// the packaged headers, the vendored nlohmann/json and forti-api.pc work outside the source tree.
// Network-free: it only builds and serializes an object.
#include <forti_api.hpp>
#include <iostream>

int main() {
    fortiapi::firewall::Policy policy;
    policy.name = "example";
    policy.action = std::string(fortiapi::firewall::Policy::Action::deny);
    std::cout << "forti-api consumer: nlohmann " << NLOHMANN_JSON_VERSION_MAJOR << '.' << NLOHMANN_JSON_VERSION_MINOR
              << ", policy create body " << fortiapi::to_json(policy, fortiapi::Write::create).dump() << '\n';
}
