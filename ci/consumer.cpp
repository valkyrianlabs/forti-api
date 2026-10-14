// Built by CI against the *installed* forti-api (pkg-config --cflags --libs forti-api) to prove
// the packaged headers, the vendored nlohmann/json and forti-api.pc work outside the source tree.
#include <forti_api.hpp>
#include <iostream>

int main() {
    FirewallPolicy policy{};
    std::cout << "forti-api consumer: nlohmann " << NLOHMANN_JSON_VERSION_MAJOR << '.'
              << NLOHMANN_JSON_VERSION_MINOR << ", FirewallPolicy keys: " << nlohmann::json(policy).size() << '\n';
}
