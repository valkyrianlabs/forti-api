// Every generated endpoint against the live device (read-only): each Table lists and each Singleton
// reads, and every object decodes into its generated type. Failures are collected per endpoint so
// one run reports them all.
#include <gtest/gtest.h>
#include "live.hpp"
#include <forti_api/gen/registry.hpp>

#include <map>

TEST(Coverage, EveryGeneratedEndpointDecodesTheDevice) {
    std::map<std::string, std::string> failures, unavailable;
    std::size_t tables = 0, singletons = 0, objects = 0;
    fortiapi::gen::for_each_endpoint([&]<typename E>() {
        std::string path(E::path);
        try {
            if constexpr (requires { E::list(); }) {
                objects += E::list().size();
                ++tables;
            } else {
                (void) E::get();
                ++objects;
                ++singletons;
            }
        } catch (const fortiapi::DecodeError& error) {
            failures[path] = error.what();
        } catch (const fortiapi::ApiError& error) {
            // Not available on this model, licence or access profile: reported, not a decode failure.
            unavailable[path] = "HTTP " + std::to_string(error.http_status());
        }
    });
    std::cout << "endpoints: " << tables << " tables, " << singletons << " singletons, " << objects
              << " objects decoded; " << unavailable.size() << " unavailable\n";
    for (const auto& [path, why]: unavailable) std::cout << "  unavailable " << path << ": " << why << "\n";
    for (const auto& [path, why]: failures) ADD_FAILURE() << why;
    EXPECT_EQ(tables + singletons + unavailable.size() + failures.size(), fortiapi::gen::endpoint_count);
}

// Every generated monitor endpoint (all read-only GETs the GUI recon policy allowed) decodes the device.
TEST(Coverage, EveryGeneratedMonitorEndpointDecodesTheDevice) {
    std::map<std::string, std::string> failures, unavailable;
    std::size_t ok = 0;
    fortiapi::gen::for_each_monitor([&]<typename E>() {
        std::string path = "monitor/" + std::string(E::path);
        try {
            (void) E::get();
            ++ok;
        } catch (const fortiapi::DecodeError& error) {
            failures[path] = error.what();
        } catch (const fortiapi::ApiError& error) {
            unavailable[path] = "HTTP " + std::to_string(error.http_status());
        }
    });
    std::cout << "monitor endpoints: " << ok << " decoded, " << unavailable.size() << " unavailable\n";
    for (const auto& [path, why]: unavailable) std::cout << "  unavailable " << path << ": " << why << "\n";
    for (const auto& [path, why]: failures) ADD_FAILURE() << why;
    EXPECT_EQ(ok + unavailable.size() + failures.size(), fortiapi::gen::monitor_count);
}
