// Every generated endpoint against the live device (read-only): each Table lists and each Singleton
// reads, and every object decodes into its generated type. Failures are collected per endpoint so
// one run reports them all.
//
// Compiled COVERAGE_SHARDS times with -DCOVERAGE_SHARD=k: each translation unit instantiates the
// endpoints whose path hashes to shard k (one TU over the whole registry needs ~6 GB with GCC).
#include <gtest/gtest.h>
#include "live.hpp"
#include <forti_api/gen/registry.hpp>

#include <map>

#ifndef COVERAGE_SHARD
#error "COVERAGE_SHARD and COVERAGE_SHARDS must be defined"
#endif

namespace {

    constexpr bool in_shard(std::string_view path) {
        unsigned hash = 2166136261u;   // FNV-1a
        for (char c: path) {
            hash ^= static_cast<unsigned char>(c);
            hash *= 16777619u;
        }
        return hash % COVERAGE_SHARDS == COVERAGE_SHARD;
    }

    template<typename ForEach>
    std::size_t count_in_shard(ForEach&& for_each) {
        std::size_t n = 0;
        for_each([&]<typename E>() { n += in_shard(E::path); });
        return n;
    }

}  // namespace

#define COVERAGE_CONCAT2(a, b) a##b
#define COVERAGE_CONCAT(a, b) COVERAGE_CONCAT2(a, b)

TEST(Coverage, COVERAGE_CONCAT(EveryGeneratedEndpointDecodesTheDevice, COVERAGE_SHARD)) {
    std::map<std::string, std::string> failures, unavailable;
    std::size_t tables = 0, singletons = 0, objects = 0;
    fortiapi::gen::for_each_endpoint([&]<typename E>() {
        if constexpr (in_shard(E::path)) {
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
        }
    });
    std::cout << "endpoints: " << tables << " tables, " << singletons << " singletons, " << objects
              << " objects decoded; " << unavailable.size() << " unavailable\n";
    for (const auto& [path, why]: unavailable) std::cout << "  unavailable " << path << ": " << why << "\n";
    for (const auto& [path, why]: failures) ADD_FAILURE() << why;
    EXPECT_EQ(tables + singletons + unavailable.size() + failures.size(),
              count_in_shard([](auto&& f) { fortiapi::gen::for_each_endpoint(f); }));
}

// Every generated monitor endpoint (all read-only GETs the GUI recon policy allowed) decodes the device.
TEST(Coverage, COVERAGE_CONCAT(EveryGeneratedMonitorEndpointDecodesTheDevice, COVERAGE_SHARD)) {
    std::map<std::string, std::string> failures, unavailable;
    std::size_t ok = 0;
    fortiapi::gen::for_each_monitor([&]<typename E>() {
        if constexpr (in_shard(E::path)) {
            std::string path = "monitor/" + std::string(E::path);
            try {
                (void) E::get();
                ++ok;
            } catch (const fortiapi::DecodeError& error) {
                failures[path] = error.what();
            } catch (const fortiapi::ApiError& error) {
                unavailable[path] = "HTTP " + std::to_string(error.http_status());
            }
        }
    });
    std::cout << "monitor endpoints: " << ok << " decoded, " << unavailable.size() << " unavailable\n";
    for (const auto& [path, why]: unavailable) std::cout << "  unavailable " << path << ": " << why << "\n";
    for (const auto& [path, why]: failures) ADD_FAILURE() << why;
    EXPECT_EQ(ok + unavailable.size() + failures.size(), count_in_shard([](auto&& f) { fortiapi::gen::for_each_monitor(f); }));
}
