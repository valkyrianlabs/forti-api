//
// Live suite entry point: guarded client, leftover purge, and an independent audit of the device's
// config-change log after the run (AGENTS.md).
//

#include <gtest/gtest.h>
#include "live.hpp"

namespace {

    class LiveEnvironment : public ::testing::Environment {
        std::shared_ptr<fortiapi::Client> client_;
        live::ConfigAudit audit_;

    public:
        void SetUp() override {
            client_ = live::guarded_client();
            fortiapi::set_default_client(client_);
            audit_.begin(*client_);
            if (!live::read_only_requested() && !live::purge_skip_requested()) live::purge_leftovers();
        }

        void TearDown() override {
            if (!live::read_only_requested() && !live::purge_skip_requested()) live::purge_leftovers();
            for (const auto& change: audit_.violations(*client_))
                ADD_FAILURE() << "config audit: the run changed a non-test object: " << change;
        }
    };

}  // namespace

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new LiveEnvironment());
    return RUN_ALL_TESTS();
}
