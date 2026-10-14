//
// Created by Cooper Larson on 9/4/24.
//

#include <gtest/gtest.h>
#include <forti_api/api.hpp>


class GlobalEnv : public ::testing::Environment {
public:
    void SetUp() override {
        std::cout << "[INFO] Setting up environment variables for FortiAuth...\n";
        FortiAuth::set_vars_from_env();
    }

    void TearDown() override {
        std::cout << "[INFO] Tearing down environment after all tests.\n";
    }
};

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new GlobalEnv());

    return RUN_ALL_TESTS();
}

