//
// Created by Cooper Larson on 8/28/24.
//

#include <gtest/gtest.h>
#include <forti_api/system.hpp>
#include <regex>

bool validate_ip_addr(const std::string& ip) {
    std::regex ipv4_regex(R"(^(\d{1,3}\.){3}\d{1,3}$)");
    return std::regex_match(ip, ipv4_regex);
}

TEST(TestSystem, TestGetWan1IP) {
    auto ip = System::Interface::get_wan_ip();
    ASSERT_TRUE(validate_ip_addr(ip)) << "Invalid IP: " << ip;
}

TEST(TestSystem, TestGetPhysicalInterface) {
    auto interface = System::Interface::get_physical_interface("wan1");
    ASSERT_TRUE(interface.name == "wan1") << "Unexpected interface name: " << interface.name;
    ASSERT_TRUE(interface.vdom == "root") << "Default interface vdom !== root";
    ASSERT_TRUE(!interface.ipv4_addresses.empty());
    ASSERT_TRUE(interface.type == "physical");
}
