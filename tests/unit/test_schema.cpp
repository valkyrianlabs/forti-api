// fortiapi::schema on its own: the tables' metadata and lookups, and the documented behavior of
// decode / create_body / update_body / diff / key_of / object_path / check_values on real endpoints.
// This TU includes no typed model (test_schema_typed.cpp compares the two, endpoint by endpoint).
#include <gtest/gtest.h>
#include <forti_api/schema.hpp>

#include <algorithm>
#include <set>

#ifdef FORTI_API_GEN_ALL_HPP
#error "forti_api/schema.hpp must not include the typed models"
#endif

using nlohmann::json;
namespace schema = fortiapi::schema;
using schema::Kind;
using Reason = schema::ValidationError::Reason;

namespace {

    const schema::Endpoint& endpoint(std::string_view path) {
        const auto* ep = schema::find(path);
        if (!ep) throw std::runtime_error("no endpoint " + std::string(path));
        return *ep;
    }

    const schema::Type& type(std::string_view path) { return *endpoint(path).type; }

    template<typename F>
    schema::ValidationError refused(F&& f) {
        try {
            f();
        } catch (const schema::ValidationError& error) {
            return error;
        }
        throw std::runtime_error("expected a ValidationError");
    }

}  // namespace

TEST(Schema, EndpointsAreSortedUniqueAndFound) {
    auto all = schema::endpoints();
    ASSERT_GT(all.size(), 500u);
    EXPECT_TRUE(std::ranges::is_sorted(all, {}, &schema::Endpoint::path));
    std::set<std::string_view> paths;
    for (const auto& ep: all) {
        EXPECT_TRUE(paths.insert(ep.path).second) << ep.path;
        EXPECT_EQ(schema::find(ep.path), &ep);
        EXPECT_TRUE(ep.path.starts_with("cmdb/") || ep.path.starts_with("monitor/")) << ep.path;
        ASSERT_NE(ep.value, nullptr) << ep.path;
    }
    EXPECT_EQ(schema::find("cmdb/firewall/nope"), nullptr);
    EXPECT_EQ(schema::find("firewall/address"), nullptr);   // the API path, with its prefix
    EXPECT_EQ(fortiapi::gen::fortios_version, "7.4.8");
}

TEST(Schema, TablesSingletonsAndMonitors) {
    const auto& address = endpoint("cmdb/firewall/address");
    EXPECT_EQ(address.kind, schema::EndpointKind::table);
    EXPECT_EQ(address.key, "name");
    EXPECT_EQ(address.key_kind, Kind::string);
    EXPECT_EQ(address.cpp_name, "fortiapi::firewall::Addresses");
    EXPECT_EQ(address.header, "forti_api/gen/firewall/address.hpp");
    EXPECT_EQ(address.type->name, "fortiapi::firewall::Address");
    EXPECT_EQ(address.type->key, "name");

    const auto& policy = endpoint("cmdb/firewall/policy");
    EXPECT_EQ(policy.key, "policyid");
    EXPECT_EQ(policy.key_kind, Kind::uint32);

    const auto& global = endpoint("cmdb/system/global");
    EXPECT_EQ(global.kind, schema::EndpointKind::singleton);
    EXPECT_TRUE(global.key.empty());

    const auto& interfaces = endpoint("monitor/system/available-interfaces");
    EXPECT_EQ(interfaces.kind, schema::EndpointKind::monitor);
    EXPECT_EQ(interfaces.value->kind, Kind::array);   // `results` is a list of entries
    ASSERT_NE(interfaces.type, nullptr);
    for (const auto& f: interfaces.type->fields) EXPECT_TRUE(f.read_only) << f.name;

    const auto& untyped = endpoint("monitor/firewall/policy");   // results kept as JSON
    EXPECT_EQ(untyped.type, nullptr);
}

TEST(Schema, AttributeMetadata) {
    const auto& address = type("cmdb/firewall/address");
    const auto* kind = address.field("type");
    ASSERT_NE(kind, nullptr);
    EXPECT_EQ(kind->kind, Kind::string);
    EXPECT_EQ(kind->fortios_type, "option");
    EXPECT_EQ(kind->reset, R"("ipmask")");
    EXPECT_NE(std::ranges::find(kind->options, "fqdn"), kind->options.end());
    EXPECT_FALSE(kind->help.empty());

    const auto* ttl = address.field("cache-ttl");
    ASSERT_NE(ttl, nullptr);
    EXPECT_EQ(ttl->kind, Kind::uint32);
    ASSERT_NE(ttl->range, nullptr);
    EXPECT_EQ(ttl->range->min, 0);
    EXPECT_EQ(ttl->range->max, 86400);

    const auto* interface = address.field("interface");
    ASSERT_NE(interface, nullptr);
    EXPECT_EQ(interface->size, 35u);
    EXPECT_TRUE(interface->required);
    ASSERT_EQ(interface->references.size(), 1u);
    EXPECT_EQ(interface->references[0], "system.interface.name");

    const auto* tagging = address.field("tagging");   // a table of entries
    ASSERT_NE(tagging, nullptr);
    EXPECT_TRUE(tagging->is_table());
    EXPECT_EQ(tagging->reset, "[]");
    EXPECT_EQ(tagging->item->type->name, "fortiapi::firewall::Address::TaggingEntry");

    const auto* srcaddr = type("cmdb/firewall/policy").field("srcaddr");   // a table of references
    ASSERT_NE(srcaddr, nullptr);
    EXPECT_TRUE(srcaddr->is_table());
    EXPECT_EQ(srcaddr->item->type->name, "fortiapi::Ref");
    EXPECT_NE(std::ranges::find(srcaddr->references, "firewall.address.name"), srcaddr->references.end());

    EXPECT_EQ(address.field("nope"), nullptr);
}

TEST(Schema, DecodeNormalizesLikeTheTypedModels) {
    const auto& address = endpoint("cmdb/firewall/address");
    json decoded = schema::decode(*address.value, json{{"name", "web"}, {"cache-ttl", "60"}, {"color", ""},
                                                       {"comment", 7}, {"forti-api-unknown", 1},
                                                       {"tagging", json::array({json{{"name", "t"}, {"tags", json::array({json{{"name", "a"}, {"x", 1}}})}}})}});
    EXPECT_EQ(decoded, (json{{"name", "web"}, {"cache-ttl", 60}, {"comment", "7"},
                             {"tagging", json::array({json{{"name", "t"}, {"tags", json::array({json{{"name", "a"}}})}}})}}));
    // Errors name the attribute path, as from_json<T> does.
    try {
        schema::decode(*address.value, json{{"tagging", json::array({json{{"name", "t"}, {"tags", "x"}}})}});
        FAIL();
    } catch (const fortiapi::detail::DecodeFailure& failure) {
        EXPECT_EQ(failure.where, "tagging[0].tags");
    }
    EXPECT_THROW(schema::decode(*address.value, json::array()), nlohmann::json::type_error);
}

TEST(Schema, CreateBody) {
    const auto& address = type("cmdb/firewall/address");
    EXPECT_EQ(schema::create_body(address, json{{"name", "web"}, {"subnet", "192.0.2.10 255.255.255.255"}, {"cache-ttl", "5"}}),
              (json{{"name", "web"}, {"subnet", "192.0.2.10 255.255.255.255"}, {"cache-ttl", 5}}));

    auto invalid = refused([&] { schema::create_body(address, json{{"name", "web"}, {"cache-ttl", "soon"}}); });
    EXPECT_EQ(invalid.reason(), Reason::invalid_value);
    EXPECT_EQ(invalid.attribute(), "cache-ttl");
    EXPECT_NE(invalid.detail().find("expected a number"), std::string::npos);
    EXPECT_EQ(std::string(invalid.what()).rfind("attribute cache-ttl: ", 0), 0u);

    auto unknown = refused([&] { schema::create_body(address, json{{"name", "web"}, {"colour", 3}, {"zz", 1}}); });
    EXPECT_EQ(unknown.reason(), Reason::unknown);
    EXPECT_EQ(unknown.attributes(), (std::vector<std::string>{"colour", "zz"}));

    EXPECT_EQ(refused([&] { schema::create_body(address, json::array()); }).reason(), Reason::not_object);

    const auto& interfaces = type("monitor/system/available-interfaces");   // every attribute is read-only
    auto read_only = refused([&] { schema::create_body(interfaces, json{{interfaces.fields[0].name, 1}}); });
    EXPECT_EQ(read_only.reason(), Reason::read_only);
}

TEST(Schema, UpdateBody) {
    const auto& address = type("cmdb/firewall/address");
    std::vector<std::string> clear{"comment", "tagging"};
    EXPECT_EQ(schema::update_body(address, json{{"color", "3"}}, clear),
              (json{{"color", 3}, {"comment", ""}, {"tagging", json::array()}}));
    EXPECT_EQ(schema::update_body(address, json::object()), json::object());   // nothing to send

    std::vector<std::string> both{"color"};
    auto conflict = refused([&] { schema::update_body(address, json{{"color", 3}}, both); });
    EXPECT_EQ(conflict.reason(), Reason::set_and_cleared);
    EXPECT_EQ(conflict.attribute(), "color");

    std::vector<std::string> nope{"nope"};
    EXPECT_EQ(refused([&] { schema::update_body(address, json::object(), nope); }).attributes(), nope);
    EXPECT_EQ(refused([&] { schema::update_body(address, "x"); }).reason(), Reason::not_object);
}

TEST(Schema, Diff) {
    const auto& address = type("cmdb/firewall/address");
    json current{{"name", "web"}, {"subnet", "192.0.2.10 255.255.255.255"}, {"color", 0}, {"uuid", "u"}};
    EXPECT_EQ(schema::diff(address, current, json{{"name", "web"}, {"color", "3"}, {"comment", "c"}}),
              (json{{"color", 3}, {"comment", "c"}}));
    EXPECT_EQ(schema::diff(address, current, json{{"subnet", "192.0.2.10 255.255.255.255"}}), json::object());
}

TEST(Schema, KeysAndPaths) {
    const auto& address = endpoint("cmdb/firewall/address");
    EXPECT_EQ(schema::key_of(address, json{{"name", "10.0.0.0/24"}, {"color", "bad"}}), json("10.0.0.0/24"));
    EXPECT_EQ(schema::key_of(address, json{{"color", 1}}), std::nullopt);
    EXPECT_EQ(schema::object_path(address, "10.0.0.0/24"), "cmdb/firewall/address/10.0.0.0%2F24");
    EXPECT_EQ(schema::object_path(address, ".."), "cmdb/firewall/address/%2E%2E");

    const auto& policy = endpoint("cmdb/firewall/policy");
    EXPECT_EQ(schema::key_of(policy, json{{"policyid", "12"}}), json(12));
    EXPECT_EQ(schema::object_path(policy, 12), "cmdb/firewall/policy/12");
    EXPECT_EQ(schema::object_path(policy, "12"), "cmdb/firewall/policy/12");
    EXPECT_EQ(schema::key_of(endpoint("cmdb/system/global"), json{{"hostname", "fw"}}), std::nullopt);
}

TEST(Schema, CheckValuesIsAdvisory) {
    const auto& address = type("cmdb/firewall/address");
    auto findings = schema::check_values(address, json{{"type", "ipmasq"}, {"cache-ttl", 999999}, {"interface", std::string(40, 'i')},
                                                       {"tagging", json::array({json{{"name", "t"}}})}});
    ASSERT_EQ(findings.size(), 3u);
    EXPECT_EQ(findings[0].attribute, "type");
    EXPECT_NE(findings[0].message.find("\"ipmasq\" is not one of"), std::string::npos);
    EXPECT_EQ(findings[1].attribute, "cache-ttl");
    EXPECT_EQ(findings[1].message, "999999 is outside 0..86400");
    EXPECT_EQ(findings[2].attribute, "interface");
    EXPECT_TRUE(schema::check_values(address, json{{"type", "fqdn"}, {"cache-ttl", "60"}}).empty());
}
