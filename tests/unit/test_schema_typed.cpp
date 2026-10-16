// fortiapi::schema against the typed models it describes, endpoint by endpoint. Instantiating a typed
// model is what the runtime schema exists to avoid, so this TU is built in one of two ways:
//   -DSCHEMA_SAMPLE                            the unit suite: a fixed sample of endpoints that covers
//                                              every attribute kind, key type and result shape
//   -DSCHEMA_SHARD=k -DSCHEMA_SHARDS=n         -Dexhaustive_tests=true: every endpoint, the ones whose
//                                              path hashes to shard k (all of them in one TU would
//                                              need ~6 GB of compiler memory)
// For every endpoint selected:
//   - the tables describe the generated struct exactly: keys in visit() order, C++ types, reset values,
//     read-only flags, nested types, the endpoint kind, the table key and its type;
//   - on generated inputs (valid values, numbers as text, empty strings, wrong types, invalid nested
//     values, unknown and read-only attributes), decode / writable / create_body / update_body /
//     key_of / object_path agree with from_json / to_json / Table's key and path: same results, and
//     the same errors with the same messages.
// The typed side of create_body / update_body is what a program writes with the typed API: decode
// each attribute with from_json<V>, assign it, clear the cleared ones, and to_json the object.
#include <gtest/gtest.h>
#include <forti_api/schema.hpp>

#ifdef SCHEMA_SAMPLE
#include <forti_api/gen/emailfilter/options.hpp>
#include <forti_api/gen/extension-controller/fortigate_profile.hpp>
#include <forti_api/gen/firewall/address.hpp>
#include <forti_api/gen/firewall/vendor_mac.hpp>
#include <forti_api/gen/ips/decoder.hpp>
#include <forti_api/gen/ips/rule_settings.hpp>
#include <forti_api/gen/monitor/endpoint_control/ems/status_summary.hpp>
#include <forti_api/gen/monitor/firewall/address6_dynamic.hpp>
#include <forti_api/gen/monitor/firewall/address_dynamic.hpp>
#include <forti_api/gen/monitor/firewall/local_in.hpp>
#include <forti_api/gen/monitor/system/available_certificates.hpp>
#include <forti_api/gen/monitor/system/available_interfaces/meta.hpp>
#include <forti_api/gen/monitor/system/csf.hpp>
#include <forti_api/gen/monitor/system/wan_lan_ip_conflict.hpp>
#include <forti_api/gen/monitor/utm/application_categories.hpp>
#include <forti_api/gen/monitor/web_ui/extend_session.hpp>
#include <forti_api/gen/monitor/web_ui/navbar_dependencies.hpp>
#include <forti_api/gen/monitor/web_ui/object_urls.hpp>
#else
#include <forti_api/gen/registry.hpp>
#endif

#include <algorithm>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <type_traits>
#include <vector>

#if !defined(SCHEMA_SAMPLE) && !defined(SCHEMA_SHARD)
#error "define SCHEMA_SAMPLE, or SCHEMA_SHARD and SCHEMA_SHARDS"
#endif

using nlohmann::json;
namespace schema = fortiapi::schema;
using fortiapi::detail::Visitable;

namespace {

#ifdef SCHEMA_SAMPLE
    // The smallest endpoints that together cover every kind the tables describe (string and numeric
    // table keys, a singleton, nested objects, tables of entries and of references, read-only attributes
    // and tables, booleans, int64, lists of strings and of JSON, JSON values, maps of strings and of
    // objects, monitor results that are objects, lists and JSON), plus firewall/address as a typical
    // object. Only their headers are included, so this TU stays cheap.
    template<typename F>
    void for_each_endpoint(F&& f) {
        f.template operator()<fortiapi::firewall::Addresses>();
        f.template operator()<fortiapi::ips::RuleSettingses>();
        f.template operator()<fortiapi::emailfilter::OptionsSettings>();
        f.template operator()<fortiapi::extension_controller::FortigateProfiles>();
        f.template operator()<fortiapi::ips::Decoders>();
        f.template operator()<fortiapi::firewall::VendorMacs>();
    }

    template<typename F>
    void for_each_monitor(F&& f) {
        f.template operator()<fortiapi::monitor::system::WanLanIpConflict>();
        f.template operator()<fortiapi::monitor::web_ui::ExtendSession>();
        f.template operator()<fortiapi::monitor::system::AvailableInterfacesMeta>();
        f.template operator()<fortiapi::monitor::web_ui::ObjectUrls>();
        f.template operator()<fortiapi::monitor::system::AvailableCertificates>();
        f.template operator()<fortiapi::monitor::web_ui::NavbarDependencies>();
        f.template operator()<fortiapi::monitor::firewall::LocalIn>();
        f.template operator()<fortiapi::monitor::utm::ApplicationCategories>();
        f.template operator()<fortiapi::monitor::firewall::AddressDynamic>();
        f.template operator()<fortiapi::monitor::endpoint_control::EmsStatusSummary>();
        f.template operator()<fortiapi::monitor::firewall::Address6Dynamic>();
        f.template operator()<fortiapi::monitor::system::Csf>();
    }

    constexpr std::size_t sample_size = 18;
    constexpr bool selected(std::string_view) { return true; }
#define SCHEMA_TEST Sample
#else
    constexpr unsigned fnv1a(std::string_view text) {
        unsigned hash = 2166136261u;
        for (char c: text) {
            hash ^= static_cast<unsigned char>(c);
            hash *= 16777619u;
        }
        return hash;
    }

    constexpr bool selected(std::string_view path) { return fnv1a(path) % SCHEMA_SHARDS == SCHEMA_SHARD; }
#define SCHEMA_CONCAT2(a, b) a##b
#define SCHEMA_CONCAT(a, b) SCHEMA_CONCAT2(a, b)
#define SCHEMA_TEST SCHEMA_CONCAT(Shard, SCHEMA_SHARD)
    using fortiapi::gen::for_each_endpoint;
    using fortiapi::gen::for_each_monitor;
#endif

    template<typename T> struct is_vector : std::false_type {};
    template<typename T> struct is_vector<std::vector<T>> : std::true_type {};
    template<typename T> struct is_map : std::false_type {};
    template<typename T> struct is_map<std::map<std::string, T>> : std::true_type {};
    template<typename> inline constexpr bool always_false = false;

    // ---- structure ----

    template<typename V>
    void check_kind(const schema::Field& d, const std::string& at);

    template<typename T>
    void check_type(const schema::Type& type, const std::string& at) {
        std::size_t i = 0;
        T object;
        T::visit(object, [&](std::string_view key, auto& field, std::string_view reset, unsigned flags) {
            using V = typename std::decay_t<decltype(field)>::value_type;
            std::string where = at + "." + std::string(key);
            ASSERT_LT(i, type.fields.size()) << where;
            const schema::Field& d = type.fields[i++];
            EXPECT_EQ(d.name, key) << where;
            EXPECT_EQ(d.reset, reset) << where;
            EXPECT_EQ(d.read_only, (flags & fortiapi::read_only) != 0) << where;
            check_kind<V>(d, where);
        });
        EXPECT_EQ(i, type.fields.size()) << at << ": the tables have more attributes than " << type.name;
    }

    template<typename V>
    void check_kind(const schema::Field& d, const std::string& at) {
        using schema::Kind;
        if constexpr (std::is_same_v<V, std::string>) EXPECT_EQ(d.kind, Kind::string) << at;
        else if constexpr (std::is_same_v<V, std::uint32_t>) EXPECT_EQ(d.kind, Kind::uint32) << at;
        else if constexpr (std::is_same_v<V, std::int64_t>) EXPECT_EQ(d.kind, Kind::int64) << at;
        else if constexpr (std::is_same_v<V, double>) EXPECT_EQ(d.kind, Kind::number) << at;
        else if constexpr (std::is_same_v<V, bool>) EXPECT_EQ(d.kind, Kind::boolean) << at;
        else if constexpr (std::is_same_v<V, json>) EXPECT_EQ(d.kind, Kind::json) << at;
        else if constexpr (Visitable<V>) {
            ASSERT_EQ(d.kind, Kind::object) << at;
            ASSERT_NE(d.type, nullptr) << at;
            check_type<V>(*d.type, at);
        } else if constexpr (is_vector<V>::value) {
            ASSERT_EQ(d.kind, Kind::array) << at;
            ASSERT_NE(d.item, nullptr) << at;
            check_kind<typename V::value_type>(*d.item, at + "[]");
        } else if constexpr (is_map<V>::value) {
            ASSERT_EQ(d.kind, Kind::map) << at;
            ASSERT_NE(d.item, nullptr) << at;
            check_kind<typename V::mapped_type>(*d.item, at + "{}");
        } else static_assert(always_false<V>, "an attribute type the schema tables cannot describe");
    }

    // ---- generated inputs ----

    json valid(const schema::Field& f, int depth);

    json valid_object(const schema::Type& type, int depth) {
        json out = json::object();
        for (const auto& f: type.fields) {
            bool nested = f.kind == schema::Kind::object || f.kind == schema::Kind::array || f.kind == schema::Kind::map;
            if (nested && depth >= 3) continue;
            out[std::string(f.name)] = valid(f, depth);
        }
        return out;
    }

    json valid(const schema::Field& f, int depth) {
        using schema::Kind;
        switch (f.kind) {
            case Kind::string: return "x";
            case Kind::uint32: return 7;
            case Kind::int64: return -3;
            case Kind::number: return 1.5;
            case Kind::boolean: return true;
            case Kind::json: return json{{"a", json::array({1})}};
            case Kind::object: return valid_object(*f.type, depth + 1);
            case Kind::array: return json::array({valid(*f.item, depth + 1), valid(*f.item, depth + 1)});
            case Kind::map: return json{{"k", valid(*f.item, depth + 1)}};
        }
        return nullptr;
    }

    // An object of `type` with one attribute that does not decode, if the type has such an attribute.
    std::optional<json> invalid_object(const schema::Type& type) {
        for (const auto& f: type.fields)
            if (f.kind != schema::Kind::string && f.kind != schema::Kind::json) return json{{std::string(f.name), "x"}};
        return std::nullopt;
    }

    // Values for an attribute: a valid one first, then what the device or a caller may send instead.
    std::vector<json> values(const schema::Field& f, int depth) {
        using schema::Kind;
        std::vector<json> out{valid(f, depth)};
        switch (f.kind) {
            case Kind::string:
                out.insert(out.end(), {"", 5, -1.5, true, nullptr, json{{"a", 1}}, json::array({1, "b"})});
                break;
            case Kind::uint32:
                out.insert(out.end(), {"42", "", "4x", -1, 3.7, true, nullptr, " 1", 4294967295u, "4294967296", "-1",
                                       json::object()});
                break;
            case Kind::int64:
                out.insert(out.end(), {"-7", "", "x", 1.5, false, nullptr, "9223372036854775807", json::array()});
                break;
            case Kind::number:
                out.insert(out.end(), {"2.5", "", "x", true, nullptr, 3});
                break;
            case Kind::boolean:
                out.insert(out.end(), {false, "", 1, "true", nullptr});
                break;
            case Kind::json:
                out.insert(out.end(), {nullptr, 1, "s"});
                break;
            case Kind::object: {
                out.insert(out.end(), {"x", json::array(), json::object(), json{{"forti-api-unknown", 1}}});
                if (auto bad = invalid_object(*f.type)) out.push_back(*bad);
                break;
            }
            case Kind::array: {
                out.insert(out.end(), {json::array(), "x", json::object()});
                for (const auto& item: values(*f.item, depth + 1)) {
                    out.push_back(json::array({item}));
                    if (out.size() > 24) break;
                }
                out.push_back(json::array({valid(*f.item, depth + 1), "x"}));
                break;
            }
            case Kind::map:
                out.insert(out.end(), {json::object(), json::array(), json{{"k", "x"}}});
                break;
        }
        return out;
    }

    // ---- outcomes ----

    struct Outcome {
        bool ok = false;
        std::string text;            // the result's JSON, or the error
        bool decode_failure = false; // a fortiapi::detail::DecodeFailure (else a nlohmann exception)

        bool operator==(const Outcome&) const = default;
    };

    std::ostream& operator<<(std::ostream& out, const Outcome& o) {
        return out << (o.ok ? "ok " : o.decode_failure ? "DecodeFailure " : "error ") << o.text;
    }

    template<typename F>
    Outcome capture(F&& f) {
        try {
            return {true, f().dump(), false};
        } catch (const fortiapi::detail::DecodeFailure& failure) {
            return {false, failure.what(), true};
        } catch (const schema::ValidationError& error) {
            json why{{"reason", static_cast<int>(error.reason())}, {"attributes", error.attributes()}, {"detail", error.detail()}};
            return {false, why.dump(), false};
        } catch (const std::exception& error) {
            return {false, error.what(), false};
        }
    }

    // The typed API's way of building a body (ValidationError mirrors the checks schema adds).
    using Reason = schema::ValidationError::Reason;

    [[noreturn]] void refuse(Reason reason, std::vector<std::string> attributes, std::string detail = {}) {
        throw schema::ValidationError(reason, std::move(attributes), std::move(detail));
    }

    // Nested objects assigned whole are written whole by an update.
    template<typename T>
    void touch(T& object) {
        T::visit(object, [](std::string_view, auto& field, std::string_view, unsigned) {
            using V = typename std::decay_t<decltype(field)>::value_type;
            if (V* value = field.storage()) {
                if constexpr (Visitable<V>) touch(*value);
                V copy = *value;
                field = std::move(copy);
            }
        });
    }

    template<typename V>
    V typed_value(const json& value, std::string_view key) {
        try {
            return fortiapi::from_json<V>(value);
        } catch (const std::exception& error) {
            refuse(Reason::invalid_value, {std::string(key)}, error.what());
        }
    }

    template<typename T>
    json typed_create(const json& object) {
        if (!object.is_object()) refuse(Reason::not_object, {});
        T built;
        std::set<std::string, std::less<>> known;
        std::vector<std::string> read_only, unknown;
        T::visit(built, [&](std::string_view key, auto& field, std::string_view, unsigned flags) {
            using V = typename std::decay_t<decltype(field)>::value_type;
            known.emplace(key);
            auto it = object.find(key);
            if (it == object.end()) return;
            if (flags & fortiapi::read_only) {
                read_only.emplace_back(key);
                return;
            }
            field = typed_value<V>(*it, key);
        });
        for (auto it = object.begin(); it != object.end(); ++it)
            if (!known.contains(it.key())) unknown.push_back(it.key());
        if (!unknown.empty()) refuse(Reason::unknown, unknown);
        if (!read_only.empty()) refuse(Reason::read_only, read_only);
        return fortiapi::to_json(built, fortiapi::Write::create);
    }

    template<typename T>
    json typed_update(const json& set, const std::vector<std::string>& clear) {
        if (!set.is_object()) refuse(Reason::not_object, {});
        T object;
        std::set<std::string, std::less<>> seen;
        std::vector<std::string> read_only, unknown;
        T::visit(object, [&](std::string_view key, auto& field, std::string_view, unsigned flags) {
            using V = typename std::decay_t<decltype(field)>::value_type;
            auto it = set.find(key);
            bool cleared = std::ranges::find(clear, key) != clear.end();
            if (it == set.end() && !cleared) return;
            seen.emplace(key);
            if (flags & fortiapi::read_only) {
                read_only.emplace_back(key);
                return;
            }
            if (it != set.end() && cleared) refuse(Reason::set_and_cleared, {std::string(key)});
            if (cleared) field.clear();
            else {
                field = typed_value<V>(*it, key);
                if constexpr (Visitable<V>) touch(*field.storage());
            }
        });
        for (auto it = set.begin(); it != set.end(); ++it)
            if (!seen.contains(it.key())) unknown.push_back(it.key());
        for (const auto& name: clear)
            if (!seen.contains(name)) unknown.push_back(name);
        if (!unknown.empty()) refuse(Reason::unknown, unknown);
        if (!read_only.empty()) refuse(Reason::read_only, read_only);
        return fortiapi::to_json(object, fortiapi::Write::update);
    }

    // Every attribute with a value, read-only ones included: the JSON form of a decoded object.
    template<typename V>
    json snapshot(const V& value) {
        if constexpr (Visitable<V>) {
            json out = json::object();
            V::visit(value, [&](std::string_view key, const auto& field, std::string_view, unsigned) {
                if (field.has_value()) out[std::string(key)] = snapshot(field.value());
            });
            return out;
        } else if constexpr (is_vector<V>::value) {
            json out = json::array();
            for (const auto& item: value) out.push_back(snapshot(item));
            return out;
        } else if constexpr (is_map<V>::value) {
            json out = json::object();
            for (const auto& [key, item]: value) out[key] = snapshot(item);
            return out;
        } else return json(value);
    }

    // ---- per endpoint ----

    // Inputs for an endpoint value: the valid object, each attribute alone with each of its values,
    // the valid object with an unknown attribute, and inputs that are not objects.
    std::vector<json> inputs(const schema::Field& value) {
        if (value.kind != schema::Kind::object) return values(value, 0);
        std::vector<json> out{valid(value, 0)};
        for (const auto& f: value.type->fields)
            for (const auto& v: values(f, 1)) out.push_back(json{{std::string(f.name), v}});
        json extra = valid(value, 0);
        extra["forti-api-unknown"] = 1;
        out.insert(out.end(), {extra, "x", json::array(), nullptr});
        return out;
    }

    // `value` describes T (an object type).
    template<typename T>
    void check_decoding(const schema::Field& value, const json& input) {
        SCOPED_TRACE(input.dump());
        Outcome typed = capture([&] { return snapshot(fortiapi::from_json<T>(input)); });
        Outcome tables = capture([&] { return schema::decode(value, input); });
        ASSERT_EQ(tables, typed);
        if (!typed.ok) return;
        EXPECT_EQ(schema::writable(value, schema::decode(value, input)).dump(),
                  fortiapi::to_json(fortiapi::from_json<T>(input), fortiapi::Write::create).dump());
    }

    template<typename E>
    std::string key_name() {
        typename E::type object;
        const void* key = &(object.*E::key);
        std::string name;
        E::type::visit(object, [&](std::string_view field_key, auto& field, std::string_view, unsigned) {
            if (static_cast<const void*>(&field) == key) name = field_key;
        });
        return name;
    }

    template<typename E>
    void check_cmdb(const schema::Endpoint& ep, std::size_t& inputs_checked) {
        using T = typename E::type;
        constexpr bool table = requires { E::key; };
        EXPECT_EQ(ep.kind, table ? schema::EndpointKind::table : schema::EndpointKind::singleton);
        ASSERT_NE(ep.type, nullptr);
        ASSERT_NE(ep.value, nullptr);
        ASSERT_EQ(ep.value->kind, schema::Kind::object);
        ASSERT_EQ(ep.value->type, ep.type);
        check_type<T>(*ep.type, std::string(ep.path));
        if constexpr (table) {
            using K = typename E::key_type;
            EXPECT_EQ(ep.key, key_name<E>());
            EXPECT_EQ(ep.type->key, ep.key);
            constexpr schema::Kind key_kind = std::is_same_v<K, std::uint32_t> ? schema::Kind::uint32
                                              : std::is_same_v<K, std::int64_t> ? schema::Kind::int64 : schema::Kind::string;
            EXPECT_EQ(ep.key_kind, key_kind);
        }

        for (const json& input: inputs(*ep.value)) {
            ++inputs_checked;
            check_decoding<T>(*ep.value, input);
            SCOPED_TRACE(input.dump());
            EXPECT_EQ(capture([&] { return schema::create_body(*ep.type, input); }),
                      capture([&] { return typed_create<T>(input); }));
            EXPECT_EQ(capture([&] { return schema::update_body(*ep.type, input); }),
                      capture([&] { return typed_update<T>(input, {}); }));
            if constexpr (table) {
                std::optional<T> object;
                try {
                    object = fortiapi::from_json<T>(input);
                } catch (const std::exception&) {
                }
                if (object) {
                    const auto& key = (*object).*E::key;
                    auto from_tables = schema::key_of(ep, input);
                    ASSERT_EQ(from_tables.has_value(), key.has_value());
                    if (key.has_value()) {
                        EXPECT_EQ(from_tables->dump(), json(key.value()).dump());
                        EXPECT_EQ(schema::object_path(ep, *from_tables), fortiapi::path(E::path, key.value()));
                    }
                }
            }
        }
        // Clearing: each attribute alone, with an unknown name, and set and cleared at once.
        for (const auto& f: ep.type->fields) {
            std::vector<std::string> clear{std::string(f.name)};
            EXPECT_EQ(capture([&] { return schema::update_body(*ep.type, json::object(), clear); }),
                      capture([&] { return typed_update<T>(json::object(), clear); })) << f.name;
            json set{{std::string(f.name), valid(f, 1)}};
            EXPECT_EQ(capture([&] { return schema::update_body(*ep.type, set, clear); }),
                      capture([&] { return typed_update<T>(set, clear); })) << f.name;
        }
        std::vector<std::string> unknown{"forti-api-unknown"};
        EXPECT_EQ(capture([&] { return schema::update_body(*ep.type, json::object(), unknown); }),
                  capture([&] { return typed_update<T>(json::object(), unknown); }));
        EXPECT_EQ(capture([&] { return schema::update_body(*ep.type, "x"); }), capture([&] { return typed_update<T>("x", {}); }));
    }

    template<typename M>
    void check_monitor(const schema::Endpoint& ep, std::size_t& inputs_checked) {
        using T = typename M::type;
        using R = typename M::result_type;
        EXPECT_EQ(ep.kind, schema::EndpointKind::monitor);
        ASSERT_NE(ep.value, nullptr);
        if constexpr (std::is_same_v<T, json>) EXPECT_EQ(ep.type, nullptr);
        else {
            ASSERT_NE(ep.type, nullptr);
            check_type<T>(*ep.type, std::string(ep.path));
        }
        check_kind<R>(*ep.value, std::string(ep.path));
        for (const json& input: values(*ep.value, 0)) {
            ++inputs_checked;
            SCOPED_TRACE(input.dump());
            EXPECT_EQ(capture([&] { return schema::decode(*ep.value, input); }),
                      capture([&] { return snapshot(fortiapi::from_json<R>(input)); }));
        }
        if constexpr (!std::is_same_v<T, json>) {
            const schema::Field object{"", schema::Kind::object, ep.type, nullptr, "null", false, "", "", {}, {}, nullptr, 0, false, false};
            for (const json& input: inputs(object)) {
                ++inputs_checked;
                check_decoding<T>(object, input);
            }
        }
    }

#ifndef SCHEMA_SAMPLE
    // The registry path of a descriptor: Table::path, or the monitor Spec::path (relative to monitor/).
    std::string_view registry_path(const schema::Endpoint& ep) {
        return ep.kind == schema::EndpointKind::monitor ? ep.path.substr(std::string_view("monitor/").size()) : ep.path;
    }
#endif

}  // namespace

TEST(SchemaDifferential, SCHEMA_TEST) {
    std::size_t endpoints = 0, inputs_checked = 0;
    for_each_endpoint([&]<typename E>() {
        if constexpr (selected(E::path)) {
            SCOPED_TRACE(std::string(E::path));
            const schema::Endpoint* ep = schema::find(E::path);
            ASSERT_NE(ep, nullptr) << "no descriptor for " << E::path;
            ++endpoints;
            check_cmdb<E>(*ep, inputs_checked);
        }
    });
    for_each_monitor([&]<typename M>() {
        if constexpr (selected(M::path)) {
            std::string path = fortiapi::Monitor::path(M::path);
            SCOPED_TRACE(path);
            const schema::Endpoint* ep = schema::find(path);
            ASSERT_NE(ep, nullptr) << "no descriptor for " << path;
            ++endpoints;
            check_monitor<M>(*ep, inputs_checked);
        }
    });
#ifdef SCHEMA_SAMPLE
    EXPECT_EQ(endpoints, sample_size);
#else
    // Every descriptor in this shard was matched by a typed endpoint, and nothing is described twice.
    std::size_t described = 0;
    for (const auto& ep: schema::endpoints()) described += selected(registry_path(ep));
    EXPECT_EQ(described, endpoints);
    EXPECT_EQ(schema::endpoints().size(), fortiapi::gen::endpoint_count + fortiapi::gen::monitor_count);
#endif
    std::cout << ::testing::UnitTest::GetInstance()->current_test_info()->name() << ": " << endpoints
              << " endpoints, " << inputs_checked << " inputs\n";
}
