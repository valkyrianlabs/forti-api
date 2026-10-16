//
// fortiapi::schema: every generated endpoint as data, and JSON decoding, validation and encoding for
// any of them without the typed models.
//
// The typed API (Table<Spec>, Field<T>, from_json<T>, to_json<T>) is the way to work with a known
// endpoint in code. A program that handles endpoints chosen at run time (a CLI, an MCP server) would
// have to instantiate it for all of them: hundreds of types and their std::vector / optional /
// JSON code, several GB of compiler memory. This header gives the same behavior from tables
// instead (gen/schema.hpp, generated with the typed headers and checked against them by the unit
// tests), in ordinary functions compiled once:
//
//   const auto* ep = fortiapi::schema::find("cmdb/firewall/address");
//   auto body = fortiapi::schema::create_body(*ep->type, R"({"name": "web", "subnet": "192.0.2.10/32"})"_json);
//   client.post(ep->path, body);
//
// decode() reproduces fortiapi::from_json<T> exactly (results and errors); create_body() and
// update_body() produce the bodies Table::add and Table::update send for the same attributes.
// Including this header pulls in no generated model.
//

#ifndef FORTI_API_SCHEMA_HPP
#define FORTI_API_SCHEMA_HPP

#include "client.hpp"
#include "field.hpp"
#include "gen/schema.hpp"
#include "schema_types.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace fortiapi::schema {

    // Every generated endpoint (cmdb tables and singletons, typed monitor GETs), sorted by path.
    inline std::span<const Endpoint> endpoints() { return gen::schema_tables::endpoints; }

    // The endpoint with this API path ("cmdb/firewall/address", "monitor/system/status"), or nullptr.
    inline const Endpoint* find(std::string_view path) {
        auto all = endpoints();
        auto it = std::ranges::lower_bound(all, path, {}, &Endpoint::path);
        return it != all.end() && it->path == path ? &*it : nullptr;
    }

    // A body that cannot be written: why, and which attributes. The typed models never see these
    // inputs; create_body and update_body check what a caller handing in arbitrary JSON needs.
    class ValidationError : public Error {
    public:
        enum class Reason {
            not_object,        // the object (or `set`) is not a JSON object
            invalid_value,     // attribute(): the value does not decode as its type; detail() says why
            unknown,           // attributes(): not attributes of the type
            read_only,         // attributes(): reported by the device, never written
            set_and_cleared,   // attribute(): both set and cleared in one update
        };

        ValidationError(Reason reason, std::vector<std::string> attributes, std::string detail = {})
                : Error(message(reason, attributes, detail)), reason_(reason), attributes_(std::move(attributes)),
                  detail_(std::move(detail)) {}

        [[nodiscard]] Reason reason() const { return reason_; }
        [[nodiscard]] const std::vector<std::string>& attributes() const { return attributes_; }
        [[nodiscard]] const std::string& attribute() const {
            static const std::string none;
            return attributes_.empty() ? none : attributes_.front();
        }
        // invalid_value: the decoding error, word for word what fortiapi::from_json<T> reports.
        [[nodiscard]] const std::string& detail() const { return detail_; }

    private:
        Reason reason_;
        std::vector<std::string> attributes_;
        std::string detail_;

        static std::string message(Reason reason, const std::vector<std::string>& attributes, const std::string& detail) {
            std::string list;
            for (const auto& name: attributes) list += (list.empty() ? "" : ", ") + name;
            switch (reason) {
                case Reason::not_object: return "expected a JSON object";
                case Reason::invalid_value: return "attribute " + list + ": " + detail;
                case Reason::unknown: return "unknown attribute(s): " + list;
                case Reason::read_only: return "read-only attribute(s) cannot be written: " + list;
                case Reason::set_and_cleared: return "attribute " + list + " is both set and cleared";
            }
            return "invalid body";
        }
    };

    namespace detail {

        using fortiapi::detail::DecodeFailure;

        template<typename T>
        T number(const nlohmann::json& json) {
            if (json.is_string()) {   // numbers FortiOS sends as text ("5")
                const auto& text = json.get_ref<const std::string&>();
                T value{};
                if (!fortiapi::detail::parse_number(text, value))
                    throw nlohmann::json::type_error::create(302, "expected a number", &json);
                return value;
            }
            return json.get<T>();
        }

        inline nlohmann::json decode_object(const Type& type, const nlohmann::json& json);

        // fortiapi::detail::from_json_value<T> for the T a Field describes, statement for statement:
        // the same conversions, and the same exceptions with the same messages.
        inline nlohmann::json decode_value(const Field& field, const nlohmann::json& json) {
            switch (field.kind) {
                case Kind::object: return decode_object(*field.type, json);
                case Kind::array: {
                    if (!json.is_array()) throw nlohmann::json::type_error::create(302, "expected an array", &json);
                    nlohmann::json out = nlohmann::json::array();
                    for (std::size_t i = 0; i < json.size(); ++i) {
                        try {
                            out.push_back(decode_value(*field.item, json[i]));
                        } catch (const DecodeFailure& failure) {
                            throw DecodeFailure("[" + std::to_string(i) + "]" + (failure.where.starts_with('[') ? "" : ".") +
                                                failure.where, failure.why);
                        }
                    }
                    return out;
                }
                case Kind::map: {
                    if (!json.is_object()) throw nlohmann::json::type_error::create(302, "expected an object", &json);
                    nlohmann::json out = nlohmann::json::object();
                    for (auto it = json.begin(); it != json.end(); ++it) {
                        try {
                            out[it.key()] = decode_value(*field.item, it.value());
                        } catch (const DecodeFailure& failure) {
                            throw DecodeFailure("[" + it.key() + "]" + (failure.where.starts_with('[') ? "" : ".") +
                                                failure.where, failure.why);
                        }
                    }
                    return out;
                }
                case Kind::string: return json.is_string() ? json : nlohmann::json(json.dump());
                case Kind::uint32: return number<std::uint32_t>(json);
                case Kind::int64: return number<std::int64_t>(json);
                case Kind::number: return number<double>(json);
                case Kind::boolean: return json.get<bool>();
                case Kind::json: return json;
            }
            return json;
        }

        // fortiapi::detail::read_object: every attribute present (an empty string is absent for the
        // arithmetic ones), unknown keys ignored.
        inline nlohmann::json decode_object(const Type& type, const nlohmann::json& json) {
            if (!json.is_object()) throw nlohmann::json::type_error::create(302, "expected an object", &json);
            nlohmann::json out = nlohmann::json::object();
            for (const Field& field: type.fields) {
                auto it = json.find(field.name);
                if (it == json.end() || (field.is_arithmetic() && it->is_string() && it->get_ref<const std::string&>().empty()))
                    continue;
                try {
                    out[std::string(field.name)] = decode_value(field, *it);
                } catch (const DecodeFailure& failure) {
                    failure.rethrow_within(field.name);
                } catch (const nlohmann::json::exception& error) {
                    throw DecodeFailure(std::string(field.name), error.what() + std::string(" (value: ") + it->dump() + ")");
                }
            }
            return out;
        }

        // A value decode_value produced, as fortiapi::to_json writes it: read-only attributes left out.
        inline nlohmann::json writable(const Field& field, const nlohmann::json& value) {
            switch (field.kind) {
                case Kind::object: {
                    nlohmann::json out = nlohmann::json::object();
                    for (const Field& member: field.type->fields) {
                        if (member.read_only) continue;
                        auto it = value.find(member.name);
                        if (it != value.end()) out[std::string(member.name)] = writable(member, *it);
                    }
                    return out;
                }
                case Kind::array: {
                    nlohmann::json out = nlohmann::json::array();
                    for (const auto& item: value) out.push_back(writable(*field.item, item));
                    return out;
                }
                case Kind::map: {
                    nlohmann::json out = nlohmann::json::object();
                    for (auto it = value.begin(); it != value.end(); ++it) out[it.key()] = writable(*field.item, it.value());
                    return out;
                }
                default: return value;
            }
        }

        // One attribute of a body: decoded as fortiapi::from_json<V> would, then as written.
        inline nlohmann::json body_value(const Field& field, const nlohmann::json& value) {
            try {
                return writable(field, decode_value(field, value));
            } catch (const std::exception& error) {
                throw ValidationError(ValidationError::Reason::invalid_value, {std::string(field.name)}, error.what());
            }
        }

        inline void check_lists(std::vector<std::string> unknown, std::vector<std::string> read_only) {
            if (!unknown.empty()) throw ValidationError(ValidationError::Reason::unknown, std::move(unknown));
            if (!read_only.empty()) throw ValidationError(ValidationError::Reason::read_only, std::move(read_only));
        }

    }  // namespace detail

    // fortiapi::from_json for the type a descriptor names (an endpoint's Endpoint::value, an attribute,
    // a Type): the attributes present, each as the typed model holds it (numbers sent as text become
    // numbers, non-string values of string attributes become their JSON text), read-only ones
    // included. Throws exactly what from_json<T> throws: nlohmann::json::type_error, or
    // fortiapi::detail::DecodeFailure naming the attribute path (both std::exception).
    inline nlohmann::json decode(const Field& value, const nlohmann::json& json) { return detail::decode_value(value, json); }
    inline nlohmann::json decode(const Type& type, const nlohmann::json& json) { return detail::decode_object(type, json); }

    // A decoded value (decode()) as a write sends it: what to_json(object, Write::create) writes for a
    // typed object holding it, i.e. without the read-only attributes of its objects, at every depth.
    inline nlohmann::json writable(const Field& value, const nlohmann::json& decoded) { return detail::writable(value, decoded); }

    // The POST body Table::add sends for an object built from `object`: every attribute given, each
    // decoded as Field<V> would hold it and written as to_json(object, Write::create) writes it (nested
    // read-only attributes left out). Throws ValidationError: not_object; invalid_value for the first
    // attribute (in visit() order) that does not decode; then unknown; then read_only.
    inline nlohmann::json create_body(const Type& type, const nlohmann::json& object) {
        if (!object.is_object()) throw ValidationError(ValidationError::Reason::not_object, {});
        nlohmann::json body = nlohmann::json::object();
        std::vector<std::string> read_only, unknown;
        for (const Field& field: type.fields) {
            auto it = object.find(field.name);
            if (it == object.end()) continue;
            if (field.read_only) {
                read_only.emplace_back(field.name);
                continue;
            }
            body[std::string(field.name)] = detail::body_value(field, *it);
        }
        for (auto it = object.begin(); it != object.end(); ++it)
            if (!type.field(it.key())) unknown.push_back(it.key());
        detail::check_lists(std::move(unknown), std::move(read_only));
        return body;
    }

    // The PUT body Table::update sends after the attributes in `set` are assigned (each written in
    // full, nested objects included) and those in `clear` are cleared (their reset value). Empty when
    // there is nothing to send (Table::update then sends nothing). Throws ValidationError like
    // create_body, plus set_and_cleared; `set` must be an object.
    inline nlohmann::json update_body(const Type& type, const nlohmann::json& set, std::span<const std::string> clear = {}) {
        if (!set.is_object()) throw ValidationError(ValidationError::Reason::not_object, {});
        nlohmann::json body = nlohmann::json::object();
        std::vector<std::string> read_only, unknown, seen;
        for (const Field& field: type.fields) {
            auto it = set.find(field.name);
            bool cleared = std::ranges::find(clear, field.name) != clear.end();
            if (it == set.end() && !cleared) continue;
            seen.emplace_back(field.name);
            if (field.read_only) {
                read_only.emplace_back(field.name);
                continue;
            }
            if (it != set.end() && cleared)
                throw ValidationError(ValidationError::Reason::set_and_cleared, {std::string(field.name)});
            body[std::string(field.name)] = cleared ? nlohmann::json::parse(field.reset) : detail::body_value(field, *it);
        }
        auto was_seen = [&](std::string_view name) { return std::ranges::find(seen, name) != seen.end(); };
        for (auto it = set.begin(); it != set.end(); ++it)
            if (!was_seen(it.key())) unknown.push_back(it.key());
        for (const auto& name: clear)
            if (!was_seen(name)) unknown.push_back(name);
        detail::check_lists(std::move(unknown), std::move(read_only));
        return body;
    }

    // The PUT body that makes `current` (an object as the device returns it) match `desired`: the
    // attributes of `desired` whose written value differs from the current one. Attributes `desired`
    // leaves out are left alone. `desired` is checked like create_body; `current` decodes like decode().
    inline nlohmann::json diff(const Type& type, const nlohmann::json& current, const nlohmann::json& desired) {
        nlohmann::json want = create_body(type, desired);
        nlohmann::json have = decode(type, current);
        nlohmann::json body = nlohmann::json::object();
        for (auto it = want.begin(); it != want.end(); ++it) {
            const Field& field = *type.field(it.key());
            auto old = have.find(it.key());
            if (old == have.end() || detail::writable(field, *old) != it.value()) body[it.key()] = it.value();
        }
        return body;
    }

    // A table object's key (mkey) as the typed model reads it, or nullopt when the object has none.
    // Only the key attribute is decoded; throws like decode() when it does not decode.
    inline std::optional<nlohmann::json> key_of(const Endpoint& endpoint, const nlohmann::json& object) {
        if (endpoint.kind != EndpointKind::table || !endpoint.type) return std::nullopt;
        const Field* key = endpoint.type->field(endpoint.key);
        if (!key) return std::nullopt;
        auto decoded = detail::decode_object(Type{endpoint.type->name, {}, {}, std::span<const Field>(key, 1)}, object);
        auto it = decoded.find(endpoint.key);
        return it == decoded.end() ? std::nullopt : std::optional<nlohmann::json>(*it);
    }

    // The object's API path, as Table::get / update / del address it: fortiapi::path(endpoint.path, key).
    inline std::string object_path(const Endpoint& endpoint, const nlohmann::json& key) {
        switch (endpoint.key_kind) {
            case Kind::uint32: return fortiapi::path(endpoint.path, detail::number<std::uint32_t>(key));
            case Kind::int64: return fortiapi::path(endpoint.path, detail::number<std::int64_t>(key));
            default: return fortiapi::path(endpoint.path, key.is_string() ? key.get<std::string>() : key.dump());
        }
    }

    // Advisory checks against the FortiOS schema metadata, which the device enforces and the typed
    // models do not: option values, integer ranges, string sizes. FortiOS options can depend on the
    // model and licence, so a finding is a warning, not a refusal. Paths: "type", "srcaddr[0].name".
    struct Finding {
        std::string attribute;
        std::string message;
    };

    namespace detail {

        inline void check_values(const Type& type, const nlohmann::json& object, const std::string& prefix,
                                 std::vector<Finding>& out) {
            if (!object.is_object()) return;
            for (const Field& field: type.fields) {
                auto it = object.find(field.name);
                if (it == object.end()) continue;
                std::string where = prefix + std::string(field.name);
                const nlohmann::json& value = *it;
                if (field.kind == Kind::object && field.type) check_values(*field.type, value, where + ".", out);
                else if (field.is_table() && value.is_array())
                    for (std::size_t i = 0; i < value.size(); ++i)
                        check_values(*field.item->type, value[i], where + "[" + std::to_string(i) + "].", out);
                else if (value.is_string() && !field.options.empty()) {
                    const auto& text = value.get_ref<const std::string&>();
                    std::size_t start = 0;
                    while (start < text.size()) {
                        std::size_t end = field.multiple_values ? text.find(' ', start) : std::string::npos;
                        std::string token = text.substr(start, end == std::string::npos ? std::string::npos : end - start);
                        start = end == std::string::npos ? text.size() : end + 1;
                        if (token.empty()) continue;
                        if (std::ranges::find(field.options, std::string_view(token)) == field.options.end()) {
                            std::string allowed;
                            for (auto option: field.options) allowed += (allowed.empty() ? "" : ", ") + std::string(option);
                            out.push_back({where, "\"" + token + "\" is not one of: " + allowed});
                        }
                    }
                } else if (field.range && (field.kind == Kind::uint32 || field.kind == Kind::int64)) {
                    std::int64_t number = 0;
                    bool ok = true;
                    try {
                        number = detail::number<std::int64_t>(value);
                    } catch (const std::exception&) {
                        ok = false;
                    }
                    if (ok && (number < field.range->min || number > field.range->max))
                        out.push_back({where, std::to_string(number) + " is outside " + std::to_string(field.range->min) +
                                              ".." + std::to_string(field.range->max)});
                } else if (field.size && field.kind == Kind::string && value.is_string() &&
                           value.get_ref<const std::string&>().size() > field.size)
                    out.push_back({where, "longer than " + std::to_string(field.size) + " characters"});
            }
        }

    }  // namespace detail

    inline std::vector<Finding> check_values(const Type& type, const nlohmann::json& object) {
        std::vector<Finding> out;
        detail::check_values(type, object, "", out);
        return out;
    }

}  // namespace fortiapi::schema

#endif  // FORTI_API_SCHEMA_HPP
