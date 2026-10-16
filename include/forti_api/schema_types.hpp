//
// The descriptor types of fortiapi::schema (schema.hpp): every generated endpoint as data. The tables
// themselves are generated into gen/schema.hpp from the same schema snapshots and the same type
// decisions as the typed headers, so a Field describes exactly the Field<T> member of the
// generated struct: its key, C++ type, reset value and flags, in visit() order. Standard library
// only, so the tables cost a consumer no template instantiation at all.
//

#ifndef FORTI_API_SCHEMA_TYPES_HPP
#define FORTI_API_SCHEMA_TYPES_HPP

#include <cstdint>
#include <span>
#include <string_view>

namespace fortiapi::schema {

    // The C++ type of an attribute (Field<T>::value_type), as data.
    enum class Kind : std::uint8_t {
        string,    // std::string
        uint32,    // std::uint32_t
        int64,     // std::int64_t
        number,    // double (monitor results)
        boolean,   // bool
        json,      // nlohmann::json: any value, kept as it is
        object,    // a generated struct: Field::type
        array,     // std::vector of Field::item (a table when the item is an object)
        map,       // std::map<std::string, Field::item> (monitor results)
    };

    struct Type;

    // Integer bounds from the FortiOS schema (min-value, max-value).
    struct Range {
        std::int64_t min, max;
    };

    struct Field {
        std::string_view name;           // the FortiOS key ("srcintf"); empty for an array or map element
        Kind kind;
        const Type* type;                // Kind::object: the struct
        const Field* item;               // Kind::array, Kind::map: the element
        std::string_view reset;          // JSON written when the attribute is cleared
        bool read_only;                  // reported by the device, never written (fortiapi::read_only)

        // FortiOS schema metadata, for cmdb attributes (empty for monitor results and elements).
        std::string_view fortios_type;   // "option", "integer", "string", "ipv4-address", "password", "table", "complex", ...
        std::string_view help;
        std::span<const std::string_view> options;      // the values an option attribute takes
        std::span<const std::string_view> references;   // datasource ("system.interface.name"); for a
                                                        // table of references, its entries' targets
        const Range* range;              // integer bounds, nullptr when the schema states none
        std::uint32_t size;              // maximum string length, 0 when the schema states none
        bool required;                   // as the schema states it (often conditional on other attributes)
        bool multiple_values;            // space-separated values in one string

        // A member table (std::vector of a struct, including references).
        [[nodiscard]] constexpr bool is_table() const { return kind == Kind::array && item && item->kind == Kind::object; }

        // std::is_arithmetic_v of the C++ type: "" from the device means absent for these.
        [[nodiscard]] constexpr bool is_arithmetic() const {
            return kind == Kind::uint32 || kind == Kind::int64 || kind == Kind::number || kind == Kind::boolean;
        }
    };

    struct Type {
        std::string_view name;           // the C++ type ("fortiapi::firewall::Address::MacaddrEntry")
        std::string_view help;
        std::string_view key;            // the mkey attribute, for the object of a table or a table entry ("" when none)
        std::span<const Field> fields;   // every attribute, in visit() order

        [[nodiscard]] constexpr const Field* field(std::string_view key_name) const {
            for (const Field& f: fields)
                if (f.name == key_name) return &f;
            return nullptr;
        }
    };

    enum class EndpointKind : std::uint8_t {
        table,       // fortiapi::Table<Spec>
        singleton,   // fortiapi::Singleton<Spec>
        monitor,     // fortiapi::MonitorGet<Spec> (read-only)
    };

    struct Endpoint {
        std::string_view path;           // the API path: "cmdb/firewall/address" (Table::path),
                                         // "monitor/system/status" (Monitor::path(Spec::path))
        EndpointKind kind;
        const Type* type;                // the object (cmdb) or result type; nullptr for a monitor whose results stay JSON
        const Field* value;              // what fortiapi::from_json decodes: the object, or a monitor's `results`
        std::string_view key;            // tables: the mkey attribute ("name", "policyid")
        Kind key_kind;                   // tables: Kind::string, Kind::uint32 or Kind::int64 (Table::key_type)
        std::string_view cpp_name;       // "fortiapi::firewall::Addresses"
        std::string_view header;         // "forti_api/gen/firewall/address.hpp"
    };

}  // namespace fortiapi::schema

#endif  // FORTI_API_SCHEMA_TYPES_HPP
