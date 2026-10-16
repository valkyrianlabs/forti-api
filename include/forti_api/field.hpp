//
// fortiapi::Field<T>: one FortiOS attribute with a state, so writes are exact.
//
//   absent     not known: never read from the device, never set
//   populated  read from the device and untouched since
//   modified   set by the caller (assignment or edit())
//   cleared    explicitly reset by the caller (clear()); written as the schema's reset value
//
// An update (PUT) sends only modified and cleared fields; nothing unrelated is serialized. A create
// (POST) sends every known field. Read access is const and never changes the state; mutable access
// goes through edit(), which marks the field modified.
//
// Generated structs describe themselves with one static `visit(self, visitor)` that calls
// `visitor(key, field, reset_json, flags)` per attribute; the functions below do everything else.
//

#ifndef FORTI_API_FIELD_HPP
#define FORTI_API_FIELD_HPP

#include <nlohmann/json.hpp>

#include <charconv>
#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace fortiapi {

    enum class FieldState : std::uint8_t { absent, populated, modified, cleared };

    template<typename T>
    class Field {
        std::optional<T> value_;
        FieldState state_ = FieldState::absent;

    public:
        using value_type = T;

        Field() = default;

        Field& operator=(T value) {
            value_ = std::move(value);
            state_ = FieldState::modified;
            return *this;
        }

        template<typename U>
        requires (std::is_constructible_v<T, U&&> && !std::is_same_v<std::decay_t<U>, T> &&
                  !std::is_same_v<std::decay_t<U>, Field>)
        Field& operator=(U&& value) { return *this = T(std::forward<U>(value)); }

        // Mutable access; the field becomes modified (and default-constructed if it had no value).
        T& edit() {
            if (!value_) value_.emplace();
            state_ = FieldState::modified;
            return *value_;
        }

        // Writes the schema's reset value on the next update.
        void clear() {
            value_.reset();
            state_ = FieldState::cleared;
        }

        // Forgets the field: nothing is sent for it.
        void reset() {
            value_.reset();
            state_ = FieldState::absent;
        }

        [[nodiscard]] FieldState state() const { return state_; }
        [[nodiscard]] bool has_value() const { return value_.has_value(); }
        [[nodiscard]] explicit operator bool() const { return has_value(); }
        [[nodiscard]] bool dirty() const { return state_ == FieldState::modified || state_ == FieldState::cleared; }

        [[nodiscard]] const T& value() const {
            if (!value_) throw std::logic_error("fortiapi::Field has no value");
            return *value_;
        }

        [[nodiscard]] const T& operator*() const { return value(); }
        [[nodiscard]] const T* operator->() const { return &value(); }

        template<typename U>
        [[nodiscard]] T value_or(U&& fallback) const { return value_ ? *value_ : T(std::forward<U>(fallback)); }

        // Library internals: values read from the device, and the state after a successful write.
        void load(T value) {
            value_ = std::move(value);
            state_ = FieldState::populated;
        }

        void mark_clean() {
            if (state_ == FieldState::modified) state_ = FieldState::populated;
            else if (state_ == FieldState::cleared) state_ = FieldState::absent;
        }

        // Mutable access that leaves the state alone (library internals only).
        T* storage() { return value_ ? &*value_ : nullptr; }

        friend bool operator==(const Field& field, const T& value) { return field.value_ && *field.value_ == value; }
    };

    // Attribute flags passed by generated visit() functions.
    enum FieldFlags : unsigned {
        none = 0,
        read_only = 1u << 0,   // reported by the device, never written
    };

    // How much of an object to serialize.
    enum class Write {
        update,   // modified and cleared fields only (PUT)
        create,   // every field with a value, plus cleared ones (POST, table entries)
    };

    namespace detail {

        // All of `text` as a number of type T. Integers go through std::from_chars. Floating point
        // goes through the JSON number grammar instead: floating-point from_chars needs Xcode 26's
        // libc++, so it would break every build on macOS 15 and older (forti-api G16), and strtod
        // depends on the C locale. FortiOS sends numbers as text only now and then, so the cost of
        // the JSON parser on that path does not matter.
        template<typename T>
        [[nodiscard]] bool parse_number(std::string_view text, T& value) {
            if constexpr (std::is_integral_v<T>) {
                auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
                return ec == std::errc() && end == text.data() + text.size();
            } else {
                static_assert(std::is_floating_point_v<T>);
                // The grammar allows surrounding whitespace; from_chars (and so this function) does not.
                auto blank = [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; };
                if (text.empty() || blank(text.front()) || blank(text.back())) return false;
                nlohmann::json parsed = nlohmann::json::parse(text, nullptr, false);
                if (!parsed.is_number()) return false;
                value = parsed.get<T>();
                return true;
            }
        }

        template<typename T>
        concept Visitable = requires(T& object) {
            T::visit(object, [](std::string_view, auto&, std::string_view, unsigned) {});
        };

        template<typename T>
        struct is_vector : std::false_type {};

        template<typename T>
        struct is_vector<std::vector<T>> : std::true_type {};

        template<typename T>
        struct is_string_map : std::false_type {};

        template<typename T>
        struct is_string_map<std::map<std::string, T>> : std::true_type {};

        template<typename T>
        nlohmann::json to_json_value(const T& value, Write mode);

        template<typename T>
        T from_json_value(const nlohmann::json& json);

        template<Visitable T>
        nlohmann::json write_object(const T& object, Write mode) {
            nlohmann::json out = nlohmann::json::object();
            T::visit(object, [&](std::string_view key, const auto& field, std::string_view reset, unsigned flags) {
                if (flags & read_only) return;
                switch (field.state()) {
                    case FieldState::absent:
                        return;
                    case FieldState::populated:
                        if (mode == Write::update) return;
                        out[std::string(key)] = to_json_value(field.value(), Write::create);
                        return;
                    case FieldState::modified:
                        out[std::string(key)] = to_json_value(field.value(), mode);
                        return;
                    case FieldState::cleared:
                        out[std::string(key)] = nlohmann::json::parse(reset);
                        return;
                }
            });
            return out;
        }

        // Thrown while decoding; `where` accumulates the attribute path ("ftgd-dns.filters[2].category").
        class DecodeFailure : public std::runtime_error {
        public:
            std::string where, why;

            DecodeFailure(std::string where_, std::string why_)
                    : std::runtime_error(where_ + ": " + why_), where(std::move(where_)), why(std::move(why_)) {}

            [[noreturn]] void rethrow_within(std::string_view outer) const {
                bool index = where.starts_with('[');
                throw DecodeFailure(std::string(outer) + (index ? "" : ".") + where, why);
            }
        };

        template<Visitable T>
        void read_object(const nlohmann::json& json, T& object) {
            if (!json.is_object()) throw nlohmann::json::type_error::create(302, "expected an object", &json);
            T::visit(object, [&](std::string_view key, auto& field, std::string_view, unsigned) {
                using V = typename std::decay_t<decltype(field)>::value_type;
                auto it = json.find(key);
                // FortiOS reports an unset numeric attribute as "": that is an absent value.
                if (it == json.end() || (std::is_arithmetic_v<V> && it->is_string() && it->get_ref<const std::string&>().empty())) {
                    field.reset();
                    return;
                }
                try {
                    field.load(from_json_value<V>(*it));
                } catch (const DecodeFailure& failure) {
                    failure.rethrow_within(key);
                } catch (const nlohmann::json::exception& error) {
                    throw DecodeFailure(std::string(key), error.what() + std::string(" (value: ") + it->dump() + ")");
                }
            });
        }

        template<Visitable T>
        void mark_clean(T& object) {
            T::visit(object, [](std::string_view, auto& field, std::string_view, unsigned) {
                using V = typename std::decay_t<decltype(field)>::value_type;
                if constexpr (Visitable<V>) {
                    if (V* nested = field.storage()) mark_clean(*nested);
                }
                field.mark_clean();
            });
        }

        template<Visitable T>
        bool dirty(const T& object) {
            bool any = false;
            T::visit(object, [&](std::string_view, const auto& field, std::string_view, unsigned flags) {
                if (!(flags & read_only) && field.dirty()) any = true;
            });
            return any;
        }

        // A modified nested object is written with the caller's mode (an update sends only its
        // dirty attributes); table entries are always written whole, since FortiOS replaces tables.
        template<typename T>
        nlohmann::json to_json_value(const T& value, Write mode) {
            if constexpr (Visitable<T>) return write_object(value, mode);
            else if constexpr (is_vector<T>::value) {
                nlohmann::json out = nlohmann::json::array();
                for (const auto& item: value) out.push_back(to_json_value(item, Write::create));
                return out;
            } else if constexpr (is_string_map<T>::value) {
                nlohmann::json out = nlohmann::json::object();
                for (const auto& [key, item]: value) out[key] = to_json_value(item, Write::create);
                return out;
            } else return nlohmann::json(value);
        }

        template<typename T>
        T from_json_value(const nlohmann::json& json) {
            if constexpr (Visitable<T>) {
                T object;
                read_object(json, object);
                return object;
            } else if constexpr (is_vector<T>::value) {
                T out;
                if (!json.is_array()) throw nlohmann::json::type_error::create(302, "expected an array", &json);
                out.reserve(json.size());
                for (std::size_t i = 0; i < json.size(); ++i) {
                    try {
                        out.push_back(from_json_value<typename T::value_type>(json[i]));
                    } catch (const DecodeFailure& failure) {
                        throw DecodeFailure("[" + std::to_string(i) + "]" + (failure.where.starts_with('[') ? "" : ".") +
                                            failure.where, failure.why);
                    }
                }
                return out;
            } else if constexpr (is_string_map<T>::value) {
                T out;
                if (!json.is_object()) throw nlohmann::json::type_error::create(302, "expected an object", &json);
                for (auto it = json.begin(); it != json.end(); ++it) {
                    try {
                        out.emplace(it.key(), from_json_value<typename T::mapped_type>(it.value()));
                    } catch (const DecodeFailure& failure) {
                        throw DecodeFailure("[" + it.key() + "]" + (failure.where.starts_with('[') ? "" : ".") +
                                            failure.where, failure.why);
                    }
                }
                return out;
            } else if constexpr (std::is_same_v<T, std::string>) {
                // FortiOS reports some string attributes as numbers (e.g. an id in a string field).
                return json.is_string() ? json.get<std::string>() : json.dump();
            } else if constexpr (std::is_arithmetic_v<T> && !std::is_same_v<T, bool>) {
                if (json.is_string()) {   // numbers FortiOS sends as text ("5")
                    const auto& text = json.get_ref<const std::string&>();
                    T number{};
                    if (!parse_number(text, number))
                        throw nlohmann::json::type_error::create(302, "expected a number", &json);
                    return number;
                }
                return json.get<T>();
            } else return json.get<T>();
        }

    }  // namespace detail

    // Serializes a generated object: Write::update for PUT bodies, Write::create for POST bodies.
    template<detail::Visitable T>
    nlohmann::json to_json(const T& object, Write mode) { return detail::write_object(object, mode); }

    // Builds a generated object (or a vector / string map of them) from a device reply; every
    // attribute present becomes populated.
    template<typename T>
    T from_json(const nlohmann::json& json) { return detail::from_json_value<T>(json); }

    // True when an update would send something.
    template<detail::Visitable T>
    bool dirty(const T& object) { return detail::dirty(object); }

    // After a successful write: modified → populated, cleared → absent, recursively.
    template<detail::Visitable T>
    void mark_clean(T& object) { detail::mark_clean(object); }

    // A reference to another object by name: the {"name": ...} entries of member tables
    // (srcintf, srcaddr, service, ...).
    struct Ref {
        Field<std::string> name;

        Ref() = default;
        Ref(std::string ref) { name = std::move(ref); }       // NOLINT: implicit by design
        Ref(const char* ref) { name = std::string(ref); }    // NOLINT

        template<typename Self, typename Visitor>
        static void visit(Self& self, Visitor&& v) { v("name", self.name, R"("")", none); }
    };

}  // namespace fortiapi

#endif //FORTI_API_FIELD_HPP
