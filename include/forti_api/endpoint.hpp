//
// Behavior shared by every generated endpoint. A generated Spec names the type, the API path and,
// for tables, the key member; everything else lives here once.
//
//   struct PolicySpec {
//       using type = Policy;
//       static constexpr std::string_view path = "cmdb/firewall/policy";
//       static constexpr auto key = &Policy::policyid;
//   };
//   using Policies = fortiapi::Table<PolicySpec>;
//
// A table attribute of a table object (a child table) is addressed entry by entry with
// ChildTable<Spec, &Type::attribute>, or Table<Spec>::child<&Type::attribute>:
//
//   using Reservations = system::dhcp::Servers::child<&system::dhcp::Server::reserved_address>;
//   Reservations::del(1, 7);   // DELETE cmdb/system.dhcp/server/1/reserved-address/7
//
// Every call takes an optional Query (vdom, filter, format, ...) and Client (default_client()).
//

#ifndef FORTI_API_ENDPOINT_HPP
#define FORTI_API_ENDPOINT_HPP

#include "client.hpp"
#include "field.hpp"

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace fortiapi {

    // The metadata FortiOS returns with every write.
    struct Reply {
        long http_status = 0;
        std::string status, revision, vdom, path, name, serial, version;
        std::string http_method;   // "POST", "PUT", "DELETE", as the device echoes it
        // The table's configuration revision before the write (FortiOS 7.4.8 keeps one revision per
        // cmdb table, e.g. router.access-list, shared by all its objects) and whether the write changed
        // it. A failed write reports `revision` without `old_revision`, and revision_changed false.
        std::string old_revision;
        bool revision_changed = false;
        nlohmann::json mkey;   // the created object's key (string or number), when reported
        long build = 0;
        // Requests to a child table (ChildTable): the table attribute and the entry's key. What
        // `mkey` names depends on the method (FortiOS 7.4.8, observed live):
        //   POST    mkey = the new entry's key (a number for numeric keys); no child_mkey
        //   PUT     mkey = the parent's key;   child_mkey = the entry's key, as text
        //   DELETE  mkey = the entry's key;    child_mkey = the entry's key, as text
        //   GET     mkey = the parent's key;   child_mkey = the entry's key
        //   errors  mkey = the parent's key;   no child_mkey
        std::string child_path;
        nlohmann::json child_mkey;

        static Reply from(const nlohmann::json& body) {
            Reply reply;
            auto text = [&](const char* key) {
                auto it = body.find(key);
                return it != body.end() && it->is_string() ? it->get<std::string>() : std::string();
            };
            reply.http_status = body.value("http_status", 0L);
            reply.status = text("status");
            reply.revision = text("revision");
            reply.vdom = text("vdom");
            reply.path = text("path");
            reply.name = text("name");
            reply.serial = text("serial");
            reply.version = text("version");
            reply.build = body.value("build", 0L);
            reply.http_method = text("http_method");
            reply.old_revision = text("old_revision");
            if (auto it = body.find("revision_changed"); it != body.end() && it->is_boolean())
                reply.revision_changed = it->get<bool>();
            if (auto it = body.find("mkey"); it != body.end()) reply.mkey = *it;
            reply.child_path = text("child_path");
            if (auto it = body.find("child_mkey"); it != body.end()) reply.child_mkey = *it;
            return reply;
        }
    };

    namespace detail {

        template<typename M>
        struct member_traits;

        template<typename C, typename F>
        struct member_traits<F C::*> {
            using object = C;
            using field = F;
        };

        // Decodes one device object, naming the endpoint and attribute path on failure.
        template<typename T>
        T decode(const nlohmann::json& json, std::string_view path) {
            try {
                return from_json<T>(json);
            } catch (const DecodeFailure& failure) {
                throw DecodeError(std::string(path) + ": attribute " + failure.what());
            } catch (const nlohmann::json::exception& error) {
                throw DecodeError(std::string(path) + ": " + error.what());
            }
        }

        // Returns a reference into `body`: keep the reply alive while using it.
        inline const nlohmann::json& results(const nlohmann::json& body, std::string_view path) {
            auto it = body.find("results");
            if (it == body.end()) throw DecodeError(std::string(path) + ": reply has no results");
            return *it;
        }

        // A table entry type: generated entries and Ref name their key member as `mkey`.
        template<typename T>
        concept KeyedEntry = Visitable<T> && requires { T::mkey; } &&
                             std::is_member_object_pointer_v<std::remove_cv_t<decltype(T::mkey)>>;

        // The FortiOS name of the attribute `Member` ("reserved-address"), from the type's visit():
        // the attribute whose field is the member's field in one probe object.
        template<auto Member>
        std::string_view attribute_name() {
            using Object = typename member_traits<decltype(Member)>::object;
            using F = typename member_traits<decltype(Member)>::field;
            static const std::string_view name = [] {
                Object probe{};
                std::string_view found;
                Object::visit(probe, [&](std::string_view key, auto& field, std::string_view, unsigned) {
                    if constexpr (std::is_same_v<std::remove_cvref_t<decltype(field)>, F>) {
                        if (&field == &(probe.*Member)) found = key;
                    }
                });
                if (found.empty()) throw std::logic_error("fortiapi::ChildTable: member is not a visited attribute");
                return found;
            }();
            return name;
        }

    }  // namespace detail

    template<typename Spec, auto Member>
    struct ChildTable;

    // A cmdb table: a collection of objects addressed by a key (mkey).
    template<typename Spec>
    struct Table {
        using type = typename Spec::type;
        using key_type = typename detail::member_traits<std::remove_cv_t<decltype(Spec::key)>>::field::value_type;

        static constexpr std::string_view path = Spec::path;
        static constexpr auto key = Spec::key;   // the key member (mkey)

        // One table attribute of this table's objects, entry by entry (see ChildTable).
        template<auto Member>
        using child = ChildTable<Spec, Member>;

        static std::vector<type> list(const Query& query = {}, Client& client = default_client()) {
            auto body = client.get(path, query);
            const auto& items = detail::results(body, path);
            std::vector<type> out;
            out.reserve(items.size());
            for (const auto& item: items) out.push_back(detail::decode<type>(item, path));
            return out;
        }

        // nullopt when the device reports 404.
        static std::optional<type> find(const key_type& key, const Query& query = {}, Client& client = default_client()) {
            Result result = client.exchange(Method::Get, fortiapi::path(path, key), query);
            if (result.http_status == 404) return std::nullopt;
            if (!result.ok()) throw ApiError(Method::Get, fortiapi::path(path, key), result.http_status, std::move(result.body));
            const auto& items = detail::results(result.body, path);
            if (!items.is_array() || items.empty()) return std::nullopt;
            return detail::decode<type>(items.front(), path);
        }

        // Throws ApiError (not_found()) when the object does not exist.
        static type get(const key_type& key, const Query& query = {}, Client& client = default_client()) {
            auto body = client.get(fortiapi::path(path, key), query);
            const auto& items = detail::results(body, path);
            if (!items.is_array() || items.empty())
                throw ApiError(Method::Get, fortiapi::path(path, key), 404, nlohmann::json::object());
            return detail::decode<type>(items.front(), path);
        }

        static bool contains(const key_type& key, const Query& query = {}, Client& client = default_client()) {
            return find(key, query, client).has_value();
        }

        // POST every known attribute. On success the object is clean and, when the device assigned
        // the key (e.g. policyid 0), the key member holds it.
        //
        // FortiOS creates are not transactional: an attribute error after creation returns an error
        // AND leaves the object behind. The caller decides about cleanup; nothing is retried.
        static Reply add(type& object, const Query& query = {}, Client& client = default_client()) {
            Reply reply = Reply::from(client.post(path, to_json(object, Write::create), query));
            if constexpr (std::is_arithmetic_v<key_type>) {
                if (reply.mkey.is_number_integer()) (object.*Spec::key).load(reply.mkey.template get<key_type>());
            }
            mark_clean(object);
            return reply;
        }

        // PUT only the modified and cleared attributes. Sends nothing (and returns nullopt) when the
        // object has no changes. Requires the key member.
        static std::optional<Reply> update(type& object, const Query& query = {}, Client& client = default_client()) {
            const auto& key = object.*Spec::key;
            if (!key.has_value()) throw Error(std::string(path) + ": update needs the key attribute");
            if (!dirty(object)) return std::nullopt;
            Reply reply = Reply::from(client.put(fortiapi::path(path, key.value()), to_json(object, Write::update), query));
            mark_clean(object);
            return reply;
        }

        static Reply del(const key_type& key, const Query& query = {}, Client& client = default_client()) {
            return Reply::from(client.del(fortiapi::path(path, key), query));
        }

        static nlohmann::json schema(Client& client = default_client()) {
            return detail::results(client.get(path, Query().action("schema")), path);
        }
    };

    // One table attribute of the objects of a cmdb table (a child table), addressed entry by entry
    // instead of through the parent's whole list:
    //
    //   cmdb/<path>/<parent key>/<attribute>               GET (list), POST (add one entry)
    //   cmdb/<path>/<parent key>/<attribute>/<entry key>   GET, PUT (update), DELETE
    //
    // `Member` is the attribute's member of Spec::type (&Server::reserved_address); its entries name
    // their key member (`mkey`: id, name, ...). Each write changes one entry and leaves the others
    // alone, unlike Table::update with the whole list, which replaces the list. Keys are encoded like
    // Table keys: each key is one path segment, and "." / ".." are sent as "%2E" / "%2E%2E".
    template<typename Spec, auto Member>
    struct ChildTable {
        using parent = Table<Spec>;
        using parent_key_type = typename parent::key_type;

    private:
        using member = detail::member_traits<std::remove_cv_t<decltype(Member)>>;
        using list_type = typename member::field::value_type;
        static_assert(std::is_same_v<typename member::object, typename Spec::type>,
                      "fortiapi::ChildTable: the member must be an attribute of Spec::type");
        static_assert(detail::is_vector<list_type>::value,
                      "fortiapi::ChildTable: the member must be a table attribute (Field<std::vector<Entry>>)");

    public:
        using type = typename list_type::value_type;
        static_assert(detail::KeyedEntry<type>, "fortiapi::ChildTable: the entry type names no key member (mkey)");
        static constexpr auto key = type::mkey;   // the entry's key member
        using key_type = typename detail::member_traits<std::remove_cv_t<decltype(type::mkey)>>::field::value_type;

        // The FortiOS attribute name ("reserved-address").
        static std::string_view attribute() { return detail::attribute_name<Member>(); }

        // cmdb/<path>/<parent key>/<attribute>, and with the entry key.
        static std::string path(const parent_key_type& parent_key) {
            return fortiapi::path(Spec::path, parent_key, attribute());
        }

        static std::string path(const parent_key_type& parent_key, const key_type& entry_key) {
            return fortiapi::path(Spec::path, parent_key, attribute(), entry_key);
        }

        // Every entry. Throws ApiError (not_found()) when the parent object does not exist.
        static std::vector<type> list(const parent_key_type& parent_key, const Query& query = {},
                                      Client& client = default_client()) {
            const std::string at = path(parent_key);
            auto body = client.get(at, query);
            const auto& items = detail::results(body, at);
            if (!items.is_array()) throw DecodeError(at + ": results is not a list");
            std::vector<type> out;
            out.reserve(items.size());
            for (const auto& item: items) out.push_back(detail::decode<type>(item, at));
            return out;
        }

        // nullopt when the device reports 404 (no such entry, or no such parent).
        static std::optional<type> find(const parent_key_type& parent_key, const key_type& entry_key,
                                        const Query& query = {}, Client& client = default_client()) {
            const std::string at = path(parent_key, entry_key);
            Result result = client.exchange(Method::Get, at, query);
            if (result.http_status == 404) return std::nullopt;
            if (!result.ok()) throw ApiError(Method::Get, at, result.http_status, std::move(result.body));
            const auto& items = detail::results(result.body, at);
            if (items.is_object()) return detail::decode<type>(items, at);
            if (!items.is_array() || items.empty()) return std::nullopt;
            return detail::decode<type>(items.front(), at);
        }

        // Throws ApiError (not_found()) when the entry (or the parent) does not exist.
        static type get(const parent_key_type& parent_key, const key_type& entry_key, const Query& query = {},
                        Client& client = default_client()) {
            const std::string at = path(parent_key, entry_key);
            auto body = client.get(at, query);
            const auto& items = detail::results(body, at);
            if (items.is_object()) return detail::decode<type>(items, at);
            if (!items.is_array() || items.empty()) throw ApiError(Method::Get, at, 404, nlohmann::json::object());
            return detail::decode<type>(items.front(), at);
        }

        static bool contains(const parent_key_type& parent_key, const key_type& entry_key, const Query& query = {},
                             Client& client = default_client()) {
            return find(parent_key, entry_key, query, client).has_value();
        }

        // POST every known attribute of one new entry. On success the entry is clean. A numeric key
        // left to the device (absent or 0) takes the entry key the reply reports; a key the caller set
        // is never overwritten. FortiOS 7.4.8 reports the new entry's key as `mkey` of a child POST
        // reply (Reply), so that is taken only from a reply that names this child table and the POST;
        // `child_mkey` wins when a reply carries it. When the reply reports no entry key, the key stays
        // as it was: list() the entries to find it. Adding an entry whose key exists fails (HTTP 500,
        // FortiOS error -5) and changes nothing: a POST never overwrites. As with Table::add, nothing
        // is retried.
        static Reply add(const parent_key_type& parent_key, type& entry, const Query& query = {},
                         Client& client = default_client()) {
            Reply reply = Reply::from(client.post(path(parent_key), to_json(entry, Write::create), query));
            if constexpr (std::is_arithmetic_v<key_type>) {
                auto& entry_key = entry.*type::mkey;
                bool device_assigned = !entry_key.has_value() || entry_key.value() == key_type{};
                if (device_assigned) {
                    auto assigned = reported_key(reply.child_mkey);
                    if (!assigned && reply.http_method == "POST" && reply.child_path == attribute())
                        assigned = reported_key(reply.mkey);
                    if (assigned) entry_key.load(*assigned);
                }
            }
            mark_clean(entry);
            return reply;
        }

        // PUT only the entry's modified and cleared attributes to the entry's own path; the entry's
        // other attributes, the other entries and the parent's other attributes keep their values.
        // Sends nothing (and returns nullopt) when the entry has no changes. Requires the entry's key
        // member. A PUT never creates: a missing entry or parent is ApiError (not_found()).
        static std::optional<Reply> update(const parent_key_type& parent_key, type& entry, const Query& query = {},
                                           Client& client = default_client()) {
            const auto& entry_key = entry.*type::mkey;
            if (!entry_key.has_value())
                throw Error(path(parent_key) + ": update needs the entry's key attribute");
            if (!dirty(entry)) return std::nullopt;
            Reply reply = Reply::from(client.put(path(parent_key, entry_key.value()), to_json(entry, Write::update), query));
            mark_clean(entry);
            return reply;
        }

        // Removes one entry. A missing entry or parent is ApiError (not_found()).
        static Reply del(const parent_key_type& parent_key, const key_type& entry_key, const Query& query = {},
                         Client& client = default_client()) {
            return Reply::from(client.del(path(parent_key, entry_key), query));
        }

    private:
        // A numeric entry key as a reply reports it: a number, or a number as text ("12"); nullopt
        // when absent or out of the key type's range.
        static std::optional<key_type> reported_key(const nlohmann::json& value) {
            key_type key{};
            if (value.is_number_unsigned()) {
                auto number = value.get<std::uint64_t>();
                if (!std::in_range<key_type>(number)) return std::nullopt;
                return static_cast<key_type>(number);
            }
            if (value.is_number_integer()) {
                auto number = value.get<std::int64_t>();
                if (!std::in_range<key_type>(number)) return std::nullopt;
                return static_cast<key_type>(number);
            }
            if (value.is_string() && detail::parse_number(value.get_ref<const std::string&>(), key)) return key;
            return std::nullopt;
        }
    };

    // A cmdb object that exists exactly once (system/global, log.memory/setting, ...).
    template<typename Spec>
    struct Singleton {
        using type = typename Spec::type;

        static constexpr std::string_view path = Spec::path;

        static type get(const Query& query = {}, Client& client = default_client()) {
            auto body = client.get(path, query);
            const auto& result = detail::results(body, path);
            return detail::decode<type>(result.is_array() && !result.empty() ? result.front() : result, path);
        }

        static std::optional<Reply> update(type& object, const Query& query = {}, Client& client = default_client()) {
            if (!dirty(object)) return std::nullopt;
            Reply reply = Reply::from(client.put(path, to_json(object, Write::update), query));
            mark_clean(object);
            return reply;
        }

        static nlohmann::json schema(Client& client = default_client()) {
            return detail::results(client.get(path, Query().action("schema")), path);
        }
    };

}  // namespace fortiapi

#endif //FORTI_API_ENDPOINT_HPP
