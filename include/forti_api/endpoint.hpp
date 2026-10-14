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
// Every call takes an optional Query (vdom, filter, format, ...) and Client (default_client()).
//

#ifndef FORTI_API_ENDPOINT_HPP
#define FORTI_API_ENDPOINT_HPP

#include "client.hpp"
#include "field.hpp"

#include <optional>
#include <string>
#include <vector>

namespace fortiapi {

    // The metadata FortiOS returns with every write.
    struct Reply {
        long http_status = 0;
        std::string status, revision, vdom, path, name, serial, version;
        nlohmann::json mkey;   // the created object's key (string or number), when reported
        long build = 0;

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
            if (auto it = body.find("mkey"); it != body.end()) reply.mkey = *it;
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

    }  // namespace detail

    // A cmdb table: a collection of objects addressed by a key (mkey).
    template<typename Spec>
    struct Table {
        using type = typename Spec::type;
        using key_type = typename detail::member_traits<std::remove_cv_t<decltype(Spec::key)>>::field::value_type;

        static constexpr std::string_view path = Spec::path;

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
