//
// fortiapi::Client: the HTTP transport for the FortiOS v2 REST API.
//
// Config (where and how to connect), Query (FortiOS query parameters), Error types, a Transport
// seam (CurlTransport in production, a fake in unit tests) and Client, which turns a method + path
// into a JSON result and FortiOS errors into exceptions. Nothing here writes to stdout/stderr.
//

#ifndef FORTI_API_CLIENT_HPP
#define FORTI_API_CLIENT_HPP

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <charconv>
#include <chrono>
#include <cstdlib>
#include <format>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace fortiapi {

    enum class Method { Get, Post, Put, Delete };

    constexpr std::string_view to_string(Method method) {
        switch (method) {
            case Method::Get: return "GET";
            case Method::Post: return "POST";
            case Method::Put: return "PUT";
            case Method::Delete: return "DELETE";
        }
        return "GET";
    }

    // Percent-encodes everything except RFC 3986 unreserved characters, so an object name such as
    // "10.0.0.0/24" stays one path segment ("10.0.0.0%2F24").
    inline std::string encode(std::string_view text) {
        static constexpr char hex[] = "0123456789ABCDEF";
        std::string out;
        out.reserve(text.size());
        for (unsigned char c: text) {
            bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                              c == '-' || c == '.' || c == '_' || c == '~';
            if (unreserved) out += static_cast<char>(c);
            else {
                out += '%';
                out += hex[c >> 4];
                out += hex[c & 15];
            }
        }
        return out;
    }

    // `base` is a literal API path ("cmdb/firewall/policy"); each key is one encoded path segment.
    template<typename... Keys>
    std::string path(std::string_view base, const Keys&... keys) {
        std::string out(base);
        auto append = [&out](const auto& key) {
            out += '/';
            if constexpr (std::is_arithmetic_v<std::decay_t<decltype(key)>>) out += std::to_string(key);
            else out += encode(std::string_view(key));
        };
        (append(keys), ...);
        return out;
    }

    // FortiOS query parameters. Repeated filter() calls are ANDed by FortiOS; use "," inside one
    // expression for OR ("name==a,name==b").
    class Query {
        std::vector<std::pair<std::string, std::string>> params_;

    public:
        Query& set(std::string key, std::string value) {
            params_.emplace_back(std::move(key), std::move(value));
            return *this;
        }

        Query& vdom(std::string name) { return set("vdom", std::move(name)); }
        Query& filter(std::string expression) { return set("filter", std::move(expression)); }
        Query& start(std::size_t index) { return set("start", std::to_string(index)); }
        Query& count(std::size_t items) { return set("count", std::to_string(items)); }
        Query& datasource(bool on = true) { return set("datasource", on ? "1" : "0"); }
        Query& with_meta(bool on = true) { return set("with_meta", on ? "1" : "0"); }
        Query& skip(bool on = true) { return set("skip", on ? "1" : "0"); }
        Query& action(std::string name) { return set("action", std::move(name)); }

        // Restricts the returned fields ("name|policyid").
        Query& format(std::initializer_list<std::string_view> fields) {
            std::string joined;
            for (auto field: fields) {
                if (!joined.empty()) joined += '|';
                joined += field;
            }
            return set("format", std::move(joined));
        }

        [[nodiscard]] bool empty() const { return params_.empty(); }

        [[nodiscard]] bool has(std::string_view key) const {
            for (const auto& [k, v]: params_) if (k == key) return true;
            return false;
        }

        [[nodiscard]] std::string encoded() const {
            std::string out;
            for (const auto& [key, value]: params_) {
                if (!out.empty()) out += '&';
                out += encode(key);
                out += '=';
                out += encode(value);
            }
            return out;
        }
    };

    class Error : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    // The request did not complete (DNS, connect, TLS, timeout). `before_send()` is true when the
    // connection failed before any request byte could have reached the device.
    class TransportError : public Error {
        int code_;
        bool before_send_;

    public:
        TransportError(const std::string& what, int code, bool before_send)
                : Error(what), code_(code), before_send_(before_send) {}

        [[nodiscard]] int code() const { return code_; }
        [[nodiscard]] bool before_send() const { return before_send_; }
    };

    // The device answered with an error: HTTP >= 400, or a JSON envelope with "status": "error".
    class ApiError : public Error {
        Method method_;
        std::string path_;
        long http_status_;
        nlohmann::json body_;

        static std::string describe(Method method, std::string_view path, long status, const nlohmann::json& body) {
            std::string what = std::format("{} {}: HTTP {}", to_string(method), path, status);
            if (body.is_object() && body.contains("error") && body["error"].is_number_integer())
                what += std::format(", FortiOS error {}", body["error"].get<int>());
            if (body.is_object() && body.contains("cli_error") && body["cli_error"].is_array())
                for (const auto& line: body["cli_error"]) if (line.is_string()) what += "; " + line.get<std::string>();
            return what;
        }

    public:
        ApiError(Method method, std::string path, long http_status, nlohmann::json body)
                : Error(describe(method, path, http_status, body)), method_(method), path_(std::move(path)),
                  http_status_(http_status), body_(std::move(body)) {}

        [[nodiscard]] Method method() const { return method_; }
        [[nodiscard]] const std::string& path() const { return path_; }
        [[nodiscard]] long http_status() const { return http_status_; }
        [[nodiscard]] const nlohmann::json& body() const { return body_; }
        [[nodiscard]] bool not_found() const { return http_status_ == 404; }

        // FortiOS internal error code (e.g. -3 "entry not found"), 0 when absent.
        [[nodiscard]] int fortios_error() const {
            return body_.is_object() && body_.contains("error") && body_["error"].is_number_integer()
                   ? body_["error"].get<int>() : 0;
        }
    };

    // A 2xx response whose body is not the JSON the caller expected.
    class DecodeError : public Error {
    public:
        using Error::Error;
    };

    // One request/response pair, passed to Config::on_exchange. Credentials never appear here: the
    // API key travels in a header that is not part of the record.
    struct Exchange {
        Method method;
        std::string url;
        std::string request_body;
        long http_status = 0;
        std::string response_body;
        std::chrono::milliseconds elapsed{};
        unsigned attempt = 0;
    };

    struct Config {
        std::string host;                   // hostname or IP of the FortiGate
        unsigned port = 443;                // admin HTTPS port
        std::string api_key;                // REST API administrator token
        std::string ca_bundle;              // PEM bundle; empty = system trust store
        std::string client_cert;            // PKCS#12 client certificate; empty = none
        std::string client_cert_password;
        std::string resolve_ip;             // connect here while verifying TLS for `host`
        std::string vdom;                   // default VDOM for every request; empty = device default
        std::chrono::milliseconds connect_timeout{5000};
        std::chrono::milliseconds timeout{30000};
        unsigned retries = 2;               // extra attempts for safe-to-retry failures
        std::chrono::milliseconds retry_backoff{500};
        std::function<void(const Exchange&)> on_exchange;

        // FORTIGATE_HOST (or FORTIGATE_GATEWAY_IP), FORTIGATE_ADMIN_HTTPS_PORT, FORTIGATE_API_KEY,
        // PATH_TO_FORTIGATE_CA_CERT, PATH_TO_FORTIGATE_SSL_CERT, FORTIGATE_SSL_CERT_PASS,
        // FORTIGATE_RESOLVE_IP, FORTIGATE_VDOM. Unset or empty optional variables keep the defaults.
        static Config from_env() {
            auto var = [](const char* name) -> std::string {
                const char* value = std::getenv(name);
                return value ? value : "";
            };
            auto require = [&](const char* name, const std::string& value) {
                if (value.empty()) throw Error(std::format("fortiapi: environment variable {} is not set", name));
                return value;
            };

            Config config;
            std::string host = var("FORTIGATE_HOST");
            config.host = require("FORTIGATE_HOST", host.empty() ? var("FORTIGATE_GATEWAY_IP") : host);
            config.api_key = require("FORTIGATE_API_KEY", var("FORTIGATE_API_KEY"));
            if (auto port = var("FORTIGATE_ADMIN_HTTPS_PORT"); !port.empty()) {
                auto [end, ec] = std::from_chars(port.data(), port.data() + port.size(), config.port);
                if (ec != std::errc() || end != port.data() + port.size() || config.port == 0 || config.port > 65535)
                    throw Error("fortiapi: FORTIGATE_ADMIN_HTTPS_PORT is not a port number: " + port);
            }
            config.ca_bundle = var("PATH_TO_FORTIGATE_CA_CERT");
            config.client_cert = var("PATH_TO_FORTIGATE_SSL_CERT");
            config.client_cert_password = var("FORTIGATE_SSL_CERT_PASS");
            config.resolve_ip = var("FORTIGATE_RESOLVE_IP");
            config.vdom = var("FORTIGATE_VDOM");
            return config;
        }
    };

    struct HttpRequest {
        Method method = Method::Get;
        std::string url;
        std::vector<std::string> headers;
        std::string body;
    };

    struct HttpResponse {
        long status = 0;
        std::string body;
    };

    // Sends one HTTP request. Throws TransportError when no response arrived.
    class Transport {
    public:
        virtual ~Transport() = default;
        virtual HttpResponse perform(const HttpRequest& request) = 0;
    };

    // libcurl transport: one easy handle per client (kept alive between requests, TLS sessions
    // reused), serialized by a mutex.
    class CurlTransport final : public Transport {
        struct GlobalInit {
            GlobalInit() { curl_global_init(CURL_GLOBAL_DEFAULT); }
        };

        struct SlistDeleter {
            void operator()(curl_slist* list) const { curl_slist_free_all(list); }
        };
        using Slist = std::unique_ptr<curl_slist, SlistDeleter>;

        struct HandleDeleter {
            void operator()(CURL* handle) const { curl_easy_cleanup(handle); }
        };

        Config config_;
        std::unique_ptr<CURL, HandleDeleter> handle_;
        Slist resolve_;
        std::mutex mutex_;

        static size_t write(char* data, size_t size, size_t count, void* out) {
            static_cast<std::string*>(out)->append(data, size * count);
            return size * count;
        }

        static bool fails_before_send(CURLcode code) {
            return code == CURLE_COULDNT_RESOLVE_HOST || code == CURLE_COULDNT_CONNECT ||
                   code == CURLE_SSL_CONNECT_ERROR || code == CURLE_PEER_FAILED_VERIFICATION ||
                   code == CURLE_SSL_CACERT_BADFILE || code == CURLE_SSL_CERTPROBLEM;
        }

    public:
        explicit CurlTransport(Config config) : config_(std::move(config)) {
            static GlobalInit init;
            handle_.reset(curl_easy_init());
            if (!handle_) throw TransportError("fortiapi: curl_easy_init failed", CURLE_FAILED_INIT, true);
            if (!config_.resolve_ip.empty())
                resolve_.reset(curl_slist_append(nullptr, std::format("{}:{}:{}", config_.host, config_.port,
                                                                      config_.resolve_ip).c_str()));
        }

        HttpResponse perform(const HttpRequest& request) override {
            std::lock_guard lock(mutex_);
            CURL* curl = handle_.get();
            // Keeps live connections, TLS session and DNS caches; clears per-request options.
            curl_easy_reset(curl);

            HttpResponse response;
            char error[CURL_ERROR_SIZE] = {};
            curl_slist* list = nullptr;
            for (const auto& header: request.headers) {
                curl_slist* next = curl_slist_append(list, header.c_str());
                if (!next) {
                    curl_slist_free_all(list);
                    throw TransportError("fortiapi: out of memory building headers", CURLE_OUT_OF_MEMORY, true);
                }
                list = next;
            }
            Slist headers(list);

            curl_easy_setopt(curl, CURLOPT_URL, request.url.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &CurlTransport::write);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
            curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
            curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
            // gzip only: FortiOS answers some endpoints (log/*) with a deflate stream libcurl cannot decode.
            curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(config_.connect_timeout.count()));
            curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(config_.timeout.count()));
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
            if (!config_.ca_bundle.empty()) curl_easy_setopt(curl, CURLOPT_CAINFO, config_.ca_bundle.c_str());
            if (!config_.client_cert.empty()) {
                curl_easy_setopt(curl, CURLOPT_SSLCERT, config_.client_cert.c_str());
                curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "P12");
                curl_easy_setopt(curl, CURLOPT_KEYPASSWD, config_.client_cert_password.c_str());
            }
            if (resolve_) curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve_.get());

            switch (request.method) {
                case Method::Get:
                    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
                    break;
                case Method::Post:
                case Method::Put:
                    if (request.method == Method::Put) curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(request.body.size()));
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.body.c_str());
                    break;
                case Method::Delete:
                    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
                    break;
            }

            CURLcode code = curl_easy_perform(curl);
            if (code != CURLE_OK)
                throw TransportError(std::format("{} {}: {}", to_string(request.method), request.url,
                                                 error[0] ? error : curl_easy_strerror(code)),
                                     code, fails_before_send(code));
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);
            return response;
        }
    };

    // The parsed reply. `ok()` is false for HTTP >= 400 and for envelopes with "status": "error".
    struct Result {
        long http_status = 0;
        nlohmann::json body;

        [[nodiscard]] bool ok() const {
            if (http_status < 200 || http_status >= 300) return false;
            return !(body.is_object() && body.value("status", "") == "error");
        }
    };

    class Client {
        Config config_;
        std::shared_ptr<Transport> transport_;

        static bool retryable_status(long status) {
            return status == 429 || status == 502 || status == 503 || status == 504;
        }

        [[nodiscard]] std::string url(std::string_view api_path, const Query& query) const {
            while (api_path.starts_with('/')) api_path.remove_prefix(1);
            std::string out = std::format("https://{}:{}/api/v2/{}", config_.host, config_.port, api_path);
            Query effective = query;
            if (!config_.vdom.empty() && !query.has("vdom")) effective.vdom(config_.vdom);
            if (!effective.empty()) out += "?" + effective.encoded();
            return out;
        }

        void sleep_before(unsigned attempt) const {
            if (config_.retry_backoff.count() > 0) std::this_thread::sleep_for(config_.retry_backoff * (1u << attempt));
        }

    public:
        explicit Client(Config config)
                : config_(std::move(config)), transport_(std::make_shared<CurlTransport>(config_)) {}

        Client(Config config, std::shared_ptr<Transport> transport)
                : config_(std::move(config)), transport_(std::move(transport)) {}

        [[nodiscard]] const Config& config() const { return config_; }

        // Sends a request and returns the parsed reply, including FortiOS error envelopes. Throws
        // TransportError when no reply arrived and DecodeError for a successful non-JSON reply.
        //
        // Retries: GET on transport errors and HTTP 429/502/503/504. POST/PUT/DELETE only when the
        // connection failed before the request was sent, never once it may have reached the device.
        Result exchange(Method method, std::string_view api_path, const Query& query = {},
                        const nlohmann::json* body = nullptr) {
            HttpRequest request;
            request.method = method;
            request.url = url(api_path, query);
            request.headers = {"Accept: application/json", "Authorization: Bearer " + config_.api_key};
            if (body) {
                request.headers.emplace_back("Content-Type: application/json");
                request.body = body->dump();
            }

            for (unsigned attempt = 0;; ++attempt) {
                bool last = attempt >= config_.retries;
                auto started = std::chrono::steady_clock::now();
                HttpResponse response;
                try {
                    response = transport_->perform(request);
                } catch (const TransportError& error) {
                    bool safe = method == Method::Get || error.before_send();
                    if (last || !safe) throw;
                    sleep_before(attempt);
                    continue;
                }

                if (config_.on_exchange)
                    config_.on_exchange(Exchange{method, request.url, request.body, response.status, response.body,
                                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                                         std::chrono::steady_clock::now() - started),
                                                 attempt});

                if (method == Method::Get && retryable_status(response.status) && !last) {
                    sleep_before(attempt);
                    continue;
                }

                Result result{response.status, nullptr};
                if (!response.body.empty()) {
                    result.body = nlohmann::json::parse(response.body, nullptr, false);
                    if (result.body.is_discarded()) {
                        if (response.status >= 200 && response.status < 300)
                            throw DecodeError(std::format("{} {}: HTTP {} with a non-JSON body", to_string(method),
                                                          api_path, response.status));
                        result.body = {{"raw", response.body}};
                    }
                }
                return result;
            }
        }

        // Like exchange(), but a FortiOS error becomes an ApiError. Returns the full envelope.
        nlohmann::json request(Method method, std::string_view api_path, const Query& query = {},
                               const nlohmann::json* body = nullptr) {
            Result result = exchange(method, api_path, query, body);
            if (!result.ok()) throw ApiError(method, std::string(api_path), result.http_status, std::move(result.body));
            return std::move(result.body);
        }

        nlohmann::json get(std::string_view api_path, const Query& query = {}) {
            return request(Method::Get, api_path, query);
        }

        nlohmann::json post(std::string_view api_path, const nlohmann::json& body, const Query& query = {}) {
            return request(Method::Post, api_path, query, &body);
        }

        nlohmann::json put(std::string_view api_path, const nlohmann::json& body, const Query& query = {}) {
            return request(Method::Put, api_path, query, &body);
        }

        nlohmann::json del(std::string_view api_path, const Query& query = {}) {
            return request(Method::Delete, api_path, query);
        }
    };

    namespace detail {
        inline std::mutex default_client_mutex;
        inline std::shared_ptr<Client> default_client;
    }

    // Replaces the process-wide client used when no Client is passed explicitly.
    inline void set_default_client(std::shared_ptr<Client> client) {
        std::lock_guard lock(detail::default_client_mutex);
        detail::default_client = std::move(client);
    }

    // The process-wide client, created from Config::from_env() on first use. Set it up front with
    // set_default_client() when the environment is not the configuration source.
    inline Client& default_client() {
        std::lock_guard lock(detail::default_client_mutex);
        if (!detail::default_client) detail::default_client = std::make_shared<Client>(Config::from_env());
        return *detail::default_client;
    }

}  // namespace fortiapi

#endif //FORTI_API_CLIENT_HPP
