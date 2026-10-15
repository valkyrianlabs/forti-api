//
// fortiapi::Client: the HTTP transport for the FortiOS v2 REST API.
//
// Config (where and how to connect), Query (FortiOS query parameters), Error types, a Transport
// seam (CurlTransport in production, a fake in unit tests) and Client, which turns a method + path
// into a JSON result (or, with download(), raw bytes) and FortiOS errors into exceptions. Nothing
// here writes to stdout/stderr.
//

#ifndef FORTI_API_CLIENT_HPP
#define FORTI_API_CLIENT_HPP

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <exception>
#include <format>
#include <functional>
#include <limits>
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
    // A key that is exactly "." or ".." is sent as "%2E" / "%2E%2E": as a literal dot segment it would
    // address the table or its parent instead of an object (RFC 3986 dot-segment removal). Dots inside
    // a key ("10.0.0.0/24") stay readable.
    template<typename... Keys>
    std::string path(std::string_view base, const Keys&... keys) {
        std::string out(base);
        auto append = [&out](const auto& key) {
            out += '/';
            if constexpr (std::is_arithmetic_v<std::decay_t<decltype(key)>>) out += std::to_string(key);
            else {
                std::string_view text(key);
                if (text == ".") out += "%2E";
                else if (text == "..") out += "%2E%2E";
                else out += encode(text);
            }
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
            if (body.is_object() && body.contains("error") && body["error"].is_string())
                what += ": " + body["error"].get<std::string>();
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

    // A response body exceeded the byte limit of the request (DownloadOptions::max_bytes). The transfer
    // was aborted and what had arrived was discarded. Never retried.
    class SizeLimitError : public Error {
        std::size_t limit_;

    public:
        SizeLimitError(const std::string& what, std::size_t limit) : Error(what), limit_(limit) {}

        [[nodiscard]] std::size_t limit() const { return limit_; }
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
        // Deepest nesting of objects and arrays accepted in a JSON reply; a deeper 2xx reply is a
        // DecodeError. FortiOS replies nest well under 10 levels; the limit protects consumers that
        // copy, dump or walk replies recursively from a hostile or broken peer.
        std::size_t max_reply_depth = 256;

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
        // Set by Client::download(); exchange() leaves both at their defaults (no limit, no sink).
        std::size_t max_body = std::numeric_limits<std::size_t>::max();
        std::function<void(std::string_view)> on_body{};
    };

    struct HttpResponse {
        long status = 0;
        std::string body;
        std::vector<std::pair<std::string, std::string>> headers{};   // the final response's, as received

        // The first header with this name (case-insensitive), or "" when absent.
        [[nodiscard]] std::string header(std::string_view name) const {
            auto same = [](std::string_view a, std::string_view b) {
                if (a.size() != b.size()) return false;
                for (std::size_t i = 0; i < a.size(); ++i) {
                    auto lower = [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; };
                    if (lower(a[i]) != lower(b[i])) return false;
                }
                return true;
            };
            for (const auto& [key, value]: headers) if (same(key, name)) return value;
            return {};
        }
    };

    namespace detail {
        // Overwrites a buffer that may hold sensitive bytes, then empties it. Best effort: copies made
        // while the string grew are not reached.
        inline void wipe(std::string& text) {
            volatile char* data = text.data();
            for (std::size_t i = 0; i < text.size(); ++i) data[i] = 0;
            text.clear();
        }

        // Routes response body chunks for a transport: a 2xx body goes to request.on_body when set,
        // anything else into response.body, and never more than request.max_body bytes in total.
        // write() returns false when the transfer must stop: then `exceeded` or `error` (an exception
        // thrown by on_body) says why.
        class BodyWriter {
            const HttpRequest& request_;
            HttpResponse& response_;
            std::size_t received_ = 0;

        public:
            bool exceeded = false;
            std::exception_ptr error;

            BodyWriter(const HttpRequest& request, HttpResponse& response) : request_(request), response_(response) {}

            [[nodiscard]] std::size_t received() const { return received_; }

            bool write(std::string_view chunk, long status) {
                if (chunk.size() > request_.max_body - received_) {
                    exceeded = true;
                    return false;
                }
                received_ += chunk.size();
                if (request_.on_body && status >= 200 && status < 300) {
                    try {
                        request_.on_body(chunk);
                    } catch (...) {
                        error = std::current_exception();
                        return false;
                    }
                } else response_.body.append(chunk);
                return true;
            }
        };

        // Records one raw header line ("Name: value\r\n"). A status line ("HTTP/1.1 200 OK") starts
        // a new response (an interim or proxy reply came first): earlier headers are dropped. Returns
        // the status code of a status line, 0 otherwise.
        inline long header_line(HttpResponse& response, std::string_view line) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.remove_suffix(1);
            if (line.starts_with("HTTP/")) {
                response.headers.clear();
                auto space = line.find(' ');
                long status = 0;
                if (space == std::string_view::npos ||
                    std::from_chars(line.data() + space + 1, line.data() + line.size(), status).ec != std::errc())
                    return 0;
                return status;
            }
            auto colon = line.find(':');
            if (colon == std::string_view::npos || colon == 0) return 0;
            auto value = line.substr(colon + 1);
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
            response.headers.emplace_back(std::string(line.substr(0, colon)), std::string(value));
            return 0;
        }

        // Parses a reply body. nlohmann's parser is iterative, but copying, dumping or comparing the
        // resulting value recurses once per level, so a hostile body thousands of levels deep would
        // overflow the stack later. The parser callback sees each object or array open with the number
        // of enclosing containers, and parsing stops at the first one past `max_depth`: `too_deep` is
        // set and the result is discarded, as it is for invalid JSON.
        inline nlohmann::json parse_reply(std::string_view body, std::size_t max_depth, bool& too_deep) {
            struct TooDeep {};
            too_deep = false;
            nlohmann::json::parser_callback_t limit =
                    [max_depth](int depth, nlohmann::json::parse_event_t event, nlohmann::json&) {
                        bool opens = event == nlohmann::json::parse_event_t::object_start ||
                                     event == nlohmann::json::parse_event_t::array_start;
                        if (opens && static_cast<std::size_t>(depth) >= max_depth) throw TooDeep{};
                        return true;
                    };
            try {
                return nlohmann::json::parse(body, limit, false);
            } catch (const TooDeep&) {
                too_deep = true;
                return nlohmann::json(nlohmann::json::value_t::discarded);
            }
        }
    }  // namespace detail

    // Sends one HTTP request. Throws TransportError when no response arrived.
    //
    // A transport used with Client::download() should also honor the request's download fields, as
    // CurlTransport does (detail::BodyWriter implements both): stop reading once the body exceeds
    // `max_body` and throw SizeLimitError, and pass the body of a 2xx response to `on_body` in chunks
    // instead of storing it (other bodies still go into HttpResponse::body). It should fill
    // HttpResponse::headers. A transport that ignores these fields still works: the client then
    // enforces the limit and feeds the sink once the whole body has arrived in memory.
    class Transport {
    public:
        virtual ~Transport() = default;
        virtual HttpResponse perform(const HttpRequest& request) = 0;
    };

    // libcurl transport: one easy handle per client (kept alive between requests, TLS sessions
    // reused), serialized by a mutex. Reads share the kept-alive connection; each write (POST, PUT,
    // DELETE) gets a new connection that is closed after it, so libcurl can never re-send it.
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

        // Per-transfer state for the libcurl callbacks.
        struct Transfer {
            HttpResponse& response;
            detail::BodyWriter body;
            long status = 0;   // from the latest status line, so the body callback knows a 2xx reply
        };

        static size_t write(char* data, size_t size, size_t count, void* out) {
            auto* transfer = static_cast<Transfer*>(out);
            return transfer->body.write(std::string_view(data, size * count), transfer->status) ? size * count : 0;
        }

        static size_t header(char* data, size_t size, size_t count, void* out) {
            auto* transfer = static_cast<Transfer*>(out);
            if (long status = detail::header_line(transfer->response, std::string_view(data, size * count)))
                transfer->status = status;
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
            Transfer transfer{response, detail::BodyWriter(request, response)};
            char error[CURL_ERROR_SIZE] = {};
            bool mutation = request.method != Method::Get;
            curl_slist* list = nullptr;
            auto add = [&list](const std::string& header) {
                curl_slist* next = curl_slist_append(list, header.c_str());
                if (!next) {
                    curl_slist_free_all(list);
                    throw TransportError("fortiapi: out of memory building headers", CURLE_OUT_OF_MEMORY, true);
                }
                list = next;
            };
            for (const auto& header: request.headers) add(header);
            // No "Expect: 100-continue" on writes (libcurl adds it to bodies over 1 MiB): a 417 reply to
            // it makes libcurl send the request again.
            if (mutation) add("Expect:");
            Slist headers(list);

            curl_easy_setopt(curl, CURLOPT_URL, request.url.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &CurlTransport::write);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &transfer);
            curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &CurlTransport::header);
            curl_easy_setopt(curl, CURLOPT_HEADERDATA, &transfer);
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
            // The path is the SDK's (path() encodes keys): never let libcurl remove dot segments.
            curl_easy_setopt(curl, CURLOPT_PATH_AS_IS, 1L);

            // A write is never sent twice. libcurl re-sends a request on its own in two cases
            // (Curl_retry_request, lib/transfer.c, 8.5 through 8.7 at least): nothing came back on a
            // *reused* connection (taken for a stale keep-alive connection), or an HTTP/2 stream was
            // refused or answered HTTP_1_1_REQUIRED, which can happen on a new connection too. So a
            // write never takes a connection from the pool (FRESH_CONNECT: bits.reuse stays false),
            // never returns one to it (FORBID_REUSE: no write leaves a half-used connection behind),
            // and speaks HTTP/1.1 (no stream-level retries). A dropped reply then ends the transfer
            // with CURLE_GOT_NOTHING or a receive error, a TransportError with before_send() false,
            // and Client never retries it. The cost is one TCP + TLS handshake per write; reads keep
            // the kept-alive connection.
            if (mutation) {
                curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L);
                curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);
                curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, static_cast<long>(CURL_HTTP_VERSION_1_1));
            }

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
            if (code != CURLE_OK) detail::wipe(response.body);   // a partial body is never returned
            if (transfer.body.error) std::rethrow_exception(transfer.body.error);
            if (transfer.body.exceeded)
                throw SizeLimitError(std::format("{} {}: response body exceeds the limit of {} bytes",
                                                 to_string(request.method), request.url, request.max_body),
                                     request.max_body);
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

    // Options for Client::download().
    struct DownloadOptions {
        // The most body bytes accepted, buffered or streamed. A larger body aborts the transfer with a
        // SizeLimitError and nothing is returned.
        std::size_t max_bytes = 64 * 1024 * 1024;
        // When set, the body of a successful reply goes here in chunks and Download::body stays empty.
        // After an exception the sink may have received part of the body: discard it.
        std::function<void(std::string_view)> sink{};
    };

    // A raw reply: any bytes (text or binary), never decoded. A JSON error envelope with HTTP 2xx is
    // returned as is; check content_type when the endpoint can answer either way.
    struct Download {
        long http_status = 0;
        std::string content_type;          // "" when the device sent none
        std::string content_disposition;   // e.g. attachment; filename="..."
        std::string body;                  // empty when DownloadOptions::sink received it
        std::size_t bytes = 0;             // body size, also when streamed to a sink
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

        [[nodiscard]] HttpRequest make_request(Method method, std::string_view api_path, const Query& query,
                                               const nlohmann::json* body, std::string_view accept) const {
            HttpRequest request;
            request.method = method;
            request.url = url(api_path, query);
            request.headers = {std::format("Accept: {}", accept), "Authorization: Bearer " + config_.api_key};
            if (body) {
                request.headers.emplace_back("Content-Type: application/json");
                request.body = body->dump();
            }
            return request;
        }

        // Sends with the retry policy (see exchange()) and reports each reply to on_exchange. The record
        // carries the response body only when `trace_body` is true or the reply is not a 2xx. A GET whose
        // body already reached a sink (`*streamed` > 0) is not retried: the sink cannot take it back.
        HttpResponse send(const HttpRequest& request, bool trace_body, const std::size_t* streamed = nullptr) {
            for (unsigned attempt = 0;; ++attempt) {
                bool last = attempt >= config_.retries;
                auto started = std::chrono::steady_clock::now();
                HttpResponse response;
                try {
                    response = transport_->perform(request);
                } catch (const TransportError& error) {
                    bool fresh = !streamed || *streamed == 0;
                    bool safe = (request.method == Method::Get && fresh) || error.before_send();
                    if (last || !safe) throw;
                    sleep_before(attempt);
                    continue;
                }

                if (config_.on_exchange) {
                    bool success = response.status >= 200 && response.status < 300;
                    config_.on_exchange(Exchange{request.method, request.url, request.body, response.status,
                                                 trace_body || !success ? response.body : std::string(),
                                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                                         std::chrono::steady_clock::now() - started),
                                                 attempt});
                }

                if (request.method == Method::Get && retryable_status(response.status) && !last) {
                    sleep_before(attempt);
                    continue;
                }
                return response;
            }
        }

    public:
        explicit Client(Config config)
                : config_(std::move(config)), transport_(std::make_shared<CurlTransport>(config_)) {}

        Client(Config config, std::shared_ptr<Transport> transport)
                : config_(std::move(config)), transport_(std::move(transport)) {}

        [[nodiscard]] const Config& config() const { return config_; }

        // Sends a request and returns the parsed reply, including FortiOS error envelopes. Throws
        // TransportError when no reply arrived and DecodeError for a successful reply that is not JSON
        // or nests deeper than Config::max_reply_depth. An error reply (HTTP >= 400) that is not
        // usable JSON, for either reason, is returned as {"raw": body}.
        //
        // Retries: GET on transport errors and HTTP 429/502/503/504. POST/PUT/DELETE only when the
        // connection failed before the request was sent, never once it may have reached the device.
        Result exchange(Method method, std::string_view api_path, const Query& query = {},
                        const nlohmann::json* body = nullptr) {
            HttpResponse response = send(make_request(method, api_path, query, body, "application/json"), true);
            Result result{response.status, nullptr};
            if (!response.body.empty()) {
                bool too_deep = false;
                result.body = detail::parse_reply(response.body, config_.max_reply_depth, too_deep);
                if (result.body.is_discarded()) {
                    if (response.status >= 200 && response.status < 300) {
                        if (too_deep)
                            throw DecodeError(std::format("{} {}: HTTP {} with JSON nested deeper than {} levels",
                                                          to_string(method), api_path, response.status,
                                                          config_.max_reply_depth));
                        throw DecodeError(std::format("{} {}: HTTP {} with a non-JSON body", to_string(method),
                                                      api_path, response.status));
                    }
                    result.body = {{"raw", response.body}};
                }
            }
            return result;
        }

        // Sends a request and returns the reply body as raw bytes (file downloads such as a configuration
        // backup), with the same transport, authentication, TLS, timeouts and retry policy as exchange().
        // A transport error after part of the body reached the sink is not retried.
        //
        // HTTP outside 2xx throws ApiError (its body parsed when it is JSON within
        // Config::max_reply_depth, else {"raw": ...}); a body over options.max_bytes throws
        // SizeLimitError. The on_exchange record of a 2xx reply never carries the body: downloads can
        // be secrets.
        Download download(Method method, std::string_view api_path, const Query& query, const nlohmann::json* body,
                          DownloadOptions options = {}) {
            HttpRequest request = make_request(method, api_path, query, body, "*/*");
            Download result;
            request.max_body = options.max_bytes;
            if (options.sink)
                request.on_body = [&](std::string_view chunk) {
                    result.bytes += chunk.size();
                    options.sink(chunk);
                };

            auto too_large = [&] {
                return SizeLimitError(std::format("{} {}: response body exceeds the limit of {} bytes",
                                                  to_string(method), api_path, options.max_bytes),
                                      options.max_bytes);
            };
            HttpResponse response;
            try {
                response = send(request, false, &result.bytes);
            } catch (const SizeLimitError&) {
                throw too_large();   // the same message whichever transport stopped the transfer
            }
            if (response.status < 200 || response.status >= 300) {
                nlohmann::json error = nullptr;
                if (!response.body.empty()) {
                    bool too_deep = false;
                    error = detail::parse_reply(response.body, config_.max_reply_depth, too_deep);
                    if (error.is_discarded()) error = {{"raw", response.body}};
                }
                throw ApiError(method, std::string(api_path), response.status, std::move(error));
            }
            // A transport that ignores max_body / on_body returned the whole body in memory.
            if (response.body.size() > options.max_bytes) {
                detail::wipe(response.body);
                throw too_large();
            }
            if (options.sink && !response.body.empty()) {
                result.bytes += response.body.size();
                options.sink(response.body);
                detail::wipe(response.body);
            } else if (!options.sink) {
                result.bytes = response.body.size();
                result.body = std::move(response.body);
            }
            result.http_status = response.status;
            result.content_type = response.header("Content-Type");
            result.content_disposition = response.header("Content-Disposition");
            return result;
        }

        // GET as raw bytes; see the overload above.
        Download download(std::string_view api_path, const Query& query = {}, DownloadOptions options = {}) {
            return download(Method::Get, api_path, query, nullptr, std::move(options));
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
