//
// A scripted Transport for network-free tests: records every request, replays queued responses.
//

#ifndef FORTI_API_TESTS_FAKE_TRANSPORT_HPP
#define FORTI_API_TESTS_FAKE_TRANSPORT_HPP

#include <forti_api/client.hpp>

#include <deque>
#include <variant>

namespace fortiapi::testing {

    class FakeTransport final : public Transport {
    public:
        using Step = std::variant<HttpResponse, TransportError>;

        std::vector<HttpRequest> requests;
        std::deque<Step> script;
        // 0: return bodies whole and ignore HttpRequest::max_body / on_body, like a transport written
        // before downloads existed. Otherwise deliver bodies in chunks of this size through
        // detail::BodyWriter, honoring both, like CurlTransport.
        std::size_t chunk = 0;
        // Bytes delivered to a sink before each scripted TransportError (a connection lost mid-body).
        std::string partial;

        FakeTransport& reply(long status, std::string body) {
            script.emplace_back(HttpResponse{status, std::move(body)});
            return *this;
        }

        FakeTransport& reply(HttpResponse response) {
            script.emplace_back(std::move(response));
            return *this;
        }

        FakeTransport& reply(long status, const nlohmann::json& body) { return reply(status, body.dump()); }

        FakeTransport& fail(int code, bool before_send) {
            script.emplace_back(TransportError("scripted transport failure", code, before_send));
            return *this;
        }

        HttpResponse perform(const HttpRequest& request) override {
            requests.push_back(request);
            if (script.empty()) throw std::logic_error("FakeTransport: no scripted response left");
            Step step = std::move(script.front());
            script.pop_front();
            if (auto* error = std::get_if<TransportError>(&step)) {
                if (!partial.empty() && request.on_body) request.on_body(partial);
                throw *error;
            }
            auto scripted = std::get<HttpResponse>(std::move(step));
            if (chunk == 0) return scripted;

            HttpResponse response{scripted.status, {}, scripted.headers};
            detail::BodyWriter writer(request, response);
            std::string_view body = scripted.body;
            for (std::size_t at = 0; at < body.size(); at += chunk) {
                if (writer.write(body.substr(at, chunk), scripted.status)) continue;
                detail::wipe(response.body);
                if (writer.error) std::rethrow_exception(writer.error);
                throw SizeLimitError("FakeTransport: body over the limit", request.max_body);
            }
            return response;
        }
    };

    inline Config test_config() {
        Config config;
        config.host = "fortigate.test";
        config.port = 8443;
        config.api_key = "test-key";
        config.retry_backoff = std::chrono::milliseconds(0);
        return config;
    }

    inline nlohmann::json envelope(nlohmann::json results, long status = 200) {
        return {{"http_method", "GET"}, {"status", status < 400 ? "success" : "error"}, {"http_status", status},
                {"results", std::move(results)}, {"vdom", "root"}, {"version", "v7.4.8"}, {"build", 2795}};
    }

}  // namespace fortiapi::testing

#endif //FORTI_API_TESTS_FAKE_TRANSPORT_HPP
