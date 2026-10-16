//
// fortiapi::probe_tls: what a FortiGate presents in the TLS handshake, for trust on first use.
//
// A device with a self-signed or factory certificate fails verification until its consumer is told
// what to trust. probe_tls lets a person see the certificate first: it connects, completes the TLS
// handshake and stops. It never sends an HTTP request and never uses a credential (the API key and
// the client certificate of the Config are ignored).
//
// The first handshake verifies exactly as every request does (CA bundle or system trust store, and
// the host name). Only when that fails on the certificate does a second handshake run with
// verification off, to collect the chain for the person to inspect and, if they accept it, pin as
// the Config's ca_bundle. That second connection carries no data and is closed at once: never use it,
// or anything learned from it beyond the certificates, to talk to the device.
//

#ifndef FORTI_API_TLS_HPP
#define FORTI_API_TLS_HPP

#include "client.hpp"

#include <curl/curl.h>

#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace fortiapi {

    struct TlsProbe {
        bool trusted = false;            // the presented chain verified for the host against the configured trust
        int verify_code = 0;             // the libcurl code of the verifying handshake (0 when trusted)
        std::string verify_error;        // its message ("" when trusted)
        std::vector<std::string> chain;  // the certificates as presented, PEM, the device's own first
        std::string local_ip;            // this side's address of the connection, as the device sees it before any NAT
        std::string peer_ip;             // the address connected to (the host's, or resolve_ip)
    };

    namespace detail {

        // The PEM certificates of CURLINFO_CERTINFO ("Cert:" entries), in the order presented.
        inline std::vector<std::string> pem_chain(const curl_certinfo* info) {
            std::vector<std::string> chain;
            if (!info) return chain;
            for (int i = 0; i < info->num_of_certs; ++i)
                for (const curl_slist* entry = info->certinfo[i]; entry; entry = entry->next) {
                    std::string_view field(entry->data);
                    if (field.starts_with("Cert:") && field.find("-----BEGIN CERTIFICATE-----") != std::string_view::npos) {
                        std::string pem(field.substr(5));
                        if (!pem.ends_with('\n')) pem += '\n';
                        chain.push_back(std::move(pem));
                    }
                }
            return chain;
        }

        // The codes of a handshake that reached the peer and rejected its certificate (as opposed to
        // DNS, connect or timeout failures, which a probe reports as TransportError).
        constexpr bool certificate_rejected(CURLcode code) {
            return code == CURLE_PEER_FAILED_VERIFICATION || code == CURLE_SSL_ISSUER_ERROR ||
                   code == static_cast<CURLcode>(51);   // CURLE_SSL_PEER_CERTIFICATE (merged into 60 since 7.62)
        }

    }  // namespace detail

    // Connects to config.host:config.port (or config.resolve_ip, verifying for config.host) within
    // config.connect_timeout and returns what the handshake showed. Throws TransportError when no TLS
    // handshake was possible (DNS, connect, timeout, protocol), and when a CA bundle cannot be read.
    inline TlsProbe probe_tls(const Config& config) {
        struct HandleDeleter {
            void operator()(CURL* handle) const { curl_easy_cleanup(handle); }
        };
        struct SlistDeleter {
            void operator()(curl_slist* list) const { curl_slist_free_all(list); }
        };
        static const bool initialized = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
        (void) initialized;

        std::string host = config.host;
        std::string url = std::format("https://{}:{}/", host, config.port);
        std::unique_ptr<curl_slist, SlistDeleter> resolve;
        if (!config.resolve_ip.empty())
            resolve.reset(curl_slist_append(nullptr, std::format("{}:{}:{}", host, config.port, config.resolve_ip).c_str()));

        // One handshake, verifying or not. Returns the libcurl code; fills `probe` with what it saw.
        auto handshake = [&](bool verify, TlsProbe& probe, std::string& message) {
            std::unique_ptr<CURL, HandleDeleter> handle(curl_easy_init());
            if (!handle) throw TransportError("fortiapi: curl_easy_init failed", CURLE_FAILED_INIT, true);
            CURL* curl = handle.get();
            char error[CURL_ERROR_SIZE] = {};
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);   // the handshake, and no request
            curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);
            curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(config.connect_timeout.count()));
            curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(config.connect_timeout.count()) * 2);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify ? 1L : 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify ? 2L : 0L);
            if (verify && !config.ca_bundle.empty()) curl_easy_setopt(curl, CURLOPT_CAINFO, config.ca_bundle.c_str());
            if (resolve) curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve.get());
            CURLcode code = curl_easy_perform(curl);
            message = error[0] ? error : curl_easy_strerror(code);
            if (code == CURLE_OK) {
                curl_certinfo* info = nullptr;
                if (curl_easy_getinfo(curl, CURLINFO_CERTINFO, &info) == CURLE_OK) probe.chain = detail::pem_chain(info);
                char* local = nullptr;
                if (curl_easy_getinfo(curl, CURLINFO_LOCAL_IP, &local) == CURLE_OK && local) probe.local_ip = local;
                char* peer = nullptr;
                if (curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &peer) == CURLE_OK && peer) probe.peer_ip = peer;
            }
            return code;
        };

        TlsProbe probe;
        std::string message;
        CURLcode code = handshake(true, probe, message);
        if (code == CURLE_OK) {
            probe.trusted = true;
            return probe;
        }
        if (!detail::certificate_rejected(code))
            throw TransportError(std::format("TLS probe of {}:{}: {}", host, config.port, message), code, true);
        probe.verify_code = code;
        probe.verify_error = message;
        std::string unverified_message;
        CURLcode unverified = handshake(false, probe, unverified_message);
        if (unverified != CURLE_OK)
            throw TransportError(std::format("TLS probe of {}:{}: {}", host, config.port, unverified_message), unverified, true);
        return probe;
    }

}  // namespace fortiapi

#endif  // FORTI_API_TLS_HPP
