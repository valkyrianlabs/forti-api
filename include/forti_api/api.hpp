//
// Created by Cooper Larson on 8/26/24.
//

#ifndef FORTI_API_API_HPP
#define FORTI_API_API_HPP

#include <string>
#include <nlohmann/json.hpp>
#include <iostream>
#include <format>
#include <curl/curl.h>
#include <algorithm>
#include <cctype>
#include <utility>
#include <cstdlib>
#include <stdexcept>
#include <regex>
#include "types/response.h"

inline static std::regex ipv4("(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])");
inline static std::regex ipv6("((([0-9a-fA-F]){1,4})\\:){7}([0-9a-fA-F]){1,4}");

inline static nlohmann::json convert_keys_to_hyphens(const nlohmann::json& j) {
    nlohmann::json result;

    std::array<std::string, 10> ignore_keys{
            "q_origin_key"
    };

    for (auto it = j.begin(); it != j.end(); ++it) {
        std::string key = it.key();

        // Ignore certain keys
        bool should_process = true;
        for (const auto& ignore : ignore_keys) {
            if (key == ignore) {
                should_process = false;
                break;
            }
        }
        if (!should_process) continue;

        // Replace underscores with hyphens in the key
        std::replace(key.begin(), key.end(), '_', '-');

        // Recursively process objects and arrays
        if (it->is_object()) result[key] = convert_keys_to_hyphens(*it);
        else if (it->is_array()) {
            nlohmann::json array_result = nlohmann::json::array();
            for (const auto& elem : *it) {  // Use *it instead of it.value()
                if (elem.is_object()) array_result.push_back(convert_keys_to_hyphens(elem));
                else array_result.push_back(elem);  // Directly add the element if it's not an object
            }
            result[key] = array_result;
        } else result[key] = *it;  // Directly copy the value if it's neither an object nor array
    }

    return result;
}

inline static nlohmann::json convert_keys_to_underscores(const nlohmann::json& j) {
    nlohmann::json result;

    for (auto it = j.begin(); it != j.end(); ++it) {
        std::string key = it.key();
        std::replace(key.begin(), key.end(), '-', '_');

        if (it->is_object()) result[key] = convert_keys_to_underscores(*it);
        else if (it->is_array()) {
            nlohmann::json array_result = nlohmann::json::array();
            for (const auto& elem : *it) {  // Use *it instead of it.value()
                if (elem.is_object()) array_result.push_back(convert_keys_to_underscores(elem));
                else array_result.push_back(elem);  // Directly add the element if it's not an object
            }
            result[key] = array_result;
        } else result[key] = *it;  // Directly copy the value if it's neither an object nor array
    }

    return result;
}

class FortiAuth {
    inline static unsigned int admin_https_port = 0;
    inline static std::string gateway_ip;
    inline static std::string ca_cert_path;
    inline static std::string ssl_cert_path;
    inline static std::string cert_password;
    inline static std::string api_key;
    inline static std::string auth_header;

    static std::string check_env(const char* env_var_name) {
        const char* value = std::getenv(env_var_name);
        if (value == nullptr) {
            std::cerr << "[DEBUG] Missing required field: '" << env_var_name << "'. Please set this in your environment.\n";
            return "";
        }
        return value;
    }

public:
    inline static bool PROGRAM_IS_RUNNING = false;

    static void set_vars_from_env() {
        set_admin_https_port(std::stoi(check_env("FORTIGATE_ADMIN_HTTPS_PORT")));
        set_gateway_ip(check_env("FORTIGATE_GATEWAY_IP"));
        set_ca_cert_path(check_env("PATH_TO_FORTIGATE_CA_CERT"));
        set_ssl_cert_path(check_env("PATH_TO_FORTIGATE_SSL_CERT"));
        set_cert_password(check_env("FORTIGATE_SSL_CERT_PASS"));
        set_api_key(check_env("FORTIGATE_API_KEY"));
        set_auth_header();
    }

    static void set_admin_https_port(unsigned int port) { admin_https_port = port; }

    static void set_gateway_ip(const std::string& ip) { gateway_ip = ip; }

    static void set_ca_cert_path(const std::string& path) { ca_cert_path = path; }

    static void set_ssl_cert_path(const std::string& path) { ssl_cert_path = path; }

    static void set_cert_password(const std::string& password) { cert_password = password; }

    static void set_api_key(const std::string& key) {
        api_key = key;
        set_auth_header();
    }

    static void set_auth_header() { if (!api_key.empty()) auth_header = "Authorization: Bearer " + api_key; }

    static unsigned int get_admin_https_port() {
        if (PROGRAM_IS_RUNNING && admin_https_port == 0) {
            std::cerr << "[WARNING] admin_ssh_port is uninitialized!\n";
        }
        return admin_https_port;
    }

    static std::string get_gateway_ip() {
        if (PROGRAM_IS_RUNNING && gateway_ip.empty()) std::cerr << "[WARNING] gateway_ip is uninitialized!\n";
        return gateway_ip;
    }

    static std::string get_ca_cert_path() {
        if (PROGRAM_IS_RUNNING && ca_cert_path.empty()) std::cerr << "[WARNING] ca_cert_path is uninitialized!\n";
        return ca_cert_path;
    }

    static std::string get_ssl_cert_path() {
        if (PROGRAM_IS_RUNNING && ssl_cert_path.empty()) std::cerr << "[WARNING] ssl_cert_path is uninitialized!\n";
        return ssl_cert_path;
    }

    static std::string get_cert_password() {
        if (PROGRAM_IS_RUNNING && cert_password.empty()) std::cerr << "[WARNING] cert_password is uninitialized!\n";
        return cert_password;
    }

    static std::string get_api_key() {
        if (PROGRAM_IS_RUNNING && api_key.empty()) std::cerr << "[WARNING] api_key is uninitialized!\n";
        return api_key;
    }

    static std::string get_auth_header() {
        if (PROGRAM_IS_RUNNING && auth_header.empty()) std::cerr << "[WARNING] auth_header is uninitialized!\n";
        return auth_header;
    }
};


class FortiAPI {
    inline static std::string BASE_API_ENDPOINT() {
        return std::format("https://{}:{}/api/v2", FortiAuth::get_gateway_ip(), FortiAuth::get_admin_https_port());
    }

    static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    static int curl_debug_callback(CURL *handle, curl_infotype type, char *data, size_t size, void *userptr) {
        switch (type) {
            case CURLINFO_TEXT:
                std::cerr << "== Info: " << std::string(data, size);
                break;
            case CURLINFO_HEADER_OUT:
                std::cerr << "=> Send header: " << std::string(data, size);
                break;
            case CURLINFO_DATA_OUT:
                std::cerr << "=> Send data: " << std::string(data, size);
                break;
            case CURLINFO_SSL_DATA_OUT:
                std::cerr << "=> Send SSL data: " << std::string(data, size);
                break;
            case CURLINFO_HEADER_IN:
                std::cerr << "<= Recv header: " << std::string(data, size);
                break;
            case CURLINFO_DATA_IN:
                std::cerr << "<= Recv data: " << std::string(data, size);
                break;
            case CURLINFO_SSL_DATA_IN:
                std::cerr << "<= Recv SSL data: " << std::string(data, size);
                break;
            default:
                break;
        }
        return 0;
    }

    template<typename T>
    static T request(const std::string &method, const std::string &path, const nlohmann::json &data = {}) {
        if (!FortiAuth::PROGRAM_IS_RUNNING) FortiAuth::PROGRAM_IS_RUNNING = true;

        CURL *curl;
        CURLcode res;
        std::string readBuffer;

        curl = curl_easy_init();
        if (curl) {
            std::string url = BASE_API_ENDPOINT() + path;

            struct curl_slist *headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            headers = curl_slist_append(headers, FortiAuth::get_auth_header().c_str());

            curl_easy_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE, 1L);
            curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 0L);
            curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 0L);
            curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, -1);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
            curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "P12");  // Explicitly set certificate type to P12
            curl_easy_setopt(curl, CURLOPT_CAINFO, FortiAuth::get_ca_cert_path().c_str());
            curl_easy_setopt(curl, CURLOPT_SSLCERT, FortiAuth::get_ssl_cert_path().c_str());
            curl_easy_setopt(curl, CURLOPT_KEYPASSWD, FortiAuth::get_cert_password().c_str());

            std::string json_payload = convert_keys_to_hyphens(data).dump();  // do not simplify by deleting this
            if (method == "POST" || method == "PUT")
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload.c_str());

            if (method != "POST" && method != "GET")
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());

#ifdef ENABLE_DEBUG
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
            curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_debug_callback);
            curl_easy_setopt(curl, CURLOPT_DEBUGDATA, nullptr);
#endif

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            curl_easy_cleanup(curl);
        }

        return convert_keys_to_underscores(nlohmann::json::parse(readBuffer));
    }

    static Response validate(const std::string &method, const std::string &path, const nlohmann::json &data = {}) {
        auto response = request<Response>(method, path, data);
        if (response.status != "success") std::cerr << nlohmann::json(response).dump(4) << std::endl;
        return response;
    }

public:
    template<typename T>
    static T get(const std::string &path) { return request<T>("GET", path); }

    static Response post(const std::string &path, const nlohmann::json &data) { return validate("POST", path, data); }
    static Response put(const std::string &path, const nlohmann::json &data) { return validate("PUT", path, data); }
    static Response del(const std::string &path) { return validate("DELETE", path); }
};

#endif //FORTI_API_API_HPP
