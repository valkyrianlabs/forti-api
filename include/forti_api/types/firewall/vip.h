//
// Created by Cooper Larson on 3/24/25.
//
#ifndef FORTI_API_VIP_H
#define FORTI_API_VIP_H

#include <nlohmann/json.hpp>
#include <string>
#include <vector>

using json = nlohmann::json;

struct QuicConfig {
    int max_idle_timeout, max_udp_payload_size, active_connection_id_limit,
            ack_delay_exponent, max_ack_delay, max_datagram_frame_size;
    std::string active_migration, grease_quic_bit;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(QuicConfig,
                                   max_idle_timeout, max_udp_payload_size, active_connection_id_limit,
                                   ack_delay_exponent, max_ack_delay, max_datagram_frame_size,
                                   active_migration, grease_quic_bit)
};

struct MappedIP {
    std::string range, q_origin_key;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(MappedIP, range, q_origin_key)
};

struct VIP {
    // Strings
    std::string name, q_origin_key, uuid, comment, type, server_type, ldb_method,
            src_vip_filter, extip, mapped_addr, extintf, arp_reply,
            http_redirect, persistence, nat_source_vip, portforward, status, protocol,
            extport, mappedport, portmapping_type, http_cookie_domain_from_host,
            http_cookie_domain, http_cookie_path, http_cookie_share, https_cookie_secure,
            http_multiplex, http_ip_header, http_ip_header_name, outlook_web_access,
            weblogic_server, websphere_server, ssl_mode, ssl_dh_bits, ssl_algorithm,
            ssl_server_algorithm, ssl_pfs, ssl_min_version, ssl_max_version,
            ssl_server_min_version, ssl_server_max_version, ssl_accept_ffdhe_groups,
            ssl_send_empty_frags, ssl_client_fallback, ssl_client_renegotiation,
            ssl_client_session_state_type, ssl_server_renegotiation, ssl_server_session_state_type,
            ssl_http_location_conversion, ssl_http_match_host, ssl_hpkp, ssl_hpkp_primary,
            ssl_hpkp_backup, ssl_hpkp_report_uri, ssl_hpkp_include_subdomains, ssl_hsts,
            ssl_hsts_include_subdomains, h2_support, h3_support, nat44, nat46, add_nat46_route,
            ipv6_mappedip, ipv6_mappedport, one_click_gslb_server, gslb_hostname,
            gslb_domain_name;

    // Integers
    int id, dns_mapping_ttl, http_cookie_generation, http_cookie_age,
            http_multiplex_ttl, http_multiplex_max_request, http_multiplex_max_concurrent_request,
            ssl_client_session_state_timeout, ssl_client_session_state_max, ssl_client_rekey_count,
            ssl_server_session_state_timeout, ssl_server_session_state_max,
            ssl_hpkp_age, ssl_hsts_age, max_embryonic_connections, color, gratuitous_arp_interval;

    // Vectors
    std::vector<std::string> src_filter, service, extaddr, ssl_certificate,
            ssl_cipher_suites, ssl_server_cipher_suites, monitor,
            srcintf_filter, gslb_public_ips;

    // Structs
    std::vector<MappedIP> mappedip;
    QuicConfig quic;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(VIP,
                                   name, q_origin_key, uuid, comment, type, server_type, ldb_method,
                                   src_vip_filter, extip, mapped_addr, extintf, arp_reply, http_redirect,
                                   persistence, nat_source_vip, portforward, status, protocol, extport,
                                   mappedport, portmapping_type, http_cookie_domain_from_host, http_cookie_domain,
                                   http_cookie_path, http_cookie_share, https_cookie_secure, http_multiplex,
                                   http_ip_header, http_ip_header_name, outlook_web_access, weblogic_server,
                                   websphere_server, ssl_mode, ssl_dh_bits, ssl_algorithm, ssl_server_algorithm,
                                   ssl_pfs, ssl_min_version, ssl_max_version, ssl_server_min_version,
                                   ssl_server_max_version, ssl_accept_ffdhe_groups, ssl_send_empty_frags,
                                   ssl_client_fallback, ssl_client_renegotiation, ssl_client_session_state_type,
                                   ssl_server_renegotiation, ssl_server_session_state_type, ssl_http_location_conversion,
                                   ssl_http_match_host, ssl_hpkp, ssl_hpkp_primary, ssl_hpkp_backup,
                                   ssl_hpkp_report_uri, ssl_hpkp_include_subdomains, ssl_hsts, ssl_hsts_include_subdomains,
                                   h2_support, h3_support, nat44, nat46, add_nat46_route, ipv6_mappedip,
                                   ipv6_mappedport, one_click_gslb_server, gslb_hostname, gslb_domain_name,
                                   id, dns_mapping_ttl, http_cookie_generation, http_cookie_age,
                                   http_multiplex_ttl, http_multiplex_max_request, http_multiplex_max_concurrent_request,
                                   ssl_client_session_state_timeout, ssl_client_session_state_max, ssl_client_rekey_count,
                                   ssl_server_session_state_timeout, ssl_server_session_state_max, ssl_hpkp_age,
                                   ssl_hsts_age, max_embryonic_connections, color, gratuitous_arp_interval,
                                   src_filter, service, extaddr, ssl_certificate, ssl_cipher_suites,
                                   ssl_server_cipher_suites, monitor, srcintf_filter, gslb_public_ips,
                                   mappedip, quic)
};

#endif // FORTI_API_VIP_H
