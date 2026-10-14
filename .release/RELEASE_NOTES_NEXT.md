<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Safer DNS filter and threat feed writes

- `DNSFilter::add` no longer fails with HTTP 500 on firewalls without a domain filter table: new
  profiles default to no domain filter instead of table 2, which FortiOS rejected after
  half-creating the profile.
- `DNSFilter::global_allow_category` and `ThreatFeed::del` only rewrite DNS filter profiles that
  actually use the category, and `ThreatFeed::del` leaves profiles alone while another feed still
  provides it.
- `DNSFilter::add`, `update`, `del` and `ThreatFeed::add` return the FortiGate response, so callers
  can check `status`.

## New transport: `fortiapi::Client`

- Connect and request timeouts, one kept-alive connection per client (TLS sessions reused), and the
  system trust store unless a CA bundle is configured; the client certificate is optional.
- Object names are percent-encoded (`10.0.0.0/24` stays one path segment) and a `Query` builder covers
  `vdom`, `filter`, `format`, `start`/`count`, `datasource`, `with_meta`, `skip` and `action`.
- FortiOS errors become `ApiError` (HTTP status, FortiOS error code, CLI messages); no output on
  stdout/stderr, and the debug hook never sees the API key.
- Reads retry on throttling and gateway errors; configuration changes are never retried once they may
  have reached the device.
- `FORTIGATE_HOST` + `FORTIGATE_RESOLVE_IP` connect to a pinned address while verifying TLS for the
  hostname.

## Generated endpoints

FortiOS objects are now generated from the device's own schema (FortiOS 7.4.8): every attribute,
with its documentation, as a `fortiapi::Field<T>`, and a `Table`/`Singleton` per endpoint:

```cpp
#include <forti_api/gen/firewall/address.hpp>
using namespace fortiapi;

auto address = firewall::Addresses::get("LAN 10.0.0.0/24");
address.comment = "managed";
firewall::Addresses::update(address);   // sends {"comment": "managed"} and nothing else
```

Fields know whether they are absent, read from the device, modified or cleared: an update sends only
what you changed (`clear()` resets an attribute to its default), reads never mark anything changed,
and option attributes come with constants (`firewall::Policy::Action::deny`). Generated so far:
firewall policy, address, VIP, service, service category, recurring schedule, DNS filter profile,
external resource, API user, interface and global settings.

## Breaking: the pre-generation API is gone

`FortiAPI`, `FortiAuth`, `FortiGate::Policies`/`Services`/`Schedules`, `DNSFilter`, `ThreatFeed`,
`System::Interface`, `System::Admin` and the hand-written types are removed. Everything lives in
`fortiapi::` on generated endpoints, with small helpers for the domain logic:

| Before | Now |
|---|---|
| `FortiAuth::set_vars_from_env()` | automatic (`Config::from_env()`), or `set_default_client(...)` |
| `FortiGate::Policies::get()` | `firewall::Policies::list()` |
| `DNSFilter::add(name)` / `del(name)` | `dnsfilter::Profiles::add(profile)` / `del(name)` |
| `DNSProfile::block_category(c)` | `dnsfilter::block_category(profile, c)` + `Profiles::update(profile)` |
| `DNSFilter::global_allow_category(c)` | `dnsfilter::allow_category_everywhere(c)` |
| `ThreatFeed::add(name, category)` | `system::ExternalResources::add(system::push_threat_feed(name, category))` |
| `ThreatFeed::update_feed(commands)` | `system::push_entries(feed, entries, FeedCommand::snapshot)` |
| `ThreatFeed::get_entry_list(feed)` | `system::feed_state(feed).entries` |
| `ThreatFeed::del(name)` | `system::delete_threat_feed(name)` |
| `System::Interface::get_wan_ip()` | `system::interface_addresses("wan1")` |
| `APIUser::trust(subnet)` | `system::trust(user, subnet)` + `ApiUsers::update(user)` |
| `FirewallSchedule::set_days(...)` | `schedule.day = firewall::days({...})` |
| `FirewallService::set_port_range(...)` | `service.tcp_portrange = firewall::port_ranges({...})` |

Fixed on the way: schedule days are written as FortiOS day names (were ordinals), IPv6 trusted hosts
get the IPv6 type, CIDR trusted hosts are accepted, and rejected threat-feed pushes raise an error
instead of passing silently.

## Every configuration endpoint, and typed monitor reads

- All 487 configuration (cmdb) endpoints FortiOS 7.4.8 reports on a FortiGate-60F are generated: firewall,
  system, router, VPN, user, log, security profiles, switch and wireless controllers and more. Each
  decodes every object on a live device without loss (35,000+ objects verified).
- Read-only monitor endpoints the web GUI uses are generated with typed results from recorded
  response shapes (`fortiapi::monitor::system::Time::get()`); others remain available through
  `fortiapi::Monitor`.
- Option constants now live in their type: `firewall::Policy::Action::deny` (was
  `firewall::policy::action::deny`).
- Group headers (`forti_api/gen/router.hpp`) and `fortiapi::gen::for_each_endpoint` /
  `for_each_monitor` for introspection.
