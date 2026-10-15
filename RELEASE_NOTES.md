# forti-api release notes

<!-- vl-release:entry version=1.0.1 -->
## 1.0.1 — Raw downloads, configuration backups and write safety

_Released 2026-10-15_

forti-api can now fetch endpoints that answer with a file instead of JSON, most importantly the
FortiOS configuration backup, so tools can take a backup before a critical change.

```cpp
auto backup = fortiapi::Monitor::download("system/config/backup",
                                          fortiapi::Query().set("scope", "global"));
// backup.body starts with "#config-version=", backup.content_type, backup.content_disposition
```

- `Client::download(api_path, query, options)` (and an overload taking a method and JSON body)
  returns the reply as raw bytes, text or binary, with the HTTP status, `Content-Type` and
  `Content-Disposition`. It uses the same connection, authentication, TLS verification, timeouts
  and retry policy as every other call. HTTP errors still raise `ApiError`, with the FortiOS error
  code and CLI messages when the error body is JSON.
- Memory is bounded: `DownloadOptions::max_bytes` (64 MiB by default) aborts a larger reply with
  `SizeLimitError` and discards what arrived. `DownloadOptions::sink` streams the body in chunks,
  for example straight into a file, instead of holding it in memory.
- `Config::on_exchange` never receives the body of a successful download.
- Custom `Transport` implementations keep compiling unchanged. To bound memory and stream, they can
  honor the new `HttpRequest::max_body` and `on_body` fields and fill `HttpResponse::headers`
  (see the downloads guide).

Configuration backups contain password hashes, keys and the network layout: store them with
owner-only permissions, never log them, and never put them in shared temporary directories.

Validated against FortiOS 7.4.8: `GET monitor/system/config/backup?scope=global` returns the
configuration as `application/octet-stream`.

### Writes are never sent twice

libcurl re-sends a request on its own when a reused keep-alive connection turns out to be dead.
For a write that had already reached the FortiGate, that meant running it twice: a second firewall
policy with a new id, a delete reported as "not found", a monitor action executed twice. forti-api
now gives every write (POST, PUT, DELETE) its own new connection, which libcurl never re-sends on,
and closes it afterwards. When the connection drops before the reply, the call throws
`TransportError` with `before_send() == false`: the write may or may not have happened, and it is
never repeated. Each write pays one TCP and TLS handshake (a few milliseconds on a LAN); reads keep
sharing one kept-alive connection.

### Safer object keys and replies

- A key that is exactly `.` or `..` is sent as `%2E` / `%2E%2E`, and paths go out exactly as built.
  Before, libcurl removed such dot segments, so `Addresses::del("..")` addressed a different path
  than the object named.
- JSON replies nested deeper than `Config::max_reply_depth` (256 by default) are refused with a
  `DecodeError`, so a hostile or broken peer cannot make later copies or dumps of the reply
  overflow the stack.

### Meson subprojects

Used as a Meson subproject, forti-api no longer builds its example and tests and no longer installs
its headers and `forti-api.pc` alongside your project. `dependency('forti-api')` and
`forti_api_dep` work as before.

<!-- vl-release:entry version=1.0.0 -->
## 1.0.0 — The complete FortiOS SDK

_Released 2026-10-14_

forti-api is rebuilt around the FortiGate's own schema: every configuration endpoint FortiOS 7.4.8
reports is generated, writes change exactly what you changed, and the transport is careful about
what it sends and repeats. This release breaks the previous API on purpose (migration table below).

### Every endpoint, generated

- All 487 configuration (cmdb) endpoints a FortiGate-60F reports on FortiOS 7.4.8: firewall,
  system, router, VPN, user, log, security profiles, switch and wireless controllers and more,
  each as a struct with every attribute documented, plus a `Table` (`list`, `find`, `get`,
  `contains`, `add`, `update`, `del`, `schema`) or `Singleton` (`get`, `update`). Every one decodes
  every object on a live device (35,000+ objects verified).
- Typed read-only monitor endpoints for what the web GUI reads (`fortiapi::monitor::system::Time::get()`),
  generated from recorded response shapes; every other monitor call goes through `fortiapi::Monitor`.
- Option constants live in their type: `firewall::Policy::Action::deny`.

```cpp
#include <forti_api/firewall.hpp>
using namespace fortiapi;

auto address = firewall::Addresses::get("LAN 10.0.0.0/24");   // keys are URL-encoded for you
address.comment = "managed";
firewall::Addresses::update(address);                         // sends {"comment": "managed"} only
```

### Writes change exactly what you changed

Every attribute is a `Field<T>` that knows whether it is absent, read from the device, modified or
cleared. An update sends only modified and cleared attributes (`clear()` resets one to its FortiOS
default); reads never mark anything changed; read-only attributes are never sent. A create sends
only what you set and FortiOS fills in its own defaults.

### A careful transport: `fortiapi::Client`

- Connect and request timeouts, one kept-alive connection per client, TLS verified against the
  system trust store (or a configured CA), optional client certificate, `FORTIGATE_RESOLVE_IP` to
  pin the address while verifying the hostname.
- Object names are percent-encoded; a `Query` builder covers `vdom`, `filter`, `format`,
  `start`/`count`, `datasource`, `with_meta`, `skip` and `action`.
- Errors are exceptions: `ApiError` (HTTP status, FortiOS error code, CLI messages), `TransportError`,
  `DecodeError` (naming the attribute that did not match). Nothing is printed.
- Reads retry on throttling and gateway errors; configuration changes are never retried once they
  may have reached the device.

### Helpers

DNS filter categories (`block_category`, `allow_category_everywhere`, ...), push threat feeds
(`push_entries` reports rejected commands, `feed_state`, `delete_threat_feed` frees the category
first), schedule days, service port ranges, API-user trusted hosts (IPv4/IPv6, CIDR) and live
interface addresses.

### Install

- Debian/Ubuntu: `sudo apt install libforti-api-dev` from the ValkyrianLabs APT repository.
- Homebrew (macOS and Linux): `brew install valkyrianlabs/tap/forti-api`.
- Or vendor `include/` and `third_party/nlohmann/include/`; libcurl is the only system dependency.
- Documentation is published with the release (docs set `forti-api`).

### Migrating from 0.x

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

Fixed along the way: DNS filter profiles no longer reference a missing domain filter table (which
made creation fail with HTTP 500 after half-creating the profile), category sweeps only write
profiles that use the category, schedule days use FortiOS names, IPv6 trusted hosts get the IPv6
type, and rejected threat-feed pushes raise an error instead of passing silently.

<!-- vl-release:entry version=0.3.0 -->
## 0.3.0 — Native packages, no Conan

_Released 2026-10-14_

forti-api no longer uses Conan. It builds with Meson and ships as a Debian package from the
ValkyrianLabs APT repository.

- **Debian/Ubuntu:** `sudo apt install libforti-api-dev` (after adding
  `https://apt.valkyrianlabs.com`, see the README). It installs the headers to
  `/usr/include/forti_api` and `forti-api.pc`; build with
  `pkg-config --cflags --libs forti-api`.
- **Vendoring or from source (Linux or macOS):** copy `include/` and
  `third_party/nlohmann/include/`, or `meson setup build && meson install -C build`. libcurl is the
  only system dependency; nlohmann/json 3.12.0 ships with forti-api under
  `forti_api/third_party`, so it never conflicts with a system nlohmann-json.
- The headers include their siblings by relative path, so installed headers work from any include
  root, and compile cleanly with `-Wall -Wextra -Wpedantic -Werror` on GCC 13/14 and Apple Clang.
- New firewall VIP types (`types/firewall/vip.h`).
