# forti-api audit (2026-10-14, v0.3.0 + test-hygiene branch)

Scope: every header under `include/`, the tests, and live behavior against the lab FortiGate-60F
(FortiOS 7.4.8 build 2795). Companion: `buildout-plan.md` (what to do about it).

## The conventions this codebase is built around

Keep these unless the plan says otherwise; they are the author's deliberate choices.

- **Header-only C++23.** No compiled library; consumers include `forti_api.hpp` or a module header
  (`firewall.hpp`, `dns_filter.hpp`, `threat_feed.hpp`, `system.hpp`).
- **Schema-first plain structs.** One struct per FortiOS object, field names = FortiOS keys with
  `-` → `_` (`ssl_ssh_profile`, `q_origin_key`). Serialization via
  `NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT`; very large objects (VIP) were to be hand-written.
- **Member initializers double as "create" defaults** (`DNSProfile::block_action = "redirect"`,
  `PushThreatFeed::update_method = "push"`), so `T(name)` is a ready-to-POST object.
- **Response envelope**: `struct Response` (http_status, status, revision, serial, version, …) and one
  `XResponse : Response { std::vector<T> results; }` per type.
- **Static accessor classes per FortiOS area** with a uniform verb set: `get()` (list),
  `get(name)`, `contains(name)`, `add`, `update`, `del` (`FortiGate::Policies`, `FortiGate::Services`,
  `FortiGate::Schedules`, `DNSFilter`, `ThreatFeed`, `System::Interface`, `System::Admin::API`).
- **Endpoint path lives as an `inline static std::string`** on the accessor or the type.
- **Domain helpers on the types**: DNS category block/allow/monitor with a sorted filter vector and
  binary search; trusthost management; port ranges; schedule days; `Color` enum.
- **Transport is one static class** (`FortiAPI` in `api.hpp`): `get<T>`, `post`, `put`, `del`, JSON keys
  rewritten `_`↔`-` recursively on every request/response.
- **Auth/config from the environment** via static `FortiAuth` (`FORTIGATE_*`, `.env`).
- **Default VDOM `root`**, appended as `?vdom=` by hand where supported.
- **Tests run against a live device** (AGENTS.md rule: never touch existing config, `forti-api-test-*`
  only, always clean up, never in CI).

## Findings

Severity: **H** wrong behavior / data risk, **M** robustness, **L** hygiene.

### Transport (`include/forti_api/api.hpp`)

| Sev | Finding | Where |
|---|---|---|
| H | No connect/total timeouts: an unreachable device hangs callers for minutes (seen live). | `request()` 217-258 |
| H | Failures are invisible or crash: curl errors print and continue, then `json::parse("")` throws an unrelated `parse_error`; HTTP status is never checked; GET returns the error envelope as `T`, and callers index `results[0]` on an empty vector (UB). | 253-258; `dns_filter.hpp:42`, `threat_feed.hpp:40`, `firewall.hpp:45,88` |
| H | Object names are not URL-encoded. FortiOS names routinely contain `/` (`10.0.0.0/24`), spaces, `#`, `?`: these requests hit the wrong path. | every `std::format("{}/{}", endpoint, name)` |
| H | `ENABLE_DEBUG` dumps request headers including `Authorization: Bearer <key>` to stderr. | 185-186 |
| M | `curl_slist` headers leak on every request (never `curl_slist_free_all`). | 222-223 |
| M | New easy handle per request: no keep-alive, the `SSL_SESSIONID_CACHE` / `FORBID_REUSE` options are moot, every call pays a TLS handshake. No `curl_global_init`. | 217-232 |
| M | TLS options hard-wired: `CAINFO` always set (empty path when unset, never falls back to the system store), client cert always configured as P12 even when absent, `VERIFYHOST 1L` (legacy value). | 233-238 |
| M | `convert_keys_to_hyphens/underscores` rewrite keys recursively at runtime: cost on every payload, corrupts maps whose keys are data, needs an ignore-list hack (`std::array<std::string,10>` with one entry). | 24-81, 240, 258 |
| M | No retry/backoff; repeated 401s trip the FortiOS API lockout (HTTP 429, seen live) with no signal to the caller. | — |
| M | No query support beyond hand-appended `?vdom=`: no `filter`, `format`, `start/count`, `datasource`, `with_meta`, `action`. `Policies::get(name)` downloads every policy and filters client-side. | `firewall.hpp:24-28` |
| M | Global mutable static state (`FortiAuth`), not thread-safe; `std::stoi` throws on a missing port env var; `PROGRAM_IS_RUNNING` flag only gates warnings. | 84-170, 211 |
| L | The library writes to stderr (`[DEBUG]`, `[WARNING]`, error envelopes); libraries should report, not print. | throughout |
| L | `inline static std::regex` at namespace scope: internal linkage, constructed at startup in every TU that includes `api.hpp`. | 21-22 |

### Models (`include/forti_api/types/**`)

| Sev | Finding | Where |
|---|---|---|
| H | **Create-defaults leak into updates.** `WITH_DEFAULT` fills fields missing from a GET with the create defaults, and a PUT of the round-tripped object writes them back. Same root cause as the DNS profile `domain-filter-table = 2` bug fixed on test-hygiene (FortiOS half-created the profile and returned HTTP 500). Needs an "unset" state so PUT sends only what was set. | all structs with member defaults |
| H | `vip.h` does not compile: 95 fields exceed the 64-argument limit of the nlohmann macros. Nothing includes it, so CI never noticed. | `types/firewall/vip.h:65-89` |
| H | Type mismatches throw on real data: `DNSProfile::dns_translation` / `external_ip_blocklist` are `vector<string>` but FortiOS returns tables of objects (works only while empty). Several numeric fields are strings and vice versa (`session_ttl`). | `dns/filter.h:83`, `firewall/services.h` |
| H | Hidden writes in "active record" types: `FirewallSchedule(name)` **POSTs from the constructor**, and calls `set_all_day()` → `update()` (a PUT) *before* the POST; every `set_*` helper on services/schedules PUTs immediately. | `firewall/schedules.h:27-31`, `firewall/services.h` setters |
| M | `set_days` writes enum ordinals (`"0,1"`); FortiOS expects `"sunday monday"`. | `firewall/schedules.h:72` |
| M | `IPV6TrustHost` sets type `"ipv4-trusthost"`; `APIUser::trust()` regex-matches a bare IP while FortiOS trusthosts are `"10.0.0.0 255.255.255.0"` (silently no-op); `update()` PUTs `api_key`. | `system/admin.h:68`, `:107-117` |
| M | `Services::delete_category(name)` returns after the first loop iteration, so it only ever checks the first category. | `firewall.hpp:68-74` |
| M | `ThreatFeed::set` POSTs to `cmdb/.../<name>` (an update must be PUT); `get_entry_list` builds `...&mkey=/<feed>` (stray `/`) against a cmdb path for what is a monitor endpoint. | `threat_feed.hpp:20-26, 43-46` |
| M | `System::Interface::get(name)` converts the response envelope (an object) to `vector<json>` → throws; interface caches are static, never refreshed, not thread-safe; `admin_profiles_endpoint` lacks the leading `/`. | `system.hpp:48-53, 21-42, 91` |
| M | 13-field envelope re-listed in every `XResponse` macro (9 copies) and `SystemResponse` duplicates `Response`. | every `*Response` |
| L | Global namespace pollution: `Response`, `Module`, `Interface`, `Address`, `Service`, `Filter`, `Entry`, unscoped `enum Color { RED, … }`, `using json = nlohmann::json` in a header. Namespaces are inconsistent (`FortiGate::`, `System::`, none). | types, `vip.h:11` |
| L | Accessor verbs differ per area (`del` vs `delete_category`, `get_physical_interface`, `new_schedule`), endpoint strings live sometimes on the type, sometimes on the accessor. | — |

### Tests and tooling

- Fixed on `test-hygiene`: prefix naming, scope-guard cleanup, leftover purge, free threat-feed
  category, no assertions on existing config, responses asserted.
- Still missing: network-free unit tests (serialization round-trips, URL/query building, error
  mapping) that CI can run; a "every public header compiles standalone" check (would have caught
  `vip.h`).

### Live observations (FortiOS 7.4.8)

- Admin/API on `forti.cooperhlarson.com:8443` (Let's Encrypt). `peer-auth` is disabled on
  `api_admin`, so the client certificate is not enforced yet; accprofile `api-admin`.
- cmdb POSTs are **not transactional**: an attribute error after creation returns HTTP 500 and leaves
  the object behind. Clients must check the response and clean up.
- No-op PUTs are not logged; every real change is logged with its attributes in
  `log/memory/event/system` (`cfgpath`, `cfgobj`, `cfgattr`): an audit trail for verifying tests.
- `GET cmdb/<path>?action=schema` works per path (tables and singletons) and returns complete field
  metadata; `?action=default` returns create defaults. `cmdb?action=schema` (global listing) is 403
  for `api-admin`, even with CLI permissions.
- The GUI bundle (`/static/main.js`) is fetchable with the API token and names ~98 monitor endpoints
  literally; others are built from templates at runtime.
