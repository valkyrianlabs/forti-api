# forti-api build-out plan (drafted 2026-10-14)

Goal: finish forti-api as a lightweight, DRY, header-only C++23 SDK covering the FortiOS v2 REST
API, released as 1.0.0. Companion: `audit.md` (findings and the author's conventions).

**Recommendation in one line:** generate the *data* (models, endpoint specs) from the FortiGate's
own schema, keep the *behavior* in a handful of hand-written templates, and keep the generated
output checked in as plain readable headers. Templates alone cannot carry the volume; generation
alone would hide behavior in a generator.

## 1. Why generation (measured, not assumed)

- One read-only crawl from 12 seed paths found **144 cmdb tables / 2,738 top-level fields**, and it is
  a fraction of FortiOS. `firewall/policy` alone has 170 fields; hand-typing and maintaining that
  across FortiOS versions is the boilerplate the author wants gone.
- The nlohmann macros cap at 64 fields: `vip.h` (95) already fails to compile. Generated explicit
  `to_json`/`from_json` has no cap, writes the real hyphenated keys (no runtime `_`↔`-` rewriting),
  and can omit unset fields.
- The device describes itself: `GET cmdb/<path>?action=schema` returns, per path, the category
  (table / complex singleton), `mkey` + `mkey_type`, size limits, and per field: `type` (integer,
  option, string, var-string, uuid, ipv4-classnet, user, datetime, …), `options` with help text,
  `size`, `min-value`/`max-value`, `default`, `required`, `datasource` references, and nested
  `children` tables with their own `mkey`. That is everything a generator needs, and it is
  authoritative for the exact FortiOS version.

What stays hand-written: transport, the ~5 behavior templates, domain helpers (DNS category ops,
trusthost, port ranges, schedule days), and the manifest that curates names.

## 2. Target architecture

```
include/forti_api/
  client.hpp          Client, Config, Error, Query, Transport (hand-written)
  endpoint.hpp        Envelope<T>, Table<Spec>, Singleton<Spec>, Monitor<Spec> (hand-written)
  field.hpp           Field<T> (optional-with-presence) + json glue (hand-written)
  gen/<group>/<name>.hpp   generated: model struct + Spec + `using` alias, one per path
  firewall.hpp …      thin umbrella headers including gen/ + hand-written helpers
tools/fortios/        schema pull, crawl, catalog, generator (Python 3 stdlib, deterministic)
schema/7.4.8/         committed schema snapshots (one JSON per path) = generator input
api.toml              manifest: which paths are exposed, C++ names, overrides
```

### 2.1 Transport (`Client`) — replaces `FortiAPI` + `FortiAuth`

- `Config { host, port = 443, api_key, ca_bundle (optional → system store), client_cert + password
  (optional), vdom = "root", connect_timeout = 5s, timeout = 30s, retries }`;
  `Config::from_env()` keeps today's `.env` workflow.
- `Client` owns one reused `CURL*` (keep-alive, TLS session reuse) behind a mutex, and a `curl_slist`
  RAII; `curl_global_init` once. `VERIFYHOST 2L`; client cert only when configured.
- `Request { method, path, query, body }`; `Query` builder for `vdom`, `filter` (FortiOS `==`, `=@`,
  `!=`, `,` OR, `&` AND), `format` (field projection), `start`/`count`, `datasource`, `with_meta`,
  `skip`, `action`. **mkeys are percent-encoded** (`10.0.0.0/24` → `10.0.0.0%2F24`).
- Errors are values or exceptions, never stderr: `fortiapi::Error { http_status, fortios_error
  (e.g. -3), cli_error lines, method, path }`. 401/403/404/424/429/500 mapped; 429 and idempotent
  5xx retried with backoff, and a 401 never retried (lockout).
- Debug hook (`Config::on_exchange`) with the `Authorization` header redacted.
- `Transport` interface (`virtual Response send(const Request&)`) so tests inject a fake: this is
  the seam for **mocked CI tests** (allowed by AGENTS.md rule 4).
- A process-wide default client (`fortiapi::default_client()`, lazily from env) keeps the current
  static call style working: `Policies::list()` uses it; `Policies::list(client)` is explicit.

### 2.2 Field presence (`Field<T>`) — fixes create-defaults leaking into updates

Generated members are `fortiapi::Field<T>` (an optional with value semantics and `operator=`):
unset fields are omitted from JSON, so a PUT sends exactly what the caller set, and a GET that lacks
a key leaves it unset instead of inventing a default. Create defaults move out of the structs into
generated `static T defaults()` (from schema `default`, overridable in the manifest) used only by
`T::create(name)`. This removes the whole class of the `domain-filter-table = 2` bug.

### 2.3 Behavior templates — the DRY core (~200 lines total)

```cpp
template<class T> struct Envelope : Response { T results; };   // one envelope, not 9 copies

template<class Spec> struct Table {            // cmdb table: firewall/policy, dnsfilter/profile …
    using T = typename Spec::type; using Key = typename Spec::key_type;
    static std::vector<T> list(const Query& = {}, Client& = default_client());
    static std::optional<T> find(const Key&, const Query& = {}, Client& = …);   // 404 → nullopt
    static T get(const Key&, …);                                                 // 404 → Error
    static bool contains(const Key&, …);
    static Response add(const T&, …);         // POST cmdb/<path>
    static Response update(const T&, …);      // PUT  cmdb/<path>/<encoded mkey>, sparse body
    static Response del(const Key&, …);       // DELETE
    static Schema schema(Client& = …);        // ?action=schema, for diagnostics
};
template<class Spec> struct Singleton { static T get(…); static Response update(const T&, …); };
template<class Spec> struct Monitor  { /* GET/POST with typed Request/Response per Spec */ };
```

Generated per path, and that is all:

```cpp
namespace fortiapi::firewall {
struct Policy { Field<std::uint32_t> policyid; Field<std::string> name; Field<std::string> action;
                Field<std::vector<Ref>> srcintf; /* … 170 fields … */ };
struct policy_spec { using type = Policy; using key_type = std::uint32_t;
                     static constexpr std::string_view path = "firewall/policy", mkey = "policyid"; };
using Policies = Table<policy_spec>;
namespace policy::action { inline constexpr std::string_view accept = "accept", deny = "deny", ipsec = "ipsec"; }
}
```

No virtual dispatch is needed; polymorphism stays limited to `Transport`. Hand-written helpers
(e.g. DNS category block/allow) become free functions or small mixins on the generated types, and
anything that writes is an explicit call (no constructor POSTs, no auto-PUT setters).

### 2.4 Generator (`tools/fortios/gen.py`)

- Input: `schema/<version>/*.json` + `api.toml`. Output: `include/forti_api/gen/**`, deterministic
  (sorted, stable formatting), checked in so consumers need no Python.
- `api.toml` per exposed path: C++ namespace/name, plural alias (`Policies`), fields to hide or mark
  write-only/secret (`api-key`, passwords: never serialized on update), helper mixins, extra create
  defaults. Unlisted paths can still be generated into `gen/` with mechanical names.
- Type map: `integer` → sized int from min/max; `option` → `std::string` + generated constants
  namespace (robust across FortiOS versions; an `enum class` breaks on new options); `string`,
  `var-string`, `uuid`, `ipv4-*`, `datetime`, `user` → `std::string`; member tables → vector of
  generated child struct (`Ref` for the common `{name, q_origin_key}` reference shape);
  `multiple_values` → vector.
- CI: `tools/fortios/gen.py --check` regenerates and diffs; plus a test that compiles every public
  header standalone.

### 2.5 Compile-time budget

One header per path, grouped umbrella headers, nothing includes `gen/` wholesale by default. Track
the cost of the umbrella `forti_api.hpp` in CI and keep it bounded (target: a full-umbrella TU in
seconds, not minutes).

## 3. Endpoint discovery without the author in the loop

The author originally sniffed GUI traffic by hand. Everything below runs from the dev box with the
existing API token, read-only, and is repeatable for new FortiOS versions.

| Surface | Source | Status |
|---|---|---|
| cmdb (config) | `?action=schema` per path; crawl `datasource` references from seeds | proven: 144 paths |
| cmdb path list | seed list from FortiOS CLI tree knowledge (training data) + crawl; each verified by schema GET (404 = absent on this model/version) | to build |
| monitor (status/actions) | static mining of the GUI bundle (`/static/main.js` + lazy chunks) | proven: 98 literal paths in main.js |
| monitor, complete | headless Chromium (Playwright on dev, in a container) logged into the GUI, visiting every menu page and recording XHR (HAR) | needs one GUI login (below) |
| monitor shapes | sample GETs → JSON shape inference (merge samples), stored as sanitized fixtures | to build |
| log | known tree `log/{memory,disk,fortianalyzer,forticloud}/{type}/{subtype}` + bundle mining; 60F has no disk (404) | to build |

Guardrails: discovery is GET-only. The HAR crawler aborts every non-GET request except the login
itself (Playwright route interception), so clicking through the GUI can never change config.
Fixtures are sanitized (serials, keys, public IPs, MACs) before they enter the repository.

One-time author steps (each optional, each unlocks more coverage):
1. A **read-only GUI admin** `forti-api-recon` (profile `super_admin_readonly`, trusthost = dev box)
   for the HAR crawler. Without it: bundle mining + training knowledge only.
2. Optionally the same profile on a recon **API user**, to test whether `cmdb?action=schema` (the
   global listing, 403 for `api-admin`) works there; that would replace the seed list entirely.
3. Optionally FNDN access, if the author has an account, as a cross-check for monitor semantics.

Training knowledge (honest scope): the overall REST layout, common cmdb paths, mkey conventions,
filter syntax and many monitor endpoints are well known; exact field sets and 7.4.8 additions are
not, which is why the device schema is the source of truth and discovery verifies every path.

## 4. Phases

Each phase lands as its own PR with CI green; live tests run on dev per AGENTS.md.

0. **Done:** Meson + vl-release + APT (v0.3.0); test hygiene (`test-hygiene` branch).
1. **Transport** (§2.1): `Client`, `Config`, `Error`, `Query`, encoding, timeouts, keep-alive,
   retries, redacted debug, `Transport` seam. Unit tests with a fake transport run in CI. Keep the
   old `FortiAPI` as a thin deprecated shim until phase 3 so downstream (forti-hole, forti2ban) keeps
   compiling.
2. **Generator MVP:** `tools/fortios` (pull schema, crawl, gen, --check), `Field<T>`, `Envelope`,
   `Table`/`Singleton`; generate the paths already covered (firewall policy/service custom/service
   category/schedule recurring/VIP/address, dnsfilter profile, system external-resource, api-user,
   global). Fixes `vip.h` by construction.
3. **Migrate the existing API** onto the templates; port domain helpers; remove `FortiAPI`/
   `FortiAuth`, the key-rewriting functions, the per-type `XResponse`s; namespaces under
   `fortiapi::`. Breaking changes are fine before 1.0, recorded in the staged release notes.
4. **Discovery** (§3): cmdb catalog (seed + crawl), monitor catalog (bundle mining, then HAR), log
   catalog, committed as `catalog/<version>/*.json` (metadata only) with sanitized fixtures.
5. **Breadth:** expose cmdb groups in priority order (firewall, system, router, user, vpn, dnsfilter/
   webfilter/ips/av profiles, log settings, switch/wifi controllers); typed monitor endpoints for the
   top tier (system status/interfaces/resources, firewall sessions/policy stats, routing tables,
   DHCP leases, VPN status, license, log queries), generic `Monitor::get(path, Query)` → `json` for
   the long tail.
6. **Live coverage:** a generated CRUD smoke test per exposed table that can be created from schema
   defaults + `required` fields alone: creates `forti-api-test-<path>`, reads, updates a comment,
   deletes, all under the cleanup guard; tables that need real references are skipped or get a
   hand-written fixture. Verified against the device's config log (only `forti-api-test-*` touched).
7. **1.0.0:** docs (README usage with `Client`), examples, header compile budget, `vlr cut 1.0.0`.

## 5. Open decisions for the author

- **FortiOS versions:** 7.4.x only (the lab device), or snapshots for several versions? Recommended:
  generate from 7.4.8, keep `schema/<version>/` so another version is a re-pull + diff.
- **Option fields:** string + generated constants (recommended) vs `enum class`.
- **Namespace:** `fortiapi::` (recommended; matches the package and pkg-config name) vs keeping
  `FortiGate::`.
- **Downstream:** confirm forti-hole and forti2ban are the only consumers to keep compiling through
  the deprecation window.
