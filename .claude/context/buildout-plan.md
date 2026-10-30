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

## 5. Decisions and requirements (approved 2026-10-14)

Decisions:
1. Generate against FortiOS 7.4.8 first; keep versioned `schema/<version>/` snapshots for later.
2. Option fields: `std::string` + generated constants.
3. Namespace `fortiapi::`. Header-only, vendorable C++23 stays.
4. **No legacy compatibility.** forti-hole is retired, forti2ban was never finished: remove old
   abstractions outright (no shim, no deprecation window), break anything before 1.0.
5. GUI recon account (`forti-api-recon`, password `FORTI_API_RECON_ADMIN_PASS` in `.env` on both
   machines) is **deferred** until the schema crawler and bundle mining stop yielding coverage.
   When used: GET-only interception for discovery traffic, authentication handled separately, an
   explicit safe-route allowlist (GET is not assumed side-effect-free; unknown or mutating
   operations rejected), HAR sanitized before persisting (auth headers, cookies, tokens, network
   addresses, device identifiers).
6. The author cuts 1.0.0 personally; phases land as PRs merged on green CI, no releases cut.

Architectural requirements:
1. **Field states:** generated fields distinguish *absent*, *populated* (from the device),
   *modified* and *explicitly cleared*. Updates serialize only modified and cleared fields; nothing
   unrelated is ever sent.
2. **No automatic retry of configuration mutations** that may have partially succeeded. POST/PUT/
   DELETE are retried only when the connection failed before the request was sent (resolve/connect
   /TLS handshake); never after a response, a timeout or a send error. GETs retry on 429/502/503/504
   and transport errors.
3. **Live mutation tests touch only explicitly approved test resources**, with guaranteed cleanup
   and independent verification: a guard transport rejects (before sending) any mutation outside the
   allowlisted cmdb paths or without the `forti-api-test-` prefix, and each run is verified against
   the device's config-change log.

## 6. Deviations from the original draft

- §2.1 / phase 1 / phase 3: no deprecated `FortiAPI` shim. Phase 1 replaces the transport and moves
  the existing accessors onto `Client` directly; the old `FortiAPI`/`FortiAuth`, key rewriting and
  `FortiGate::` names go away as soon as their replacement lands.
- §2.2: `Field<T>` has four states (absent / populated / modified / cleared) instead of
  presence-only; cleared fields serialize the schema's reset value.
- §2.1 retries: mutations are not retried after anything may have reached the device
  (requirement 2), replacing "idempotent 5xx retried".
- §2.2: no generated create defaults. Writes are sparse, so a create sends only what the caller set
  and FortiOS applies its own defaults; `T::defaults()` would only reintroduce the leak §2.2 removes.
- §2 layout: generator inputs live in `codegen/` (`api.toml`, `schema/<version>/cmdb/...`,
  `catalog/<version>/`), the tool in `tools/fortios/` (`fortios.py` CLI + `codegen.py`), output in
  `include/forti_api/gen/<path>.hpp` + `gen/all.hpp`. Option constants live in a snake_case
  namespace beside the type (`fortiapi::firewall::policy::action::deny`), table entries are
  `<Field>Entry` structs, `{name}`-only member tables are `std::vector<fortiapi::Ref>`.
- Device quirks the runtime absorbs (found live on 7.4.8): unset integers arrive as `""` (decoded as
  absent), some numbers arrive as numeric text, log endpoints answer with deflate streams libcurl
  cannot decode (client asks for gzip only), config-change log entries appear 5-8 s late and edits
  right after a create are folded into the Add record (the live audit polls until the log settles
  and parses attribute names from `cfgattr`).
- Release tooling (author note 2026-10-14): `valkyrianlabs/homebrew-tap` exists; phase 7 adds the
  vl-release `[homebrew]` + `[source_archive]` channel for a header-only formula, as vl-release does.
- Phase 4 (discovery) results on the lab 60F / 7.4.8: the cmdb crawl (430 seeds + GUI cmdb refs +
  datasource references) converges at 487 paths (353 tables, 125 singletons; 7,338 top-level
  attributes); 24 seeds do not exist on this model (wanopt, ztna, report, ...). Bundle mining
  (`fortios.py mine`, main.js + common.js + 405 lazy chunks) converges at 274 monitor paths (105 GET,
  45 POST, 122 method not visible statically, 9 templated), 6 log and 6 service paths. Static
  coverage is exhausted, which meets the author's condition for the read-only GUI recon: it is the
  only remaining source for monitor methods, parameters and response shapes.
- Phase 5 deviations: option constants are nested in their type (`firewall::Policy::Action::deny`)
  instead of `snake_type::field::value` namespaces, which collided once every cmdb path was generated
  (a type's field constants and a child endpoint's namespace can share a name). Name fallbacks are
  deterministic: `...Values` (constants), `...Object` (nested objects), `...TableEntry` (tables);
  identifiers avoid C++ keywords and common preprocessor macros (`NULL` -> `NULL_`). Typed monitor
  endpoints are generated from the sanitized GUI recon shapes (`gui-recon.json`), not hand-written.
- GUI recon (phase 4b) results: pass 1 refused 2,755 requests incl. writes the GUI attempts merely
  from viewing pages (POST cmdb/firewall/policy, cmdb/firewall/security-policy, cmdb/system/ddns,
  cmdb/system/admin/..., monitor/system/debug); 27 monitor GETs learned and 24 reviewed into
  tools/recon/reviewed-gets.txt (4 kept out: FortiGuard/FortiSandbox outbound). Pass 2: 2,587 reads,
  44 monitor endpoints with shapes.
- Phase 6 (live coverage): instead of auto-generating CRUD tests for every table (most need real
  references or have live effects on creation), the live suite round-trips a reviewed set of 24
  inert collections with hand-picked minimal fixtures; read-only decode coverage spans all 487 cmdb
  and every typed monitor endpoint. Curated names for common firewall tables (AddressGroups,
  Addresses6, ServiceGroups, OnetimeSchedules, ScheduleGroups, WildcardFqdns, Vips6).

## 7. Status and cutting 1.0.0 (2026-10-14)

Phases 1-6 merged or in review; phase 7 adds the Homebrew channel (formula template, source
archive without the generator inputs, macOS install check in CI and release, tap publication with
HOMEBREW_TAP_TOKEN), docs (13 pages, generated endpoint reference, published on release over OIDC)
and the consolidated 1.0 release notes. Validated: formula installs and tests on macOS (local tap),
deb + source archive + formula rehearsal in the CI container, docs OIDC dry-run accepted on main.

The author cuts the release: from an up-to-date main, `vlr cut 1.0.0 --push`. Before the first
release, check:
- The `forti-api` docs set trusts this repository's release workflow on tag refs for OIDC (PR
  tokens are refused by design; push-to-main tokens are accepted, sync run 91).
- vars.RELEASE_PUBLISH_MODE is unset (defaults to nexus) or `nexus`; NEXUS_* org secrets reach the
  Production environment.
- HOMEBREW_TAP_TOKEN can push to valkyrianlabs/homebrew-tap. Users install with
  `brew install valkyrianlabs/tap/forti-api` and no `brew trust`: Homebrew trusts a formula named
  in full. The forti tools' formulae carry forti-api as a resource, never a dependency.

Compile budget (measured, GCC 13 in the CI container): a TU including everything (`forti_api.hpp`,
`gen/all.hpp`, `gen/registry.hpp`) needs ~1.5 GB and ~19 s with `-g`; an area header ~2 s. Tests and
helpers include only the area/group headers they use (only `test_coverage.cpp` takes the registry),
and CI compiles with `-j 4`: unbounded parallel umbrella TUs exhausted the shared runner's 12 GB
container in phase 6's first CI run.

Later (not blocking 1.0): more FortiOS versions (`schema/<version>`), typed monitor *actions*
(POST) once reviewed endpoint by endpoint, monitor endpoints with path parameters
(`router/lookup`), Windows (`interface` is a member name; windows.h defines it).
