# Forti-API

## Header-only, Type-Safe C++23 SDK for FortiGate (FortiOS v2)

**Forti-API** is a header-only C++23 client for the FortiGate REST API (FortiOS v2), built around strongly-typed domain models and intrusive `nlohmann::json` serialization.

This project prioritizes:

- Schema-first domain modeling  
- Thin protocol plumbing  
- Modular accessors (firewall, system, dns_filter, threat_feed, etc.)  
- Maintainability and scalable endpoint expansion  

Most of the codebase consists of structured types. The HTTP layer is intentionally minimal. Adding new endpoints should be boring and predictable.

---

## Installation

Forti-API is header-only. [nlohmann/json](third_party/nlohmann/README.md) 3.12.0 ships with it;
libcurl is the only system dependency.

### Debian/Ubuntu (APT)

`libforti-api-dev` is published to the ValkyrianLabs APT repository:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://apt.valkyrianlabs.com/pubkey.gpg \
  -o /etc/apt/keyrings/valkyrianlabs.gpg
sudo chmod 0644 /etc/apt/keyrings/valkyrianlabs.gpg

echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/valkyrianlabs.gpg] https://apt.valkyrianlabs.com stable main" | \
  sudo tee /etc/apt/sources.list.d/valkyrianlabs.list > /dev/null

sudo apt update
sudo apt install -y libforti-api-dev
```

The packages depend on `valkyrianlabs-archive-keyring`, which installs the repository key at
`/usr/share/keyrings/valkyrianlabs.gpg` and keeps it current through normal upgrades (for example when its
expiry changes). When the key downloaded above is unmodified, the package replaces it with a symlink to the
packaged key, so the source line above keeps working and you never need to download the key again. Removing
the package turns the symlink back into a plain copy. Signing key fingerprint:
`494D 71A1 EEDD F87B D48E  5048 6D64 CB7B DFC3 0EC6`.

The headers install to `/usr/include/forti_api`, the bundled nlohmann/json to
`/usr/include/forti_api/third_party` (never clashing with a system nlohmann-json), and
`forti-api.pc` to `/usr/share/pkgconfig`:

```bash
c++ -std=c++23 app.cpp $(pkg-config --cflags --libs forti-api)
```

### macOS and Linux (Homebrew)

```bash
brew install valkyrianlabs/tap/forti-api
```

Recent Homebrew versions ask you to trust a third-party tap first (`brew trust valkyrianlabs/tap`).
The formula installs the headers and `forti-api.pc`; libcurl comes from the system.

### Vendoring

Copy `include/` and `third_party/nlohmann/include/` into your project, add both to the include
path and link libcurl (`-lcurl`). Meson projects can instead use forti-api as a subproject
(`dependency('forti-api')`).

### Building from source

```bash
# Ubuntu: sudo apt install meson ninja-build g++ pkgconf libcurl4-openssl-dev [libgtest-dev]
# macOS:  brew install meson ninja [googletest]      (libcurl comes with the SDK)
meson setup build
meson install -C build
```

### Tests

```bash
meson setup build -Dtests=enabled            # network-free unit tests (GoogleTest)
meson test -C build --suite unit
```

The live suite runs against a real FortiGate and is opt-in (`-Dlive_tests=true`, suite `live`).
It only ever writes `forti-api-test-*` objects in an allowlist of collections (enforced in the
transport before a request is sent), always cleans up, and checks the device's config-change log
afterwards; the rules are in [AGENTS.md](AGENTS.md). CI never runs it (an on-demand workflow compiles it). Configure
`.env` from `.env.example` (`tools/gen-certs.sh <gateway IP>...` creates test certificates), then:

```bash
meson setup build -Dtests=enabled -Dlive_tests=true
set -a; . ./.env; set +a
meson test -C build --suite live -v
```

---

## Usage

```cpp
#include <forti_api.hpp>      // or just the area you need: <forti_api/firewall.hpp>
using namespace fortiapi;

int main() {
    // Connection from the environment (FORTIGATE_HOST, FORTIGATE_API_KEY, ... see .env.example),
    // or set_default_client(std::make_shared<Client>(Config{...})).
    for (const auto& policy: firewall::Policies::list(Query().filter("status==enable")))
        std::cout << *policy.policyid << " " << policy.name.value_or("") << "\n";

    auto address = firewall::Addresses::get("LAN 10.0.0.0/24");   // keys are URL-encoded for you
    address.comment = "managed by forti-api";
    firewall::Addresses::update(address);                        // sends {"comment": ...} only

    firewall::Address host;
    host.name = "printer";
    host.subnet = "192.168.1.50 255.255.255.255";
    firewall::Addresses::add(host);
}
```

Every FortiOS attribute is a `fortiapi::Field<T>` that knows whether it is absent, read from the device,
modified, or cleared (`clear()` resets it to the FortiOS default). An update sends exactly the modified
and cleared attributes, so reading an object, changing one field and writing it back never touches
anything else. Option attributes come with constants (`firewall::Policy::Action::deny`).

Each table offers `list`, `find` (nullopt on 404), `get`, `contains`, `add`, `update`, `del` and `schema`;
singletons (`system::GlobalSettings`) offer `get` and `update`. Every call takes an optional `Query`
(`vdom`, `filter`, `format`, `start`/`count`, ...) and `Client`. Errors are exceptions:
`fortiapi::ApiError` (HTTP status, FortiOS error code and CLI messages), `TransportError`, `DecodeError`
(naming the attribute that did not match). Reads retry on throttling; writes are never retried.

The monitor API (status, statistics, actions) is available as `Monitor::get("system/status")`.
Non-JSON replies come back as raw bytes with a size limit (64 MiB by default) or streamed to a sink:
`Monitor::download("system/config/backup", Query().set("scope", "global"))` returns the configuration
backup, a secret to store with owner-only permissions and never log ([docs/guides/downloads.md](docs/guides/downloads.md)).

For endpoints chosen at run time (a CLI, an MCP server), `forti_api/schema.hpp` describes every
generated endpoint as data and decodes, validates and builds request bodies for any of them in plain
functions, with the typed models' exact behavior and without compiling them
([docs/guides/runtime-schema.md](docs/guides/runtime-schema.md)):
`schema::create_body(*schema::find("cmdb/firewall/address")->type, object)`.

Helpers on top of the generated endpoints:

- **DNS filter** (`forti_api/dnsfilter.hpp`): `block_category`, `monitor_category`, `allow_category`,
  `category_action`, `allow_category_everywhere`.
- **Threat feeds** (`forti_api/threat_feed.hpp`): `push_threat_feed`, `push_entries` (snapshot / add /
  remove), `feed_state`, `delete_threat_feed` (frees the category in profiles that block it first).
- **Firewall** (`forti_api/firewall.hpp`): `days({Weekday::monday, ...})`, `port_ranges({{80}, {8000, 8080}})`.
- **System** (`forti_api/system.hpp`): `trust` / `distrust` / `trusts` for API-user trusted hosts,
  `interface_addresses("wan1")`.

`examples/inventory.cpp` is a complete read-only program.

---

## Coverage

Generated from FortiOS 7.4.8 schemas: every configuration (cmdb) endpoint the device reports, 487 on
a FortiGate-60F, from firewall policies, addresses and VIPs to routing, VPN, users, logging, security
profiles, switch and wireless controllers. Read-only monitor endpoints the web GUI uses have typed
results generated from recorded response shapes; every other monitor call is available untyped
through `fortiapi::Monitor`. The full list is in [docs/reference/endpoints.md](docs/reference/endpoints.md).

Include an area header (`forti_api/firewall.hpp`, `forti_api/system.hpp`, ...), a whole group
(`forti_api/gen/router.hpp`) or a single endpoint (`forti_api/gen/router/static.hpp`) to keep compile
times down; `forti_api.hpp` includes everything.

---

## Contribution Requirements

Contributions require access to either:

- A physical FortiGate device, or  
- A FortiVM subscription  

API interactions modify live security infrastructure. All pull requests undergo careful review to ensure correctness and operational safety.

Security and integrity are non-negotiable.

---

Forti-API aims to provide a clean, type-safe foundation for serious FortiGate automation in modern C++.
