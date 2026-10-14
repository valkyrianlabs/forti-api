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

The headers install to `/usr/include/forti_api`, the bundled nlohmann/json to
`/usr/include/forti_api/third_party` (never clashing with a system nlohmann-json), and
`forti-api.pc` to `/usr/share/pkgconfig`:

```bash
c++ -std=c++23 app.cpp $(pkg-config --cflags --libs forti-api)
```

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
afterwards; the rules are in [AGENTS.md](AGENTS.md). CI compiles it but never runs it. Configure
`.env` from `.env.example` (`tools/gen-certs.sh <gateway IP>...` creates test certificates), then:

```bash
meson setup build -Dtests=enabled -Dlive_tests=true
set -a; . ./.env; set +a
meson test -C build --suite live -v
```

---

## Basic Usage

```cpp
#include <forti_api/firewall.hpp>

using namespace FortiGate;

auto policies = Policies::get();

for (const auto& policy : policies) {
    std::cout << policy.name << " -> " << policy.action << "\n";
}
```

Updating a policy:

```cpp
auto policy = Policies::get("Allow-Internal");
policy.comments = "Updated via Forti-API";
Policies::update(policy);
```

---

## Current Module Coverage

- Firewall (policies, services, schedules)
- DNS Filter
- Threat Feed
- System
- Additional modules expanding incrementally

The architecture is designed to support full FortiOS coverage without collapsing into a monolithic wrapper.

---

## Real-World Integration

Forti-API powers tools such as:

- **forti-hole** (Pi-hole integration)
- **forti2ban** (Fail2Ban integration)

These integrations leverage FortiGate’s API surface for automated enforcement and network hygiene workflows.

---

## Contribution Requirements

Contributions require access to either:

- A physical FortiGate device, or  
- A FortiVM subscription  

API interactions modify live security infrastructure. All pull requests undergo careful review to ensure correctness and operational safety.

Security and integrity are non-negotiable.

---

Forti-API aims to provide a clean, type-safe foundation for serious FortiGate automation in modern C++.
