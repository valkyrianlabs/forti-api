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

Forti-API is header-only and can be vendored directly:

```bash
git clone https://github.com/valkyrianlabs/forti-api.git
```

Add the `include/` directory to your project's include path.

> Conan packaging is currently being refreshed and will return in a future release.

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
