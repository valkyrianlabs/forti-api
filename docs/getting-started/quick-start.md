---
title: Quick start
description: Connect to a FortiGate and read, change and create objects.
order: 20
status: published
tags:
  - getting-started
---

# Quick start

## 1. Create an API administrator

On the FortiGate, create a REST API administrator (System, Administrators, Create New, REST API
Admin), give it an access profile with the permissions you need, restrict its trusted hosts to the
machines that will call the API, and copy the generated API key.

## 2. Configure the connection

The default client reads its configuration from the environment:

```bash
export FORTIGATE_HOST=fortigate.example.com
export FORTIGATE_ADMIN_HTTPS_PORT=443
export FORTIGATE_API_KEY=...
```

See [Configuration](/reference/configuration) for every variable, or configure a client in code:

```cpp
#include <forti_api.hpp>

fortiapi::Config config;
config.host = "fortigate.example.com";
config.port = 8443;
config.api_key = api_key;
fortiapi::set_default_client(std::make_shared<fortiapi::Client>(config));
```

## 3. Read, change, create

```cpp
#include <forti_api/firewall.hpp>
#include <iostream>

using namespace fortiapi;

int main() try {
    for (const auto& policy: firewall::Policies::list(Query().filter("status==enable")))
        std::cout << *policy.policyid << " " << policy.name.value_or("") << "\n";

    auto address = firewall::Addresses::get("LAN 10.0.0.0/24");
    address.comment = "managed by forti-api";
    firewall::Addresses::update(address);

    firewall::Address host;
    host.name = "printer";
    host.subnet = "192.168.1.50 255.255.255.255";
    firewall::Addresses::add(host);
} catch (const fortiapi::Error& error) {
    std::cerr << error.what() << "\n";
    return 1;
}
```

Every call accepts an optional `Query` and `Client` as trailing arguments, so the same code works
against several devices:

```cpp
fortiapi::Client branch(branch_config);
auto policies = firewall::Policies::list({}, branch);
```

The repository's `examples/inventory.cpp` is a complete read-only program.
