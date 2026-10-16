---
title: Quick start
description: Connect to a FortiGate and read, change and create objects.
order: 20
status: published
tags:
  - getting-started
---

# Quick start

Create a REST API administrator on the FortiGate, point forti-api at it, and read, change and create
objects.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Connect and make your first calls

:::steps{
  variant="cards"
  layout="stack"
  numbered
  stepTheme="cyan"
}

### Create an API administrator

On the FortiGate, create a REST API administrator (System, Administrators, Create New, REST API
Admin), give it an access profile with the permissions you need, restrict its trusted hosts to the
machines that will call the API, and copy the generated API key.

### Configure the connection

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

### Read, change, create

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

:::

:::callout[Repeated authentication failures lock the API]{variant="warning"}
If requests keep failing to authenticate, stop and fix the key or trusted hosts: FortiOS locks the
API out (HTTP 429) after repeated authentication failures, and forti-api never retries HTTP 401.
:::

## Endpoint operations

Each generated endpoint is a `Table` (objects addressed by a key) or a `Singleton` (an object that
exists exactly once, such as `system/global`):

| Operation | `Table` | `Singleton` | Result |
|---|---|---|---|
| `list(query)` | yes | | every object, decoded |
| `find(key, query)` | yes | | the object, or `std::nullopt` when it does not exist |
| `get(key, query)` / `get(query)` | yes | yes | the object; a `Table` throws `ApiError` (`not_found()`) when it does not exist |
| `contains(key, query)` | yes | | whether the object exists |
| `add(object, query)` | yes | | creates the object; see [Fields and updates](/guides/fields-and-updates#creating) |
| `update(object, query)` | yes | yes | sends only modified and cleared attributes; `std::nullopt` when there is nothing to send |
| `del(key, query)` | yes | | deletes the object |
| `schema()` | yes | yes | the endpoint's FortiOS schema (`?action=schema`) |

## Several devices

Every call accepts an optional `Query` and `Client` as trailing arguments, so the same code works
against several devices:

```cpp
fortiapi::Client branch(branch_config);
auto policies = firewall::Policies::list({}, branch);
```

The repository's `examples/inventory.cpp` is a complete read-only program.
