---
title: forti-api
description: Header-only C++23 SDK for the FortiGate REST API (FortiOS v2).
order: 0
status: published
tags:
  - overview
---

# forti-api

forti-api is a header-only C++23 client for the FortiGate REST API (FortiOS v2). Its types are
generated from the FortiGate's own schema, so every attribute of a supported object is available,
documented and correctly typed, and writes change exactly what you changed.

```cpp
#include <forti_api/firewall.hpp>
using namespace fortiapi;

auto address = firewall::Addresses::get("LAN 10.0.0.0/24");
address.comment = "managed by forti-api";
firewall::Addresses::update(address);   // sends {"comment": "managed by forti-api"} and nothing else
```

## What you get

- **Generated endpoints**: one struct per FortiOS object with every attribute as a
  `fortiapi::Field<T>`, and a `Table` (list, find, get, contains, add, update, del) or `Singleton`
  (get, update) per endpoint.
- **Exact writes**: fields know whether they are absent, read from the device, modified or
  cleared. An update sends only modified and cleared attributes.
- **A careful transport**: timeouts, one kept-alive connection per client, URL-encoded object
  names, typed errors, reads retried on throttling and configuration changes never retried.
- **Domain helpers**: DNS filter categories, push threat feeds, schedule days, service port
  ranges, API-user trusted hosts and live interface addresses.
- **Header-only**: install the `libforti-api-dev` package or vendor the headers; libcurl is the
  only system dependency.

## Where to go next

- [Installation](/getting-started/installation)
- [Quick start](/getting-started/quick-start)
- [Fields and updates](/guides/fields-and-updates)
- [Supported endpoints](/reference/endpoints)
