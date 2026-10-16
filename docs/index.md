---
title: forti-api
description: Header-only C++23 SDK for the FortiGate REST API (FortiOS v2).
order: 0
status: published
tags:
  - overview
---

# forti-api

:::badges{gap="sm"}
::badge[Latest release]{
  type="github"
  target="release"
  repo="valkyrianlabs/forti-api"
  href="https://github.com/valkyrianlabs/forti-api/releases"
  newTab=true
}
::badge[CI]{
  type="github"
  target="workflow"
  repo="valkyrianlabs/forti-api"
  workflow="ci.yml"
  href="https://github.com/valkyrianlabs/forti-api/actions/workflows/ci.yml"
  newTab=true
}
::badge[License]{
  type="github"
  target="license"
  repo="valkyrianlabs/forti-api"
  href="https://github.com/valkyrianlabs/forti-api/blob/main/LICENSE"
  newTab=true
}
:::

forti-api is a header-only C++23 client for the FortiGate REST API (FortiOS v2). Its types are
generated from the FortiGate's own schema, so every attribute of a supported object is available,
documented and correctly typed, and writes change exactly what you changed.

:::buttons{align="left" stack="mobile" gap="md"}
::button[Install forti-api]{href="/getting-started/installation" variant="primary"}
::button[Quick start]{href="/getting-started/quick-start" variant="secondary"}
::button[GitHub]{href="https://github.com/valkyrianlabs/forti-api" variant="outline" newTab=true}
:::

```cpp
#include <forti_api/firewall.hpp>
using namespace fortiapi;

auto address = firewall::Addresses::get("LAN 10.0.0.0/24");
address.comment = "managed by forti-api";
firewall::Addresses::update(address);   // sends {"comment": "managed by forti-api"} and nothing else
```

## What you get

:::cards{
  columns="2"
  cardTheme="muted"
}

:::card[Every configuration endpoint]{eyebrow="Catalog"}
Generated from FortiOS 7.4.8 schemas: 487 endpoints on a FortiGate-60F, one struct per object with
every attribute as a `fortiapi::Field<T>`, and a `Table` (list, find, get, contains, add, update,
del) or `Singleton` (get, update) per endpoint.
:::

:::card[Typed monitor reads]{eyebrow="Monitor"}
The read-only monitor endpoints the web GUI uses, with result types generated from recorded
response shapes; everything else through `fortiapi::Monitor`.
:::

:::card[Exact writes]{eyebrow="Fields"}
Fields know whether they are absent, read from the device, modified or cleared. An update sends
only modified and cleared attributes.
:::

:::card[A careful transport]{eyebrow="Transport"}
Timeouts, one kept-alive connection per client for reads, URL-encoded object names, typed errors,
reads retried on throttling and configuration changes never sent twice.
:::

:::card[Raw downloads]{eyebrow="Downloads"}
Non-JSON replies such as configuration backups, with a size limit and optional streaming.
:::

:::card[Domain helpers]{eyebrow="Helpers"}
DNS filter categories, push threat feeds, schedule days, service port ranges, API-user trusted
hosts and live interface addresses.
:::

:::card[Header-only]{eyebrow="Packaging"}
Install the `libforti-api-dev` package or vendor the headers; libcurl is the only system
dependency.
:::

:::

## Where to go next

### Get started

:::cards{
  columns="2"
  cardTheme="glass"
}

:::card[Installation]{href="/getting-started/installation"}
APT, Homebrew, vendoring or a source build, and how to compile against the headers.
:::

:::card[Quick start]{href="/getting-started/quick-start"}
Create an API administrator, configure the connection, then read, change and create objects.
:::

:::

### Guides

:::cards{
  columns="2"
  cardTheme="muted"
}

:::card[Fields and updates]{href="/guides/fields-and-updates"}
`Field<T>` states, changing, clearing and creating objects, nested objects and tables.
:::

:::card[Queries]{href="/guides/queries"}
VDOMs, filters, field selection, paging and how object keys are encoded.
:::

:::card[Errors and retries]{href="/guides/errors-and-retries"}
The exception types, what is retried and what never is, and tracing.
:::

:::card[Downloads and configuration backups]{href="/guides/downloads"}
`Client::download`, size limits, streaming, and handling backups safely.
:::

:::card[DNS filter]{href="/guides/dns-filter"}
FortiGuard category actions on DNS filter profiles.
:::

:::card[Threat feeds]{href="/guides/threat-feeds"}
Create a push feed, push entries, read them back and delete it safely.
:::

:::card[System and firewall helpers]{href="/guides/system-and-firewall"}
Interface addresses, the monitor API, trusted hosts, schedule days and port ranges.
:::

:::

### Reference

:::cards{
  columns="2"
  cardTheme="muted"
}

:::card[Configuration]{href="/reference/configuration"}
Environment variables and `fortiapi::Config` fields, with their defaults.
:::

:::card[Supported endpoints]{href="/reference/endpoints"}
Every generated FortiOS endpoint with its C++ type, endpoint alias and header.
:::

:::

### Development

:::cards{
  columns="2"
  cardTheme="muted"
}

:::card[Code generation]{href="/development/code-generation"}
How the generated headers are produced, endpoint discovery and adding an endpoint.
:::

:::card[Testing]{href="/development/testing"}
The unit suite, the live FortiGate suite and its safeguards.
:::

:::
