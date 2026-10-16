---
title: Queries
description: VDOMs, filters, field selection and paging with fortiapi::Query.
order: 40
status: published
tags:
  - guides
---

# Queries

Every endpoint call takes an optional `fortiapi::Query`. Values are URL-encoded for you.

```cpp
using fortiapi::Query;

auto enabled = firewall::Policies::list(Query().filter("status==enable"));
auto names = firewall::Addresses::list(Query().format({"name", "subnet"}));
auto page = firewall::Addresses::list(Query().start(100).count(50));
auto dmz = firewall::Policies::list(Query().vdom("dmz"));
```

## Query methods

| Method | Parameter | Use |
|---|---|---|
| `vdom(name)` | `vdom` | Target a VDOM (overrides `Config::vdom`) |
| `filter(expression)` | `filter` | FortiOS filter expression; repeated calls are combined with AND |
| `format({fields...})` | `format` | Return only these attributes (`name\|subnet`) |
| `start(n)`, `count(n)` | `start`, `count` | Paging |
| `datasource()` | `datasource` | Include datasource details |
| `with_meta()` | `with_meta` | Include object metadata |
| `skip()` | `skip` | Skip attributes not applicable to the object |
| `action(name)` | `action` | Endpoint actions such as `schema` or `default` |
| `set(key, value)` | any | Any other parameter |

## Filter expressions

Filter expressions use FortiOS syntax, for example `name==web`, `name=@web` (contains) or
`status!=disable`; separate alternatives with a comma inside one expression for OR.

| Expression | Meaning |
|---|---|
| `name==web` | equals |
| `status!=disable` | does not equal |
| `name=@web` | contains |
| `name==web,name==mail` | either alternative (OR), within one expression |
| `filter(...)` called twice | both expressions must match (AND) |

## Object keys

Object keys are always URL-encoded, so names with spaces or slashes work as-is:

```cpp
auto subnet = firewall::Addresses::get("LAN 10.0.0.0/24");
```

Each key is exactly one path segment. Dots inside a key stay readable (`10.0.0.0%2F24`), but a key
that is exactly `.` or `..` is sent as `%2E` or `%2E%2E`.

:::callout[Why dot keys are encoded]{variant="warning"}
Left literal, a key of `.` or `..` would be a dot segment and address the table itself or its
parent, so `Addresses::del("..")` could reach far more than one object. The transport sends paths
exactly as built (libcurl never removes dot segments). Build paths for `Client` calls with
`fortiapi::path(base, keys...)` to get the same encoding.
:::
