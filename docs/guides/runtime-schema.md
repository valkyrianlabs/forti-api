---
title: Runtime schema
description: Every generated endpoint as data, with JSON decoding, validation and request bodies for endpoints chosen at run time, without compiling the typed models.
order: 35
status: published
tags:
  - guides
---

# Runtime schema

`forti_api/schema.hpp` describes every generated endpoint as data and works with them through plain
functions. Use it when the endpoint is chosen at run time: a command-line tool, an MCP server, a
validator, or anything that takes a path and a JSON object.

:::toc[On this page]{depth="2" theme="compact"}
:::

## When to use it

The typed API (`fortiapi::firewall::Addresses`, `Field<T>`, `from_json<T>`, `to_json<T>`) is the way
to work with an endpoint you know when you write the code. To handle any endpoint at run time with it,
a program would have to instantiate every model. That is hundreds of types and their containers and
JSON code, which takes several gigabytes of compiler memory.

The runtime schema gives the same behavior from tables that are generated with the typed headers:

| | Typed API | Runtime schema |
|---|---|---|
| Endpoint chosen | at compile time | at run time, by path |
| Values | C++ structs and `Field<T>` | `nlohmann::json` |
| Cost of including it | one model per header you include | about a second, no model included |
| Results | `from_json<T>`, `to_json<T>` | the same JSON and the same errors |

:::callout[Same behavior, checked]{variant="info"}
The tables come from the same schema snapshots and type decisions as the typed headers. A unit test
compares the two for every endpoint: the attributes and their types, and decoding, request bodies,
keys and paths on generated inputs, errors included.
:::

## Find an endpoint

```cpp
#include <forti_api/schema.hpp>

namespace schema = fortiapi::schema;

const schema::Endpoint* ep = schema::find("cmdb/firewall/address");   // nullptr when not generated
for (const schema::Endpoint& each: schema::endpoints()) { /* every endpoint, sorted by path */ }
```

An `Endpoint` holds the API path (`cmdb/...` or `monitor/...`), its kind (`table`, `singleton` or
`monitor`), the object type and, for tables, the key attribute and its type. A `Type` lists its
attributes in the order of the generated struct. Each `Field` has:

- `name`, `kind` (`string`, `uint32`, `int64`, `number`, `boolean`, `json`, `object`, `array`, `map`),
  the nested `type` or element `item`, the `reset` value written when the attribute is cleared, and
  `read_only`;
- the FortiOS schema metadata: `fortios_type`, `help`, `options`, `references` (datasources), `range`,
  `size`, `required` and `multiple_values`.

`fortiapi::gen::fortios_version` is the FortiOS version the tables follow.

## Decode and build request bodies

```cpp
using nlohmann::json;

// As from_json<T>: numbers sent as text become numbers, "" is absent for numeric attributes.
json object = schema::decode(*ep->type, device_reply);

// What Table::add sends for these attributes.
json post = schema::create_body(*ep->type, json{{"name", "web"}, {"subnet", "192.0.2.10 255.255.255.255"}});

// What Table::update sends: the attributes set, and the reset value of those cleared.
std::vector<std::string> clear{"comment"};
json put = schema::update_body(*ep->type, json{{"color", 3}}, clear);   // empty: nothing to send

// The object's key and API path, as Table::get, update and del address it.
if (auto key = schema::key_of(*ep, object)) {
    std::string path = schema::object_path(*ep, *key);   // "cmdb/firewall/address/web"
}
```

The bodies go through the client like any other request, for example
`fortiapi::default_client().post(ep->path, post)`.

`diff(type, current, desired)` returns the update body that makes the current object match the
attributes given in `desired`.

## Validation errors

`create_body` and `update_body` throw `schema::ValidationError` when a body cannot be written.
`reason()` says why and `attributes()` names the attributes:

| Reason | Meaning |
|---|---|
| `not_object` | The object, or `set`, is not a JSON object. |
| `invalid_value` | The value does not decode as the attribute's type. `detail()` is the decoding error. |
| `unknown` | The attributes are not attributes of the type. |
| `read_only` | The attributes are reported by the device and never written. |
| `set_and_cleared` | An update both sets and clears the attribute. |

`decode` throws what `from_json<T>` throws: a `nlohmann::json::type_error`, or a decoding failure that
names the attribute path (`tagging[0].tags`).

## Advisory checks

`check_values(type, object)` compares values with the FortiOS schema metadata: option values, integer
ranges and string sizes. The device enforces these and the typed models do not.

:::callout[Findings are warnings]{variant="warning"}
Some option lists depend on the FortiGate model and licence. Report findings as warnings and let the
device decide.
:::
