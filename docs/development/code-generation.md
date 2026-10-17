---
title: Code generation
description: How the generated endpoint headers are produced and how to add an endpoint.
order: 110
status: published
tags:
  - development
---

# Code generation

`include/forti_api/gen/**` is generated and checked in, so users never need the generator.

:::toc[On this page]{depth="2" theme="compact"}
:::

:::callout[Never edit generated headers]{variant="warning"}
Change the inputs and run `fortios.py gen` instead; `fortios.py check` fails CI when the checked-in
headers are out of date. The same goes for `docs/reference/endpoints.md`, which `gen` writes too.
:::

## Inputs and tool

The inputs are:

- `codegen/api.toml`: which FortiOS paths are generated and their C++ names
  (namespace, type and endpoint alias overrides).
- `codegen/schema/<version>/cmdb/<path>.json`: schema snapshots the FortiGate itself returns for
  `GET /api/v2/cmdb/<path>?action=schema`.

The tool is `tools/fortios/fortios.py` (Python 3.12, standard library only):

```bash
tools/fortios/fortios.py --env-file .env pull [PATH...]   # refresh snapshots from a device (GET only)
tools/fortios/fortios.py --env-file .env crawl            # discover cmdb paths via datasource references
tools/fortios/fortios.py gen                              # regenerate the headers
tools/fortios/fortios.py check                            # fail if the headers are out of date (CI)
```

Generation is deterministic: the same manifest and snapshots always produce byte-identical headers.

## Discovery

The catalogs in `codegen/catalog/<version>/` record what a device offers; they contain paths and
schema metadata only, never device data:

- `cmdb.json` (`fortios.py crawl`): every configuration path, found from `codegen/seeds.txt`, the
  cmdb paths the web GUI references, and the `datasource` references inside each schema, with its
  category, key and attribute count. Every entry was confirmed by the device answering
  `?action=schema`.
- `gui-api.json` (`fortios.py mine`): the monitor, log and service paths the device's web GUI calls,
  extracted statically from its JavaScript bundle (and the HTTP method where the call site shows
  it). Only path strings are kept.

:::callout[Read-only against the device]{variant="info"}
Both are read-only against the device and converge: running them again finds nothing new.
:::

## Adding an endpoint

:::steps

### Add it to the manifest

Add a `[[cmdb]]` entry to `codegen/api.toml` (`path`, and `namespace`, `type`, `alias` when the
defaults do not read well).

### Pull its schema

`fortios.py pull <path>` fetches its schema snapshot.

### Generate and test

`fortios.py gen`, then build and run the tests.

:::

## What the generator produces

- A struct per object with every attribute as `fortiapi::Field<T>`, documented from the schema;
  nested objects as nested structs, table rows as `...Entry` structs, name references as
  `std::vector<fortiapi::Ref>`. Each `...Entry` names its key, the table's mkey from the schema
  (`static constexpr auto mkey = &ReservedAddressEntry::id;`), which is how
  [child tables](/guides/child-tables) address one entry; `mkey` is reserved, so an attribute of that
  name would become `mkey_`.
- A static `visit()` listing every attribute's FortiOS key, member, reset value and flags; the
  serialization in `field.hpp` is driven by it.
- A `...Spec` and a `Table` or `Singleton` alias.
- Option constants in a namespace beside the type.
- `gen/schema.hpp`: every type and endpoint as constexpr tables for the
  [runtime schema](/guides/runtime-schema): attributes in `visit()` order with their C++ type, reset
  value and flags, and the schema's options, ranges, sizes, references and help. It is built from the
  same traversal as the structs and includes none of them.

Behavior lives in hand-written headers: `client.hpp` (transport), `field.hpp` (field states and
serialization), `endpoint.hpp` (`Table`, `Singleton`), `monitor.hpp`, `schema.hpp` (the runtime
schema), and the helper headers.
