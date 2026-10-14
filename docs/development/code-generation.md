---
title: Code generation
description: How the generated endpoint headers are produced and how to add an endpoint.
order: 110
status: published
tags:
  - development
---

# Code generation

`include/forti_api/gen/**` is generated and checked in, so users never need the generator. Its
inputs are:

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

## Adding an endpoint

1. Add a `[[cmdb]]` entry to `codegen/api.toml` (`path`, and `namespace`, `type`, `alias` when the
   defaults do not read well).
2. `fortios.py pull <path>` to fetch its schema snapshot.
3. `fortios.py gen`, then build and run the tests.

## What the generator produces

- A struct per object with every attribute as `fortiapi::Field<T>`, documented from the schema;
  nested objects as nested structs, table rows as `...Entry` structs, name references as
  `std::vector<fortiapi::Ref>`.
- A static `visit()` listing every attribute's FortiOS key, member, reset value and flags; the
  serialization in `field.hpp` is driven by it.
- A `...Spec` and a `Table` or `Singleton` alias.
- Option constants in a namespace beside the type.

Behavior lives in hand-written headers: `client.hpp` (transport), `field.hpp` (field states and
serialization), `endpoint.hpp` (`Table`, `Singleton`), `monitor.hpp`, and the helper headers.
