<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Trust on first use, and a lighter schema for consumers

## See a device's certificate before trusting it

`fortiapi::probe_tls(config)` (`forti_api/tls.hpp`) connects to the FortiGate, completes the TLS
handshake and stops: no HTTP request, no API key, no client certificate. It reports whether the
certificate verified, and the chain as presented, so a person can inspect a self-signed or factory
certificate and pin it as the `ca_bundle`. The device's own certificate works as a trust anchor, and
the host name is still verified. It also reports the local address of the connection, which is what
the FortiGate sees (before any NAT), for example for an API user's trusted host. TLS verification of
requests is unchanged: it cannot be turned off.

## Every endpoint as data: the runtime schema

`forti_api/schema.hpp` describes every generated endpoint as data, with plain functions that decode,
validate and build request bodies for any of them. It is for programs that pick
the endpoint at run time (a CLI, an MCP server, a validator), which until now had to compile the typed
model of every endpoint to get the SDK's behavior: several GB of compiler memory and minutes of build
time. A translation unit that includes the runtime schema compiles in about 2.5 seconds and 360 MB
(Apple clang, -O0) and includes no typed model. The typed API is unchanged.

```cpp
namespace schema = fortiapi::schema;
const schema::Endpoint* ep = schema::find("cmdb/firewall/address");
nlohmann::json post = schema::create_body(*ep->type, {{"name", "web"}, {"subnet", "192.0.2.10/32"}});
fortiapi::default_client().post(ep->path, post);
```

- **Tables** (`gen/schema.hpp`, generated with the typed headers): for every endpoint its path, kind
  (table, singleton, monitor), object type and table key; for every attribute its key, C++ type,
  reset value and read-only flag in `visit()` order, nested types, and the FortiOS schema metadata
  that was only in comments so far: options, integer ranges, string sizes, references (datasources),
  required, help. `fortiapi::gen::fortios_version` names the FortiOS version (7.4.8).
- **Functions**: `decode` (exactly `from_json<T>`: results and error messages), `writable`,
  `create_body` and `update_body` (the bodies `Table::add` and `Table::update` send), `diff`, `key_of`
  and `object_path` (the object's key and API path), and the advisory `check_values` (options, ranges,
  sizes). Invalid bodies throw `schema::ValidationError` with a reason and the attributes involved.
- **Checked against the typed models**: a unit test compares both on generated inputs (descriptions,
  decoded values, request bodies, keys, paths and every error message) for a sample of endpoints that
  covers every attribute kind; the weekly exhaustive build compares all 534 endpoints (about 72,000
  inputs).

## Faster CI

- CI builds once per job and runs the tests on that build: the network-free unit suite at -O0 without
  debug info, under AddressSanitizer and UndefinedBehaviorSanitizer on Linux, on every core the memory
  allows. It no longer builds the live suite, whose coverage test needed about 6 GB of compiler memory
  in one translation unit. The live suite and the full schema comparison build in a separate workflow,
  on demand and weekly, in 10 shards each.
- Releases test an -O3 build of the unit suite before publishing.
- The standalone header check compiles the hand-written headers (11) instead of every generated
  header (582); `fortios.py check` already proves the generated ones.
