---
title: Child tables
description: Read, add, update and delete one entry of a table attribute, such as a DHCP reservation, without rewriting the others.
order: 32
status: published
tags:
  - guides
---

# Child tables

Many FortiOS objects carry tables as attributes: the reserved addresses of a DHCP server, the
`srcaddr` names of a policy, the rules of an access list. Through `Table<Spec>::update` such a table
is always written whole, so changing one entry means sending the whole list back, and a bug in that
list drops or changes the other entries. `fortiapi::ChildTable` addresses one entry at a time
instead, on the paths FortiOS provides for child tables:

| Request | Path |
|---|---|
| `list` (GET), `add` (POST) | `cmdb/<path>/<parent key>/<attribute>` |
| `find`, `get` (GET), `update` (PUT), `del` (DELETE) | `cmdb/<path>/<parent key>/<attribute>/<entry key>` |

Each write changes one entry; the parent object and the other entries are left alone.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Naming a child table

A child table is the parent's `Spec` and the attribute's member. `Table<Spec>::child<&Type::member>`
and `ChildTable<Spec, &Type::member>` are the same type:

```cpp
#include <forti_api/gen/system/dhcp/server.hpp>

using fortiapi::system::dhcp::Server;
using Reservations = fortiapi::system::dhcp::Servers::child<&Server::reserved_address>;

Reservations::attribute();   // "reserved-address"
Reservations::path(1, 7);    // "cmdb/system.dhcp/server/1/reserved-address/7"
```

It works for every table attribute of a generated table: entries are the generated `...Entry`
structs (`Reservations::type` is `Server::ReservedAddressEntry`), or `fortiapi::Ref` for tables of
names such as `srcaddr`. Each entry type names its key member, the schema's mkey
(`Reservations::key` is `&Server::ReservedAddressEntry::id`), and `key_type` and `parent_key_type`
follow from the key members: `std::uint32_t` for ids, `std::string` for names.

## Reading entries

```cpp
for (const auto& entry: Reservations::list(1))        // every reservation of DHCP server 1
    std::cout << *entry.id << " " << *entry.mac << " " << *entry.ip << "\n";

auto entry = Reservations::get(1, 7);                 // ApiError (not_found()) when missing
auto maybe = Reservations::find(1, 7);                // std::nullopt on 404
bool exists = Reservations::contains(1, 7);
```

`list` throws `ApiError` with `not_found()` when the parent object does not exist; `find` and
`contains` report a missing parent like a missing entry.

## Adding an entry

`add` posts one entry, with every attribute you set, to the child table:

```cpp
Server::ReservedAddressEntry reservation;
reservation.id = 0u;                                  // 0: the device assigns the next id
reservation.ip = "192.0.2.50";
reservation.mac = "00:00:5e:00:53:32";
reservation.description = "printer";
Reservations::add(1, reservation);
```

When the key is numeric and left to the device (unset or `0`), `add` stores the key the reply
reports for the entry. A key you set is never overwritten.

:::callout[The reply's mkey is the parent's]{variant="warning"}
On child paths FortiOS reports the parent object's key as `mkey` and the entry's key as
`child_mkey` (FortiOS 7.4.8 replies to reads of an entry do; `Reply::mkey` and `Reply::child_mkey`).
`add` only ever takes `child_mkey`, never `mkey`. When a reply has no `child_mkey`, the key stays as
it was: `list` the entries to find the new one.
:::

As with `Table::add`, a write is sent at most once, never retried.

## Updating an entry

`update` sends only the entry's modified and cleared attributes, to the entry's own path, exactly as
[Fields and updates](/guides/fields-and-updates) describes for whole objects:

```cpp
auto reservation = Reservations::get(1, 7);
reservation.ip = "192.0.2.51";
reservation.description.clear();
Reservations::update(1, reservation);   // PUT .../reserved-address/7 {"ip": "192.0.2.51", "description": ""}
```

`update` needs the entry's key member, and returns `std::nullopt` without sending anything when the
entry has no changes.

## Deleting an entry

```cpp
Reservations::del(1, 7);   // DELETE cmdb/system.dhcp/server/1/reserved-address/7
```

A missing entry is an `ApiError` with `not_found()`.

## Keys and other tables

Both keys are encoded like table keys: each is exactly one path segment, and `.` or `..` is sent as
`%2E` or `%2E%2E`, so a key can never address the table or its parent instead of one entry.

```cpp
using SourceAddresses = fortiapi::firewall::Policies::child<&fortiapi::firewall::Policy::srcaddr>;
fortiapi::Ref address("LAN 10.0.0.0/24");
SourceAddresses::add(12, address);                    // POST cmdb/firewall/policy/12/srcaddr
SourceAddresses::del(12, "LAN 10.0.0.0/24");          // DELETE .../srcaddr/LAN%2010.0.0.0%2F24
```

:::callout[One level, table parents]{variant="note"}
`ChildTable` addresses tables of a table object. Tables nested inside an entry (an `ip-range`'s
`vci-string`) and tables of singletons are not covered; change those through the parent.
:::
