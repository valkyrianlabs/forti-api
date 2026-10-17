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

When the key is numeric and left to the device (unset or `0`), the device assigns the next free id
(the highest id plus one) and `add` stores it in the entry. A key you set is never overwritten.

:::callout[What mkey names depends on the method]{variant="warning"}
On child paths FortiOS 7.4.8 uses `mkey` for different keys. A POST reply reports the new entry's
key as `mkey` and has no `child_mkey`. PUT replies report the parent's key as `mkey`, and reads and
errors do too. DELETE replies report the entry's key as `mkey`. PUT and DELETE also report the
entry's key, as text, in `child_mkey`. `add` takes `child_mkey` when a reply has it, and otherwise
`mkey` only from a reply that names the POST (`http_method`) and this child table (`child_path`),
so the entry never gets the parent's key. When neither is usable, the key stays as it was: `list`
the entries to find the new one.
:::

Adding an entry whose key already exists (an id in use, or a name already in a member table) fails
with HTTP 500 and FortiOS error `-5`, and the existing entry is not changed: a POST never
overwrites. As with `Table::add`, a write is sent at most once, never retried.

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
entry has no changes. The entry's other attributes, the other entries and the parent's own
attributes keep their values. A PUT never creates an entry: a missing entry is an `ApiError` with
`not_found()`.

## Deleting an entry

```cpp
Reservations::del(1, 7);   // DELETE cmdb/system.dhcp/server/1/reserved-address/7
```

A missing entry is an `ApiError` with `not_found()`. The last entry can be deleted too: FortiOS
leaves an address group with no member, for example, so a check that a group keeps one is yours.

## Replies and missing objects

Every write returns a `Reply`. On child paths it carries `child_path` (the attribute name) and the
keys described above, plus the table's configuration revision before and after the write:

| Field | On a successful child write (FortiOS 7.4.8) |
|---|---|
| `http_method` | `"POST"`, `"PUT"` or `"DELETE"` |
| `mkey` | POST: the new entry's key. PUT: the parent's key. DELETE: the entry's key. |
| `child_mkey` | PUT and DELETE: the entry's key, as text. POST: not reported. |
| `child_path` | The attribute, such as `"rule"` or `"member"` |
| `old_revision`, `revision` | The table's revision before and after the write |
| `revision_changed` | `true` |

Failed writes carry `revision` without `old_revision`, and `revision_changed` is `false`.
Missing objects are reported with HTTP 404 and no FortiOS error code, for every method:

| Request | Missing entry | Missing parent |
|---|---|---|
| `get`, `list` | `ApiError`, `not_found()` | `ApiError`, `not_found()` |
| `find`, `contains` | `std::nullopt`, `false` | `std::nullopt`, `false` |
| `add` | Creates the entry | `ApiError`, `not_found()`; the parent is not created |
| `update`, `del` | `ApiError`, `not_found()` | `ApiError`, `not_found()` |

## Concurrent writers

FortiOS serializes writes to a table, and each child write changes only its own entry, so separate
writers adding or changing different entries never lose each other's changes. The live suite
checked this with two clients on separate connections (`tests/live/test_child_table.cpp`):

- Two adds with device-assigned ids, back to back or at the same moment: both succeed, with
  distinct ids.
- Two adds with the same explicit id at the same moment: one succeeds, the other fails with error
  `-5`. Nothing is overwritten.
- One writer updates an entry while another changes a different attribute of the parent with
  `Table::update` (which sends only that attribute): both changes are kept.

:::callout[A whole-table write still wins silently]{variant="danger"}
Writing the parent with its table attribute (a `Table::update` after the list was modified, or any
PUT that includes the list) replaces the whole table with the list it sends. If another writer
added or changed an entry after that list was read, its change is lost without an error: the PUT
returns HTTP 200. Use `ChildTable` for single entries, and do not send a table you read earlier.
:::

To find out whether anything changed a table since you read it, compare revisions. A GET reply
(`client.get(...)`, the envelope around the results) carries the table's current `revision`, and
every write's `Reply::old_revision` is the revision the write replaced. If they differ, another
write landed in between. The revision belongs to the whole table, such as `router.access-list`,
not to one object, so a write to another object of the same table changes it too. Treat a
mismatch as "re-read before you trust your copy", not as proof that your object changed.

## Keys and other tables

Both keys are encoded like table keys: each is exactly one path segment, and `.` or `..` is sent as
`%2E` or `%2E%2E`, so a key can never address the table or its parent instead of one entry.

```cpp
using SourceAddresses = fortiapi::firewall::Policies::child<&fortiapi::firewall::Policy::srcaddr>;
fortiapi::Ref address("LAN 10.0.0.0/24");
SourceAddresses::add(12, address);                    // POST cmdb/firewall/policy/12/srcaddr
SourceAddresses::del(12, "LAN 10.0.0.0/24");          // DELETE .../srcaddr/LAN%2010.0.0.0%2F24
```

For a table attribute chosen at run time (a CLI, an MCP server), `fortiapi::schema` has the same
paths and the same key rule without the typed models: `child_table`, `child_path` and
`created_entry_key` ([Runtime schema](/guides/runtime-schema#child-tables)).

:::callout[One level, table parents]{variant="note"}
`ChildTable` addresses tables of a table object. Tables nested inside an entry (an `ip-range`'s
`vci-string`) and tables of singletons are not covered; change those through the parent.
:::
