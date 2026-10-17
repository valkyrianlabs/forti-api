---
title: Fields and updates
description: How Field<T> tracks state so that writes change exactly what you changed.
order: 30
status: published
tags:
  - guides
---

# Fields and updates

Every attribute of a generated object is a `fortiapi::Field<T>` with one of four states:

| State | Meaning | Sent by `update` | Sent by `add` |
|---|---|---|---|
| absent | never read from the device, never set | no | no |
| populated | read from the device, untouched since | no | yes |
| modified | set by you (assignment or `edit()`) | yes, its value | yes, its value |
| cleared | reset by you with `clear()` | yes, the FortiOS default | yes, the FortiOS default |

:::toc[On this page]{depth="2" theme="compact"}
:::

## Reading

Reads never change a field's state:

```cpp
auto policy = firewall::Policies::get(12);
if (policy.comments)                          // has a value
    std::cout << *policy.comments << "\n";
std::cout << policy.name.value_or("(unnamed)") << "\n";
bool denies = policy.action == std::string(firewall::Policy::Action::deny);
```

:::callout[Check before dereferencing]{variant="note"}
`value()` and `*field` throw `std::logic_error` when the field has no value; check with
`has_value()` or `operator bool` first, or use `value_or()`.
:::

## Changing

Assignment marks a field modified. For containers and nested objects, `edit()` returns a mutable
reference and marks the field modified:

```cpp
policy.comments = "reviewed";
policy.srcaddr.edit().push_back("printer");   // fortiapi::Ref converts from a name
firewall::Policies::update(policy);           // sends comments and srcaddr only
```

`update` returns `std::nullopt` without sending anything when nothing is modified or cleared.
After a successful write the object is clean: modified fields become populated, cleared fields
become absent.

## Clearing and forgetting

`clear()` resets an attribute to its FortiOS default (an empty string, `0`, the default option or an
empty table, from the schema). `reset()` only forgets the local value so nothing is sent for it.

```cpp
policy.comments.clear();       // the device's comment becomes ""
policy.schedule.reset();       // not part of the next update
```

## Creating

A new object starts with every field absent. Set what you need; FortiOS fills in its own defaults
for the rest:

```cpp
firewall::Address host;
host.name = "printer";
host.subnet = "192.168.1.50 255.255.255.255";
firewall::Addresses::add(host);
```

When the device assigns the key (a firewall policy created with `policyid` 0 or unset), `add` stores
the assigned key in the object.

:::callout[Creates are not transactional]{variant="warning"}
When FortiOS rejects an attribute after it created the object, `add` throws an `ApiError` and the
object still exists on the device. See [Partial creates](/guides/errors-and-retries#partial-creates).
:::

## Nested objects and tables

- A nested object (for example `dnsfilter::Profile::ftgd_dns`) is updated attribute by attribute:
  `profile.ftgd_dns.edit().options = "error-allow"` sends only `ftgd-dns.options`.
- References to other objects by name (`srcintf`, `srcaddr`, `service`, ...) are
  `std::vector<fortiapi::Ref>`; a `Ref` converts from a string.

:::callout[Tables are sent whole]{variant="warning"}
A table (for example `ftgd_dns.filters` or `srcintf`) is always sent whole, because FortiOS
replaces tables. Edit the list you read and send it back. To add, change or remove one entry
without rewriting the others (one DHCP reservation, one address in `srcaddr`), use a
[child table](/guides/child-tables).
:::

## Read-only attributes

Attributes the schema marks read-only are parsed but never sent, even if you assign them.

## Option constants

Every option attribute has constants nested in its type, for example
`firewall::Policy::Action::accept` or `dnsfilter::Profile::BlockAction::redirect`. They are
`std::string_view`; assign them with `std::string(...)`.

## Serializing yourself

`fortiapi::to_json(object, Write::update)` and `Write::create` produce the exact request bodies,
and `fortiapi::from_json<T>(json)` builds an object from a device reply. `fortiapi::dirty(object)`
tells whether an update would send anything.
