---
title: DNS filter
description: FortiGuard category actions on DNS filter profiles.
order: 60
status: published
tags:
  - guides
---

# DNS filter

`#include <forti_api/dnsfilter.hpp>` adds category helpers to the generated
`dnsfilter::Profiles` endpoint. A profile lists FortiGuard categories in `ftgd-dns.filters` with an
action (`block` or `monitor`); a category that is not listed is allowed.

## Category actions

The helpers change the profile in memory and mark only `ftgd-dns` as modified; send it with
`Profiles::update()`:

```cpp
using namespace fortiapi;

auto profile = dnsfilter::Profiles::get("home");
dnsfilter::block_category(profile, 26);      // malicious websites
dnsfilter::monitor_category(profile, 61);
dnsfilter::allow_category(profile, 30);      // removes the filter, if listed
dnsfilter::Profiles::update(profile);

auto action = dnsfilter::category_action(profile, 26);   // "block", "monitor" or std::nullopt
```

## Allowing a category everywhere

```cpp
std::vector<std::string> changed = dnsfilter::allow_category_everywhere(200);
```

Every profile that lists the category is updated to allow it; profiles that do not list it are
never written. The names of the updated profiles are returned.

:::callout[It writes to every matching profile]{variant="warning"}
`allow_category_everywhere` changes every DNS filter profile on the device (or in the VDOM a
`Query` selects) that lists the category, not only the profiles your program manages. Run it only
when every profile that can match should allow the category.
:::
