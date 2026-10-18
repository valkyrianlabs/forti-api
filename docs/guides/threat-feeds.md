---
title: Threat feeds
description: Push threat feeds: create a feed, push entries, check its status, read entries back page by page, delete safely.
order: 70
status: published
tags:
  - guides
---

# Threat feeds

FortiOS threat feeds are external resources (`system::ExternalResources`). A push feed receives
its entries through the monitor API instead of downloading them. `#include <forti_api/threat_feed.hpp>`.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Create a push feed

```cpp
using namespace fortiapi;

auto feed = system::push_threat_feed("blocklist", 200);   // remote category 192-221, type domain
feed.comments = "Managed by forti-api";
system::ExternalResources::add(feed);
```

:::callout[Wait for the feed to load]{variant="note"}
FortiOS loads a new feed asynchronously (a few seconds); until then pushes are rejected.
`system::feed_status(name).loaded` tells when it is ready.
:::

## Push entries

```cpp
system::push_entries("blocklist", {"bad.example", "worse.example"});                      // replace all
system::push_entries("blocklist", {"new.example"}, system::FeedCommand::add);
system::push_entries("blocklist", {"bad.example"}, system::FeedCommand::remove);
```

FortiOS reports a rejected command inside an otherwise successful reply; `push_entries` turns it
into a `fortiapi::ApiError`, so a failed push is never silent.

## Check a feed's status

`feed_status` reads a feed's counters in one request that never transfers an entry, so it costs
the same for five entries as for a million:

```cpp
auto status = system::feed_status("blocklist");
if (!status.loaded) std::cerr << "not loaded yet: " << status.error << "\n";   // "Connect pending"
std::cout << status.accepted << " in use, " << status.invalid << " invalid, cap " << status.limit << "\n";
```

| Member | Meaning |
|---|---|
| `loaded` | FortiOS has loaded the feed and accepts pushes |
| `error` | Why it is not loaded yet (`"Connect pending"` for a feed created seconds ago) |
| `file_status` | `"downloaded"` once pushed entries are applied, `"unavailable"` before the first push |
| `accepted` | Entries FortiOS uses: the valid ones |
| `valid`, `invalid` | Entries FortiOS kept, by validity. An exact duplicate is kept once (case matters); an entry such as `a..b.example` is kept but invalid |
| `limit` | The device-wide entry cap (1000000 on a FortiGate-60F), shared by every feed |
| `overflow` | FortiOS flags the feed as over the cap |
| `last_update` | When FortiOS last applied new content (Unix seconds); 0 if not reported |

To confirm that a push was applied, remember `last_update` before pushing and poll until it
advances (a few seconds on FortiOS 7.4):

```cpp
auto before = system::feed_status("blocklist").last_update;
system::push_entries("blocklist", entries);
while (system::feed_status("blocklist").last_update <= before) std::this_thread::sleep_for(1s);   // add a deadline
```

:::callout[The cap is per device, not per feed]{variant="warning"}
`limit` is the same number for every feed: all feeds on the device share it, and FortiOS sets
`overflow` once a feed is over it. The push reply does not say how many entries FortiOS took, so
compare `accepted` with the number of distinct valid entries you pushed.
:::

## Read entries page by page

`feed_entries(name, start, count)` returns one window of the entry list in FortiOS order. FortiOS
pages server-side, so a sample costs one small request however large the feed is:

```cpp
auto sample = system::feed_entries("blocklist", 0, 100);                 // the first 100
auto later = system::feed_entries("blocklist", 5000, 100);               // entries 5000-5099
for (const auto& entry: sample) if (!entry.valid) std::cerr << "invalid: " << entry.entry << "\n";
```

Past the end, or before the feed is loaded, the page is short or empty. `count` 0 returns nothing
without a request.

:::details[Why feed_status does not ask for the first entry]
FortiOS counts `valid_count` and `invalid_count` only up to the end of the requested window: asked
for `start=0&count=1`, it reports one valid entry however many the feed holds, and `count=0` means
every entry. `feed_status` therefore asks for one entry at a start no feed reaches, which returns
the counts of the whole feed and an empty window.
:::

## Read the whole feed

`feed_state` downloads every entry at once; for large feeds prefer `feed_status` and
`feed_entries`.

```cpp
auto state = system::feed_state("blocklist");
// state.loaded, state.file_status ("downloaded" once applied), state.error, state.entries
for (const auto& entry: state.entries) std::cout << entry.entry << (entry.valid ? "" : " (invalid)") << "\n";
```

Pushed entries become visible a few seconds after the push.

## Block the feed's category

Use the feed's category in DNS filter profiles (see [DNS filter](/guides/dns-filter)):

```cpp
auto profile = dnsfilter::Profiles::get("home");
dnsfilter::block_category(profile, 200);
dnsfilter::Profiles::update(profile);
```

## Delete a feed

FortiOS refuses to delete a feed whose category a profile still lists. `delete_threat_feed` first
allows the category in the profiles that list it (unless another feed provides the same category),
then deletes the feed:

```cpp
system::delete_threat_feed("blocklist");
```

:::callout[Deleting a feed can change DNS filter profiles]{variant="warning"}
Unless another feed provides the same category, `delete_threat_feed` uses
[`dnsfilter::allow_category_everywhere`](/guides/dns-filter#allowing-a-category-everywhere), so every
DNS filter profile that lists the category is updated to allow it.
:::
