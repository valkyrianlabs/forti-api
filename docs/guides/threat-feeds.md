---
title: Threat feeds
description: Push threat feeds: create a feed, push entries, read them back, delete safely.
order: 70
status: published
tags:
  - guides
---

# Threat feeds

FortiOS threat feeds are external resources (`system::ExternalResources`). A push feed receives
its entries through the monitor API instead of downloading them. `#include <forti_api/threat_feed.hpp>`.

## Create a push feed

```cpp
using namespace fortiapi;

auto feed = system::push_threat_feed("blocklist", 200);   // remote category 192-221, type domain
feed.comments = "Managed by forti-api";
system::ExternalResources::add(feed);
```

FortiOS loads a new feed asynchronously (a few seconds); until then pushes are rejected.
`system::feed_state(name).loaded` tells when it is ready.

## Push entries

```cpp
system::push_entries("blocklist", {"bad.example", "worse.example"});                      // replace all
system::push_entries("blocklist", {"new.example"}, system::FeedCommand::add);
system::push_entries("blocklist", {"bad.example"}, system::FeedCommand::remove);
```

FortiOS reports a rejected command inside an otherwise successful reply; `push_entries` turns it
into a `fortiapi::ApiError`, so a failed push is never silent.

## Read them back

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
