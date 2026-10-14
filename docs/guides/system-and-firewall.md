---
title: System and firewall helpers
description: Interface addresses, monitor calls, trusted hosts, schedule days and port ranges.
order: 80
status: published
tags:
  - guides
---

# System and firewall helpers

## Interface addresses

The configured address of a DHCP interface is `0.0.0.0`; the monitor API reports what it holds
right now:

```cpp
#include <forti_api/system.hpp>

for (const auto& address: fortiapi::system::interface_addresses("wan1"))
    std::cout << address.ip << "/" << address.prefix_length << "\n";
```

## Monitor API

Read-only monitor endpoints the web GUI uses are generated with typed results, from response shapes
recorded on a FortiOS 7.4.8 device (see [Supported endpoints](/reference/endpoints)):

```cpp
#include <forti_api/gen/monitor.hpp>

auto now = fortiapi::monitor::system::Time::get();                    // TimeResult
std::cout << now.time.value_or(0) << "\n";
auto routes = fortiapi::monitor::router::Statistics::get(Query().vdom("root"));   // StatisticsResult
```

Attributes the device did not report while the shapes were recorded are absent; unknown attributes
are ignored. Every other monitor path and every monitor action goes through `fortiapi::Monitor`,
which passes JSON through. Paths are relative to `monitor/`:

```cpp
auto status = fortiapi::Monitor::get("system/status");
std::cout << status.value("hostname", "") << "\n";
```

`Monitor::post(path, body)` calls monitor actions; like every write, it is never retried.

## API-user trusted hosts

```cpp
auto user = system::ApiUsers::get("automation");
system::trust(user, "10.0.0.0/24");           // or "10.0.0.0 255.255.255.0", or IPv6 "2001:db8::/32"
system::distrust(user, "192.168.1.0/24");
if (system::trusts(user, "10.0.0.0/24")) { /* ... */ }
system::ApiUsers::update(user);               // sends the trusthost table only
```

## Schedule days

```cpp
#include <forti_api/firewall.hpp>
using fortiapi::firewall::Weekday;

firewall::RecurringSchedule schedule;
schedule.name = "weekdays";
schedule.day = firewall::days({Weekday::monday, Weekday::tuesday, Weekday::wednesday,
                               Weekday::thursday, Weekday::friday});   // "monday tuesday ..."
schedule.start = "08:00";
schedule.end = "18:00";
firewall::RecurringSchedules::add(schedule);
```

## Service port ranges

```cpp
firewall::Service web;
web.name = "web-alt";
web.tcp_portrange = firewall::port_ranges({{80}, {8000, 8080}});   // "80 8000-8080"
firewall::Services::add(web);
```
