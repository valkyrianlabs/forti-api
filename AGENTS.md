# forti-api

Header-only C++23 client for the FortiGate REST API (FortiOS v2). Meson build, vendored
nlohmann/json, libcurl as the only system dependency, released with vl-release (`release.toml`,
`.claude/skills/vl-release/`).

```sh
meson setup build -Dtests=enabled -Dlive_tests=true            # Linux (apt) or macOS (Homebrew)
meson test -C build --suite unit                               # network-free; what CI runs
set -a; . ./.env; set +a; meson test -C build --suite live -v  # the live FortiGate suite
./ci/run-ci bash -c '...'                                      # the CI container (ci/README.md)
```

Agent context: `.claude/context/audit.md` and `.claude/context/buildout-plan.md`.

## The live FortiGate: the one rule

The test suite runs against a real FortiGate: the maintainer's home lab firewall, carrying real
policies and config. It is backed up and recoverable, so work on it normally (read freely, run the
suite, probe the API), but carefully and methodically. The rule for every test and every manual
write:

1. **Never modify existing config.** No update, delete, rename or move of any object a test did
   not create in the same run: policies, addresses, services, schedules, VIPs, DNS filter and
   threat feed profiles, interfaces, admins, certificates, global settings. Reading existing
   config is fine. Never attach test objects to real policies or profiles. Helpers that sweep
   across existing objects (`DNSFilter::global_allow_category`, `block_category_in_profiles`, and
   `ThreatFeed::del`, which uses the former) may only run when nothing real can match, e.g. a
   threat-feed category no existing feed or profile uses (`live::free_threat_feed_category()`).
2. **Everything written is visibly test content.** Names start with `forti-api-test-`; where the
   object has a comment or description field, set it to say it was created by the forti-api test
   suite.
3. **Clean up every time, including on failure.** Each test deletes what it created even when an
   assertion fails (a fixture `TearDown` or RAII guard, not cleanup after the last `ASSERT_*`,
   which a failed assertion skips). A suite may also delete leftovers from an aborted earlier run,
   but only objects carrying the `forti-api-test-` prefix.
4. **No live tests in CI.** CI compiles the live suite but never runs it. Only tests that need no
   network (mocked HTTP, serialization round-trips) may run in CI.

These are enforced, not just documented: the live suite's client goes through
`live::GuardTransport` (`tests/live/guard.hpp`), which refuses before sending any POST/PUT/DELETE
outside `live::approved_collections` or without the prefix, and `live::ConfigAudit` fails the run if
the device's config-change log shows a REST change to any non-test object. Adding a collection to
the allowlist is a deliberate, reviewed change.

Before writing anything new to the device, know exactly which objects the change touches. If an
auth request fails repeatedly, stop: FortiOS locks the API out (HTTP 429) after a few failures.
