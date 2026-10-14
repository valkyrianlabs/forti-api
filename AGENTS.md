# forti-api

Header-only C++23 client for the FortiGate REST API (FortiOS v2). Meson build, vendored
nlohmann/json, libcurl as the only system dependency, released with vl-release (`release.toml`,
`.claude/skills/vl-release/`).

```sh
meson setup build -Dtests=enabled && meson compile -C build   # Linux (apt) or macOS (Homebrew)
./ci/run-ci bash -c '...'                                      # the CI container (ci/README.md)
```

## The live FortiGate: the one rule

The test suite runs against a real FortiGate: the maintainer's home lab firewall, carrying real
policies and config. It is backed up and recoverable, so work on it normally (read freely, run the
suite, probe the API), but carefully and methodically. The rule for every test and every manual
write:

1. **Never modify existing config.** No update, delete, rename or move of any object a test did
   not create in the same run: policies, addresses, services, schedules, VIPs, DNS filter and
   threat feed profiles, interfaces, admins, certificates, global settings. Reading existing
   config is fine. Never attach test objects to real policies or profiles, and never call helpers
   that sweep across existing objects (e.g. `DNSFilter::global_allow_category`,
   `DNSFilter::block_category_in_profiles`) against the live device.
2. **Everything written is visibly test content.** Names start with `forti-api-test-`; where the
   object has a comment or description field, set it to say it was created by the forti-api test
   suite.
3. **Clean up every time, including on failure.** Each test deletes what it created even when an
   assertion fails (a fixture `TearDown` or RAII guard, not cleanup after the last `ASSERT_*`,
   which a failed assertion skips). A suite may also delete leftovers from an aborted earlier run,
   but only objects carrying the `forti-api-test-` prefix.
4. **No live tests in CI.** CI compiles the live suite but never runs it. Only tests that need no
   network (mocked HTTP, serialization round-trips) may run in CI.

Before writing anything new to the device, know exactly which objects the change touches. If an
auth request fails repeatedly, stop: FortiOS locks the API out (HTTP 429) after a few failures.
