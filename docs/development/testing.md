---
title: Testing
description: Unit tests, the live FortiGate suite and its safeguards.
order: 120
status: published
tags:
  - development
---

# Testing

```bash
meson setup build -Dtests=enabled -Dlive_tests=true
meson test -C build --suite unit                                  # network-free; what CI runs
set -a; . ./.env; set +a; meson test -C build --suite live -v     # against a real FortiGate
```

## Unit tests

The unit suite uses a scripted transport and needs no device: transport behavior (encoding,
errors, the retry policy), field states and serialization, the endpoint templates and the helpers.
CI runs it on Linux and macOS and under AddressSanitizer and UndefinedBehaviorSanitizer.

## Live tests

The live suite runs against a real FortiGate and is never run in CI. It may change only objects
it creates, all named `forti-api-test-*`, and it cleans up even when an assertion fails. This is
enforced in code:

- A guard transport refuses, before sending, every write outside an allowlist of test
  collections or without the `forti-api-test-` prefix.
- After the run, an audit reads the device's configuration-change log and fails the suite if any
  change through the REST API touched another object.

The full rules are in the repository's `AGENTS.md`.
