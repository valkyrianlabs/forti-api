---
title: Testing
description: Unit tests, the live FortiGate suite and its safeguards.
order: 120
status: published
tags:
  - development
---

# Testing

forti-api has two test suites: a network-free unit suite, which CI runs, and a live suite that runs
against a real FortiGate and never runs in CI.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Running the tests

:::steps{
  variant="cards"
  layout="stack"
  numbered
  stepTheme="cyan"
}

### Configure the build

```bash
meson setup build -Dtests=enabled -Dlive_tests=true
```

### Run the unit suite

```bash
meson test -C build --suite unit                                  # network-free; what CI runs
```

### Run the live suite

```bash
set -a; . ./.env; set +a; meson test -C build --suite live -v     # against a real FortiGate
```

The `.env` file (start from `.env.example`) holds the connection variables from [Configuration](/reference/configuration).

:::

## Unit tests

The unit suite uses a scripted transport and needs no device: transport behavior (encoding,
errors, the retry policy, raw downloads with limits and sinks), field states and serialization, the
endpoint templates and the helpers.

CI runs it on Linux and macOS and under AddressSanitizer and UndefinedBehaviorSanitizer. The
libcurl transport is tested against local HTTP servers on 127.0.0.1, without any other network
access: header and body handling, connection reuse for reads, a connection that drops after a write
arrived (the write must reach the server exactly once), and paths sent verbatim.

## Live tests

:::callout[The live suite runs against a real FortiGate]{variant="danger"}
The live suite runs against a real FortiGate and is never run in CI. It may change only objects
it creates, all named `forti-api-test-*`, and it cleans up even when an assertion fails.
:::

This is enforced in code:

- A guard transport refuses, before sending, every write outside an allowlist of test
  collections or without the `forti-api-test-` prefix.
- After the run, an audit reads the device's configuration-change log and fails the suite if any
  change through the REST API touched another object.

### Coverage

- Every generated configuration endpoint and every typed monitor endpoint is listed and decoded
  read-only.
- The configuration backup is downloaded into memory only (never written, printed or logged) to
  check the raw download path.
- Create, read, update and delete round-trips run on 24 approved collections (addresses, services,
  schedules, security profiles, routing lists, threat feeds), all inert unless something references
  them.

### Read-only runs

To run only read-only tests, set `FORTI_API_LIVE_READ_ONLY=1`: the guard then refuses every
write and the suite skips its leftover cleanup, so it cannot interfere with another run's test
objects.

```bash
FORTI_API_LIVE_READ_ONLY=1 ./build/liveTests --gtest_filter='ConfigBackup.*'
```

:::callout[The full rules]{variant="info"}
The full rules for the live FortiGate are in the repository's `AGENTS.md`.
:::
