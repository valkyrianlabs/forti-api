@../AGENTS.md

The live-FortiGate rule in AGENTS.md is the one hard rule of this repository: tests never modify
existing config, everything they write is named `forti-api-test-*` (and marked as test content in
its comment field), they clean up after themselves every run including on failure, and the live
suite never runs in CI (only network-free, mocked tests may).
