@../AGENTS.md

The live-FortiGate rule in AGENTS.md is the one hard rule of this repository: tests never modify
existing config, everything they write is named `forti-api-test-*` (and marked as test content in
its comment field), they clean up after themselves every run including on failure, and the live
suite never runs in CI (only network-free, mocked tests may).

Working context (read before larger changes):
- `.claude/context/audit.md`: the conventions this codebase is built around and the audit findings.
- `.claude/context/buildout-plan.md`: the plan to finish the SDK (transport, schema-driven
  generation + templates, endpoint discovery, phases, open decisions).
