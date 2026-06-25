# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/). A change to any invariant
in `spec/invariants.md` is a major version bump.

## [Unreleased]

### Added
- Initial open-core scaffold of the Prometheus Protocol runtime.
- Core models, service interfaces, and environment-driven configuration.
- Vendor-neutral provider boundary: a configuration-driven remote provider over
  the chat-completions request shape, and a deterministic offline simulated
  provider used as the default.
- Subprocess verifier with timeout and POSIX resource limits (documented as not
  a sandbox).
- SQLite experience ledger, markdown skill registry with retrieval, lesson
  forge, and promotion gate with the held-out firewall.
- Scoped memory tiers (interface plus in-memory implementation).
- Runtime orchestrator (baseline run and one learning cycle), composition-root
  factory, and a console entry point (`prometheus-protocol`).
- Example Python-function benchmark with train/held-out splits, plus an
  evaluation and audit harness.
- Unit, integration, and conformance test suites.
- Repository hygiene guard and CI (compile, hygiene, tests, build) across
  Python 3.10–3.12.
