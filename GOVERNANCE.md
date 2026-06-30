# Governance

This document describes how decisions are made for Prometheus Protocol.

For the boundary between the open-source project and commercial products, see
`docs/open-core-boundary.md`.

## Roles

- **Maintainers** review and merge changes, triage issues, and keep CI green.
- **Specification owners** are the subset of maintainers responsible for the
  protocol (`spec/`).
- **Release manager** is the maintainer who cuts a given release.

The current maintainers are listed in `.github/CODEOWNERS`.

## Ordinary changes

Code and documentation changes follow the normal pull-request flow in
`CONTRIBUTING.md`: at least one maintainer approval, green CI (including the
hygiene check and the conformance suite), and no unresolved blocking review.

## Changing an invariant

The invariants in `spec/invariants.md` are the project's contract, and the
held-out firewall (I1) is load-bearing for safety. Changing, weakening, or
removing an invariant requires:

1. A written proposal (an issue or ADR under `docs/adr/`) stating the change
   and its rationale.
2. Approval from **two specification owners**, at least one of whom did not
   author the proposal.
3. Updates to `spec/`, the enforcing code, and `tests/conformance/` landing
   together in the same change.

A change that would let the forge see held-out tasks will not be accepted; the
firewall may be strengthened, not removed.

## Cutting a release

A release may be cut by any maintainer acting as release manager, provided:

1. CI is green on `main`.
2. `CHANGELOG.md` (and `spec/CHANGELOG.md` if the spec changed) is updated.
3. The version in `pyproject.toml` follows semantic versioning. Any change to
   an invariant is a major version bump.

The release manager tags the release and publishes the build artifacts.

## Amending this document

Changes to governance follow the ordinary change process and require approval
from a majority of maintainers.
