# License history

A diligence-honest record. The license that applied to earlier commits is a
fact, stated here rather than hidden.

| Period | Commits on `main` | License | Copyright notice |
|---|---|---|---|
| 2026-06-30 → 2026-09-05 | `d9a2bb7` (first commit on `main`) through `0c782e5` (#72, PIH-2) | **Apache License 2.0** — `LICENSE` carried the full Apache-2.0 text; `NOTICE` was added and the owner named in #44 (2026-07-11) | `Copyright 2026 William Nunlist` |
| 2026-09-06 → | the PROM-IP relicense commit (this change) onward — SHA recorded below after merge | **Proprietary, all rights reserved** — `LICENSE` is a placeholder notice; commercial, OEM and evaluation terms are separate written agreements | `Copyright (c) 2026 DriivAIDev. All rights reserved.` |

**Relicense commit:** _pending — filled in when this change lands on `main`,
and updated with the post-rewrite SHA after the history rewrite (Part B of
PROM-IP)._ The old→new SHA mapping from that rewrite is kept in
`docs/provenance/commit-map.txt`.

## What the boundary means

- **Apache-2.0 is perpetual and irrevocable for the copies it covered.** The
  repository was public during the Apache period. Anyone who obtained the code
  at or before `0c782e5` holds that snapshot under Apache-2.0 and may keep
  using, modifying and redistributing it under those terms. A relicense does
  not reach back, and this document does not pretend it does.
- **From the relicense commit onward** the code is offered only under the
  proprietary notice in `LICENSE`. No Apache grant applies to later versions.
  The notice is deliberately not a license agreement: the enforceable terms
  are negotiated per deal and executed separately.
- **The copyright holder named changed from a person to the project identity.**
  `William Nunlist` is the natural person behind `DriivAIDev`; the relicense
  names `DriivAIDev` in `LICENSE`, `NOTICE`, `pyproject.toml` and the commit
  identity so that every artifact a reviewer cross-checks reads the same. What
  `DriivAIDev` is as a legal matter — a trade name of the person, or an entity
  to which rights are assigned — is for counsel to paper; `docs/IP-READINESS.md`
  says so plainly.
- **Contributions.** `CONTRIBUTING.md` has required a Contributor License
  Agreement for external contributions throughout. The identity inventory
  across every ref shows one committing identity (the project's) plus the
  GitHub squash-merge identity for the same person and one assistant-vendor
  identity on a since-deleted branch; there is no third-party human
  contributor on record, so no external copyright interest needed clearing for
  the relicense.
- **Third-party components** are unaffected: each remains under its own
  license, listed with positions in `docs/DEPENDENCY-LICENSES.md`.

## Where the license is declared

Every declaration must agree. `scripts/check_ip_consistency.py` verifies this
list in CI:

| Artifact | Declares |
|---|---|
| `LICENSE` | the proprietary placeholder notice, naming DriivAIDev |
| `NOTICE` | proprietary, DriivAIDev, pointers here and to the dependency list |
| `pyproject.toml` | `license = "LicenseRef-Proprietary"`, `authors = DriivAIDev <will@driivai.com>` |
| `README.md` | the License section |
| `site/index.html` | the footer line |
| source files | no SPDX headers were ever present; none are added |
| historical documents (`docs/pre-disclosure-audit.md`, `docs/readiness-assessment.md`, `docs/open-core-boundary.md`, this file) | may name Apache-2.0 as a past or superseded fact, and are marked as such |
