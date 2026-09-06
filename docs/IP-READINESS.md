# IP readiness — the one page a prime's counsel reads

**Repository:** `driivai/Promethyn` · **Prepared:** 2026-09-06 (PROM-IP) ·
**Status of the provenance rewrite:** _pending an explicit go; this line is
updated when it has run._

This is a factual summary for intellectual-property diligence. It is not legal
advice and it is not a license: the commercial, OEM and evaluation terms under
which Promethyn is licensed to any party are **separate, lawyer-negotiated
written agreements**, and nothing in this repository is one of them.

## 1. Owner

| | |
|---|---|
| Named owner, everywhere | **DriivAIDev** (`will@driivai.com`) |
| Natural person behind the name | William Nunlist |
| Where it is declared | `LICENSE`, `NOTICE`, `pyproject.toml` (`authors`), `README.md`, `site/index.html`, and the author and committer of every commit (after the rewrite) |
| Verified by | `scripts/check_ip_consistency.py` (CI) |

**Stated plainly for counsel:** `DriivAIDev` is a project identity, not a
registered legal entity as far as this repository records. The chain from the
natural person who wrote the code to whichever entity signs a license must be
papered outside the repository (an assignment or a confirmation that the name
is a trade name of the person). The repository is internally consistent about
the name; it does not, and cannot, establish the legal personhood behind it.

## 2. License

- **Current:** proprietary, all rights reserved. `LICENSE` is a **placeholder
  notice** recording that fact and pointing to `will@driivai.com` for
  licensing. It grants nothing and is deliberately not drafted as enforceable
  terms. `pyproject.toml` declares `license = "LicenseRef-Proprietary"`.
- **Commercial / OEM terms:** separate written agreements, negotiated per deal.
- **Trademark:** the name "Promethyn" and its marks are not licensed with the
  code under any version of the license (`docs/open-core-boundary.md`).

## 3. License history — Apache-2.0, then proprietary

| Period | Commits on `main` | License |
|---|---|---|
| 2026-06-30 → 2026-09-05 | `d9a2bb7` through `0c782e5` (#72) | Apache License 2.0, copyright William Nunlist |
| 2026-09-06 → | the PROM-IP relicense commit (SHA recorded in `docs/LICENSE-HISTORY.md` after merge and again after the rewrite) onward | proprietary, copyright DriivAIDev |

**The fact counsel must have:** the repository was **public** during the
Apache period. Every copy of the code at or before `0c782e5` that anyone
obtained is held under Apache-2.0 — a perpetual, irrevocable grant for that
snapshot — and the relicense does not reach back. Later versions carry no
Apache grant. No third-party human contributor appears in the identity
inventory across every ref, and `CONTRIBUTING.md` has required a CLA for
external contributions throughout, so no external copyright interest needed
clearing. Details: `docs/LICENSE-HISTORY.md`.

## 4. Dependencies — the license position

Full table with obligations: `docs/DEPENDENCY-LICENSES.md`. Machine-readable
SBOM (CycloneDX 1.6): `docs/sbom.cdx.json`. Pinned closure: `constraints.txt`
(CI installs under it).

- **No GPL or AGPL component** in the runtime or development closure.
- **`psycopg` (PostgreSQL driver) is LGPL-3.0-only.** Used as an unmodified,
  separately installed library imported through its public API — the LGPL's
  "Combined Work" case, under which Promethyn's own code carries no copyleft
  obligation and may be licensed on proprietary terms. Counsel will ask;
  `docs/DEPENDENCY-LICENSES.md` answers each question (unmodified, dynamically
  loaded, replaceable, notices preserved) and names the permissive
  alternatives (`pg8000`, BSD; `asyncpg`, Apache-2.0) should a contract
  require a zero-copyleft closure. That swap is not made here.
- **`cryptography`** (Apache-2.0 OR BSD-3-Clause), added by PIH-2 for
  asymmetric approval signing; permissive.
- Everything else is MIT, BSD, Apache-2.0 or PSF, except one MPL-2.0 package
  (`pathspec`) that is a development-only dependency of `mypy` and is neither
  modified nor shipped.
- All packages pinned to exact versions; every one resolves to its canonical
  PyPI project with the expected upstream; none abandoned (release dates in
  the dependency document).

## 5. Commit provenance — the approach taken

- **Root cause of the historical inconsistency:** GitHub's squash-merge wrote
  the merging account's personal profile name and Gmail address as the author
  of all 57 commits on `main` (audit finding H1), the committer as
  `GitHub <noreply@github.com>`, and appended a co-authorship trailer to each.
  One squash commit on `main` carried assistant-session URLs and an
  assistant-vendor co-authorship trailer (M2); three commits on a vendor-named
  branch carried the vendor's identity (M3).
- **Approach chosen: history rewrite (destructive).** Author and committer on
  every commit reachable from every ref are rewritten to
  `DriivAIDev <will@driivai.com>`; the assistant tokens and all trailers are
  stripped from commit messages; the personal address is scrubbed from the
  three historical files that carried it; the `.mailmap` (which had to name
  the old identity to redirect it) is deleted. A mirror backup is taken
  first. Every SHA changes; the old→new mapping is kept in
  `docs/provenance/commit-map.txt` so references in this repository's own
  audit documents remain resolvable.
- **Why not the non-destructive mailmap:** it corrected display only; plain
  `git log` still showed the old identity, and the mailmap file itself was the
  last copy of the personal address. The user chose the stronger position for
  diligence and accepted the cost (force-push, invalidated SHAs, re-clone).
- **Regression control:** squash merging is to be disabled in favour of rebase
  or merge-commit merging (which preserve authorship), the account identity is
  set to the project name with a private email, and CI gates `main` on the
  canonical identity (`scripts/check_ip_consistency.py --history`). Procedure:
  `docs/repository-identity.md` §4.
- **Branches:** the two vendor-named branches and every branch whose PR was
  merged or closed are deleted.
- **Secrets:** a scan of every blob reachable from every ref (680 blobs) for
  credential patterns found none — only a documentation placeholder and a
  test fixture value that exists to prove non-leakage.

## 6. Security

`SECURITY.md` names the private reporting address (`security@driivai.com`) and
the disclosure process. The adversarial hardening record is
`docs/threat-model.md`.

## 7. The consistency check, reproducibly

```
python scripts/check_ip_consistency.py                     # declarations, no stray former license
python scripts/check_ip_consistency.py --history origin/main   # every commit canonical (after the rewrite)
git log --all --format='%an <%ae>|%cn <%ce>' | sort -u      # expect one line
git grep -n -i "apache" -- . ':!docs/LICENSE-HISTORY.md' ':!docs/IP-READINESS.md' ':!docs/DEPENDENCY-LICENSES.md' ':!docs/pre-disclosure-audit.md' ':!docs/readiness-assessment.md' ':!docs/open-core-boundary.md' ':!CHANGELOG.md' ':!scripts/check_ip_consistency.py' ':!LICENSE'
```

The last command must print nothing. The historical documents it excludes
name Apache-2.0 only as a past or superseded fact and are marked as such.

## 8. What this document does not do

- It does not grant, imply or describe license terms; those are separate
  agreements.
- It does not establish the legal entity behind the owner's name (§1).
- It does not change the dependency set; the LGPL position is stated, not
  engineered around (§4).
- It does not claim the history rewrite removes the old identity from every
  copy in existence: forks, clones and GitHub's own unreachable-object
  retention can hold the old SHAs for a time. It removes it from this
  repository's reachable history.
