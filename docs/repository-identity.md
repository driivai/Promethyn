# Repository identity and commit provenance

The pre-disclosure audit (`docs/pre-disclosure-audit.md`, finding H1) found that
**every commit on `main` was authored by a personal identity that matched
neither the project account nor the copyright holder.** A reviewer's first
command is `git log`; three different names across the repository read as a
provenance question. This document records the canonical identity, the root
cause, the decision taken under PROM-IP, and the procedure that keeps it from
recurring.

## 1. The canonical identity

One name, everywhere a reviewer cross-checks:

| Where | Value |
|---|---|
| Git commits (author **and** committer) | **`DriivAIDev <will@driivai.com>`** |
| `LICENSE`, `NOTICE` | `Copyright (c) 2026 DriivAIDev. All rights reserved.` |
| `pyproject.toml` | `authors = [{ name = "DriivAIDev", email = "will@driivai.com" }]` |
| `README.md`, `site/index.html` | DriivAIDev |

`DriivAIDev` is the project identity of William Nunlist, the natural person
behind it. Before PROM-IP the copyright notices named the person and the
commits named the account; PROM-IP names the account uniformly so that every
artifact agrees. What that name is as a legal matter — a trade name of the
person, or an entity to which the rights are assigned — is for counsel to
paper, and `docs/IP-READINESS.md` says so rather than implying it is settled.
`scripts/check_ip_consistency.py` verifies the table above in CI.

The identity that should appear **nowhere** is the personal display name and
Gmail address that GitHub's squash-merge wrote onto every `main` commit. It is
deliberately not repeated in this document.

## 2. Why it happened (the root cause)

Branch commits were authored correctly (`DriivAIDev <will@driivai.com>`). The
identity was replaced at **merge** time: GitHub's **squash-merge** writes the
squash commit with the **merging GitHub account's profile name and public
email** as the author — not the authorship of the commits being squashed — and
sets the committer to `GitHub <noreply@github.com>`. It also appends a
co-authorship trailer. So a correct branch history collapsed, on every merge,
into a squash commit attributed to whatever that account profile said.

The same path put an assistant vendor's identity on three commits of a
vendor-named branch, and assistant session URLs plus a vendor co-authorship
trailer into the body of one squash commit on `main` (audit finding M2).

## 3. The decision: rewrite history

PROM-IP chose the **destructive** option — rewrite author and committer on
every commit reachable from every ref to the canonical identity, strip the
assistant tokens and trailers from commit messages, and scrub the personal
address from historical file contents — over the non-destructive `.mailmap`
that had been in place since PROM-CLEANUP-1. The mailmap fixed *display*
(`git shortlog`, `git blame`, GitHub's contributor views) but left the old
identity in every commit object and, necessarily, in the mailmap file itself;
plain `git log` still showed it. For IP diligence that is the weaker position,
and the user chose the stronger one.

**Execution status:** _pending an explicit go — see `docs/IP-READINESS.md`,
which is updated when the rewrite has run._ The procedure, its risks and its
verification are recorded there and in the PROM-IP pull request; after the
rewrite, the old→new SHA mapping lives in `docs/provenance/commit-map.txt`,
the `.mailmap` is deleted (it would otherwise be the last copy of the old
address), and this section is updated with the verification output.

## 4. Going-forward procedure (so authorship cannot regress)

The rewrite removes the past. These keep the future correct — do all three:

1. **Stop re-authoring at merge.** Repository → *Settings → General → Pull
   Requests*: enable **rebase merging** (or merge commits) and **disable
   squash merging**. Rebase and merge-commit strategies preserve each commit's
   original author, so the `DriivAIDev <will@driivai.com>` authorship written
   on the branch survives onto `main` unchanged — and no trailer is appended.
   This is the load-bearing step; the others are defence in depth.
2. **Fix the account identity anyway.** GitHub → *Settings → Profile* → set
   **Name** to `DriivAIDev`; → *Settings → Emails* → make `will@driivai.com`
   the primary address, enable **"Keep my email addresses private"** and
   **"Block command line pushes that expose my email"**. Then even a squash
   made by mistake carries the project name and a `noreply` address, not a
   personal one.
3. **Gate it in CI.** `scripts/check_ip_consistency.py --history origin/main`
   fails the build if any commit reachable from `main` carries a non-canonical
   author or committer. It is enabled in `ci.yml` once the rewrite has run
   (before that it would fail on every historical commit).

On every machine that commits here:

```bash
git config user.name  "DriivAIDev"
git config user.email "will@driivai.com"
```

Pull requests are written with no trailers and no injected footers; the
repository's hygiene check (`scripts/check_hygiene.py`) refuses the vendor
tokens in files, and this project's standing rule refuses them in commit
messages and PR bodies.

## 5. Vendor-named and stale branches

The two vendor-named branches, and every branch whose pull request has been
merged or closed, are deleted as part of PROM-IP (the list and the verification
are in `docs/IP-READINESS.md`). Branches are named `DriivAIDev/<topic>` and are
deleted on merge (the repository setting is on).
