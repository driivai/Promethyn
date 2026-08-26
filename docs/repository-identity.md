# Repository identity and commit provenance

The pre-disclosure audit (`docs/pre-disclosure-audit.md`, finding H1) found that
**every commit on `main` is authored by a personal identity that matches neither
the project account nor the copyright holder.** A reviewer's first command is
`git log`; three different names across the repository reads as a provenance
question. This document fixes it going forward, records the canonical identity,
and lays out the one decision that remains open.

## 1. The canonical identity

| Where | Value | Note |
|---|---|---|
| Git commits | **`DriivAIDev <will@driivai.com>`** | the canonical committing identity |
| `LICENSE`, `NOTICE` | `Copyright 2026 William Nunlist` | the copyright **holder** (a person) |
| `pyproject.toml` | `authors = [{ name = "William Nunlist" }]` | the package author |

**These are reconciled, not contradictory:** `DriivAIDev` is the development
account of **William Nunlist**, who holds the copyright. The account identity
commits; the person holds the rights. A reviewer cross-checking `LICENSE` against
`git log` should find that stated somewhere — it is stated here.

The identity that should appear **nowhere** is `Benji Franclin
<williamnunlist@gmail.com>` — a personal address and an unrelated display name,
introduced by the merge path described below, not by any deliberate choice.

## 2. Why it happened (the root cause)

Branch commits are authored correctly (`DriivAIDev <will@driivai.com>`). The
identity is replaced at **merge** time: GitHub's **squash-merge** writes the
squash commit with the **merging GitHub account's profile name and public email**
as the author — not the authorship of the commits being squashed. So a correct
branch history collapses into a squash commit attributed to whatever that account
profile says. Committer becomes `GitHub <noreply@github.com>`.

## 3. Going-forward fix (do these; they prevent recurrence)

Pick either — **B is the most robust**, because it removes the re-authoring step
entirely rather than trying to make it produce the right value:

- **A — fix the account identity.** GitHub → *Settings → Profile* → set **Name**
  to the canonical identity; GitHub → *Settings → Emails* → enable **"Keep my
  email addresses private"** and **"Block command line pushes that expose my
  email"**. Future squashes then author as the profile name with a
  `…@users.noreply.github.com` address instead of a personal Gmail.
- **B — stop re-authoring at merge.** Repository → *Settings → General → Pull
  Requests*: enable **"Allow rebase merging"** (or merge commits) and use it for
  merges. Rebase/merge-commit strategies **preserve each commit's original
  author**, so the `DriivAIDev <will@driivai.com>` authorship written on the
  branch survives onto `main` unchanged.
- **C — merge from the command line** when neither is available, so the local
  `user.name` / `user.email` (or an explicit `--author`) decides.

Also set, on any machine that commits here:

```bash
git config user.name  "DriivAIDev"
git config user.email "will@driivai.com"
```

## 4. `.mailmap` (already in place, non-destructive)

`.mailmap` at the repository root maps the incorrect identity to the canonical
one. It rewrites **nothing**; it changes what Git and GitHub *display*:

```
$ git log origin/main --format='%an <%ae>' -1        # raw, unchanged
Benji Franclin <williamnunlist@gmail.com>

$ git log origin/main --use-mailmap --format='%aN <%aE>' -1
DriivAIDev <will@driivai.com>

$ git shortlog -sne --all | head -1
   261  DriivAIDev <will@driivai.com>
```

(261 of the 264 commits across all refs collapse to the canonical identity. The
remaining three sit on stale non-`main` branches and belong to a separate,
lower-severity audit finding that this sprint deliberately does not touch.)

`git shortlog`, `git blame`, and GitHub's contributor views honour it by default;
plain `git log` does not (it needs `--use-mailmap`).

**The honest limit:** a mailmap must *name* the old identity in order to redirect
it, so the personal address necessarily remains visible in `.mailmap` itself.
Mailmap fixes **attribution** and documents **provenance**. It does not remove the
address from the repository. Only a history rewrite does that.

## 5. The open decision — rewrite history, or keep mailmap only?

**Not yet executed. This is a destructive, irreversible operation and is awaiting
an explicit decision.**

### Option 1 — rewrite history (removes the identity permanently)

Rewrite all 56 `main` commits (264 across all refs) to the canonical identity.

```bash
# 1. Back up first — this is irreversible.
git clone --mirror https://github.com/driivai/Promethyn Promethyn-backup.git

# 2. Rewrite author AND committer for the incorrect identity.
pip install git-filter-repo
cat > /tmp/mailmap-rewrite <<'MAP'
DriivAIDev <will@driivai.com> Benji Franclin <williamnunlist@gmail.com>
MAP
git filter-repo --mailmap /tmp/mailmap-rewrite --force

# 3. Verify BEFORE pushing: no occurrence should remain.
git log --all --format='%an <%ae>|%cn <%ce>' | sort -u

# 4. Force-push every rewritten ref.
git push --force --all origin
git push --force --tags origin
```

**Risks — all of them real:**

- **Every commit SHA on `main` changes.** Every SHA referenced anywhere becomes
  dangling: the audit docs in this repo (which cite `267a586`, `5532510`, etc.),
  PR descriptions, review comments, external links, and any bookmark.
- **Force-push to `main`.** Requires temporarily lifting branch protection, and
  is exactly the operation a bank's reviewer would expect to see *controlled*.
- **Open PRs break.** Any PR open at rewrite time targets commits that no longer
  exist and must be closed and re-opened, or rebased onto the new history.
- **Other branches.** 43 remote heads exist; `--all` rewrites them too, and each
  must be force-pushed. Anything not rewritten still carries the old identity.
- **Clones diverge.** Every existing clone/fork must re-clone or hard-reset;
  a `git pull` into an old clone produces a duplicated, tangled history.
- **Collaborators:** currently a single-maintainer repository, which makes this
  materially safer than it would otherwise be — but the CI/Netlify integrations
  and any open PR still need to be re-pointed.
- **GitHub keeps unreferenced objects reachable for a period** via the pull-ref
  namespace, so the old identity can remain retrievable by SHA for some time even
  after a successful rewrite.

### Option 2 — mailmap only (already done; non-destructive)

Keep history as-is; `.mailmap` + §3 make attribution correct going forward.

- **Cost:** a reviewer running plain `git log` (without `--use-mailmap`) still
  sees the old identity, and the address remains in `.mailmap`.
- **Benefit:** zero risk, no SHA churn, no broken references, and the provenance
  question is *documented and answerable* rather than silently confusing —
  which is usually what a reviewer actually wants.

### Recommendation

**Option 2 (mailmap) unless the personal email must be removed for privacy.**
The provenance concern — "whose code is this?" — is fully answered by §1 and the
mailmap. The only thing a rewrite adds is deleting the personal address, and it
buys that at the cost of invalidating every SHA reference in the repository's own
audit trail, which a security reviewer may value more than a tidy `git log`. If
the address must go, do the rewrite **before** any external party clones the
repository, never after.
