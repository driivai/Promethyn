# Contributing

Thanks for your interest in improving Promethyn. This document
covers the legal and mechanical requirements for contributions.

## Contributor License Agreement (required)

Before any contribution can be merged, you must sign the project's Contributor
License Agreement (CLA). The CLA grants the project the rights it needs to
distribute your contribution under the project license while you retain
copyright in your work. A Developer Certificate of Origin sign-off is **not**
sufficient on its own; the CLA is required.

- Individuals sign the individual CLA.
- Contributors working on behalf of an employer must ensure a corporate CLA is
  in place covering their contributions.

The CLA check runs automatically on pull requests; merges are blocked until it
passes.

## Branching

- Branch from `main`.
- Use the `DriivAIDev/` prefix for working branches, with a short descriptive
  slug, e.g. `DriivAIDev/registry-retrieval-tuning`.
- Do not commit directly to `main`; open a pull request.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <summary>
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`.
Keep summaries imperative and scoped, e.g.
`feat(gate): tighten promotion threshold handling`.

## Pull request descriptions

Keep pull request descriptions free of automated tool-attribution footers. Some
authoring tools append an attribution line to the pull request body when the
pull request is created; if one appears, remove it before requesting review so
the description covers only the change itself.

The project's tool-settings file already requests that this line be suppressed.
That request is honored for pull requests opened from a local checkout, but the
hosted integration that opens pull requests from remote sessions currently
injects the footer server-side without reading the repository's settings, so it
must be stripped by hand after the pull request is opened until that gap is
closed. This mirrors the commit-message rule: metadata stays neutral and
describes the work, not the tooling that produced it.

## Before you open a pull request

Run the same checks CI runs:

```bash
python -m pip install -e ".[dev]"
python -m compileall -q src tests scripts
python scripts/check_hygiene.py
python -m pytest -q
python -m build
```

All five must pass. New behaviour needs tests; protocol-relevant behaviour
needs conformance tests under `tests/conformance/`.

## Repository hygiene

`scripts/check_hygiene.py` is a required CI step. It fails if a tracked file
contains a banned tooling or vendor token. Describe work by its engineering
outcome and keep the codebase neutral.

The same rule holds for what is NOT a tracked file: commit messages, commit
author and committer identities, and pull request titles and bodies.
`scripts/check_message_hygiene.py` refuses a banned token in any of them, and CI
runs it over every commit in a pull request and over the PR's title and body.
To be refused before a push rather than at the PR, point your clone at the
repository's hooks once:

```bash
python scripts/install_git_hooks.py
```

That sets `core.hooksPath` to `scripts/git-hooks`, which installs two hooks:
`commit-msg` (refuses a message carrying a banned token) and `pre-push`
(refuses the same in any commit being pushed, and refuses to push a branch whose
remote counterpart was merged and deleted — start a new branch from
`origin/main` instead). Hooks are per clone; CI is the check that does not
depend on you having run this.

The hygiene gate and the conformance gate are conditions of acceptance for any
contribution; see `docs/open-core-boundary.md` for the open/commercial boundary
they protect.

## Changing an invariant or the protocol

Changes to `spec/invariants.md` or the protocol have a higher bar; see
`GOVERNANCE.md`.
