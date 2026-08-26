# Maintaining this fork

This repository is a fork of
[`canonical/opensearch-dashboards-operator`](https://github.com/canonical/opensearch-dashboards-operator),
customized to deploy and manage the Wazuh dashboard instead of a generic
OpenSearch Dashboards instance. This document explains how the fork tracks
upstream and how to pull in new upstream changes.

## Strategy: rebase, not merge

Older sync attempts on this fork used merge commits (or manual squashed
reapplication of upstream diffs), which produced tangled history with no
real upstream commit lineage and made every sync harder than the last. We
now use a **rebase strategy** instead:

- `2/edge` carries the *real*, unaltered commit history from
  `upstream/2/edge` (upstream's active development branch — note upstream
  develops on `2/edge`, following Juju track/risk branch naming, not on
  `main`), with a small number of Wazuh-specific customization commits
  rebased on top.
- `main` is the fork's stable/default branch. Its tree is kept in sync with
  `2/edge` (currently: identical content, different history layout).
- Because the Wazuh commits sit *on top of* upstream history and are
  rebased (not merged) forward each sync, `git rerere` can record how a
  conflict was resolved once and automatically replay that resolution on
  every future sync that touches the same lines — this is the main payoff
  of the rebase approach.

## Branch roles

| Branch | Purpose |
|---|---|
| `main` | Default branch. Stable, released fork content. |
| `2/edge` | Clean rebase branch: `upstream/2/edge` history + a handful of Wazuh customization commits on top. Used to pull in upstream changes. |

The Wazuh customization commits on `2/edge` are grouped by area, to keep
rebase conflicts localized and reviewable:

1. **charm code** — `src/`, `lib/charms/wazuh_server/`, `metadata.yaml`,
   `actions.yaml`, `spread.yaml`, `charmcraft.yaml`, alert rules, Grafana
   dashboard, `charm_version.backup`.
2. **terraform** — `terraform/charm/`, `terraform/product/`, and edits to
   the shared `terraform/*.tf` files.
3. **tests** — `tests/unit/`, `tests/integration/`, `tests/spread/`.
4. **docs/CI/tooling** — `.github/`, `docs/`, `README.md`, `Makefile*`,
   `.vale*`, `.gitignore`, `icon.png`, `tox.ini`.

## One-time setup

`git rerere` is already enabled locally for this repository
(`.git/config`, not global), so conflict resolutions are recorded
automatically. If cloning fresh, or in doubt, run:

```shell
git config rerere.enabled true
git config rerere.autoupdate true
```

`rerere.autoupdate` stages a file automatically once rerere has replayed a
previously recorded resolution for it, so you don't need `git add` after
every auto-resolved conflict during a rebase.

The `.git/rr-cache` directory holds recorded resolutions. It is local to
your clone (not pushed/pulled) — each contributor doing syncs builds up
their own cache over time. Do not delete it.

## Syncing new upstream changes

1. Fetch upstream:

   ```shell
   git remote add upstream git@github.com:canonical/opensearch-dashboards-operator.git  # once
   git fetch upstream
   ```

2. Rebase `2/edge` onto the latest `upstream/2/edge`:

   ```shell
   git checkout 2/edge
   git rebase upstream/2/edge
   ```

   This replays the real upstream commits since your last sync, followed by
   the 4 Wazuh customization commits, on top of the new upstream tip.

3. Resolve any conflicts as they come up in the Wazuh customization commits
   (real upstream commits should never conflict with each other, since they
   are upstream's own linear history). For each conflict:

   ```shell
   # edit conflicted files
   git add <resolved files>
   git rebase --continue
   ```

   `rerere` records how you resolved each conflict. On the *next* sync, if
   the same conflict pattern recurs (e.g. upstream keeps changing a line
   that a Wazuh commit also touches), it will be auto-resolved — check for
   `Resolved '<file>' using previous resolution.` in the rebase output, and
   still review the result before committing, since rerere is a
   convenience, not a substitute for judgement.

4. If a conflict resolution needs correcting (rerere reused a bad
   resolution), forget it and redo:

   ```shell
   git rerere forget <path>
   # resolve again by hand
   git add <path>
   ```

5. Once the rebase completes cleanly, verify nothing regressed:

   ```shell
   tox -e lint
   tox -e unit
   ```

6. Push the rebased branch (it rewrites history, so a force push is
   expected — use `--force-with-lease` to avoid clobbering concurrent
   pushes):

   ```shell
   git push --force-with-lease origin 2/edge
   ```

7. Fast-forward (or otherwise bring) `main` up to `2/edge` once you're
   satisfied the sync is good — this keeps `main`'s tree identical to
   `2/edge`'s. Note: since `main`'s pre-existing history was not rebuilt as
   part of adopting this strategy, updating `main` from `2/edge` after a
   sync currently still requires a merge or a deliberate history reset;
   evaluate case by case and coordinate with the team before rewriting
   `main`'s public history.

## What to take from upstream vs. keep from the fork

These are the file-level conventions to apply while resolving conflicts
during a rebase (carried over from the previous merge-based workflow):

### Take upstream wholesale
- `lib/` folder (except `lib/charms/wazuh_server/`, which is fork-only) —
  vendored charm libs.
- `poetry.lock` — always take upstream's lock file.
- `tests/integration/` and `tests/spread/` structure/logic — only adapt
  Wazuh-specific values, don't diverge on test logic.
- New upstream files (new events, new tests) — take upstream as-is unless
  they need Wazuh-specific values.

### Keep fork version
- `src/events/wazuh_api.py`, `src/managers/wazuh.py` — Wazuh-only, no
  upstream counterpart.
- `lib/charms/wazuh_server/` — Wazuh-only library.
- `terraform/charm/` and `terraform/product/` — fork-specific Terraform
  plans.
- Snap revision/channel, COS log slots, `DASHBOARD_INDEX`, alert rule group
  name, Grafana dashboard title, `get-password` action, Vale ignores,
  disabled `lib-check` CI job — all fork-specific, see `src/literals.py`
  and `metadata.yaml`.

### Merge (take upstream structure, re-apply fork overrides)
- `src/charm.py`, `src/literals.py`, `src/core/cluster.py`,
  `src/core/models.py`, `src/managers/config.py` — take upstream's new
  logic/classes, keep Wazuh-specific values and event handler wiring.
- `.github/workflows/ci.yaml`, `.github/workflows/release.yaml` — take
  upstream job/version updates, keep Wazuh-specific overrides (disabled
  lib-check, `terraform/product` lint path, release track `"4.11"`).
- `metadata.yaml` — take upstream's new relations, keep Wazuh-specific
  relations (`wazuh-api`).
- `pyproject.toml`, unit tests — take upstream updates, keep Wazuh mock
  values and paths.

### Propagation rules
- Typo/rename fixes upstream must be propagated to all fork-only files
  referencing the renamed symbol.
- New upstream relations added to `metadata.yaml` must also be wired in
  `src/literals.py`, `src/core/cluster.py`, and `src/charm.py`.

## PR checks don't auto-run on sync branches (expected)

When you open a PR from a rebase-sync branch against `2/edge`, GitHub will
usually show `mergeable: CONFLICTING` / `mergeStateStatus: DIRTY`
(`gh pr view <number> --json mergeable,mergeStateStatus`), and **no
`pull_request`-triggered workflow runs will appear** on the PR (`gh pr
checks <number>` shows nothing, `gh run list --branch <branch>` is empty).

This is expected, not a bug in the sync: `pull_request` events run against
a synthetic `base + head` merge commit that GitHub computes for the PR. A
rebase replays the fork's own commits with brand-new SHAs on top of
upstream's new tip, so a real 3-way merge against the *old* `2/edge` tip
reproduces the same conflicts you already resolved by hand during the
rebase (you can confirm this yourself with `git merge --no-commit --no-ff
<sync-branch>` from a scratch checkout of `2/edge`). Since GitHub can't
build that merge ref, it never dispatches the `pull_request` event, so no
run is created at all — it's not a failed/errored run, it simply never
starts.

To validate the actual code on a sync branch, the "Tests" workflow
(`ci.yaml`) runs automatically whenever you push to a branch named
`sync/**`, and can also be triggered/re-run manually at any time:
```shell
gh workflow run ci.yaml --ref <sync-branch>
```
(or `tox -e lint` / `tox -e unit` locally, if you'd rather not wait on
GitHub Actions).

## Landing PRs when GitHub can't sign a rebase merge

Both `main` and `2/edge` require signed commits (`required_signatures`) and
linear history (`required_linear_history`), but this repo currently only has
**"Rebase and merge" enabled** as a merge strategy (squash and merge-commit
are disabled). This combination doesn't work: when GitHub performs a
rebase-merge via the button, it creates brand-new commit objects for every
commit in the PR, and it cannot sign those on your behalf. The merge button
fails with:

> Base branch requires signed commits. Rebase merges cannot be automatically
> signed by GitHub.

Squash-merge and merge-commit *can* be auto-signed by GitHub (it produces a
single new commit that it signs as `GitHub <noreply@github.com>`), but
enabling those isn't something to do lightly on this repo, since it changes
merge behavior for everyone and could impact the fork maintenance.

### Workaround: fast-forward push your already-signed commits

If your PR's commits are already GPG-signed locally (as they should be if
you sign your own commits — check with `git log --show-signature`), you
don't need GitHub to create/sign anything: you can land the PR with a plain
fast-forward push, bypassing the merge button entirely. This requires admin
access, since it's a direct push to a protected branch (`enforce_admins` is
`false` on both `main` and `2/edge`, so admins can bypass the button).

1. Confirm all commits on your branch are already signed with your own key:

   ```shell
   git log --show-signature origin/<base-branch>..<your-branch>
   ```

   Look for `gpg: Good signature from ...` on every commit.

2. Confirm the push will be a clean fast-forward (the base branch hasn't
   moved past what your PR was rebased onto):

   ```shell
   git fetch origin <base-branch>
   git merge-base --is-ancestor origin/<base-branch> <your-branch> && echo "safe to fast-forward"
   ```

3. Confirm CI is green and the PR shows as mergeable
   (`gh pr checks <number>`, `gh pr view <number> --json mergeable,mergeStateStatus`).

4. Push directly to the base branch:

   ```shell
   git push origin <your-branch>:<base-branch>
   ```

   Because this is a fast-forward of already-signed commits, GitHub accepts
   it even though "Rebase and merge" wouldn't have worked. GitHub detects
   the PR's commits landed on the base branch and automatically marks the
   PR as merged/closed — no further action needed.
