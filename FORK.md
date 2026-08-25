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

## History note

`chore/sync-upstream-2.19.4` contains a further sync (to upstream 2.19.4)
done with the old merge-based strategy, before this document existed. It
should be redone as the next rebase cycle on top of the new `2/edge`
baseline described here, rather than merged as-is.
