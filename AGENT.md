# wazuh-dashboard-operator

Juju machine charm (VM substrate) that deploys and manages the Wazuh Dashboard
(a fork of the Wazuh Dashboards service, itself a fork of OpenSearch
Dashboards). Built with `ops` + Canonical's `data-platform-libs`, packaged
with `poetry`, tests/lint driven via `tox`.

**This repo is a fork.** See `FORK.md` before making structural changes — it
describes the rebase-based upstream-sync strategy (tracking
`canonical/opensearch-dashboards-operator`), which files/areas are
Wazuh-specific vs. taken from upstream, and `git rerere` usage. When editing
`src/charm.py`, `src/literals.py`, `src/core/cluster.py`, `src/core/models.py`,
or `src/managers/config.py`, be mindful that these are merge points with
upstream — keep Wazuh-specific values/wiring identifiable and don't
gratuitously restructure them.

## Build, lint, test

All commands run through `tox` (uses `poetry` under the hood):

```shell
tox -e lint          # poetry check, codespell, black --check, pyright
tox -e format         # isort + black (auto-fix)
tox -e unit           # pytest tests/unit + coverage
tox -e integration    # pytest tests/integration (requires a Juju controller)
```

Run a single unit test file or test case with `posargs`:

```shell
tox -e unit -- tests/unit/test_charm.py
tox -e unit -- tests/unit/test_charm.py::TestCharm::test_some_case -k some_case
```

Integration tests accept the same `posargs` pattern and also honor `CI`,
`CHARM_UBUNTU_BASE`, and cloud credential env vars (AWS/Azure/GCP) for
storage-backed scenarios; they additionally require `playwright install
--with-deps` (done automatically in `commands_pre`).

`PYTHONPATH` is set by tox to `src:lib`, so imports in tests use bare module
names (e.g. `from charm import OpensearchDasboardsCharm`, `from literals
import ...`) rather than `src.literals` — except `tests/unit/test_charm.py`
which imports some names via `src.literals` directly; follow the existing
pattern in the file you're editing.

There is no `Justfile`; use the `tox` environments above and the top-level
`Makefile` (mostly for docs, see `Makefile.docs`).

## Architecture

- `src/charm.py` — `OpensearchDasboardsCharm` (entrypoint). Almost all hook
  observers funnel into a single `reconcile()` method that re-evaluates
  overall state on every event (peer/config/relation changes, leader
  election, update-status). Avoid adding new one-off hook handlers that
  bypass `reconcile()` unless the event is truly one-shot (e.g. `install`,
  `start`, `secret_changed`).
- `src/core/cluster.py` (`ClusterState`) and `src/core/models.py` — the
  single source of truth for relation-derived state. `ClusterState` exposes
  properties (`unit_server`, `cluster`, `servers`, `opensearch_server`,
  `oauth`, `bind_address`, `stable`, ...) built from Juju relation/peer data
  via `data_platform_libs`' `DataPeerData`/`DataPeerUnitData` interfaces.
  Read/write cluster or unit state through these model objects, not by
  touching relation data directly.
- `src/events/*.py` — one `Object` subclass per relation/feature
  (`TLSEvents`, `RequirerEvents` (opensearch client), `ODUpgradeEvents`,
  `WazuhApiEvents`, `OAuthHandler`). Each is instantiated once in
  `charm.py.__init__` and owns its own `framework.observe` calls.
- `src/managers/*.py` — stateless-ish helpers doing the actual work
  (`ConfigManager`, `TLSManager`, `APIManager`, `HealthManager`,
  `UpgradeManager`, `WazuhManager`). Managers take `state`/`workload` (and
  sometimes `substrate`/`config`) in their constructor and are the layer that
  talks to the workload/filesystem/HTTP APIs — event handlers and
  `reconcile()` should call into managers rather than duplicating logic.
- `src/workload.py` / `src/core/workload.py` — snap-based workload
  abstraction (`ODWorkload`) for installing, starting, and restarting the
  `wazuh-dashboard` snap; see `PATHS` in `src/literals.py` for on-disk
  layout (`/var/snap/wazuh-dashboard/...`).
- `src/literals.py` — all charm-wide constants: relation names, status
  message strings (grouped into `MSG_APP_STATUS`/`MSG_UNIT_STATUS` lists
  consumed by `reconcile()`'s status-clearing logic), snap paths, secret
  field names, and the upgrade `DEPENDENCIES` model.
- `lib/charms/` — vendored charm libraries (`data_platform_libs`,
  `tls_certificates_interface`, `rolling_ops`, `grafana_agent`, `hydra`,
  `operator_libs_linux`). `lib/charms/wazuh_server/` is Wazuh-fork-only (no
  upstream counterpart) — do not treat it as vendored/regeneratable.
  Don't hand-edit other vendored libs beyond what `charmcraft fetch-lib`
  would produce.
- Restarts are coordinated through `RollingOpsManager` (relation
  `restart`); trigger a rolling restart by emitting
  `self.on[f"{self.restart.name}"].acquire_lock.emit()` rather than calling
  `workload.restart()` directly from event code.
- COS/observability integration (`COSAgentProvider`) scrapes
  `src/alert_rules/prometheus` and ships Grafana dashboards from
  `src/grafana_dashboards/`.

## Conventions

- Status handling always goes through `helpers.py`'s `set_global_status` /
  `clear_global_status` / `clear_status`, and the `MSG_*` string constants in
  `literals.py` — don't set `unit.status`/`app.status` with ad-hoc strings.
- Charm class is named `OpensearchDasboardsCharm` (note the historical typo
  "Dasboards") — this is intentional/pre-existing; don't silently "fix" it.
- `SUBSTRATE` is `"vm"` for this charm; some managers/models still accept a
  `substrate` param for parity with the k8s-capable upstream code — preserve
  that parameter even though only "vm" is exercised here.
- Unit tests use `ops.testing.Harness` with `pytest-mock`'s `mocker` fixture;
  common autouse fixtures live in `tests/unit/conftest.py` (e.g. patching
  `tenacity` sleep, `Container.restart`, `ODWorkload.healthy`,
  `JujuVersion.has_secrets`). Add new cross-cutting mocks there rather than
  repeating them per test module.
- `responses` is used to mock outbound HTTP calls (Wazuh/OpenSearch API)
  in unit tests.
