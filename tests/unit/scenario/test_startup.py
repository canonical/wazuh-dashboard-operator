# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Startup/status behaviour through the ops.testing state-transition framework."""

from unittest.mock import patch

from ops import testing

from charm import OpensearchDashboardsCharm
from literals import MSG_STARTING_SERVER

Ctx = testing.Context[OpensearchDashboardsCharm]


def peer_state(upgrade_state: str = "idle") -> testing.State:
    return testing.State(
        leader=True,
        relations=[
            testing.PeerRelation("dashboard_peers", local_unit_data={"state": "started"}),
            testing.PeerRelation("restart"),
            testing.PeerRelation("upgrade", local_unit_data={"state": upgrade_state}),
        ],
    )


def test_update_status_sets_waiting_when_restarting_workload(context: Ctx) -> None:
    workload_alive = {"value": False}

    def init_server() -> None:
        workload_alive["value"] = True

    with (
        patch("workload.ODWorkload.alive", side_effect=lambda: workload_alive["value"]),
        patch("charm.OpensearchDashboardsCharm.init_server", side_effect=init_server) as patched,
        patch("charm.update_grafana_dashboards_title"),
    ):
        state = context.run(context.on.update_status(), peer_state())

    patched.assert_called_once()
    assert state.unit_status == testing.WaitingStatus(MSG_STARTING_SERVER)


def test_update_status_reports_failure_when_start_keeps_failing(context: Ctx) -> None:
    with (
        patch("workload.ODWorkload.alive", return_value=False),
        patch("charm.OpensearchDashboardsCharm.init_server") as init_server,
        patch("managers.config.ConfigManager.config_changed", return_value=False),
        patch("charm.update_grafana_dashboards_title"),
    ):
        state = context.run(context.on.update_status(), peer_state())

    init_server.assert_called_once()
    assert state.unit_status != testing.WaitingStatus(MSG_STARTING_SERVER)
    assert isinstance(state.unit_status, testing.BlockedStatus)


def test_update_status_does_not_start_running_workload(context: Ctx) -> None:
    with (
        patch("workload.ODWorkload.alive", return_value=True),
        patch("charm.OpensearchDashboardsCharm.init_server") as init_server,
        patch("managers.config.ConfigManager.config_changed", return_value=False),
        patch("charm.update_grafana_dashboards_title"),
    ):
        context.run(context.on.update_status(), peer_state())

    init_server.assert_not_called()


def test_update_status_does_not_start_workload_during_failed_upgrade(context: Ctx) -> None:
    with (
        patch("workload.ODWorkload.alive", return_value=False),
        patch("charm.OpensearchDashboardsCharm.init_server") as init_server,
        patch("charm.update_grafana_dashboards_title"),
    ):
        context.run(context.on.update_status(), peer_state(upgrade_state="failed"))

    init_server.assert_not_called()
