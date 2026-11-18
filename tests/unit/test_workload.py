#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import MagicMock

from workload import ODWorkload


def test_start_enables_snap_services(mocker):
    """The services must be enabled so they start again after a host reboot."""
    dashboards = MagicMock()
    snap_cache = mocker.patch("workload.snap.SnapCache")
    snap_cache.return_value = {ODWorkload.SNAP_NAME: dashboards}

    workload = ODWorkload()
    workload.start()

    dashboards.start.assert_called_once_with(
        services=[ODWorkload.SNAP_APP_SERVICE, ODWorkload.SNAP_EXPORTER_SERVICE],
        enable=True,
    )


def test_stop_can_disable_snap_services(mocker):
    """A deliberately stopped workload must stay stopped after a reboot."""
    dashboards = MagicMock()
    snap_cache = mocker.patch("workload.snap.SnapCache")
    snap_cache.return_value = {ODWorkload.SNAP_NAME: dashboards}

    workload = ODWorkload()
    workload.stop(disable=True)

    dashboards.stop.assert_called_once_with(
        services=[ODWorkload.SNAP_APP_SERVICE, ODWorkload.SNAP_EXPORTER_SERVICE],
        disable=True,
    )


def test_restart_starts_and_enables_a_stopped_workload(mocker):
    dashboards = MagicMock()
    snap_cache = mocker.patch("workload.snap.SnapCache")
    snap_cache.return_value = {ODWorkload.SNAP_NAME: dashboards}
    mocker.patch.object(ODWorkload, "alive", side_effect=[False, True])

    workload = ODWorkload()
    assert workload.restart() is True

    dashboards.start.assert_called_once_with(
        services=[ODWorkload.SNAP_APP_SERVICE, ODWorkload.SNAP_EXPORTER_SERVICE],
        enable=True,
    )
    dashboards.restart.assert_not_called()


def test_restart_restarts_a_running_workload(mocker):
    dashboards = MagicMock()
    snap_cache = mocker.patch("workload.snap.SnapCache")
    snap_cache.return_value = {ODWorkload.SNAP_NAME: dashboards}
    mocker.patch.object(ODWorkload, "alive", return_value=True)

    workload = ODWorkload()
    assert workload.restart() is True

    dashboards.restart.assert_called_once_with(
        services=[ODWorkload.SNAP_APP_SERVICE, ODWorkload.SNAP_EXPORTER_SERVICE]
    )
    dashboards.start.assert_not_called()
