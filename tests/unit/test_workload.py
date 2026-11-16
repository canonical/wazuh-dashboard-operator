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
