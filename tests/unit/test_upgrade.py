#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
import yaml
from charms.data_platform_libs.v0.upgrade import ClusterNotReadyError, DependencyModel
from ops.testing import Harness

from charm import OpensearchDasboardsCharm
from events.upgrade import ODUpgradeEvents, OpensearchDashboardsDependencyModel
from literals import CHARM_KEY, DEPENDENCIES
from workload import ODWorkload

logger = logging.getLogger(__name__)


CONFIG = str(yaml.safe_load(Path("./config.yaml").read_text()))
ACTIONS = str(yaml.safe_load(Path("./actions.yaml").read_text()))
METADATA = str(yaml.safe_load(Path("./metadata.yaml").read_text()))


@pytest.fixture
def harness():
    harness = Harness(OpensearchDasboardsCharm, meta=METADATA, config=CONFIG, actions=ACTIONS)
    harness.add_relation("dashboard_peers", CHARM_KEY)
    harness.add_relation("restart", CHARM_KEY)
    harness.add_relation("upgrade", CHARM_KEY)
    harness.begin()
    with harness.hooks_disabled():
        harness.update_relation_data(
            harness.charm.state.peer_relation.id, f"{CHARM_KEY}/0", {"hostname": "000.000.000"}
        )

    return harness


def test_pre_upgrade_check_succeeds(harness, mocker):
    assert harness.charm.upgrade_events.pre_upgrade_check() is None


def test_build_upgrade_stack(harness):
    with harness.hooks_disabled():
        harness.add_relation_unit(harness.charm.state.peer_relation.id, f"{CHARM_KEY}/1")
        harness.update_relation_data(
            harness.charm.state.peer_relation.id, f"{CHARM_KEY}/1", {"hostname": "111.111.111"}
        )
        harness.add_relation_unit(harness.charm.state.peer_relation.id, f"{CHARM_KEY}/2")
        harness.update_relation_data(
            harness.charm.state.peer_relation.id, f"{CHARM_KEY}/2", {"hostname": "222.222.222"}
        )
        harness.add_relation_unit(harness.charm.state.peer_relation.id, f"{CHARM_KEY}/3")
        harness.update_relation_data(
            harness.charm.state.peer_relation.id, f"{CHARM_KEY}/3", {"hostname": "333.333.333"}
        )

    stack = harness.charm.upgrade_events.build_upgrade_stack()

    assert stack[0] == 0
    assert len(stack) == 4


def test_dashboards_dependency_model():
    assert sorted(OpensearchDashboardsDependencyModel.__fields__.keys()) == sorted(
        DEPENDENCIES.keys()
    )

    for value in DEPENDENCIES.values():
        assert DependencyModel(**value)


def test_upgrade_granted_sets_failed_if_failed_snap(harness, mocker):
    mocker.patch.object(ODWorkload, "stop")
    mocker.patch.object(ODWorkload, "restart")
    mocker.patch.object(ODWorkload, "install", return_value=False)
    mocker.patch.object(ODUpgradeEvents, "pre_upgrade_check")
    mocker.patch.object(ODUpgradeEvents, "set_unit_completed")
    mocker.patch.object(ODUpgradeEvents, "set_unit_failed")

    mock_event = mocker.MagicMock()

    harness.charm.upgrade_events._on_upgrade_granted(mock_event)

    ODWorkload.stop.assert_called_once()
    ODWorkload.install.assert_called_once()
    ODWorkload.restart.assert_not_called()
    ODUpgradeEvents.set_unit_completed.assert_not_called()
    ODUpgradeEvents.set_unit_failed.assert_called_once()


def test_upgrade_granted_sets_failed_if_failed_upgrade_check(harness, mocker):
    mocker.patch.object(ODWorkload, "stop")
    mocker.patch.object(ODWorkload, "restart")
    mocker.patch.object(ODWorkload, "install", return_value=True)
    mocker.patch.object(
        ODUpgradeEvents,
        "pre_upgrade_check",
        side_effect=ClusterNotReadyError(message="Pre-upgrade check failed", cause="Reason:"),
    )
    mocker.patch.object(ODUpgradeEvents, "set_unit_completed")
    mocker.patch.object(ODUpgradeEvents, "set_unit_failed")

    mock_event = mocker.MagicMock()

    harness.charm.upgrade_events._on_upgrade_granted(mock_event)

    ODWorkload.stop.assert_called_once()
    ODWorkload.install.assert_called_once()
    ODUpgradeEvents.set_unit_completed.assert_not_called()
    ODUpgradeEvents.set_unit_failed.assert_called_once()


def test_upgrade_granted_succeeds(harness, mocker):
    mocker.patch.object(ODWorkload, "stop")
    mocker.patch.object(ODWorkload, "restart")
    mocker.patch.object(ODWorkload, "install")
    mocker.patch.object(ODUpgradeEvents, "pre_upgrade_check")
    mocker.patch.object(ODUpgradeEvents, "set_unit_completed")
    mocker.patch.object(ODUpgradeEvents, "set_unit_failed")

    mock_event = mocker.MagicMock()

    harness.charm.upgrade_events._on_upgrade_granted(mock_event)

    ODWorkload.stop.assert_called_once()
    ODWorkload.install.assert_called_once()
    ODWorkload.restart.assert_called_once()
    ODUpgradeEvents.set_unit_completed.assert_called_once()
    ODUpgradeEvents.set_unit_failed.assert_not_called()


def test_upgrade_granted_recurses_upgrade_changed_on_leader(harness, mocker):
    mocker.patch.object(ODWorkload, "stop")
    mocker.patch.object(ODWorkload, "restart")
    mocker.patch.object(ODWorkload, "install")
    mocker.patch.object(ODUpgradeEvents, "pre_upgrade_check")
    mocker.patch.object(ODUpgradeEvents, "on_upgrade_changed")

    mock_event = mocker.MagicMock()

    harness.charm.upgrade_events._on_upgrade_granted(mock_event)

    ODUpgradeEvents.on_upgrade_changed.assert_not_called()

    with harness.hooks_disabled():
        harness.set_leader(True)

    harness.charm.upgrade_events._on_upgrade_granted(mock_event)

    ODUpgradeEvents.on_upgrade_changed.assert_called_once()
