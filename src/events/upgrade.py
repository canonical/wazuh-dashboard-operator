#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Event handler for handling OpensearchDashboards in-place upgrades."""
import logging
from typing import TYPE_CHECKING

from charms.data_platform_libs.v0.upgrade import (
    BaseModel,  # pyright: ignore [reportGeneralTypeIssues, reportAttributeAccessIssue]
)
from charms.data_platform_libs.v0.upgrade import (
    ClusterNotReadyError,
    DataUpgrade,
    DependencyModel,
    VersionError,
)
from ops.charm import UpgradeCharmEvent
from ops.framework import EventBase
from ops.model import BlockedStatus
from typing_extensions import override

from exceptions import OSDInstallError
from literals import MSG_INCOMPATIBLE_UPGRADE

if TYPE_CHECKING:
    from charm import (
        OpensearchDashboardsCharm,  # pyright: ignore [reportGeneralTypeIssues, reportAttributeAccessIssue]
    )

logger = logging.getLogger(__name__)


class OpensearchDashboardsDependencyModel(BaseModel):
    """Model for OpensearchDashboards Operator dependencies."""

    osd_upstream: DependencyModel


class ODUpgradeEvents(DataUpgrade):
    """Implementation of :class:`DataUpgrade` overrides for in-place upgrades."""

    def __init__(self, charm: "OpensearchDashboardsCharm", **kwargs):
        super().__init__(charm, **kwargs)
        self.charm = charm

    def post_upgrade_check(self) -> None:
        """Runs necessary checks validating the unit is in a healthy state after upgrade."""
        if not self.charm.upgrade_manager.version_compatible():
            self.charm.unit.status = BlockedStatus(MSG_INCOMPATIBLE_UPGRADE)
            raise ClusterNotReadyError(
                message="Post-upgrade check failed and cannot safely upgrade",
                cause="Opensearch version mismatch",
            )

    @override
    def pre_upgrade_check(self) -> None:
        if not self.charm.workload.alive():
            raise ClusterNotReadyError(
                message="Pre-upgrade check failed and cannot safely upgrade",
                cause="Unit workload is not running",
            )

    @override
    def build_upgrade_stack(self) -> list[int]:
        upgrade_stack = []

        units = [self.charm.unit]
        if self.charm.state.peer_relation:
            units.extend(list(self.charm.state.peer_relation.units))

        for unit in units:
            upgrade_stack.append(int(unit.name.split("/")[-1]))

        return upgrade_stack

    @override
    def log_rollback_instructions(self) -> None:
        logger.critical(
            "\n".join(
                [
                    "Unit failed to upgrade and requires manual rollback to previous stable version.",
                    "    1. Re-run `pre-upgrade-check` action on the leader unit to enter 'recovery' state",
                    "    2. Run `juju refresh` to the previously deployed charm revision",
                ]
            )
        )
        return

    @override
    def _on_upgrade_charm(self, event: UpgradeCharmEvent) -> None:
        """Refresh the stateless workload when no coordinated upgrade was requested."""
        if self.upgrade_stack:
            super()._on_upgrade_charm(event)
            return

        logger.info("No upgrade stack found; refreshing the stateless workload directly")

        try:
            self.pre_upgrade_check()
        except ClusterNotReadyError as e:
            logger.error(e.cause)
            self.charm.unit.status = BlockedStatus(e.cause)
            return

        if self.charm.unit.is_leader() and self.stored_dependencies:
            try:
                self._upgrade_supported_check()
            except VersionError as e:
                logger.error(e)
                self.set_unit_failed()
                return

        self._on_upgrade_granted(event)
        self.on_upgrade_changed(event)

    @override
    def _on_upgrade_granted(self, event: EventBase) -> None:
        self.charm.workload.stop()

        try:
            self.charm.workload.install()
        except OSDInstallError:
            logger.error("Unable to install OpensearchDashboards...")
            self.set_unit_failed(cause="Workload install failed")
            return

        logger.info(f"{self.charm.unit.name} upgrading workload...")
        self.charm.workload.restart()

        try:
            logger.debug("Running post-upgrade check...")
            self.post_upgrade_check()

            logger.debug("Marking unit completed...")
            self.set_unit_completed()

            # ensures leader gets it's own relation-changed when it upgrades
            if self.charm.unit.is_leader():
                logger.debug("Re-emitting upgrade-changed on leader...")
                self.on_upgrade_changed(event)

        except ClusterNotReadyError as e:
            logger.error(e.cause)
            self.set_unit_failed(cause=e.cause)
