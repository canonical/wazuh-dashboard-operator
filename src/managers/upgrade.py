#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for building necessary files for TLS auth."""
import logging

from charms.data_platform_libs.v0.upgrade import DependencyModel

from core.cluster import SUBSTRATES, ClusterState
from core.workload import WorkloadBase

logger = logging.getLogger(__name__)


class UpgradeManager:
    """Manager for building necessary files for Java TLS auth."""

    def __init__(
        self,
        state: ClusterState,
        workload: WorkloadBase,
        substrate: SUBSTRATES,
        dependency_model: DependencyModel,
    ):
        self.state = state
        self.workload = workload
        self.substrate = substrate
        self.dependency_model = dependency_model

    def version_compatible(self) -> bool:
        """Verify version compatibility with Opensearch."""
        # When there's no Opensearch connection, we shouldn't report version mismatch
        if not self.state.opensearch_server:
            return True

        srv_version_actual = self.state.opensearch_server.version
        if not srv_version_actual:
            return False

        srv_version_required = self.dependency_model.osd_upstream.dependencies["opensearch"]
        major_actual, minor_actual = srv_version_actual.split(".")[:2]
        major_required, minor_required = srv_version_required.split(".")[:2]
        if major_actual > major_required or minor_actual > minor_required:
            return False
        return True
