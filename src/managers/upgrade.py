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
    """Logic relating to Rolling Upgrades."""

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
        # Wazuh: change proposed upstream: https://github.com/canonical/opensearch-dashboards-operator/pull/186
        if not self.state.opensearch_server or not self.state.opensearch_server.version:
            return True

        if not (srv_version_actual := self.state.opensearch_server.version):
            return False

        srv_version_required = self.dependency_model.osd_upstream.dependencies["wazuh-indexer"]
        major_actual, minor_actual = srv_version_actual.split(".")[:2]
        major_required, minor_required = srv_version_required.split(".")[:2]
        return major_actual <= major_required and minor_actual <= minor_required
