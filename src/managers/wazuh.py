#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for Wazuh configuration."""

import logging
from urllib.parse import urlparse

import yaml
from charms.wazuh_server.v0 import wazuh_api

import literals
from core.workload import WorkloadBase

logger = logging.getLogger(__name__)


class WazuhManager:
    """Manager for handling Wazuh configuration."""

    def __init__(
        self,
        workload: WorkloadBase,
    ) -> None:
        self.workload = workload

    def migrate_config(self) -> None:
        """Copy the pre-4.14 Wazuh config to the path used by the 4.14 snap.

        Wazuh 4.14 resolves its configuration from OpenSearch Dashboards'
        ``path.data`` ($SNAP_COMMON), while older revisions used
        $SNAP_DATA/current/config. Copy the old file to the new location when
        the new file does not exist yet so charm upgrades preserve the existing
        settings. Relation data is applied afterwards by
        ``set_dashboard_properties``.
        """
        self.workload.prepare_wazuh_config()

        legacy_config = self.workload.read_raw(literals.PATHS["LEGACY_WAZUH_CONF"])
        if not legacy_config:
            return

        if self.workload.read_raw(literals.PATHS["WAZUH_CONF"]):
            return

        self.workload.write(
            content=legacy_config,
            path=literals.PATHS["WAZUH_CONF"],
        )

    def set_dashboard_properties(self, wazuh_config: wazuh_api.WazuhApiRelationData) -> None:
        """Writes the Wazuh config file."""
        self.workload.prepare_wazuh_config()
        wazuh_conf = self.workload.read_raw(literals.PATHS["WAZUH_CONF"])
        try:
            wazuh_conf_yaml = yaml.safe_load(wazuh_conf)
        except yaml.YAMLError:
            logger.warning("Existing Wazuh configuration is not valid YAML, overwriting it")
            wazuh_conf_yaml = None
        if not isinstance(wazuh_conf_yaml, dict):
            wazuh_conf_yaml = {}
        hosts = wazuh_conf_yaml.get("hosts")
        if not isinstance(hosts, list):
            hosts = wazuh_conf_yaml["hosts"] = []

        url = urlparse(str(wazuh_config.endpoint))
        details = {
            "url": f"{url.scheme}://{url.hostname}",
            "port": url.port,
            "username": wazuh_config.user,
            "password": wazuh_config.password,
            "run_as": True,
        }
        for host in hosts:
            if isinstance(host, dict) and "default" in host:
                host["default"] = details
                break
        else:
            hosts.insert(0, {"default": details})

        content = yaml.safe_dump(wazuh_conf_yaml, sort_keys=False)
        if content == wazuh_conf:
            return

        self.workload.write(
            content=content,
            path=literals.PATHS["WAZUH_CONF"],
        )
