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

    def remove_legacy_config(self) -> None:
        """Remove the pre-4.14 Wazuh config path.

        Wazuh 4.14 resolves its configuration from OpenSearch Dashboards'
        ``path.data`` ($SNAP_COMMON) and the plugin creates ``wazuh.yml``
        there on startup, so the old $SNAP_DATA/current/config copy is stale.
        Remove it so the two locations cannot drift. The ``hosts`` entry is
        written from relation data by ``set_dashboard_properties``.

        If a rollback re-installs an older charm, that charm recreates the
        legacy file from relation data on the next ``wazuh-api`` relation
        change.
        """
        self.workload.remove(literals.PATHS["LEGACY_WAZUH_CONF"])

    def set_dashboard_properties(self, wazuh_config: wazuh_api.WazuhApiRelationData) -> None:
        """Writes the Wazuh config file."""
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
