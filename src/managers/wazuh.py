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

    def set_dashboard_properties(self, wazuh_config: wazuh_api.WazuhApiRelationData) -> None:
        """Writes the Wazuh config file."""
        try:
            wazuh_conf_yaml = yaml.safe_load(self.workload.read_raw(literals.PATHS["WAZUH_CONF"]))
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
        if hosts and isinstance(hosts[0], dict):
            hosts[0]["default"] = details
        else:
            hosts[:1] = [{"default": details}]
        self.workload.write(
            content=yaml.safe_dump(wazuh_conf_yaml, sort_keys=False),
            path=literals.PATHS["WAZUH_CONF"],
        )
