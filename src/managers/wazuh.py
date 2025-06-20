#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for for Wazuh configuration."""

from urllib.parse import urlparse

import yaml
from charms.wazuh_server.v0 import wazuh_api

import literals
from core.workload import WorkloadBase


class WazuhManager:
    """Manager for for handling Wazuh configuration."""

    def __init__(
        self,
        workload: WorkloadBase,
    ):
        self.workload = workload

    def set_dashboard_properties(self, wazuh_config: wazuh_api.WazuhApiRelationData) -> None:
        """Writes the Wazuh config file."""
        wazuh_conf = self.workload.read_raw(literals.PATHS["WAZUH_CONF"])
        wazuh_conf_yaml = yaml.safe_load(wazuh_conf)
        url = urlparse(wazuh_config.endpoint)
        details = {
            "url": f"{url.scheme}://{url.hostname}",
            "port": url.port,
            "username": wazuh_config.user,
            "password": wazuh_config.password,
            "run_as": False,
        }
        if wazuh_conf_yaml:
            wazuh_conf_yaml["hosts"][0]["default"] = details
        else:
            wazuh_conf_yaml = {"hosts": [{"default": details}]}
        self.workload.write(
            content=yaml.safe_dump(wazuh_conf_yaml, sort_keys=False),
            path=literals.PATHS["WAZUH_CONF"],
        )
