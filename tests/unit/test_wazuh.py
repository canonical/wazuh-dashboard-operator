#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
import logging
import secrets
from pathlib import Path
from unittest.mock import patch

import yaml
from ops.testing import Harness

from charm import OpensearchDasboardsCharm
from charms.wazuh_server.v0 import wazuh_api
from literals import PATHS

logger = logging.getLogger(__name__)

CONFIG = str(yaml.safe_load(Path("./config.yaml").read_text()))
ACTIONS = str(yaml.safe_load(Path("./actions.yaml").read_text()))
METADATA = str(yaml.safe_load(Path("./metadata.yaml").read_text()))

DEFAULT_WAZUH_CONFIG = {
    "hosts": [
        {
            "default": {
                "url": "https://localhost",
                "port": 55000,
                "username": "wazuh-wui",
                "password": "wazuh-wui",
                "run_as": False,
            }
        }
    ]
}

SAMPLE_RELATION_DATA = {
    "endpoint": f"https://example.wazuh:55000/",
    "user_credentials_secret": (
        "secret://59060ecc-0495-4a80-8006-5f1fc13fd783/cjqub6vubg2s77p3nio0"
    ),
}


def test_wazuh_properties_changed():
    password = secrets.token_hex()
    wazuh_config = wazuh_api.WazuhApiRelationData(
        endpoint="https://wazuh.example:55000/",
        user="api-user",
        password=password,
        user_credentials_secret=SAMPLE_RELATION_DATA["user_credentials_secret"],
    )
    with (
        patch(
            "charms.wazuh_server.v0.wazuh_api.WazuhApiRequires.get_relation_data",
            return_value=wazuh_config,
        ),
        patch("workload.ODWorkload.read_raw", return_value=yaml.safe_dump(DEFAULT_WAZUH_CONFIG)),
        patch("workload.ODWorkload.write") as write,
    ):
        harness = Harness(OpensearchDasboardsCharm, meta=METADATA, config=CONFIG, actions=ACTIONS)
        harness.begin()

        harness.add_relation(
            wazuh_api.RELATION_NAME, "wazuh-api-provider", app_data=SAMPLE_RELATION_DATA
        )

        expected_config = {
            "hosts": [
                {
                    "default": {
                        "url": "https://wazuh.example",
                        "port": 55000,
                        "username": wazuh_config.user,
                        "password": wazuh_config.password,
                        "run_as": False,
                    }
                }
            ]
        }
        write.assert_called_once_with(
            content=yaml.safe_dump(expected_config, sort_keys=False), path=PATHS["WAZUH_CONF"]
        )
