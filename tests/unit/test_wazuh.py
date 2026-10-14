# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for updating the Wazuh dashboard configuration without discarding settings."""

from unittest.mock import MagicMock

import pytest
import yaml
from charms.wazuh_server.v0 import wazuh_api

from core.workload import WorkloadBase
from literals import PATHS
from managers.wazuh import WazuhManager

EXPECTED_HOST = {
    "url": "https://wazuh.example",
    "port": 55000,
    "username": "api-user",
    "password": "rotated-password",
    "run_as": True,
}


@pytest.fixture
def workload() -> MagicMock:
    return MagicMock(spec=WorkloadBase)


def update_properties(workload: MagicMock) -> None:
    config = wazuh_api.WazuhApiRelationData(
        endpoint="https://wazuh.example:55000/",
        user=EXPECTED_HOST["username"],
        password=EXPECTED_HOST["password"],
        user_credentials_secret="secret:credentials",
    )
    WazuhManager(workload).set_dashboard_properties(config)


@pytest.mark.parametrize(
    "content",
    ["", "# empty file\n", "{}", "hosts: []", "custom: preserved", "custom: preserved\nhosts: []"],
)
def test_wazuh_initializes_default_host(workload: MagicMock, content: str) -> None:
    workload.read_raw.return_value = content
    update_properties(workload)
    expected = yaml.safe_load(content) or {}
    expected["hosts"] = [{"default": EXPECTED_HOST}]
    workload.read_raw.assert_called_once_with(PATHS["WAZUH_CONF"])
    workload.write.assert_called_once_with(
        content=yaml.safe_dump(expected, sort_keys=False), path=PATHS["WAZUH_CONF"]
    )


def test_wazuh_preserves_other_settings_and_hosts(workload: MagicMock) -> None:
    config = {
        "custom": {"nested": "preserved"},
        "hosts": [
            {"default": {"url": "https://old.example", "password": "old-password"}},
            {"other": {"url": "https://other.example", "password": "other-password"}},
        ],
    }
    workload.read_raw.return_value = yaml.safe_dump(config, sort_keys=False)
    update_properties(workload)
    config["hosts"][0]["default"] = EXPECTED_HOST
    workload.write.assert_called_once_with(
        content=yaml.safe_dump(config, sort_keys=False), path=PATHS["WAZUH_CONF"]
    )


@pytest.mark.parametrize(
    "content",
    [
        "[broken-secret-value",
        "unexpected-secret-value",
        "[]",
        "false",
        "0",
        "hosts: null",
        "hosts: {}",
        "hosts: [null]",
        "hosts: [unexpected-secret-value]",
        "hosts: [{}]",
        "hosts: [{default: null}]",
        "hosts: [{default: []}]",
    ],
)
def test_wazuh_rejects_invalid_existing_config(
    workload: MagicMock, content: str, caplog: pytest.LogCaptureFixture
) -> None:
    workload.read_raw.return_value = content
    update_properties(workload)
    workload.write.assert_not_called()
    assert "configuration unchanged" in caplog.text
    assert "secret-value" not in caplog.text
