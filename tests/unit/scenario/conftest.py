# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Fixtures for state-transition tests of the Wazuh dashboard charm."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml
from ops import testing
from pytest_mock import MockerFixture

from charm import OpensearchDashboardsCharm
from literals import PATHS

DEFAULT_CONFIG = {
    "custom": "preserved",
    "hosts": [{"default": {"url": "https://localhost", "password": "default-password"}}],
}


@pytest.fixture
def wazuh_files() -> dict[str, str]:
    """In-memory stand-in for the files managed by the workload."""
    return {PATHS["WAZUH_CONF"]: yaml.safe_dump(DEFAULT_CONFIG, sort_keys=False)}


@pytest.fixture
def workload_write(mocker: MockerFixture, wazuh_files: dict[str, str]) -> MagicMock:
    def write(content: str, path: str) -> None:
        wazuh_files[path] = content

    mocker.patch("workload.ODWorkload.read_raw", side_effect=wazuh_files.__getitem__)
    return mocker.patch("workload.ODWorkload.write", side_effect=write)


@pytest.fixture
def context(workload_write: MagicMock) -> testing.Context[OpensearchDashboardsCharm]:
    return testing.Context(
        OpensearchDashboardsCharm,
        meta=yaml.safe_load(Path("metadata.yaml").read_text()),
        config=yaml.safe_load(Path("config.yaml").read_text()),
        actions=yaml.safe_load(Path("actions.yaml").read_text()),
    )
