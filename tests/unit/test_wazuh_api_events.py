# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Exercise Wazuh API relation and secret events through to the written YAML."""

import logging
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from ops.testing import Harness
from pytest_mock import MockerFixture

from charm import OpensearchDashboardsCharm
from events.wazuh_api import _short_secret_id
from literals import PATHS

PROVIDER = "wazuh-api-provider"
ENDPOINT = "https://wazuh.example:55000/"
INITIAL_CREDENTIALS = {"user": "api-user", "password": "initial-password"}
ROTATED_CREDENTIALS = {"user": "rotated-user", "password": "rotated-password"}
DEFAULT_CONFIG = {
    "custom": "preserved",
    "hosts": [{"default": {"url": "https://localhost", "password": "default-password"}}],
}


@pytest.fixture
def wazuh_files() -> dict[str, str]:
    return {PATHS["WAZUH_CONF"]: yaml.safe_dump(DEFAULT_CONFIG, sort_keys=False)}


@pytest.fixture
def workload_write(mocker: MockerFixture, wazuh_files: dict[str, str]) -> MagicMock:
    def write(content: str, path: str) -> None:
        wazuh_files[path] = content

    mocker.patch("workload.ODWorkload.read_raw", side_effect=wazuh_files.__getitem__)
    return mocker.patch("workload.ODWorkload.write", side_effect=write)


@pytest.fixture
def harness(
    mocker: MockerFixture, workload_write: MagicMock
) -> Iterator[Harness[OpensearchDashboardsCharm]]:
    mocker.patch("workload.snap.SnapCache")
    harness = Harness(
        OpensearchDashboardsCharm,
        meta=Path("metadata.yaml").read_text(),
        config=Path("config.yaml").read_text(),
        actions=Path("actions.yaml").read_text(),
    )
    harness.begin()
    yield harness
    harness.cleanup()


def publish_credentials(
    harness: Harness[OpensearchDashboardsCharm],
) -> tuple[int, str]:
    relation_id = harness.add_relation("wazuh-api", PROVIDER)
    secret_id = harness.add_model_secret(PROVIDER, INITIAL_CREDENTIALS)
    harness.grant_secret(secret_id, harness.model.app)
    harness.update_relation_data(
        relation_id, PROVIDER, {"endpoint": ENDPOINT, "user_credentials_secret": secret_id}
    )
    return relation_id, secret_id


def assert_written_credentials(files: dict[str, str], credentials: dict[str, str]) -> None:
    config = yaml.safe_load(files[PATHS["WAZUH_CONF"]])
    assert config == {
        "custom": "preserved",
        "hosts": [
            {
                "default": {
                    "url": "https://wazuh.example",
                    "port": 55000,
                    "username": credentials["user"],
                    "password": credentials["password"],
                    "run_as": True,
                }
            }
        ],
    }


def test_wazuh_relation_changed_writes_credentials(
    harness: Harness[OpensearchDashboardsCharm],
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
) -> None:
    publish_credentials(harness)
    assert_written_credentials(wazuh_files, INITIAL_CREDENTIALS)
    workload_write.assert_called_once()
    assert workload_write.call_args.kwargs["path"] == PATHS["WAZUH_CONF"]


def test_wazuh_secret_rotations_update_written_credentials(
    harness: Harness[OpensearchDashboardsCharm],
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
) -> None:
    relation_id, secret_id = publish_credentials(harness)
    relation_data = dict(harness.get_relation_data(relation_id, PROVIDER))
    workload_write.reset_mock()

    harness.set_secret_content(secret_id, ROTATED_CREDENTIALS)
    assert_written_credentials(wazuh_files, ROTATED_CREDENTIALS)
    assert INITIAL_CREDENTIALS["password"] not in wazuh_files[PATHS["WAZUH_CONF"]]
    workload_write.assert_called_once()
    assert harness.get_relation_data(relation_id, PROVIDER) == relation_data

    latest = {"user": "latest-user", "password": "latest-password"}
    harness.set_secret_content(secret_id, latest)
    assert_written_credentials(wazuh_files, latest)
    assert ROTATED_CREDENTIALS["password"] not in wazuh_files[PATHS["WAZUH_CONF"]]
    assert workload_write.call_count == 2
    assert harness.get_secret_revisions(secret_id) == [1, 2, 3]


@pytest.mark.parametrize("trigger", ["relation", "initialization", "recreation"])
def test_wazuh_updates_use_latest_revision(
    harness: Harness[OpensearchDashboardsCharm],
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
    trigger: str,
    mocker: MockerFixture,
) -> None:
    relation_id, secret_id = publish_credentials(harness)
    workload_write.reset_mock()
    # Advance the provider revision while the consumer is offline.
    with patch("ops.framework.BoundEvent.emit"):
        harness.set_secret_content(secret_id, ROTATED_CREDENTIALS)
    assert harness.model.get_secret(id=secret_id).get_content() == INITIAL_CREDENTIALS

    if trigger == "relation":
        harness.update_relation_data(relation_id, PROVIDER, {"endpoint": ENDPOINT + "updated"})
    elif trigger == "initialization":
        mocker.patch.object(harness.charm.config_manager, "set_dashboard_properties")
        mocker.patch.object(harness.charm.workload, "start")
        mocker.patch("core.models.ODServer.update")
        harness.charm.init_server()
    else:
        harness.remove_relation(relation_id)
        relation_id = harness.add_relation("wazuh-api", PROVIDER)
        harness.grant_secret(secret_id, harness.model.app)
        harness.update_relation_data(
            relation_id, PROVIDER, {"endpoint": ENDPOINT, "user_credentials_secret": secret_id}
        )
    assert_written_credentials(wazuh_files, ROTATED_CREDENTIALS)
    workload_write.assert_called_once()
    assert harness.model.get_secret(id=secret_id).get_content() == ROTATED_CREDENTIALS


@pytest.mark.parametrize("relation_format", ["short", "qualified"])
@pytest.mark.parametrize("event_format", ["short", "qualified"])
def test_wazuh_secret_id_formats_match(
    harness: Harness[OpensearchDashboardsCharm],
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
    relation_format: str,
    event_format: str,
) -> None:
    relation_id, secret_id = publish_credentials(harness)
    short_id = f"secret:{_short_secret_id(secret_id)}"
    qualified_id = f"secret://{harness.model.uuid}/{_short_secret_id(secret_id)}"
    relation_secret_id = short_id if relation_format == "short" else qualified_id
    harness.update_relation_data(
        relation_id, PROVIDER, {"user_credentials_secret": relation_secret_id}
    )
    with patch("ops.framework.BoundEvent.emit"):
        harness.set_secret_content(secret_id, ROTATED_CREDENTIALS)
    workload_write.reset_mock()
    event_secret_id = short_id if event_format == "short" else qualified_id
    harness.charm.on.secret_changed.emit(event_secret_id, None)
    assert_written_credentials(wazuh_files, ROTATED_CREDENTIALS)
    workload_write.assert_called_once()


def test_wazuh_unrelated_secret_does_not_write(
    harness: Harness[OpensearchDashboardsCharm],
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
) -> None:
    publish_credentials(harness)
    before = dict(wazuh_files)
    unrelated = harness.add_model_secret(PROVIDER, {"unrelated": "secret-value"})
    harness.grant_secret(unrelated, harness.model.app)
    workload_write.reset_mock()
    harness.set_secret_content(unrelated, {"unrelated": "rotated-value"})
    workload_write.assert_not_called()
    assert wazuh_files == before


@pytest.mark.parametrize("relation_data", [None, {}, {"endpoint": ENDPOINT}])
def test_wazuh_not_ready_events_preserve_configuration(
    harness: Harness[OpensearchDashboardsCharm],
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
    caplog: pytest.LogCaptureFixture,
    relation_data: dict[str, str] | None,
) -> None:
    caplog.set_level(logging.DEBUG)
    if relation_data is not None:
        harness.add_relation("wazuh-api", PROVIDER, app_data=relation_data)
    before = dict(wazuh_files)
    unrelated = harness.add_user_secret({"unrelated": "secret-value"})
    harness.charm.on.secret_changed.emit(unrelated, None)
    harness.charm.wazuh_api_events.update_configuration()
    workload_write.assert_not_called()
    assert wazuh_files == before
    assert "Wazuh API" in caplog.text
    assert "secret-value" not in caplog.text


@pytest.mark.parametrize("invalid_field", ["endpoint", "user_credentials_secret"])
def test_wazuh_invalid_relation_data_preserves_configuration(
    harness: Harness[OpensearchDashboardsCharm],
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
    caplog: pytest.LogCaptureFixture,
    invalid_field: str,
) -> None:
    relation_id, _ = publish_credentials(harness)
    before = dict(wazuh_files)
    workload_write.reset_mock()
    harness.update_relation_data(relation_id, PROVIDER, {invalid_field: "invalid-secret-value"})
    workload_write.assert_not_called()
    assert wazuh_files == before
    assert "Wazuh API" in caplog.text
    assert "invalid-secret-value" not in caplog.text


@pytest.mark.parametrize("content", [{"user": "api-user"}, {"password": "invalid-password"}])
def test_wazuh_invalid_secret_preserves_configuration(
    harness: Harness[OpensearchDashboardsCharm],
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
    caplog: pytest.LogCaptureFixture,
    content: dict[str, str],
) -> None:
    _, secret_id = publish_credentials(harness)
    before = dict(wazuh_files)
    workload_write.reset_mock()
    harness.set_secret_content(secret_id, content)
    workload_write.assert_not_called()
    assert wazuh_files == before
    assert "credentials field" in caplog.text
    assert "invalid-password" not in caplog.text
    harness.set_secret_content(secret_id, ROTATED_CREDENTIALS)
    assert_written_credentials(wazuh_files, ROTATED_CREDENTIALS)
    workload_write.assert_called_once()


def test_wazuh_secret_access_failure_recovers(
    harness: Harness[OpensearchDashboardsCharm],
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _, secret_id = publish_credentials(harness)
    before = dict(wazuh_files)
    workload_write.reset_mock()
    harness.revoke_secret(secret_id, harness.model.app)
    harness.set_secret_content(secret_id, ROTATED_CREDENTIALS)
    workload_write.assert_not_called()
    assert wazuh_files == before
    assert "Could not access Wazuh API credentials secret" in caplog.text
    assert ROTATED_CREDENTIALS["password"] not in caplog.text
    harness.grant_secret(secret_id, harness.model.app)
    harness.charm.on.secret_changed.emit(secret_id, None)
    assert_written_credentials(wazuh_files, ROTATED_CREDENTIALS)
    workload_write.assert_called_once()


def test_wazuh_incomplete_publication_recovers(
    harness: Harness[OpensearchDashboardsCharm],
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
) -> None:
    relation_id = harness.add_relation("wazuh-api", PROVIDER, app_data={"endpoint": ENDPOINT})
    before = dict(wazuh_files)
    workload_write.assert_not_called()
    assert wazuh_files == before
    secret_id = harness.add_model_secret(PROVIDER, ROTATED_CREDENTIALS)
    harness.grant_secret(secret_id, harness.model.app)
    harness.update_relation_data(relation_id, PROVIDER, {"user_credentials_secret": secret_id})
    assert_written_credentials(wazuh_files, ROTATED_CREDENTIALS)
    workload_write.assert_called_once()


@pytest.mark.parametrize(
    "secret_id", ["secret:credentials", "secret://model-uuid/credentials", "credentials"]
)
def test_wazuh_normalizes_secret_ids(secret_id: str) -> None:
    assert _short_secret_id(secret_id) == "credentials"
