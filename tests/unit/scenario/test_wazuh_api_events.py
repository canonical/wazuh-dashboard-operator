# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Exercise Wazuh API relation and secret events through to the written YAML."""

import dataclasses
import logging
from unittest.mock import MagicMock

import pytest
import yaml
from ops import testing

from charm import OpensearchDashboardsCharm
from events.wazuh_api import _short_secret_id
from literals import PATHS

PROVIDER = "wazuh-api-provider"
ENDPOINT = "https://wazuh.example:55000/"
INITIAL_CREDENTIALS = {"user": "api-user", "password": "initial-password"}
ROTATED_CREDENTIALS = {"user": "rotated-user", "password": "rotated-password"}

Ctx = testing.Context[OpensearchDashboardsCharm]


def credentials_secret(
    tracked: dict[str, str] = INITIAL_CREDENTIALS, latest: dict[str, str] | None = None
) -> testing.Secret:
    return testing.Secret(tracked_content=tracked, latest_content=latest or tracked)


def wazuh_relation(secret: testing.Secret | None = None, **data: str) -> testing.Relation:
    app_data = {"endpoint": ENDPOINT}
    if secret is not None:
        app_data["user_credentials_secret"] = secret.id
    app_data.update(data)
    return testing.Relation("wazuh-api", remote_app_name=PROVIDER, remote_app_data=app_data)


def make_state(*relations: testing.Relation, secrets: tuple[testing.Secret, ...] = ()):
    return testing.State(relations=list(relations), secrets=list(secrets), leader=True)


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


def test_relation_changed_writes_credentials(
    context: Ctx, wazuh_files: dict[str, str], workload_write: MagicMock
) -> None:
    secret = credentials_secret()
    relation = wazuh_relation(secret)
    context.run(context.on.relation_changed(relation), make_state(relation, secrets=(secret,)))
    assert_written_credentials(wazuh_files, INITIAL_CREDENTIALS)
    workload_write.assert_called_once()
    assert workload_write.call_args.kwargs["path"] == PATHS["WAZUH_CONF"]


def test_secret_rotations_update_written_credentials(
    context: Ctx, wazuh_files: dict[str, str], workload_write: MagicMock
) -> None:
    secret = credentials_secret(latest=ROTATED_CREDENTIALS)
    relation = wazuh_relation(secret)
    state = context.run(context.on.secret_changed(secret), make_state(relation, secrets=(secret,)))
    assert_written_credentials(wazuh_files, ROTATED_CREDENTIALS)
    assert INITIAL_CREDENTIALS["password"] not in wazuh_files[PATHS["WAZUH_CONF"]]
    workload_write.assert_called_once()
    assert state.get_relation(relation.id).remote_app_data == relation.remote_app_data

    latest = {"user": "latest-user", "password": "latest-password"}
    rotated = dataclasses.replace(state.get_secret(id=secret.id), latest_content=latest)
    context.run(
        context.on.secret_changed(rotated),
        dataclasses.replace(state, secrets=[rotated]),
    )
    assert_written_credentials(wazuh_files, latest)
    assert ROTATED_CREDENTIALS["password"] not in wazuh_files[PATHS["WAZUH_CONF"]]
    assert workload_write.call_count == 2


def test_relation_changed_uses_latest_revision(
    context: Ctx, wazuh_files: dict[str, str], workload_write: MagicMock
) -> None:
    """A stale tracked revision must not be used when the relation changes."""
    secret = credentials_secret(latest=ROTATED_CREDENTIALS)
    relation = wazuh_relation(secret)
    state = context.run(
        context.on.relation_changed(relation), make_state(relation, secrets=(secret,))
    )
    assert_written_credentials(wazuh_files, ROTATED_CREDENTIALS)
    workload_write.assert_called_once()
    assert state.get_secret(id=secret.id).tracked_content == ROTATED_CREDENTIALS


@pytest.mark.parametrize("secret_format", ["short", "qualified"])
def test_secret_id_formats_match(
    context: Ctx,
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
    secret_format: str,
) -> None:
    model_uuid = testing.State().model.uuid
    secret_id = "secret:credentials"
    if secret_format == "qualified":
        secret_id = f"secret://{model_uuid}/credentials"
    secret = testing.Secret(
        id=secret_id, tracked_content=INITIAL_CREDENTIALS, latest_content=ROTATED_CREDENTIALS
    )
    relation = wazuh_relation(secret)
    context.run(context.on.secret_changed(secret), make_state(relation, secrets=(secret,)))
    assert_written_credentials(wazuh_files, ROTATED_CREDENTIALS)
    workload_write.assert_called_once()


def test_unrelated_secret_does_not_write(
    context: Ctx, wazuh_files: dict[str, str], workload_write: MagicMock
) -> None:
    secret = credentials_secret()
    unrelated = testing.Secret(
        tracked_content={"unrelated": "secret-value"},
        latest_content={"unrelated": "rotated-value"},
    )
    relation = wazuh_relation(secret)
    before = dict(wazuh_files)
    context.run(
        context.on.secret_changed(unrelated), make_state(relation, secrets=(secret, unrelated))
    )
    workload_write.assert_not_called()
    assert wazuh_files == before


@pytest.mark.parametrize("relation_data", [None, {}, {"endpoint": ENDPOINT}])
def test_not_ready_events_preserve_configuration(
    context: Ctx,
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
    caplog: pytest.LogCaptureFixture,
    relation_data: dict[str, str] | None,
) -> None:
    caplog.set_level(logging.DEBUG)
    unrelated = testing.Secret(tracked_content={"unrelated": "secret-value"})
    relations: list[testing.Relation] = []
    if relation_data is not None:
        relations.append(
            testing.Relation("wazuh-api", remote_app_name=PROVIDER, remote_app_data=relation_data)
        )
    before = dict(wazuh_files)
    state = make_state(*relations, secrets=(unrelated,))
    context.run(context.on.secret_changed(unrelated), state)
    if relations:
        context.run(context.on.relation_changed(relations[0]), state)
    workload_write.assert_not_called()
    assert wazuh_files == before
    assert "Wazuh API" in caplog.text
    assert "secret-value" not in caplog.text


@pytest.mark.parametrize("invalid_field", ["endpoint", "user_credentials_secret"])
def test_invalid_relation_data_preserves_configuration(
    context: Ctx,
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
    caplog: pytest.LogCaptureFixture,
    invalid_field: str,
) -> None:
    secret = credentials_secret()
    relation = wazuh_relation(secret, **{invalid_field: "invalid-secret-value"})
    before = dict(wazuh_files)
    context.run(context.on.relation_changed(relation), make_state(relation, secrets=(secret,)))
    workload_write.assert_not_called()
    assert wazuh_files == before
    assert "Wazuh API" in caplog.text
    assert "invalid-secret-value" not in caplog.text


@pytest.mark.parametrize("content", [{"user": "api-user"}, {"password": "invalid-password"}])
def test_invalid_secret_preserves_configuration(
    context: Ctx,
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
    caplog: pytest.LogCaptureFixture,
    content: dict[str, str],
) -> None:
    secret = credentials_secret(latest=content)
    relation = wazuh_relation(secret)
    before = dict(wazuh_files)
    state = make_state(relation, secrets=(secret,))
    context.run(context.on.secret_changed(secret), state)
    workload_write.assert_not_called()
    assert wazuh_files == before
    assert "credentials field" in caplog.text
    assert "invalid-password" not in caplog.text

    fixed = dataclasses.replace(secret, latest_content=ROTATED_CREDENTIALS)
    context.run(context.on.secret_changed(fixed), dataclasses.replace(state, secrets=[fixed]))
    assert_written_credentials(wazuh_files, ROTATED_CREDENTIALS)
    workload_write.assert_called_once()


def test_secret_access_failure_recovers(
    context: Ctx,
    wazuh_files: dict[str, str],
    workload_write: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = credentials_secret(latest=ROTATED_CREDENTIALS)
    relation = wazuh_relation(secret)
    before = dict(wazuh_files)
    # The secret is missing from the model, as if access was revoked.
    context.run(context.on.relation_changed(relation), make_state(relation))
    workload_write.assert_not_called()
    assert wazuh_files == before
    assert "Could not access Wazuh API credentials secret" in caplog.text
    assert ROTATED_CREDENTIALS["password"] not in caplog.text

    context.run(context.on.secret_changed(secret), make_state(relation, secrets=(secret,)))
    assert_written_credentials(wazuh_files, ROTATED_CREDENTIALS)
    workload_write.assert_called_once()


def test_incomplete_publication_recovers(
    context: Ctx, wazuh_files: dict[str, str], workload_write: MagicMock
) -> None:
    incomplete = wazuh_relation()
    before = dict(wazuh_files)
    context.run(context.on.relation_changed(incomplete), make_state(incomplete))
    workload_write.assert_not_called()
    assert wazuh_files == before

    secret = credentials_secret(ROTATED_CREDENTIALS)
    complete = dataclasses.replace(
        incomplete,
        remote_app_data={**incomplete.remote_app_data, "user_credentials_secret": secret.id},
    )
    context.run(context.on.relation_changed(complete), make_state(complete, secrets=(secret,)))
    assert_written_credentials(wazuh_files, ROTATED_CREDENTIALS)
    workload_write.assert_called_once()


@pytest.mark.parametrize(
    "secret_id", ["secret:credentials", "secret://model-uuid/credentials", "credentials"]
)
def test_normalizes_secret_ids(secret_id: str) -> None:
    assert _short_secret_id(secret_id) == "credentials"
