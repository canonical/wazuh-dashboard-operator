#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
import requests
import yaml
from pytest_operator.plugin import OpsTest

from .helpers import (
    CONFIG_OPTS,
    OPENSEARCH_APP_NAME,
    OPENSEARCH_CHANNEL,
    OPENSEARCH_CONFIG,
    OPENSEARCH_REVISION,
    TLS_CERTIFICATES_APP_NAME,
    TLS_STABLE_CHANNEL,
    get_bind_address,
)
from .helpers_jwt import generate_json_web_token

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]
JWT_APP_NAME = "jwt-integrator"
JWT_REL_NAME = "jwt-configuration"


@pytest.mark.skip(
    reason=(
        "wazuh-indexer (pinned to 4.11/revision 9, see OPENSEARCH_REVISION in "
        "helpers.py) does not yet expose the jwt-configuration relation that "
        "upstream's opensearch charm has: integrate() fails with "
        "'no relations found'. Re-enable once a wazuh-indexer revision with "
        "jwt-configuration support is available and pinned."
    )
)
@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest, charm: str, series: str):
    """Deploying all charms required for the tests, and wait for their complete setup to be done."""
    await ops_test.model.deploy(charm, application_name=APP_NAME, series=series)
    await ops_test.model.set_config(OPENSEARCH_CONFIG)
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(
        OPENSEARCH_APP_NAME,
        channel=OPENSEARCH_CHANNEL,
        revision=OPENSEARCH_REVISION,
        num_units=3,
        config=CONFIG_OPTS,
    )
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
    )
    await ops_test.model.deploy(JWT_APP_NAME, channel="1/edge")
    await ops_test.model.wait_for_idle(apps=[TLS_CERTIFICATES_APP_NAME], status="active")

    logger.info(f"Integrating {OPENSEARCH_APP_NAME} with {TLS_CERTIFICATES_APP_NAME}")
    await ops_test.model.integrate(OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME],
        status="active",
    )

    logger.info(f"Integrating {APP_NAME} with {OPENSEARCH_APP_NAME}")
    await ops_test.model.integrate(OPENSEARCH_APP_NAME, APP_NAME)

    logger.info("Create JWT configuration")
    global generated_jwt
    generated_jwt = generate_json_web_token()

    secret_name = "jwt-signing-key"
    secret_id = await ops_test.model.add_secret(
        name=secret_name, data_args=[f"signing-key={generated_jwt['signing-key']}"]
    )
    await ops_test.model.grant_secret(secret_name=secret_name, application=JWT_APP_NAME)

    jwt_config = {
        "signing-key": secret_id,
        "roles-key": "role",
        "subject-key": "user",
        "jwt-url-parameter": "jwt",
    }
    await ops_test.model.applications[JWT_APP_NAME].set_config(jwt_config)

    logger.info(f"Integrating {OPENSEARCH_APP_NAME} with {JWT_APP_NAME}")
    await ops_test.model.integrate(JWT_APP_NAME, OPENSEARCH_APP_NAME)
    await ops_test.model.wait_for_idle(apps=[OPENSEARCH_APP_NAME, JWT_APP_NAME], status="active")

    logger.info(f"Integrating {APP_NAME} with {JWT_APP_NAME}")
    await ops_test.model.integrate(JWT_APP_NAME, APP_NAME)
    await ops_test.model.wait_for_idle(apps=[APP_NAME, JWT_APP_NAME], status="active")


@pytest.mark.skip(
    reason=(
        "Depends on test_build_and_deploy, which is skipped (see reason "
        "there): wazuh-indexer 4.11/revision 9 lacks the jwt-configuration "
        "relation."
    )
)
@pytest.mark.abort_on_fail
async def test_dashboard_access(ops_test: OpsTest):
    """Test access to dashboard unit with JWT and basic auth."""
    unit = ops_test.model.applications[APP_NAME].units[0]
    host = get_bind_address(ops_test.model.name, unit.name)
    url = f"http://{host}:5601/api/status"

    logger.info("Test access with JWT")
    jwt_result = requests.get(
        url, headers={"Authorization": f"Bearer {generated_jwt['token']}"}, verify=False
    )
    assert jwt_result.status_code == 200, "Request failed"
    logger.info("Access with JWT successful")

    logger.info(f"Remove relation of {JWT_APP_NAME} with {APP_NAME}")
    remove_relation_cmd = (
        f"remove-relation {JWT_APP_NAME}:{JWT_REL_NAME} {APP_NAME}:{JWT_REL_NAME}"
    )
    await ops_test.juju(*remove_relation_cmd.split(), check=True)

    logger.info(f"Remove relation of {JWT_APP_NAME} with {OPENSEARCH_APP_NAME}")
    remove_relation_cmd = (
        f"remove-relation {JWT_APP_NAME}:{JWT_REL_NAME} {OPENSEARCH_APP_NAME}:{JWT_REL_NAME}"
    )
    await ops_test.juju(*remove_relation_cmd.split(), check=True)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, OPENSEARCH_APP_NAME],
        status="active",
        idle_period=60,
    )

    logger.info("Test access with JWT after disabling")
    jwt_result = requests.get(
        url, headers={"Authorization": f"Bearer {generated_jwt['token']}"}, verify=False
    )
    assert jwt_result.status_code == 401, "`Unauthorized` error expected"
    logger.info("Access with JWT failed as expected")
