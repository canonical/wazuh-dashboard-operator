#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Upgrade the current stable dashboard while connected to a complete Wazuh stack."""

import datetime
import json
import logging

import pytest
import requests
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pytest_operator.plugin import OpsTest

from literals import OPENSEARCH_DASHBOARDS_SNAP_CHANNEL, OPENSEARCH_DASHBOARDS_SNAP_REVISION, PATHS

from .helpers import (
    APP_NAME,
    CONFIG_OPTS,
    OPENSEARCH_APP_NAME,
    OPENSEARCH_CHANNEL,
    OPENSEARCH_CONFIG,
    OPENSEARCH_REVISION,
    TLS_CERTIFICATES_APP_NAME,
    TLS_STABLE_CHANNEL,
)

logger = logging.getLogger(__name__)
TRACK = OPENSEARCH_DASHBOARDS_SNAP_CHANNEL.split("/")[0]
SERVER_APP_NAME = "wazuh-server"
PEBBLE_EXEC = (
    "PEBBLE_SOCKET=/charm/containers/wazuh-server/pebble.socket /charm/bin/pebble exec --"
)


def logs_ca_certificate() -> str:
    """Generate the test-only client CA required by the server's logging configuration."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "upgrade-test-logs-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


async def snap_info(ops_test: OpsTest) -> list[str]:
    """Return the installed dashboard snap's list fields."""
    _, stdout, _ = await ops_test.juju(
        "ssh", f"{APP_NAME}/0", "--", "snap", "list", "wazuh-dashboard", check=True
    )
    logger.info("Installed dashboard snap:\n%s", stdout)
    return stdout.strip().splitlines()[-1].split()


async def assert_stack_healthy(ops_test: OpsTest, server_model) -> None:
    """Check Indexer health, Dashboard login, API compatibility, and Filebeat output."""
    indexer = ops_test.model.applications[OPENSEARCH_APP_NAME].units[0]
    action = await indexer.run_action("get-password", username="admin")
    await action.wait()
    password = action.results["password"]
    indexer_address = await indexer.get_public_address()
    response = requests.get(
        f"https://{indexer_address}:9200/_cluster/health",
        auth=("admin", password),
        verify=False,
        timeout=30,
    )
    response.raise_for_status()
    assert response.json()["status"] == "green", response.text

    dashboard = ops_test.model.applications[APP_NAME].units[0]
    address = await dashboard.get_public_address()
    # Logging in exercises the dashboard's authentication against Indexer.
    with requests.Session() as session:
        response = session.post(
            f"https://{address}:5601/auth/login",
            json={"username": "admin", "password": password},
            headers={"osd-xsrf": "true"},
            verify=False,
            timeout=30,
        )
        response.raise_for_status()
        response = session.get(f"https://{address}:5601/api/status", verify=False, timeout=30)
        response.raise_for_status()
        assert response.json()["status"]["overall"]["state"] == "green", response.text

    # Use the API endpoint and credentials actually configured in the dashboard,
    # rather than independent admin credentials that could mask a broken relation.
    _, stdout, _ = await ops_test.juju(
        "ssh", dashboard.name, "--", "sudo", "cat", PATHS["WAZUH_CONF"], check=True
    )
    api = yaml.safe_load(stdout)["hosts"][0]["default"]
    endpoint = f"{api['url']}:{api['port']}"
    response = requests.get(
        f"{endpoint}/security/user/authenticate",
        auth=(api["username"], api["password"]),
        verify=False,
        timeout=30,
    )
    response.raise_for_status()
    token = response.json()["data"]["token"]
    response = requests.get(
        f"{endpoint}/", headers={"Authorization": f"Bearer {token}"}, verify=False, timeout=30
    )
    response.raise_for_status()
    api_version = response.json()["data"]["api_version"].removeprefix("v")
    installed = await snap_info(ops_test)
    assert (
        installed[1] == api_version
    ), f"Wazuh API/dashboard mismatch: API {api_version}, dashboard {installed[1]}"

    response = requests.get(
        f"{endpoint}/manager/status",
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
        timeout=30,
    )
    response.raise_for_status()
    manager_status = response.json()["data"]["affected_items"][0]
    for daemon in ["wazuh-analysisd", "wazuh-remoted"]:
        assert manager_status[daemon] == "running", manager_status

    server = server_model.applications[SERVER_APP_NAME].units[0]
    action = await server.run(f"{PEBBLE_EXEC} /usr/bin/filebeat test output", timeout=60)
    await action.wait()
    assert action.results.get("return-code") == 0, action.results


@pytest.mark.abort_on_fail
async def test_deploy_current_stable(ops_test: OpsTest, ops_test_microk8s, series: str):
    """Deploy the published dashboard with Indexer, Server, TLS, and API relations."""
    await ops_test.model.set_config(OPENSEARCH_CONFIG)
    await ops_test.model.deploy(
        OPENSEARCH_APP_NAME,
        channel=OPENSEARCH_CHANNEL,
        revision=OPENSEARCH_REVISION,
        num_units=3,
        config=CONFIG_OPTS,
        series=series,
    )
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel=TLS_STABLE_CHANNEL,
        config={"ca-common-name": "upgrade-test-ca"},
    )
    await ops_test.model.deploy(APP_NAME, channel=f"{TRACK}/stable", series=series)
    await ops_test.model.integrate(OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate(APP_NAME, OPENSEARCH_APP_NAME)
    await ops_test.model.wait_for_idle(status="active", timeout=1800, idle_period=60)

    server_model = ops_test_microk8s.model
    await server_model.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel=TLS_STABLE_CHANNEL,
        config={"ca-common-name": "upgrade-test-server-ca"},
    )
    await server_model.deploy("traefik-k8s", channel="latest/stable", trust=True)
    await server_model.deploy(
        SERVER_APP_NAME,
        channel=f"{TRACK}/stable",
        trust=True,
        config={"logs-ca-cert": logs_ca_certificate(), "enable-vulnerability-detection": False},
    )
    await ops_test.model.create_offer(f"{OPENSEARCH_APP_NAME}:opensearch-client", "indexer")
    await server_model.integrate(
        f"{ops_test.controller_name}:admin/{ops_test.model.name}.indexer",
        f"{SERVER_APP_NAME}:opensearch-client",
    )
    await server_model.integrate(SERVER_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await server_model.integrate(SERVER_APP_NAME, "traefik-k8s")
    await server_model.wait_for_idle(status="active", timeout=1800, idle_period=60)
    await server_model.create_offer(f"{SERVER_APP_NAME}:wazuh-api", "wazuh-api")
    await ops_test.model.integrate(
        f"{ops_test.controller_name}:admin/{server_model.name}.wazuh-api", f"{APP_NAME}:wazuh-api"
    )
    await ops_test.model.wait_for_idle(status="active", timeout=1200, idle_period=60)
    await assert_stack_healthy(ops_test, server_model)


@pytest.mark.abort_on_fail
async def test_plain_refresh_from_charmhub(ops_test: OpsTest, ops_test_microk8s, charm: str):
    """Refresh without pre-upgrade-check and verify the complete stack still works."""
    await snap_info(ops_test)
    await ops_test.model.applications[APP_NAME].refresh(path=charm)
    await ops_test.model.wait_for_idle(status="active", timeout=1800, idle_period=60)
    await ops_test_microk8s.model.wait_for_idle(status="active", timeout=1200, idle_period=60)

    installed = await snap_info(ops_test)
    assert installed[2] == OPENSEARCH_DASHBOARDS_SNAP_REVISION
    assert installed[3] == OPENSEARCH_DASHBOARDS_SNAP_CHANNEL
    assert installed[-1] == "held"
    await assert_stack_healthy(ops_test, ops_test_microk8s.model)

    _, stdout, _ = await ops_test.juju("show-unit", f"{APP_NAME}/0", "--format=json", check=True)
    upgrade_relation = next(
        relation
        for relation in json.loads(stdout)[f"{APP_NAME}/0"]["relation-info"]
        if relation["endpoint"] == "upgrade"
    )
    assert upgrade_relation["local-unit"]["data"]["state"] == "idle"
