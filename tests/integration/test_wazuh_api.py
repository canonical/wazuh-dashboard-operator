#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test for the Wazuh dashboard/server API relation and upgrade."""

import datetime
import logging
from asyncio import gather

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pytest_operator.plugin import OpsTest

from literals import CHARM_KEY, PATHS

from .helpers import (
    OPENSEARCH_APP_NAME,
    TLS_CERTIFICATES_APP_NAME,
    TLS_STABLE_CHANNEL,
    get_app_relation_data,
    get_file_contents,
)

logger = logging.getLogger(__name__)

DASHBOARD_APP = CHARM_KEY
INDEXER_APP = OPENSEARCH_APP_NAME
TLS_APP = TLS_CERTIFICATES_APP_NAME
SERVER_APP = "wazuh-server"
TRAEFIK_APP = "traefik-k8s"

STACK_CHANNEL = "4.14/stable"
TLS_CHANNEL = TLS_STABLE_CHANNEL
TRAEFIK_CHANNEL = "latest/edge"

WAZUH_CONF = PATHS["WAZUH_CONF"]
LEGACY_WAZUH_CONF = PATHS["LEGACY_WAZUH_CONF"]


def _generate_ca_cert() -> str:
    """Generate a throwaway CA certificate for the Wazuh server config."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wazuh-test-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def _read_config(ops_test: OpsTest, unit, path: str) -> dict:
    output = get_file_contents(ops_test, unit, path)
    if not output:
        return {}
    return yaml.safe_load(output.decode())


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_and_integrate_wazuh_stack(
    ops_test: OpsTest, ops_test_microk8s: OpsTest, series: str
):
    """Deploy the three Wazuh charms from Charmhub and integrate them."""
    machine = ops_test.model
    k8s = ops_test_microk8s.model

    await machine.deploy(
        TLS_APP,
        channel=TLS_CHANNEL,
        config={"ca-common-name": "CN_CA"},
        series=series,
    )
    await machine.deploy(
        INDEXER_APP,
        channel=STACK_CHANNEL,
        num_units=3,
        config={"profile": "testing"},
        series=series,
    )
    await machine.deploy(
        DASHBOARD_APP,
        channel=STACK_CHANNEL,
        num_units=1,
        series=series,
    )
    await machine.integrate(TLS_APP, INDEXER_APP)
    await machine.integrate(INDEXER_APP, DASHBOARD_APP)

    await k8s.deploy(
        TLS_APP,
        channel=TLS_CHANNEL,
        config={"ca-common-name": "CN_CA"},
    )
    await k8s.deploy(
        TRAEFIK_APP,
        channel=TRAEFIK_CHANNEL,
        trust=True,
        config={"external_hostname": "wazuh-server.local"},
    )
    await k8s.deploy(
        SERVER_APP,
        channel=STACK_CHANNEL,
        trust=True,
        config={
            "logs-ca-cert": _generate_ca_cert(),
            "enable-vulnerability-detection": False,
        },
    )
    await k8s.integrate(TLS_APP, SERVER_APP)
    await k8s.integrate(TRAEFIK_APP, SERVER_APP)

    await machine.wait_for_idle(
        apps=[TLS_APP, INDEXER_APP],
        status="active",
        timeout=1800,
        idle_period=30,
    )

    # The indexer provides the OpenSearch endpoint used by the server.
    await machine.create_offer(f"{INDEXER_APP}:opensearch-client", "opensearch-client")
    await k8s.consume(f"admin/{machine.name}.opensearch-client")
    await k8s.integrate(f"{SERVER_APP}:opensearch-client", "opensearch-client")

    await k8s.wait_for_idle(
        apps=[TLS_APP, TRAEFIK_APP, SERVER_APP],
        status="active",
        timeout=1800,
        idle_period=30,
    )

    # The server provides the Wazuh API used by the dashboard.
    await k8s.create_offer(f"{SERVER_APP}:wazuh-api", "wazuh-api")
    await machine.consume(f"admin/{ops_test_microk8s.model_name}.wazuh-api")
    await machine.integrate(f"{DASHBOARD_APP}:wazuh-api", "wazuh-api")

    await gather(
        machine.wait_for_idle(
            apps=[TLS_APP, INDEXER_APP, DASHBOARD_APP],
            status="active",
            timeout=1800,
            idle_period=30,
        ),
        k8s.wait_for_idle(
            apps=[TLS_APP, TRAEFIK_APP, SERVER_APP],
            status="active",
            timeout=1800,
            idle_period=30,
        ),
    )

    server_data = get_app_relation_data(
        model_full_name=ops_test_microk8s.model_full_name,
        unit=f"{SERVER_APP}/0",
        endpoint="wazuh-api",
    )
    assert server_data.get("endpoint"), "Server did not publish a Wazuh API endpoint"
    assert server_data.get("user_credentials_secret"), "Server did not publish API credentials"

    # The published charm may still write to the legacy path or may already
    # contain this fix and write to the common path. Either is valid here; the
    # post-upgrade check below asserts the new path specifically.
    dashboard_unit = machine.applications[DASHBOARD_APP].units[0]
    legacy_config = _read_config(ops_test, dashboard_unit, LEGACY_WAZUH_CONF)
    common_config = _read_config(ops_test, dashboard_unit, WAZUH_CONF)
    assert legacy_config.get("hosts") or common_config.get(
        "hosts"
    ), "The wazuh-api relation data was not written"


@pytest.mark.abort_on_fail
async def test_upgrade_dashboard_writes_common_path(
    ops_test: OpsTest, ops_test_microk8s: OpsTest, charm: str
):
    """Upgrade the dashboard to the test charm and verify the new config path."""
    machine = ops_test.model

    dashboard = machine.applications[DASHBOARD_APP]
    leader = next(unit for unit in dashboard.units if await unit.is_leader_from_status())
    action = await leader.run_action("pre-upgrade-check")
    await action.wait()

    await dashboard.refresh(path=charm)
    await machine.wait_for_idle(
        apps=[DASHBOARD_APP],
        status="active",
        timeout=1800,
        idle_period=120,
    )

    server_data = get_app_relation_data(
        model_full_name=ops_test_microk8s.model_full_name,
        unit=f"{SERVER_APP}/0",
        endpoint="wazuh-api",
    )
    endpoint = server_data["endpoint"]

    dashboard_unit = dashboard.units[0]
    config = _read_config(ops_test, dashboard_unit, WAZUH_CONF)
    hosts = config.get("hosts")
    assert hosts, f"wazuh.yml was not written to {WAZUH_CONF}"

    host = hosts[0]["default"]
    assert host["url"].endswith(endpoint.split("://", 1)[1].split(":", 1)[0])
    assert host["port"] == int(endpoint.rsplit(":", 1)[1].rstrip("/"))
    assert host["username"]
