#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

from literals import OPENSEARCH_DASHBOARDS_SNAP_CHANNEL, OPENSEARCH_DASHBOARDS_SNAP_REVISION

from .helpers import (
    CONFIG_OPTS,
    OPENSEARCH_APP_NAME,
    OPENSEARCH_CHANNEL,
    OPENSEARCH_REVISION,
    TLS_CERTIFICATES_APP_NAME,
    TLS_STABLE_CHANNEL,
    access_all_dashboards,
    get_app_relation_data,
)

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]

CHANNEL = f"{OPENSEARCH_DASHBOARDS_SNAP_CHANNEL.split('/')[0]}/stable"

OPENSEARCH_CONFIG = {
    "logging-config": "<root>=INFO;unit=DEBUG",
    "cloudinit-userdata": """postruncmd:
        - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
        - [ 'sysctl', '-w', 'fs.file-max=1048576' ]
        - [ 'sysctl', '-w', 'vm.swappiness=0' ]
        - [ 'sysctl', '-w', 'net.ipv4.tcp_retries2=5' ]
    """,
}

NUM_UNITS_APP = 3
NUM_UNITS_DB = 3


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest, series: str):
    """Deploying all charms required for the tests, and wait for their complete setup to be done."""

    await ops_test.model.deploy(APP_NAME, channel=CHANNEL, num_units=NUM_UNITS_APP, series=series)
    await ops_test.model.set_config(OPENSEARCH_CONFIG)
    await ops_test.model.deploy(
        OPENSEARCH_APP_NAME,
        channel=OPENSEARCH_CHANNEL,
        revision=OPENSEARCH_REVISION,
        num_units=NUM_UNITS_DB,
        config=CONFIG_OPTS,
    )

    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
    )

    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME], status="active", timeout=1000
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME],
        status="active",
        timeout=1000,
    )

    async with ops_test.fast_forward():
        await ops_test.model.block_until(
            lambda: len(ops_test.model.applications[APP_NAME].units) == NUM_UNITS_APP
        )
        await ops_test.model.wait_for_idle(apps=[APP_NAME], timeout=1000, idle_period=30)

    assert ops_test.model.applications[APP_NAME].status == "blocked"

    pytest.relation = await ops_test.model.relate(OPENSEARCH_APP_NAME, APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[OPENSEARCH_APP_NAME, APP_NAME], status="active", timeout=1000
    )


@pytest.mark.abort_on_fail
async def test_plain_refresh_from_charmhub(ops_test: OpsTest, charm: str):
    """Refresh current stable without pre-checks and verify snap and dashboard access."""
    await ops_test.model.applications[APP_NAME].refresh(path=charm)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME],
        status="active",
        timeout=1200,
        idle_period=120,
    )

    for unit in ops_test.model.applications[APP_NAME].units:
        _, stdout, _ = await ops_test.juju(
            "ssh", unit.name, "--", "snap", "list", "wazuh-dashboard", check=True
        )
        installed = stdout.strip().splitlines()[-1].split()
        assert installed[2] == OPENSEARCH_DASHBOARDS_SNAP_REVISION, stdout
        assert installed[3] == OPENSEARCH_DASHBOARDS_SNAP_CHANNEL, stdout
        assert installed[-1] == "held", stdout

    assert await access_all_dashboards(ops_test)


@pytest.mark.abort_on_fail
async def test_in_place_upgrade_http(ops_test: OpsTest, charm: str):
    leader_unit = None
    for unit in ops_test.model.applications[APP_NAME].units:
        if await unit.is_leader_from_status():
            leader_unit = unit
    assert leader_unit

    action = await leader_unit.run_action("pre-upgrade-check")
    await action.wait()

    # ensuring that the upgrade stack is correct
    relation_data = get_app_relation_data(
        model_full_name=ops_test.model_full_name,
        unit=f"{APP_NAME}/0",
        endpoint="upgrade",
    )

    assert "upgrade-stack" in relation_data

    assert set(json.loads(relation_data["upgrade-stack"])) == set(
        [int(unit.machine.id) for unit in ops_test.model.applications[APP_NAME].units]
    )

    await ops_test.model.applications[APP_NAME].refresh(path=charm)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="active", timeout=1000, idle_period=120
    )

    assert await access_all_dashboards(ops_test)


@pytest.mark.abort_on_fail
async def test_switch_tls_on(ops_test: OpsTest):
    """Test HTTPS access to each dashboard unit."""
    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, TLS_CERTIFICATES_APP_NAME], status="active", timeout=1000
    )


@pytest.mark.abort_on_fail
async def test_in_place_upgrade_https(ops_test: OpsTest, charm: str):
    leader_unit = None
    for unit in ops_test.model.applications[APP_NAME].units:
        if await unit.is_leader_from_status():
            leader_unit = unit
    assert leader_unit

    action = await leader_unit.run_action("pre-upgrade-check")
    await action.wait()

    # ensuring that the upgrade stack is correct
    relation_data = get_app_relation_data(
        model_full_name=ops_test.model_full_name,
        unit=f"{APP_NAME}/0",
        endpoint="upgrade",
    )

    assert "upgrade-stack" in relation_data
    assert set(json.loads(relation_data["upgrade-stack"])) == set(
        [int(unit.machine.id) for unit in ops_test.model.applications[APP_NAME].units]
    )

    await ops_test.model.applications[APP_NAME].refresh(path=charm)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="active", timeout=1000, idle_period=120
    )

    assert await access_all_dashboards(ops_test, https=True)
