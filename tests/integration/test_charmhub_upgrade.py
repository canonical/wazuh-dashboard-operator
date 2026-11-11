#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Exercise a plain refresh from the current Charmhub stable release."""

import pytest
from pytest_operator.plugin import OpsTest

from literals import (
    OPENSEARCH_DASHBOARDS_SNAP_CHANNEL,
    OPENSEARCH_DASHBOARDS_SNAP_REVISION,
)

from .helpers import (
    APP_NAME,
    CONFIG_OPTS,
    OPENSEARCH_APP_NAME,
    OPENSEARCH_CHANNEL,
    OPENSEARCH_CONFIG,
    OPENSEARCH_REVISION,
    TLS_CERTIFICATES_APP_NAME,
    TLS_STABLE_CHANNEL,
    access_all_dashboards,
)

UPGRADE_FROM_CHANNEL = "4.14/stable"
STACK_APPS = [APP_NAME, OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME]


async def deploy_charmhub_stack(ops_test: OpsTest, series: str) -> None:
    """Deploy the published dashboard with its own Indexer and TLS applications."""
    await ops_test.model.set_config(OPENSEARCH_CONFIG)
    await ops_test.model.deploy(
        OPENSEARCH_APP_NAME,
        channel=OPENSEARCH_CHANNEL,
        revision=OPENSEARCH_REVISION,
        num_units=3,
        config=CONFIG_OPTS,
    )
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel=TLS_STABLE_CHANNEL,
        config={"ca-common-name": "upgrade-test-ca"},
    )
    await ops_test.model.deploy(APP_NAME, channel=UPGRADE_FROM_CHANNEL, num_units=3, series=series)
    await ops_test.model.relate(OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.relate(OPENSEARCH_APP_NAME, APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=STACK_APPS, status="active", timeout=1800, idle_period=60
    )


@pytest.mark.abort_on_fail
async def test_plain_refresh_from_charmhub(ops_test: OpsTest, charm: str, series: str):
    """Refresh without pre-checks and verify snap revision and dashboard access."""
    await deploy_charmhub_stack(ops_test, series)
    assert await access_all_dashboards(ops_test)

    # Do not run pre-upgrade-check: this exercises the no-upgrade-stack path.
    await ops_test.model.applications[APP_NAME].refresh(path=charm)
    await ops_test.model.wait_for_idle(
        apps=STACK_APPS, status="active", timeout=1200, idle_period=120
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
