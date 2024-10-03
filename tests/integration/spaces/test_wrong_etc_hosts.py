#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import subprocess

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers import (
    APP_NAME,
    OPENSEARCH_RELATION_NAME,
    SERIES,
    TLS_CERTIFICATES_APP_NAME,
    OPENSEARCH_APP_NAME,
    access_all_dashboards,
    access_all_prometheus_exporters,
    get_relations,
)

logger = logging.getLogger(__name__)


DEFAULT_NUM_UNITS = 1


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest, lxd_spaces) -> None:
    """Build and deploy OpenSearch Dashboards.

    For this test, we will create a machine in multiple spaces and inject
    the a record into /etc/hosts, as follows:
        127.0.1.1  <fqdn>

    More information: gh:canonical/opensearch-dashboards-operator#121
    """
    osd_charm = await ops_test.build_charm(".")

    subprocess.check_output(
        [
            "juju",
            "add-machine",
            f"-n{DEFAULT_NUM_UNITS}",
            f"--model={ops_test.model.name}",
            "--constraints=spaces=alpha,client,cluster,backup",
            f"--series={SERIES}",
        ]
    )

    await ops_test.model.deploy(
        osd_charm,
        num_units=DEFAULT_NUM_UNITS,
        series=SERIES,
        constraints="spaces=alpha,client,cluster,backup",
        bind={"": "cluster"},
        to=",".join([str(i) for i in range(DEFAULT_NUM_UNITS)]),
    )
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel="stable",
        constraints="spaces=alpha,client,cluster,backup",
        bind={"": "cluster"},
        config=config,
    )
    await ops_test.model.deploy(
        "opensearch",
        channel="2/edge",
        constraints="spaces=alpha,client,cluster,backup",
        bind={"": "cluster"},
        num_units=3,
    )
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate(OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate(OPENSEARCH_APP_NAME, APP_NAME)

    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME], status="active", timeout=1000
    )

    # Now, we should SSH to each machine and inject the record into /etc/hosts
    machine_ip = "127.0.1.1"
    for machine_id in range(DEFAULT_NUM_UNITS):
        subprocess.check_output(
            [
                "juju",
                "ssh",
                f"--model={ops_test.model.name}",
                str(machine_id),
                "--",
                "sudo",
                "sed",
                "-i",
                f'"1i\\{machine_ip} $(hostname -f)"',
                "/etc/hosts",
            ]
        )

    assert len(ops_test.model.applications[APP_NAME].units) == DEFAULT_NUM_UNITS


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_dashboard_access(ops_test: OpsTest):
    """Test HTTP access to each dashboard unit."""

    opensearch_relation = get_relations(ops_test, OPENSEARCH_RELATION_NAME)[0]
    assert await access_all_dashboards(ops_test, opensearch_relation.id)
    assert await access_all_prometheus_exporters(ops_test)
