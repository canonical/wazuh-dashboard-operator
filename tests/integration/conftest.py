import shutil
import subprocess

import pytest
from pytest_operator.plugin import OpsTest


@pytest.fixture(autouse=True, scope="module")
def opensearch_sysctl_settings():
    """Necessary settings for Opensearch

    This should probably rather go to ci.yaml"""
    subprocess.run(["sudo", "sysctl", "-w", "vm.swappiness=0"])
    subprocess.run(["sudo", "sysctl", "-w", "vm.max_map_count=262144"])
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.tcp_retries2=5"])


@pytest.fixture(scope="module")
async def application_charm(ops_test: OpsTest):
    """Build the application charm."""
    test_charm_path = "tests/integration/application-charm"
    shutil.copyfile(
        "lib/charms/data_platform_libs/v0/data_interfaces.py",
        f"{test_charm_path}/lib/charms/data_platform_libs/v0/data_interfaces.py",
    )
    # charm = await ops_test.build_charm(test_charm_path)
    # return charm
