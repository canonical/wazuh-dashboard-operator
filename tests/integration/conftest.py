import os
import shutil
import subprocess
import logging

import pytest
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True, scope="module")
def opensearch_sysctl_settings():
    """Necessary settings for Opensearch

    This should probably rather go to ci.yaml"""
    subprocess.run(["sudo", "sysctl", "-w", "vm.swappiness=0"])
    subprocess.run(["sudo", "sysctl", "-w", "vm.max_map_count=262144"])
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.tcp_retries2=5"])


@pytest.fixture(scope="module")
def application_charm_libs(ops_test: OpsTest):
    """Build the application charm."""
    source_path = "lib/charms/data_platform_libs/v0/data_interfaces.py"
    test_charm_path = "tests/integration/application-charm"
    dest_dir = f"{test_charm_path}/lib/charms/data_platform_libs/v0/"
    os.makedirs(dest_dir, exist_ok=True)
    shutil.copyfile(source_path, f"{dest_dir}/data_interfaces.py")
    logger.info(f"Copied {source_path} to {dest_dir}")
