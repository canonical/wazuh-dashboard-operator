#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
import tempfile
from types import SimpleNamespace
from typing import Any, Dict, Optional, Union

import requests
from pytest_operator.plugin import OpsTest
from tenacity import retry, stop_after_attempt, wait_fixed

from ..helpers import get_address, get_leader_name

logger = logging.getLogger(__name__)


@retry(wait=wait_fixed(wait=15), stop=stop_after_attempt(15))
async def run_action(
    ops_test: OpsTest,
    unit_id: int,
    action_name: str,
    params: Optional[Dict[str, Any]] = None,
    app: str = "opensearch",
) -> SimpleNamespace:
    """Run a charm action.

    Returns:
        A SimpleNamespace with "status, response (results)"
    """
    unit_name = [
        unit.name
        for unit in ops_test.model.applications[app].units
        if unit.name.endswith(f"/{unit_id}")
    ][0]

    action = await ops_test.model.units.get(unit_name).run_action(action_name, **(params or {}))
    action = await action.wait()

    return SimpleNamespace(status=action.status or "completed", response=action.results)


async def get_secrets(
    ops_test: OpsTest, unit_id: int, username: str = "admin", app: str = "opensearch"
) -> Dict[str, str]:
    """Use the charm action to retrieve the admin password and chain.

    Returns:
        Dict with the admin and cert chain stored on the peer relation databag.
    """
    # can retrieve from any unit running unit, so we pick the first
    return (
        await run_action(ops_test, unit_id, "get-password", {"username": username}, app=app)
    ).response


async def http_request(
    ops_test: OpsTest,
    method: str,
    endpoint: str,
    payload: Optional[Union[str, Dict[str, Any]]] = None,
    resp_status_code: bool = False,
    verify=True,
    user: Optional[str] = "admin",
    user_password: Optional[str] = None,
    app: str = "opensearch",
    json_resp: bool = True,
):
    """Makes an HTTP request.

    Args:
        ops_test: The ops test framework instance.
        method: the HTTP method (GET, POST, HEAD etc.)
        endpoint: the url to be called.
        payload: the body of the request if any.
        resp_status_code: whether to only return the http response code.
        verify: whether verify certificate chain or not
        user_password: use alternative password than the admin one in the secrets.
        app: the name of the current application.
        json_resp: return a json response or simply log

    Returns:
        A json object.
    """
    admin_secrets = await get_secrets(ops_test, app=app, unit_id=0)

    # fetch the cluster info from the endpoint of this unit
    with requests.Session() as session, tempfile.NamedTemporaryFile(mode="w+") as chain:
        chain.write(admin_secrets["ca-chain"])
        chain.seek(0)

        logger.info(f"Calling: {method} -- {endpoint}")

        request_kwargs = {
            "method": method,
            "url": endpoint,
            "timeout": (17, 17),
        }
        if json_resp:
            request_kwargs["headers"] = {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }

        if isinstance(payload, str):
            request_kwargs["data"] = payload
        elif isinstance(payload, dict):
            request_kwargs["data"] = json.dumps(payload)

        session.auth = (user or "admin", user_password or admin_secrets["password"])

        request_kwargs["verify"] = chain.name if verify else False
        resp = session.request(**request_kwargs)

        if resp.status_code == 503:
            logger.debug("\n\n\n\n -- Error 503 -- \n")

        if resp_status_code:
            return resp.status_code

        if json_resp:
            return resp.json()

        logger.info(f"\n{resp.text}")
        return resp


@retry(wait=wait_fixed(wait=30), stop=stop_after_attempt(15))
async def set_watermark(
    ops_test: OpsTest,
    app: str,
) -> None:
    """Set watermark on the application."""
    leader_name = await get_leader_name(ops_test, app_name=app)
    if not leader_name:
        raise ValueError(f"No leader found for app {app}")

    unit_ip = await get_address(ops_test, leader_name)

    await http_request(
        ops_test,
        "PUT",
        f"https://{unit_ip}:9200/_cluster/settings",
        {
            "persistent": {
                "cluster.routing.allocation.disk.threshold_enabled": "false",
            }
        },
        app=app,
    )
