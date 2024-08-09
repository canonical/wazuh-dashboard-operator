#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for Apache Opensearch Dashboards."""

import logging

from charms.tls_certificates_interface.v3.tls_certificates import CharmBase
from ops.model import ActiveStatus, Application, StatusBase, Unit

logger = logging.getLogger(__name__)


def clear_status(scope_obj: Unit | Application, messages: str | list[str]) -> None:
    """Clear status if set."""
    if not isinstance(messages, list):
        messages = [messages]

    if any([scope_obj.status.message == message for message in messages]):
        logger.debug(f"Clearing status {messages} from {scope_obj}.")
        scope_obj.status = ActiveStatus()


def set_global_status(charm: CharmBase, status: StatusBase | None):
    """Set status on all possible levels."""
    if not status:
        return

    charm.unit.status = status
    if charm.unit.is_leader():
        charm.app.status = status


def clear_global_status(charm: CharmBase, status: str | None):
    """Clear status on all levels."""
    if not status:
        return
    clear_status(charm.unit, status)
    if charm.unit.is_leader():
        clear_status(charm.app, status)
