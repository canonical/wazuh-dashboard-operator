#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for Apache Opensearch Dashboards."""

import logging

from ops.model import ActiveStatus, Application, Unit

logger = logging.getLogger(__name__)


def clear_status(scope_obj: Unit | Application, messages: str | list[str]) -> None:
    """Clear status if set."""
    if not isinstance(messages, list):
        messages = [messages]

    if any([scope_obj.status.message == message for message in messages]):
        logger.debug(f"Clearing status {messages} from {scope_obj}.")
        scope_obj.status = ActiveStatus()
