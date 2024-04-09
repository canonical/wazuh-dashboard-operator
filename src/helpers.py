#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for Apache Opensearch Dashboards."""

from ops.model import ActiveStatus, Application, Unit


def clear_status(scope_obj: Unit | Application, messages: str | list[str]) -> None:
    """Clear status if set."""
    if not isinstance(messages, list):
        messages = [messages]

    if any([scope_obj.status.message == message for message in messages]):
        scope_obj.status = ActiveStatus()
