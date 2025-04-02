#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Event handler for related applications on the `wazuh-api` relation interface."""
import base64
import logging
import re
from typing import TYPE_CHECKING

from charms.wazuh_server.v0 import wazuh_api
from ops.charm import RelationEvent
from ops.framework import Object


if TYPE_CHECKING:
    from charm import OpensearchDasboardsCharm

logger = logging.getLogger(__name__)


class WazuhApiEvents(Object):
    """Event handlers for related applications on the `certificates` relation interface."""

    def __init__(self, charm):
        super().__init__(charm, "tls")
        self.charm: "OpensearchDasboardsCharm" = charm
        self.wazuh_api = wazuh_api.WazuhApiRequires(self.charm)

        self.framework.observe(
            getattr(self.charm.on, "wazuh_api_relation_created"),
            self._on_wazuh_api_relation_changed,
        )
        self.framework.observe(
            getattr(self.charm.on, "wazuh_api_relation_changed"),
            self._on_wazuh_api_relation_changed,
        )

    def _on_wazuh_api_relation_changed(self, _: RelationEvent) -> None:
        """Handler for `wazuh-api` relation creation and changes."""
        data = self.wazuh_api.get_relation_data()
        if data:
            self.charm.wazuh_manager.set_wazuh_dashbaord_properties(data)
