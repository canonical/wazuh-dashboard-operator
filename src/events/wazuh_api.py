#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Event handler for related applications on the `wazuh-api` relation interface."""
import logging
from typing import TYPE_CHECKING

from charms.wazuh_server.v0 import wazuh_api
from ops.charm import RelationEvent, SecretChangedEvent
from ops.framework import Object
from ops.model import ModelError, SecretNotFoundError

if TYPE_CHECKING:
    from charm import OpensearchDashboardsCharm

logger = logging.getLogger(__name__)


RELATION_NAME = "wazuh-api"


class WazuhApiEvents(Object):
    """Event handlers for related applications on the `certificates` relation interface."""

    def __init__(self, charm):
        super().__init__(charm, RELATION_NAME)
        self.charm: "OpensearchDashboardsCharm" = charm
        self.wazuh_api = wazuh_api.WazuhApiRequires(self.charm)

        self.framework.observe(
            self.charm.on[RELATION_NAME].relation_changed,
            self._on_wazuh_api_relation_changed,
        )
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)

    def _on_wazuh_api_relation_changed(self, _: RelationEvent) -> None:
        """Handler for `wazuh-api` relation creation and changes."""
        self.update_configuration()

    def _on_secret_changed(self, event: SecretChangedEvent) -> None:
        """Handler for rotation of the secret holding the Wazuh API credentials."""
        relation = self.model.get_relation(RELATION_NAME)
        if not relation or not relation.app:
            return
        secret_id = relation.data[relation.app].get("user_credentials_secret")
        if not secret_id or _short_secret_id(secret_id) != _short_secret_id(event.secret.id):
            return

        logger.info("Wazuh API credentials secret changed, refreshing configuration")
        self.update_configuration()

    def _refresh_credentials_secret(self) -> None:
        """Track the latest revision of the credentials secret.

        Without this, get_content() keeps returning the revision first observed by the unit,
        including after the relation is recreated.
        """
        relation = self.model.get_relation(RELATION_NAME)
        if not relation or not relation.app:
            return
        secret_id = relation.data[relation.app].get("user_credentials_secret")
        if not secret_id:
            return
        try:
            self.model.get_secret(id=secret_id).get_content(refresh=True)
        except (SecretNotFoundError, ModelError):
            logger.debug("Could not refresh secret %s", secret_id)

    def update_configuration(self) -> None:
        """Update configuration from relation data."""
        self._refresh_credentials_secret()
        data = self.wazuh_api.get_relation_data()
        if data:
            self.charm.wazuh_manager.set_dashboard_properties(data)


def _short_secret_id(secret_id: str | None) -> str:
    """Strip the `secret:` / `secret://<model-uuid>/` prefix to compare secret IDs."""
    return (secret_id or "").rsplit("/", 1)[-1].removeprefix("secret:")
