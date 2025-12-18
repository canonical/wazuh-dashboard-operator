# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_application" "wazuh_dashboard" {
  model = var.model_uuid

  charm {
    name     = "wazuh-dashboard"
    channel  = var.channel
    revision = var.revision
    base     = var.base
  }

  config      = var.config
  constraints = var.constraints
  units       = var.units

  expose {}
}
