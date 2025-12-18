# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

data "juju_model" "wazuh_dashboard" {
  uuid = var.model_uuid
}

module "wazuh_dashboard" {
  source      = "../charm"
  app_name    = var.wazuh_dashboard.app_name
  channel     = var.wazuh_dashboard.channel
  config      = var.wazuh_dashboard.config
  constraints = var.wazuh_dashboard.constraints
  model_uuid  = data.juju_model.wazuh_dashboard.uuid
  revision    = var.wazuh_dashboard.revision
  base        = var.wazuh_dashboard.base
  units       = var.wazuh_dashboard.units
}

resource "juju_application" "grafana_agent" {
  name       = var.grafana_agent.app_name
  model_uuid = data.juju_model.wazuh_dashboard.uuid
  trust      = true

  charm {
    name     = "grafana-agent"
    channel  = var.grafana_agent.channel
    revision = var.grafana_agent.revision
    base     = var.wazuh_dashboard.base
  }
}

resource "juju_integration" "grafana_agent_dashboard" {
  model_uuid = data.juju_model.wazuh_dashboard.uuid

  application {
    name     = module.wazuh_dashboard.app_name
    endpoint = module.wazuh_dashboard.provides.cos_agent
  }

  application {
    name     = juju_application.grafana_agent.name
    endpoint = "cos-agent"
  }
}
