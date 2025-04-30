# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

data "juju_model" "wazuh_dashboard" {
  name = var.model
}

module "wazuh_dashboard" {
  source      = "../charm"
  app_name    = var.wazuh_dashboard.app_name
  channel     = var.wazuh_dashboard.channel
  config      = var.wazuh_dashboard.config
  constraints = var.wazuh_dashboard.constraints
  model       = data.juju_model.wazuh_dashboard.name
  revision    = var.wazuh_dashboard.revision
  base        = var.wazuh_dashboard.base
  units       = var.wazuh_dashboard.units
}

resource "juju_application" "grafana_agent" {
  name  = var.grafana_agent.app_name
  model = data.juju_model.wazuh_dashboard.name
  trust = true

  charm {
    name     = "grafana-agent"
    channel  = var.grafana_agent.channel
    revision = var.grafana_agent.revision
    base     = var.wazuh_dashboard.base
  }
}

resource "juju_integration" "grafana_agent_dashboard" {
  model = data.juju_model.wazuh_dashboard.name

  application {
    name     = module.wazuh_dashboard.app_name
    endpoint = module.wazuh_dashboard.provides.cos_agent
  }

  application {
    name     = juju_application.grafana_agent.name
    endpoint = "cos-agent"
  }
}
