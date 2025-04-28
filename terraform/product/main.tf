# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

data "juju_model" "wazuh_dashboard" {
  name = var.dashboard_model
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

module "grafana_agent" {
  source     = "git::https://github.com/canonical/grafana-agent-operator//terraform?ref=rev469&depth=1"
  app_name   = var.wazuh_dashboard.app_name
  channel    = var.wazuh_dashboard.channel
  config     = var.wazuh_dashboard.config
  model_name = data.juju_model.wazuh_dashboard.name
  revision   = var.wazuh_dashboard.revision
  units      = 0
}

resource "juju_integration" "grafana_agent_dashboard" {
  model = juju_model.wazuh_dashboard.name

  application {
    name     = module.wazuh_dashboard.app_name
    endpoint = wazuh_dashboard.provides.cos_agent
  }

  application {
    name     = module.grafana_agent.app_name
    endpoint = "cos-agent"
  }
}
