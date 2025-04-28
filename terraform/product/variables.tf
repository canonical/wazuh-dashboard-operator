# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

variable "dashboard_model" {
  description = "Reference to the VM Juju model to deploy the dashboard charms to."
  type        = string
}

variable "grafana_agent" {
  type = object({
    app_name    = optional(string, "grafana-agent")
    channel     = optional(string, "4.9/edge")
    config      = optional(map(string), {})
    constraints = optional(string, "arch=amd64")
    revision    = optional(number)
    base        = optional(string, "ubuntu@22.04")
  })
}

name  = "grafana-agent"
model = juju_model.wazuh_dashboard.name
units = 0

charm {
  name     = "grafana-agent"
  revision = 457
  channel  = "latest/stable"
  base     = "ubuntu@22.04"
}

variable "wazuh_dashboard" {
  type = object({
    app_name    = optional(string, "wazuh-dashboard")
    channel     = optional(string, "4.9/edge")
    config      = optional(map(string), {})
    constraints = optional(string, "arch=amd64")
    revision    = optional(number)
    base        = optional(string, "ubuntu@22.04")
    units       = optional(number, 3)
  })
}
