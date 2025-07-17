# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

variable "model" {
  description = "Reference to the VM Juju model to deploy the dashboard charms to."
  type        = string
}

variable "grafana_agent" {
  type = object({
    app_name = optional(string, "grafana-agent")
    channel  = optional(string, "latest/stable")
    config   = optional(map(string), {})
    revision = optional(number)
  })
}

variable "wazuh_dashboard" {
  type = object({
    app_name    = optional(string, "wazuh-dashboard")
    channel     = optional(string, "4.11/edge")
    config      = optional(map(string), {})
    constraints = optional(string, "arch=amd64")
    revision    = optional(number)
    base        = optional(string, "ubuntu@22.04")
    units       = optional(number, 3)
  })
}
