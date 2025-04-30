# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed Wazuh dashboard application."
  value       = module.wazuh_dashboard.app_name
}

output "grafana_agent_app_name" {
  description = "Name of the deployed Grafana agent application."
  value       = juju_application.grafana_agent.name
}

output "grafana_agent_requires" {
  value = {
    logging_consumer  = "logging-consumer"
    send_remote_write = "send-remote-write"
  }
}

output "grafana_agent_provides" {
  value = {
    grafana_dashboards_provider = "grafana-dashboards-provider"
  }
}

output "wazuh_dashboard_requires" {
  value = {
    certificates      = "certificates"
    opensearch_client = "opensearch-client"
    wazuh_api         = "wazuh-api"
  }
}
