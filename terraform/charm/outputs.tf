# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.wazuh_dashboard.name
}

output "requires" {
  value = {
    certificates      = "certificates"
    opensearch_client = "opensearch-client"
    wazuh_api         = "wazuh-api"
  }
}

output "provides" {
  value = {
    cos_agent = "cos-agent"
  }
}
