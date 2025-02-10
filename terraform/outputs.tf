# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.opensearch-dashboards.name
}

# integration endpoints
output "requires" {
  description = "Map of all \"requires\" endpoints"
  value = {
    opensearch_client = "opensearch-client"
    certificates      = "certificates"
  }
}

output "provides" {
  description = "Map of all \"provides\" endpoints"
  value = {
    cos_agent = "cos-agent"
  }
}
