# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.opensearch-dashboards.name
}

# Required integration endpoints

output "certificates_endpoint" {
  description = "Name of the endpoint used to integrate with the TLS certificates provider."
  value       = "certificates"
}

output "opensearch_client_endpoint" {
  description = "Name of the endpoint opensearch-client endpoint."
  value       = "opensearch-client"
}

# Provided integration endpoints

output "cos_agent_endpoint" {
  description = "Name of the endpoint used to provide COS agent integration."
  value       = "cos-agent-endpoint"
}
