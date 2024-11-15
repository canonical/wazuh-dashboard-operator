module "opensearch-dashboards" {
  source     = "../"
  app_name   = var.app_name
  model = var.model_name
  units      = var.simple_opensearch_dashboards_units

  channel = "2/edge"

  depends_on = [juju_application.self-signed-certificates]
}

module "opensearch" {
  source     = "git::https://github.com/canonical/opensearch-operator//terraform?ref=DPE-5866-terraform"
  app_name   = "opensearch"
  model = var.model_name
  units      = var.simple_opensearch_units
  config = {
    profile = "testing"
  }

  channel = "2/edge"

  depends_on = [juju_application.self-signed-certificates]
}

resource "juju_integration" "dashboards_opensearch-integration" {
  model = var.model_name

  application {
    name = module.opensearch-dashboards.app_name
    endpoint = module.opensearch-dashboards.opensearch_client_endpoint
  }
  application {
    name = module.opensearch.app_name
    endpoint = module.opensearch.opensearch_client_endpoint
  }
  depends_on = [
    module.opensearch-dashboards,
    module.opensearch
  ]

}

resource "juju_integration" "simple_deployment_tls-operator_opensearch-dashboards-integration" {
  model = var.model_name

  application {
    name = juju_application.self-signed-certificates.name
  }
  application {
    name = module.opensearch.app_name
  }
  depends_on = [
    juju_application.self-signed-certificates,
    module.opensearch
  ]

}


resource "juju_integration" "simple_deployment_tls-operator_opensearch-integration" {
  model = var.model_name

  application {
    name = juju_application.self-signed-certificates.name
  }
  application {
    name = module.opensearch.app_name
  }
  depends_on = [
    juju_application.self-signed-certificates,
    module.opensearch
  ]

}

resource "null_resource" "simple_deployment_juju_wait_deployment" {
  provisioner "local-exec" {
    command = <<-EOT
    juju-wait -v --model ${var.model_name}
    EOT
  }

  depends_on = [
    juju_integration.simple_deployment_tls-operator_opensearch-integration,
    juju_integration.dashboards_opensearch-integration,
    juju_integration.simple_deployment_tls-operator_opensearch-dashboards-integration,
  ]
}
