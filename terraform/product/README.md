<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.6.6 |
| <a name="requirement_juju"></a> [juju](#requirement\_juju) | ~> 1.1.1 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_juju"></a> [juju](#provider\_juju) | ~> 1.1.1 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_wazuh_dashboard"></a> [wazuh\_dashboard](#module\_wazuh\_dashboard) | ../charm | n/a |

## Resources

| Name | Type |
|------|------|
| [juju_application.grafana_agent](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/application) | resource |
| [juju_integration.grafana_agent_dashboard](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | resource |
| [juju_model.wazuh_dashboard](https://registry.terraform.io/providers/juju/juju/latest/docs/data-sources/model) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_grafana_agent"></a> [grafana\_agent](#input\_grafana\_agent) | n/a | <pre>object({<br/>    app_name = optional(string, "grafana-agent")<br/>    channel  = optional(string, "latest/stable")<br/>    config   = optional(map(string), {})<br/>    revision = optional(number)<br/>  })</pre> | n/a | yes |
| <a name="input_model_uuid"></a> [model\_uuid](#input\_model\_uuid) | Reference to the VM Juju model to deploy the dashboard charms to. | `string` | n/a | yes |
| <a name="input_wazuh_dashboard"></a> [wazuh\_dashboard](#input\_wazuh\_dashboard) | n/a | <pre>object({<br/>    app_name    = optional(string, "wazuh-dashboard")<br/>    channel     = optional(string, "4.11/edge")<br/>    config      = optional(map(string), {})<br/>    constraints = optional(string, "arch=amd64")<br/>    revision    = optional(number)<br/>    base        = optional(string, "ubuntu@22.04")<br/>    units       = optional(number, 3)<br/>  })</pre> | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_app_name"></a> [app\_name](#output\_app\_name) | Name of the deployed Wazuh dashboard application. |
| <a name="output_grafana_agent_app_name"></a> [grafana\_agent\_app\_name](#output\_grafana\_agent\_app\_name) | Name of the deployed Grafana agent application. |
| <a name="output_grafana_agent_provides"></a> [grafana\_agent\_provides](#output\_grafana\_agent\_provides) | n/a |
| <a name="output_grafana_agent_requires"></a> [grafana\_agent\_requires](#output\_grafana\_agent\_requires) | n/a |
| <a name="output_wazuh_dashboard_requires"></a> [wazuh\_dashboard\_requires](#output\_wazuh\_dashboard\_requires) | n/a |
<!-- END_TF_DOCS -->