variable "model_name" {
  description = "Model name"
  type        = string
}

variable "app_name" {
  description = "OpenSearch app name"
  type        = string
  default     = "opensearch-dashboards"
}

variable "simple_opensearch_units" {
  description = "Node count"
  type        = number
  default     = 2
}

variable "simple_opensearch_dashboards_units" {
  description = "OpenSearch dashboards node count"
  type        = number
  default     = 1
}
