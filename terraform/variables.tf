# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

variable "app_name" {
  description = "Application name"
  type        = string
  default     = "opensearch-dashboards"
}

variable "channel" {
  description = "Charm channel"
  type        = string
  default     = null
}

variable "base" {
  description = "Charm base (old name: series)"
  type        = string
  default     = "ubuntu@22.04"
}

variable "config" {
  description = "Map of charm configuration options"
  type        = map(string)
  default     = {}
}

variable "model" {
  description = "Model name"
  type        = string
}

variable "revision" {
  description = "Charm revision"
  type        = number
  default     = null
}

variable "units" {
  description = "Charm units"
  type        = number
  default     = 1
}

variable "constraints" {
  description = "String listing constraints for this application"
  type        = string
  default     = "arch=amd64"
}

variable "machines" {
  description = "List of machines for placement"
  type        = list(string)
  default     = []
}

variable "endpoint_bindings" {
  description = "Map of endpoint bindings"
  type        = map(string)
  default     = {}
}

# additional variables
variable "tls" {
  description = "Whether TLS should be enabled"
  type        = bool
  default     = false
}

variable "self-signed-certificates" {
  description = "Configuration for the self-signed-certificates app"
  type = object({
    channel       = optional(string, "latest/stable")
    revision      = optional(string, null)
    base          = optional(string, "ubuntu@22.04")
    config        = optional(map(string), { "ca-common-name": "CA" })
  })
  default = {
    channel  = "latest/stable"
    revision = null
    base     = "ubuntu@22.04"
    config   = { "ca-common-name" = "CA" }
  }
}
