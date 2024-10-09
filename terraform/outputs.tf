# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.pcf.name
}

output "requires" {
  value = {
    fiveg_nrf     = "fiveg_nrf"
    certificates  = "certificates"
    logging       = "logging"
    sdcore_config = "sdcore_config"
  }
}

output "provides" {
  value = {
    metrics = "metrics-endpoint"
  }
}
