# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.pcf.name
}

# Required integration endpoints

output "fiveg_nrf_endpoint" {
  description = "Name of the endpoint used to integrate with the NRF."
  value       = "fiveg_nrf"
}

output "certificates_endpoint" {
  description = "Name of the endpoint used to integrate with the TLS certificates provider."
  value       = "certificates"
}

output "logging_endpoint" {
  description = "Name of the endpoint used to integrate with the Logging provider."
  value       = "logging"
}

output "sdcore_config_endpoint" {
  description = "Name of the endpoint used to integrate with the NMS."
  value       = "sdcore-config"
}

# Provided integration endpoints

output "metrics_endpoint" {
  description = "Exposes the Prometheus metrics endpoint providing telemetry about the PCF instance."
  value       = "metrics-endpoint"
}