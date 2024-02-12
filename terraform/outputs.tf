# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "pcf_application_name" {
  description = "Name of the deployed application."
  value       = juju_application.pcf.name
}

# Required integration endpoints

output "fiveg_nrf_endpoint" {
  description = "Name of the endpoint used to integrate with the NRF."
  value = "fiveg-nrf"
}

output "database_endpoint" {
  description = "Name of the endpoint used to integrate with the database."
  value = "database"
}

output "certificates_endpoint" {
  description = "Name of the endpoint used to integrate with the TLS certificates provider."
  value = "certificates"
}
