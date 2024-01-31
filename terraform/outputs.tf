output "pcf_application_name" {
  description = "Name of the deployed application."
  value       = juju_application.pcf.name
}