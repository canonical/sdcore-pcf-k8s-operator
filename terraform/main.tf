resource "juju_application" "pcf" {
  name  = "pcf"
  model = var.model_name

  charm {
    name    = "sdcore-pcf-k8s"
    channel = var.channel
  }

  units = 1
  trust = true
}

resource "juju_integration" "pcf-db" {
  model = var.model_name

  application {
    name     = juju_application.pcf.name
    endpoint = "database"
  }

  application {
    name     = var.db_application_name
    endpoint = "database"
  }
}

resource "juju_integration" "pcf-certs" {
  model = var.model_name

  application {
    name     = juju_application.pcf.name
    endpoint = "certificates"
  }

  application {
    name     = var.certs_application_name
    endpoint = "certificates"
  }
}

resource "juju_integration" "pcf-nrf" {
  model = var.model_name

  application {
    name     = juju_application.pcf.name
    endpoint = "fiveg_nrf"
  }

  application {
    name     = var.nrf_application_name
    endpoint = "fiveg-nrf"
  }
}

