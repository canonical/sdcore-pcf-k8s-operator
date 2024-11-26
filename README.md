# Aether SD-Core PCF Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-pcf-k8s/badge.svg)](https://charmhub.io/sdcore-pcf-k8s)

A Charmed Operator for Aether SD-Core's Policy Control Function (PCF) component for K8s. 

## Usage

```bash
juju deploy mongodb-k8s --channel=6/stable --trust
juju deploy sdcore-nrf-k8s --channel=1.6/edge
juju deploy sdcore-pcf-k8s --channel=1.6/edge 
juju deploy sdcore-nms-k8s --channel=1.6/edge
juju deploy self-signed-certificates --channel=stable

juju integrate sdcore-nms-k8s:common_database mongodb-k8s:database
juju integrate sdcore-nms-k8s:auth_database mongodb-k8s:database
juju integrate sdcore-nms-k8s:certificates self-signed-certificates:certificates
juju integrate sdcore-nrf-k8s self-signed-certificates:certificates
juju integrate sdcore-nrf-k8s:database mongodb-k8s
juju integrate sdcore-pcf-k8s:fiveg_nrf sdcore-nrf-k8s:fiveg_nrf
juju integrate sdcore-pcf-k8s:certificates self-signed-certificates:certificates
juju integrate sdcore-pcf-k8s:sdcore_config sdcore-nms-k8s:sdcore_config
```

## Image

**pcf**: `ghcr.io/canonical/sdcore-pcf:1.5.2`

