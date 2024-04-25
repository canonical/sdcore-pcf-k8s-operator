# SD-Core PCF Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-pcf-k8s/badge.svg)](https://charmhub.io/sdcore-pcf-k8s)

A Charmed Operator for SD-Core's Policy Control Function (PCF) component for K8s. 

## Usage

```bash
juju deploy mongodb-k8s --channel=6/beta --trust
juju deploy sdcore-nrf-k8s --channel=1.4/edge
juju deploy sdcore-pcf-k8s --channel=1.4/edge 

juju deploy self-signed-certificates

juju integrate sdcore-pcf-k8s mongodb-k8s
juju integrate sdcore-nrf-k8s self-signed-certificates
juju integrate sdcore-pcf-k8s:fiveg_nrf sdcore-nrf-k8s:fiveg_nrf
juju integrate sdcore-pcf-k8s:certificates self-signed-certificates:certificates
```

## Image

**pcf**: `ghcr.io/canonical/sdcore-pcf:1.4.0`

