# SD-Core PCF Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-pcf/badge.svg)](https://charmhub.io/sdcore-pcf)

A Charmed Operator for SD-Core's Policy Control Function (PCF) component. 

## Usage

```bash
juju deploy mongodb-k8s --channel 5/edge --trust
juju deploy sdcore-nrf --channel edge
juju deploy sdcore-pcf --channel edge 
juju deploy self-signed-certificates --channel=beta

juju integrate sdcore-pcf mongodb-k8s
juju integrate sdcore-nrf self-signed-certificates
juju integrate sdcore-pcf:fiveg_nrf sdcore-nrf
juju integrate sdcore-pcf:certificates self-signed-certificates:certificates
```

## Image

**pcf**: `ghcr.io/canonical/sdcore-pcf:1.3`
