<div align="center">
  <img src="./icon.svg" alt="ONF Icon" width="200" height="200">
</div>
<br/>
<div align="center">
  <a href="https://charmhub.io/sdcore-pcf"><img src="https://charmhub.io/sdcore-pcf/badge.svg" alt="CharmHub Badge"></a>
  <a href="https://github.com/canonical/sdcore-pcf-operator/actions/workflows/publish-charm.yaml">
    <img src="https://github.com/canonical/sdcore-pcf-operator/actions/workflows/publish-charm.yaml/badge.svg?branch=main" alt=".github/workflows/publish-charm.yaml">
  </a>
  <br/>
  <br/>
  <h1>SD-Core PCF Operator</h1>
</div>

A Charmed Operator for SD-Core's Policy Control Function (PCF) component. 

## Usage

```bash
juju deploy mongodb-k8s --channel 6/edge --trust
juju deploy sdcore-nrf --channel edge --trust
juju deploy sdcore-pcf --channel edge --trust 
juju deploy self-signed-certificates --channel=beta

juju integrate sdcore-pcf mongodb-k8s
juju integrate sdcore-nrf self-signed-certificates
juju integrate sdcore-pcf:fiveg_nrf sdcore-nrf
juju integrate sdcore-pcf:certificates self-signed-certificates:certificates
```

## Image

**pcf**: `ghcr.io/canonical/sdcore-pcf:1.3`
