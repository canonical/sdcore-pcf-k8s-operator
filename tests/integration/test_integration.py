#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APPLICATION_NAME = METADATA["name"]
NRF_APP_NAME = "sdcore-nrf"
DATABASE_APP_NAME = "mongodb-k8s"
TLS_PROVIDER_NAME = "self-signed-certificates"


async def _deploy_database(ops_test: OpsTest):
    """Deploy a MongoDB."""
    await ops_test.model.deploy(  # type: ignore[union-attr]
        DATABASE_APP_NAME,
        application_name=DATABASE_APP_NAME,
        channel="5/edge",
        trust=True,
    )


async def _deploy_nrf(ops_test: OpsTest):
    """Deploy a NRF."""
    await ops_test.model.deploy(  # type: ignore[union-attr]
        NRF_APP_NAME,
        application_name=NRF_APP_NAME,
        channel="edge",
        trust=True,
    )


async def _deploy_tls_provider(ops_test: OpsTest):
    await ops_test.model.deploy(  # type: ignore[union-attr]
        TLS_PROVIDER_NAME,
        application_name=TLS_PROVIDER_NAME,
        channel="beta",
    )


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def build_and_deploy(ops_test: OpsTest):
    """Build the charm-under-test and deploy it."""
    charm = await ops_test.build_charm(".")
    resources = {
        "pcf-image": METADATA["resources"]["pcf-image"]["upstream-source"],
    }
    await ops_test.model.deploy(  # type: ignore[union-attr]
        charm,
        resources=resources,
        application_name=APPLICATION_NAME,
        trust=True,
    )
    await _deploy_database(ops_test)
    await _deploy_nrf(ops_test)
    await _deploy_tls_provider(ops_test)


@pytest.mark.abort_on_fail
async def test_given_charm_is_built_when_deployed_then_status_is_blocked(
    ops_test: OpsTest, build_and_deploy
):
    await ops_test.model.wait_for_idle(  # type: ignore[union-attr]
        apps=[APPLICATION_NAME],
        status="blocked",
        timeout=1000,
    )


@pytest.mark.abort_on_fail
async def test_relate_and_wait_for_active_status(ops_test: OpsTest, build_and_deploy):
    assert ops_test.model
    await ops_test.model.integrate(relation1=NRF_APP_NAME, relation2=DATABASE_APP_NAME)
    await ops_test.model.integrate(relation1=NRF_APP_NAME, relation2=TLS_PROVIDER_NAME)
    await ops_test.model.integrate(relation1=APPLICATION_NAME, relation2=DATABASE_APP_NAME)
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:fiveg_nrf", relation2=NRF_APP_NAME
    )
    await ops_test.model.integrate(relation1=APPLICATION_NAME, relation2=TLS_PROVIDER_NAME)

    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="active",
        timeout=1000,
    )


@pytest.mark.abort_on_fail
async def test_remove_nrf_and_wait_for_blocked_status(ops_test: OpsTest, build_and_deploy):
    await ops_test.model.remove_application(NRF_APP_NAME, block_until_done=True)  # type: ignore[union-attr]  # noqa: E501
    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)  # type: ignore[union-attr]  # noqa: E501


@pytest.mark.abort_on_fail
async def test_restore_nrf_and_wait_for_active_status(ops_test: OpsTest, build_and_deploy):
    assert ops_test.model
    await ops_test.model.deploy(
        NRF_APP_NAME,
        application_name=NRF_APP_NAME,
        channel="edge",
        trust=True,
    )
    await ops_test.model.integrate(
        relation1=f"{NRF_APP_NAME}:database", relation2=DATABASE_APP_NAME
    )
    await ops_test.model.integrate(relation1=NRF_APP_NAME, relation2=TLS_PROVIDER_NAME)
    await ops_test.model.integrate(relation1=APPLICATION_NAME, relation2=NRF_APP_NAME)
    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_remove_tls_and_wait_for_blocked_status(ops_test: OpsTest, build_and_deploy):
    assert ops_test.model
    await ops_test.model.remove_application(TLS_PROVIDER_NAME, block_until_done=True)
    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)


@pytest.mark.abort_on_fail
async def test_restore_tls_and_wait_for_active_status(ops_test: OpsTest, build_and_deploy):
    assert ops_test.model
    await ops_test.model.deploy(
        TLS_PROVIDER_NAME,
        application_name=TLS_PROVIDER_NAME,
        channel="beta",
        trust=True,
    )
    await ops_test.model.integrate(relation1=APPLICATION_NAME, relation2=TLS_PROVIDER_NAME)
    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)
