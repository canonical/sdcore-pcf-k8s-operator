import tempfile

import pytest
import scenario
from charm import PCFOperatorCharm
from interface_tester import InterfaceTester
from ops.pebble import Layer, ServiceStatus


@pytest.fixture
def interface_tester(interface_tester: InterfaceTester):
    with tempfile.TemporaryDirectory() as tempdir:
        config_mount = scenario.Mount(
            location="/etc/pcf/",
            src=tempdir,
        )
        certs_mount = scenario.Mount(
            location="/support/TLS/",
            src=tempdir,
        )
        container = scenario.Container(
            name="pcf",
            can_connect=True,
            layers={"pcf": Layer({"services": {"pcf": {}}})},
            service_status={
                "pcf": ServiceStatus.ACTIVE,
            },
            mounts={
                "config": config_mount,
                "certs": certs_mount,
            },
        )
        interface_tester.configure(
            charm_type=PCFOperatorCharm,
            state_template=scenario.State(
                leader=True,
                containers=[container],
            ),
        )
        yield interface_tester
