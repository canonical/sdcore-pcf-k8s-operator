# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import tempfile

from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.pebble import Layer, ServiceStatus

from tests.unit.certificates_helpers import example_cert_and_key
from tests.unit.fixtures import PCFUnitTestFixtures


class TestCharmCollectStatus(PCFUnitTestFixtures):
    def test_given_not_leader_when_collect_unit_status_then_status_is_blocked(self):
        state_in = testing.State(
            leader=False,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("Scaling is not implemented for this charm")

    def test_given_container_not_ready_when_collect_unit_status_then_status_is_waiting(self):
        container = testing.Container(
            name="pcf",
        )
        state_in = testing.State(
            containers=[container],
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for container to be ready")


    def test_given_invalid_log_level_config_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        container = testing.Container(name="pcf", can_connect=True)
        state_in = testing.State(
            leader=True,
            config={"log-level": "invalid"},
            containers={container},
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "The following configurations are not valid: ['log-level']"
        )

    def test_given_relations_not_created_when_collect_unit_status_then_status_is_blocked(self):
        container = testing.Container(
            name="pcf",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Waiting for fiveg_nrf, certificates, sdcore_config relation(s)"
        )

    def test_given_nms_relation_not_created_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        container = testing.Container(
            name="pcf",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
            relations=[certificates_relation],
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Waiting for fiveg_nrf, sdcore_config relation(s)"
        )

    def test_given_nrf_data_not_available_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        nms_relation = testing.Relation(
            endpoint="sdcore_config",
            interface="sdcore_config",
        )
        nrf_relation = testing.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg_nrf",
        )
        container = testing.Container(
            name="pcf",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
            relations=[certificates_relation, nms_relation, nrf_relation],
            leader=True,
        )
        self.mock_nrf_url.return_value = None
        self.mock_sdcore_config_webui_url.return_value = None

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for NRF endpoint to be available")

    def test_given_webui_data_not_available_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        nms_relation = testing.Relation(
            endpoint="sdcore_config",
            interface="sdcore_config",
        )
        nrf_relation = testing.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg_nrf",
        )
        container = testing.Container(
            name="pcf",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
            relations=[certificates_relation, nms_relation, nrf_relation],
            leader=True,
        )
        self.mock_nrf_url.return_value = "https://nrf.url"
        self.mock_sdcore_config_webui_url.return_value = None

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for Webui URL to be available")

    def test_given_storage_not_attached_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        nrf_relation = testing.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg_nrf",
        )
        nms_relation = testing.Relation(
            endpoint="sdcore_config",
            interface="sdcore_config",
        )
        container = testing.Container(
            name="pcf",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
            relations=[certificates_relation, nrf_relation, nms_relation],
            leader=True,
        )
        self.mock_nrf_url.return_value = "https://nrf.url"
        self.mock_sdcore_config_webui_url.return_value = "http://webui.url"

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for the storage to be attached")

    def test_given_pod_address_unavailable_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = testing.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = testing.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            config_mount = testing.Mount(
                location="/sdcore/config/",
                source=temp_dir,
            )
            certs_mount = testing.Mount(
                location="/sdcore/certs/",
                source=temp_dir,
            )
            container = testing.Container(
                name="pcf",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = testing.State(
                containers=[container],
                relations=[certificates_relation, nrf_relation, nms_relation],
                leader=True,
            )
            self.mock_nrf_url.return_value = "https://nrf.url"
            self.mock_sdcore_config_webui_url.return_value = "http://webui.url"
            self.mock_check_output.return_value = b""

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.unit_status == WaitingStatus(
                "Waiting for pod IP address to be available"
            )

    def test_given_certificate_not_stored_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = testing.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = testing.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            config_mount = testing.Mount(
                location="/sdcore/config/",
                source=temp_dir,
            )
            certs_mount = testing.Mount(
                location="/sdcore/certs/",
                source=temp_dir,
            )
            container = testing.Container(
                name="pcf",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = testing.State(
                containers=[container],
                relations=[certificates_relation, nrf_relation, nms_relation],
                leader=True,
            )
            self.mock_nrf_url.return_value = "https://nrf.url"
            self.mock_sdcore_config_webui_url.return_value = "http://webui.url"
            self.mock_check_output.return_value = b"1.2.3.4"
            self.mock_get_assigned_certificate.return_value = (None, None)
            with open(f"{temp_dir}/pcf.csr", "w") as f:
                f.write("whatever csr")

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.unit_status == WaitingStatus(
                "Waiting for certificates to be available"
            )

    def test_given_service_not_running_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = testing.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = testing.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            config_mount = testing.Mount(
                location="/sdcore/config/",
                source=temp_dir,
            )
            certs_mount = testing.Mount(
                location="/sdcore/certs/",
                source=temp_dir,
            )
            container = testing.Container(
                name="pcf",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = testing.State(
                containers=[container],
                relations=[certificates_relation, nrf_relation, nms_relation],
                leader=True,
            )
            self.mock_nrf_url.return_value = "https://nrf.url"
            self.mock_sdcore_config_webui_url.return_value = "http://webui.url"
            self.mock_check_output.return_value = b"1.2.3.4"
            provider_certificate, private_key = example_cert_and_key(
                relation_id=certificates_relation.id
            )
            self.mock_get_assigned_certificate.return_value = (provider_certificate, private_key)
            with open(f"{temp_dir}/pcf.csr", "w") as f:
                f.write("whatever csr")

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.unit_status == WaitingStatus("Waiting for PCF service to start")

    def test_given_pebble_service_running_when_collect_unit_status_then_status_is_active(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = testing.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = testing.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            config_mount = testing.Mount(
                location="/sdcore/config/",
                source=temp_dir,
            )
            certs_mount = testing.Mount(
                location="/sdcore/certs/",
                source=temp_dir,
            )
            container = testing.Container(
                name="pcf",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
                layers={"pcf": Layer({"services": {"pcf": {}}})},
                service_statuses={"pcf": ServiceStatus.ACTIVE},
            )
            state_in = testing.State(
                containers=[container],
                relations=[certificates_relation, nrf_relation, nms_relation],
                leader=True,
            )
            self.mock_nrf_url.return_value = "https://nrf.url"
            self.mock_sdcore_config_webui_url.return_value = "http://webui.url"
            self.mock_check_output.return_value = b"1.2.3.4"
            provider_certificate, private_key = example_cert_and_key(
                relation_id=certificates_relation.id
            )
            self.mock_get_assigned_certificate.return_value = (provider_certificate, private_key)
            with open(f"{temp_dir}/pcf.csr", "w") as f:
                f.write("whatever csr")

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.unit_status == ActiveStatus()

    def test_given_no_workload_version_file_when_collect_unit_status_then_workload_version_not_set(
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
            nrf_relation = testing.Relation(endpoint="fiveg_nrf", interface="fiveg_nrf")
            certificates_relation = testing.Relation(
                endpoint="certificates", interface="tls-certificates"
            )
            sdcore_config_relation = testing.Relation(
                endpoint="sdcore_config", interface="sdcore_config"
            )
            workload_version_mount = testing.Mount(
                location="/etc",
                source=tempdir,
            )
            container = testing.Container(
                name="pcf", can_connect=True, mounts={"workload-version": workload_version_mount}
            )
            state_in = testing.State(
                leader=True,
                containers=[container],
                relations=[nrf_relation, certificates_relation, sdcore_config_relation],
            )

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.workload_version == ""

    def test_given_workload_version_file_when_collect_unit_status_then_workload_version_set(
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
            nrf_relation = testing.Relation(endpoint="fiveg_nrf", interface="fiveg_nrf")
            certificates_relation = testing.Relation(
                endpoint="certificates", interface="tls-certificates"
            )
            sdcore_config_relation = testing.Relation(
                endpoint="sdcore_config", interface="sdcore_config"
            )
            workload_version_mount = testing.Mount(
                location="/etc",
                source=tempdir,
            )
            expected_version = "1.2.3"
            with open(f"{tempdir}/workload-version", "w") as f:
                f.write(expected_version)
            container = testing.Container(
                name="pcf", can_connect=True, mounts={"workload-version": workload_version_mount}
            )
            state_in = testing.State(
                leader=True,
                containers=[container],
                relations=[nrf_relation, certificates_relation, sdcore_config_relation],
            )

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.workload_version == expected_version
