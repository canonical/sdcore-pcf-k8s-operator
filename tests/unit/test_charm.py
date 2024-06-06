# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from unittest.mock import Mock

import pytest
from charm import (
    CONFIG_FILE_NAME,
    TLS_RELATION_NAME,
)
from charms.tls_certificates_interface.v3.tls_certificates import (  # type: ignore[import]
    ProviderCertificate,
)
from fixtures import PCFUnitTestFixtures
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

logger = logging.getLogger(__name__)

CERTIFICATE = "whatever certificate content"
CERTIFICATES_LIB = (
    "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3"
)
CERTIFICATE_PATH = "support/TLS/pcf.pem"
CSR = "whatever CSR content"
CSR_PATH = "support/TLS/pcf.csr"
EXPECTED_CONFIG_FILE_PATH = "tests/unit/expected_pcfcfg.yaml"
POD_IP = b"1.1.1.1"
PRIVATE_KEY = "whatever key content"
PRIVATE_KEY_PATH = "support/TLS/pcf.key"
VALID_NRF_URL = "https://nrf:443"
WEBUI_URL = "sdcore-webui:9876"
SDCORE_CONFIG_RELATION_NAME = "sdcore_config"
WEBUI_APPLICATION_NAME = "sdcore-webui-operator"


class TestCharm(PCFUnitTestFixtures):

    @staticmethod
    def _read_file(path: str) -> str:
        """Read a file and return its content as a string."""
        with open(path, "r") as f:
            content = f.read()
        return content

    def _create_certificates_relation(self):
        relation_id = self.harness.add_relation(  # type:ignore
            relation_name=TLS_RELATION_NAME, remote_app="tls-certificates-operator"
        )
        self.harness.add_relation_unit(  # type:ignore
            relation_id=relation_id, remote_unit_name="tls-certificates-operator/0"
        )

    def test_given_container_cant_connect_when_collect_status_pcf_then_status_is_waiting(self):
        self.harness.set_can_connect(container=self.container_name, val=False)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for container to be ready")

    def test_given_container_can_connect_and_fiveg_nrf_relation_is_not_created_when_collect_status_then_status_is_blocked(  # noqa: E501
        self, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_certificates_relation()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus("Waiting for fiveg_nrf relation(s)")

    def test_given_container_can_connect_and_certificates_relation_is_not_created_when_collect_status_then_status_is_blocked(  # noqa: E501
        self, nrf_relation_id, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for certificates relation(s)"
        )

    def test_given_container_can_connect_and_sdcore_config_relation_is_not_created_when_collect_status_then_status_is_blocked(  # noqa: E501
        self, nrf_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_certificates_relation()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for sdcore_config relation(s)"
        )

    def test_given_pcf_charm_in_active_state_when_nrf_relation_breaks_then_status_is_blocked(
        self, add_storage, mock_default_values, nrf_relation_id, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.remove_relation(nrf_relation_id)
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for fiveg_nrf relation(s)"
        )

    def test_given_pcf_charm_in_active_state_when_sdcore_config_relation_breaks_then_status_is_blocked(  # noqa: E501
        self, add_storage, mock_default_values, nrf_relation_id, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.remove_relation(sdcore_config_relation_id)
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for sdcore_config relation(s)"
        )

    def test_given_container_can_connect_and_fiveg_nrf_relation_is_not_available_when_collect_status_then_status_is_waiting(  # noqa: E501
        self, add_storage, mock_default_values, nrf_relation_id, sdcore_config_relation_id
    ):
        self._create_certificates_relation()
        self.mock_nrf_url.return_value = None
        self.harness.container_pebble_ready(self.container_name)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for NRF endpoint to be available")  # noqa: E501

    def test_given_container_can_connect_and_webui_url_is_not_available_when_collect_status_then_status_is_waiting(  # noqa: E501
        self, add_storage, mock_default_values, nrf_relation_id, sdcore_config_relation_id
    ):
        self._create_certificates_relation()
        self.mock_webui_url.return_value = ""
        self.harness.container_pebble_ready(self.container_name)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for Webui URL to be available")  # noqa: E501

    @pytest.mark.parametrize(
        "storage_name",
        [
            "certs",
            "config",
        ]
    )
    def test_given_container_storage_is_not_attached_when_collect_status_then_status_is_waiting(  # noqa: E501
        self, storage_name, nrf_relation_id, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name=storage_name, attach=True)
        self._create_certificates_relation()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for the storage to be attached")  # noqa: E501

    def test_given_certificate_is_not_stored_when_collect_status_then_status_is_waiting(  # noqa: E501
        self, add_storage, mock_default_values, nrf_relation_id, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_certificates_relation()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for certificates to be stored")  # noqa: E501

    def test_given_config_file_is_written_when_collect_status_is_called_then_status_is_active(  # noqa: E501
        self,
        add_storage,
        get_default_certificate,
        mock_default_values,
        nrf_relation_id,
        sdcore_config_relation_id,
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        (root / CSR_PATH).write_text(CSR)
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == ActiveStatus()

    def test_given_ip_not_available_when_collect_status_then_status_is_waiting(
        self, add_storage, nrf_relation_id, sdcore_config_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        self.mock_check_output.return_value = "".encode()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for pod IP address to be available")  # noqa: E501

    def test_given_not_leader_when_collect_status_then_status_is_blocked(self):
        self.harness.set_leader(is_leader=False)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Scaling is not implemented for this charm"
        )

    def test_given_config_file_is_not_written_when_configure_sdcore_pcf_is_called_then_config_file_is_written_with_expected_content(  # noqa: E501
        self,
        add_storage,
        get_default_certificate,
        mock_default_values,
        nrf_relation_id,
        sdcore_config_relation_id,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        (root / CSR_PATH).write_text(CSR)
        self._create_certificates_relation()
        self.harness.charm._configure_sdcore_pcf(event=Mock())

        expected_config_file_content = self._read_file(EXPECTED_CONFIG_FILE_PATH).strip()
        assert (root / f"etc/pcf/{CONFIG_FILE_NAME}").read_text() == expected_config_file_content

    def test_given_config_file_is_written_and_is_not_changed_when_configure_sdcore_pcf_is_called_then_config_file_is_not_written(  # noqa: E501
        self, add_storage, mock_default_values, nrf_relation_id, sdcore_config_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        (root / f"etc/pcf/{CONFIG_FILE_NAME}").write_text(
            self._read_file(EXPECTED_CONFIG_FILE_PATH).strip()
        )
        config_modification_time = (root / f"etc/pcf/{CONFIG_FILE_NAME}").stat().st_mtime
        self._create_certificates_relation()
        self.harness.charm._certificate_is_stored = Mock(return_value=True)

        self.harness.container_pebble_ready(self.container_name)

        assert (root / f"etc/pcf/{CONFIG_FILE_NAME}").stat().st_mtime == config_modification_time

    def test_given_config_file_exists_and_webui_url_is_changed_when_configure_pcf_then_config_file_is_updated(  # noqa: E501
        self,
        add_storage,
        get_default_certificate,
        mock_default_values,
        nrf_relation_id,
        sdcore_config_relation_id,
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CSR_PATH).write_text(CSR)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        (root / f"etc/pcf/{CONFIG_FILE_NAME}").write_text("super different config file content")
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)

        expected_content = self._read_file(EXPECTED_CONFIG_FILE_PATH)
        assert (root / f"etc/pcf/{CONFIG_FILE_NAME}").read_text() == expected_content.strip()


    def test_given_config_files_and_relations_are_created_when_configure_sdcore_pcf_is_called_then_expected_plan_is_applied(  # noqa: E501
        self,
        add_storage,
        get_default_certificate,
        mock_default_values,
        nrf_relation_id,
        sdcore_config_relation_id,
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        (root / CSR_PATH).write_text(CSR)
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)

        expected_plan = {
            "services": {
                "pcf": {
                    "override": "replace",
                    "startup": "enabled",
                    "command": "/bin/pcf --pcfcfg /etc/pcf/pcfcfg.yaml",
                    "environment": {
                        "GRPC_GO_LOG_VERBOSITY_LEVEL": "99",
                        "GRPC_GO_LOG_SEVERITY_LEVEL": "info",
                        "GRPC_TRACE": "all",
                        "GRPC_VERBOSITY": "debug",
                        "POD_IP": POD_IP.decode(),
                        "MANAGED_BY_CONFIG_POD": "true",
                    },
                }
            },
        }
        updated_plan = self.harness.get_container_pebble_plan(self.container_name).to_dict()
        assert expected_plan == updated_plan

    def test_given_can_connect_when_on_certificates_relation_created_then_private_key_is_generated(
        self, add_storage, mock_default_values, nrf_relation_id, sdcore_config_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.mock_generate_private_key.return_value = PRIVATE_KEY.encode()
        self.mock_generate_csr.return_value = CSR.encode()
        self._create_certificates_relation()
        assert (root / PRIVATE_KEY_PATH).read_text() == PRIVATE_KEY

    def test_given_certificates_are_stored_when_on_certificates_relation_broken_then_certificates_are_removed(  # noqa: E501
        self, add_storage
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        (root / CSR_PATH).write_text(CSR)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)

        self.harness.charm._on_certificates_relation_broken(event=Mock)

        with pytest.raises(FileNotFoundError):
            (root / CERTIFICATE_PATH).read_text()
            (root / PRIVATE_KEY_PATH).read_text()
            (root / CSR_PATH).read_text()

    def test_given_cannot_connect_when_on_certificates_relation_broken_then_certificates_are_not_removed(  # noqa: E501
        self, add_storage
    ):
        self.harness.set_can_connect(container=self.container_name, val=False)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        (root / CSR_PATH).write_text(CSR)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)

        self.harness.charm._on_certificates_relation_broken(event=Mock())

        container_certificate = (root / CERTIFICATE_PATH).read_text()
        container_private_key = (root / PRIVATE_KEY_PATH).read_text()
        container_csr = (root / CSR_PATH).read_text()
        assert container_certificate == CERTIFICATE
        assert container_private_key == PRIVATE_KEY
        assert container_csr == CSR

    def test_given_certificates_does_not_exist_on_certificates_relation_broken_then_no_exception_is_raised_and_files_does_not_exist(  # noqa: E501
        self, add_storage
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificates_relation_broken(event=Mock())

        root = self.harness.get_filesystem_root(self.container_name)
        with pytest.raises(FileNotFoundError):
            (root / CERTIFICATE_PATH).read_text()
            (root / PRIVATE_KEY_PATH).read_text()
            (root / CSR_PATH).read_text()

    def test_given_private_key_exists_when_on_certificates_relation_joined_then_csr_is_generated(
        self, add_storage, mock_default_values, nrf_relation_id, sdcore_config_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        self.mock_generate_csr.return_value = CSR.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)

        self._create_certificates_relation()
        assert (root / CSR_PATH).read_text() == CSR

    def test_given_private_key_exists_and_cert_not_yet_requested_when_on_certificates_relation_joined_then_cert_is_requested(  # noqa: E501
        self, add_storage, nrf_relation_id, sdcore_config_relation_id, mock_default_values
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        self.mock_generate_csr.return_value = CSR.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)

        self._create_certificates_relation()

        self.mock_request_certificate.assert_called_with(certificate_signing_request=CSR.encode())

    def test_given_cert_already_stored_when_on_certificates_relation_joined_then_cert_is_not_requested(  # noqa: E501
        self, add_storage, mock_default_values, nrf_relation_id, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        (root / CSR_PATH).write_text(CSR)

        self._create_certificates_relation()

        self.mock_request_certificate.assert_not_called()

    def test_given_csr_matches_stored_one_when_certificate_available_then_certificate_is_pushed(
        self,
        add_storage,
        get_default_certificate,
        mock_default_values,
        nrf_relation_id,
        sdcore_config_relation_id,
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        (root / CSR_PATH).write_text(CSR)
        self._create_certificates_relation()

        self.harness.container_pebble_ready(self.container_name)

        assert (root / CERTIFICATE_PATH).read_text() == CERTIFICATE

    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_certificate_is_not_pushed(  # noqa: E501
        self, add_storage, nrf_relation_id, mock_default_values, sdcore_config_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        (root / CSR_PATH).write_text(CSR)
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = CERTIFICATE
        provider_certificate.csr = "Relation CSR content (different from stored one)"
        self.mock_get_certificates.return_value = [provider_certificate]
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)

        with pytest.raises(FileNotFoundError):
            (root / CERTIFICATE_PATH).read_text()

    @pytest.mark.parametrize(
        "pod_ip,webui_url",
        [
            (b"1.2.3.4", WEBUI_URL),
            (POD_IP, "mywebui:9876"),
        ]
    )
    def test_config_pushed_but_config_changed_and_layer_already_applied_when_pebble_ready_then_pcf_service_is_restarted(  # noqa: E501
        self,
        pod_ip,
        webui_url,
        add_storage,
        nrf_relation_id,
        sdcore_config_relation_id,
        mock_default_values,
    ):
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = CERTIFICATE
        provider_certificate.csr = CSR
        self.mock_get_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(self.container_name)
        (root / CSR_PATH).write_text(CSR)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        (root / f"etc/pcf/{CONFIG_FILE_NAME}").write_text(
            self._read_file(EXPECTED_CONFIG_FILE_PATH)
        )

        self._create_certificates_relation()
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.mock_check_output.return_value = pod_ip
        self.mock_webui_url.return_value = webui_url

        self.harness.container_pebble_ready(self.container_name)
        self.mock_restart_container.assert_called_once_with(self.container_name)

    def test_given_certificate_does_not_match_stored_one_when_certificate_expiring_then_certificate_is_not_requested(  # noqa: E501
        self, add_storage
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        event = Mock()
        event.certificate = "Relation certificate content (different from stored)"
        self.mock_generate_csr.return_value = CSR.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificate_expiring(event=event)

        self.mock_request_certificate.assert_not_called()

    def test_given_container_cannot_connect_when_certificate_expiring_then_certificate_is_not_requested(  # noqa: E501
        self, add_storage
    ):
        self.harness.set_can_connect(container=self.container_name, val=False)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        event = Mock()
        event.certificate = "Relation certificate content (different from stored)"
        self.mock_generate_csr.return_value = CSR.encode()

        self.harness.charm._on_certificate_expiring(event=event)

        self.mock_request_certificate.assert_not_called()

    def test_given_certificate_matches_stored_one_when_certificate_expiring_then_certificate_is_requested(  # noqa: E501
        self, add_storage
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        event = Mock()
        event.certificate = CERTIFICATE
        self.mock_generate_csr.return_value = CSR.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificate_expiring(event=event)

        self.mock_request_certificate.assert_called_with(
            certificate_signing_request=CSR.encode()
        )
