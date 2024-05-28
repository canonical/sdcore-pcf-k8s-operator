# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from typing import Generator
from unittest.mock import Mock, PropertyMock, patch

import pytest
import yaml
from charm import (
    CONFIG_FILE_NAME,
    DATABASE_RELATION_NAME,
    NRF_RELATION_NAME,
    TLS_RELATION_NAME,
    PCFOperatorCharm,
)
from charms.tls_certificates_interface.v3.tls_certificates import (  # type: ignore[import]
    ProviderCertificate,
)
from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

logger = logging.getLogger(__name__)

CERTIFICATE = "whatever certificate content"
CERTIFICATES_LIB = (
    "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3"
)
CERTIFICATE_PATH = "support/TLS/pcf.pem"
CSR = "whatever CSR content"
CSR_PATH = "support/TLS/pcf.csr"
DATABASE_APP_NAME = "mongodb-k8s"
EXPECTED_CONFIG_FILE_PATH = "tests/unit/expected_pcfcfg.yaml"
POD_IP = b"1.1.1.1"
PRIVATE_KEY = "whatever key content"
PRIVATE_KEY_PATH = "support/TLS/pcf.key"
VALID_NRF_URL = "https://nrf:443"


class TestCharm:

    patcher_check_output = patch("charm.check_output")
    patcher_generate_csr = patch("charm.generate_csr")
    patcher_generate_private_key = patch("charm.generate_private_key")
    patcher_get_certificates = patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    patcher_nrf_url = patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)  # noqa: E501
    patcher_request_certificate = patch(f"{CERTIFICATES_LIB}.request_certificate_creation")
    patcher_restart_container = patch("ops.model.Container.restart")

    @pytest.fixture()
    def setUp(self):
        metadata = self._get_metadata()
        self.container_name = list(metadata["containers"].keys())[0]
        self.mock_check_output = TestCharm.patcher_check_output.start()
        self.mock_generate_csr = TestCharm.patcher_generate_csr.start()
        self.mock_generate_private_key = TestCharm.patcher_generate_private_key.start()
        self.mock_get_certificates = TestCharm.patcher_get_certificates.start()
        self.mock_nrf_url = TestCharm.patcher_nrf_url.start()
        self.mock_request_certificate = TestCharm.patcher_request_certificate.start()
        self.mock_restart_container = TestCharm.patcher_restart_container.start()

    @staticmethod
    def tearDown() -> None:
        patch.stopall()

    @pytest.fixture()
    def mock_default_values(self) -> None:
        self.mock_nrf_url.return_value = VALID_NRF_URL
        self.mock_check_output.return_value = POD_IP
        self.mock_generate_private_key.return_value = PRIVATE_KEY.encode()
        self.mock_generate_csr.return_value = CSR.encode()

    @pytest.fixture(autouse=True)
    def harness(self, setUp, request):
        self.harness = testing.Harness(PCFOperatorCharm)
        self.harness.set_model_name(name="whatever")
        self.harness.set_leader(is_leader=True)
        self.harness.begin()
        yield self.harness
        self.harness.cleanup()
        request.addfinalizer(self.tearDown)

    @pytest.fixture()
    def add_storage(self) -> None:
        self.harness.add_storage(storage_name="certs", attach=True)  # type:ignore
        self.harness.add_storage(storage_name="config", attach=True)  # type:ignore

    @pytest.fixture()
    def get_default_certificate(self) -> None:
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = CERTIFICATE
        provider_certificate.csr = CSR
        self.mock_get_certificates.return_value = [provider_certificate]

    @pytest.fixture()
    def nrf_relation_id(self) -> Generator[int, None, None]:
        relation_id = self.harness.add_relation(  # type:ignore
            relation_name=NRF_RELATION_NAME, remote_app="nrf-operator"
        )
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="nrf-operator/0")  # type:ignore
        yield relation_id

    @staticmethod
    def _get_metadata() -> dict:
        """Read `charmcraft.yaml` and return its content as a dictionary."""
        with open("charmcraft.yaml", "r") as f:
            data = yaml.safe_load(f)
        return data

    @staticmethod
    def _read_file(path: str) -> str:
        """Read a file and return its content as a string."""
        with open(path, "r") as f:
            content = f.read()
        return content

    def _create_database_relation(self) -> int:
        relation_id = self.harness.add_relation(  # type:ignore
            relation_name=DATABASE_RELATION_NAME, remote_app=DATABASE_APP_NAME
        )
        self.harness.add_relation_unit(  # type:ignore
            relation_id=relation_id, remote_unit_name=f"{DATABASE_APP_NAME}/0"
        )
        return relation_id

    def _create_database_relation_and_populate_data(self) -> int:
        database_relation_id = self._create_database_relation()
        self.harness.update_relation_data(  # type:ignore
            relation_id=database_relation_id,
            app_or_unit=DATABASE_APP_NAME,
            key_values={
                "username": "banana",
                "password": "pizza",
                "uris": "http://1.1.1.1",
            },
        )
        return database_relation_id

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

    def test_given_container_can_connect_and_database_relation_is_not_created_when_collect_status_pcf_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus("Waiting for database relation")

    def test_given_container_can_connect_and_fiveg_nrf_relation_is_not_created_when_collect_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_database_relation()

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus("Waiting for fiveg_nrf relation")

    def test_given_container_can_connect_and_certificates_relation_is_not_created_when_collect_status_then_status_is_blocked(  # noqa: E501
        self, nrf_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_database_relation()

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus("Waiting for certificates relation")

    def test_given_pcf_charm_in_active_state_when_nrf_relation_breaks_then_status_is_blocked(
        self, add_storage, mock_default_values, nrf_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        self._create_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.remove_relation(nrf_relation_id)
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus("Waiting for fiveg_nrf relation")

    def test_given_pcf_charm_in_active_state_when_database_relation_breaks_then_status_is_blocked(
        self, add_storage, mock_default_values, nrf_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        database_relation_id = self._create_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.remove_relation(database_relation_id)
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus("Waiting for database relation")

    def test_given_container_can_connect_and_database_relation_is_not_available_when_collect_status_then_status_is_waiting(  # noqa: E501
        self, add_storage, nrf_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_database_relation()
        self._create_certificates_relation()

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for `database` relation to be available")  # noqa: E501

    def test_given_container_can_connect_and_fiveg_nrf_relation_is_not_available_when_collect_status_then_status_is_waiting(  # noqa: E501
        self, add_storage, mock_default_values, nrf_relation_id
    ):
        self._create_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.mock_nrf_url.return_value = None
        self.harness.container_pebble_ready(self.container_name)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for NRF endpoint to be available")  # noqa: E501

    @pytest.mark.parametrize(
        "storage_name",
        [
            "certs",
            "config",
        ]
    )
    def test_given_container_storage_is_not_attached_when_collect_status_then_status_is_waiting(  # noqa: E501
        self, storage_name, nrf_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name=storage_name, attach=True)
        self._create_database_relation_and_populate_data()
        self._create_certificates_relation()

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for the storage to be attached")  # noqa: E501

    def test_given_certificate_is_not_stored_when_collect_status_then_status_is_waiting(  # noqa: E501
        self, add_storage, mock_default_values, nrf_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_database_relation_and_populate_data()
        self._create_certificates_relation()

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for certificates to be stored")  # noqa: E501

    def test_given_config_file_is_written_when_collect_status_is_called_then_status_is_active(  # noqa: E501
        self, add_storage, get_default_certificate, mock_default_values, nrf_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        (root / CSR_PATH).write_text(CSR)
        self._create_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == ActiveStatus()

    def test_given_ip_not_available_when_collect_status_then_status_is_waiting(
        self, add_storage, nrf_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        self.mock_check_output.return_value = "".encode()
        self._create_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for pod IP address to be available")  # noqa: E501

    def test_given_not_leader_when_collect_status_then_status_is_blocked(self):
        self.harness.set_leader(is_leader=False)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus("Scaling is not implemented for this charm")  # noqa: E501

    def test_given_config_file_is_not_written_when_configure_sdcore_pcf_is_called_then_config_file_is_written_with_expected_content(  # noqa: E501
        self, add_storage, get_default_certificate, mock_default_values, nrf_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        (root / CSR_PATH).write_text(CSR)
        self._create_database_relation_and_populate_data()
        self._create_certificates_relation()

        self.harness.charm._configure_sdcore_pcf(event=Mock())

        expected_config_file_content = self._read_file(EXPECTED_CONFIG_FILE_PATH).strip()
        assert (root / f"etc/pcf/{CONFIG_FILE_NAME}").read_text() == expected_config_file_content

    def test_given_config_file_is_written_and_is_not_changed_when_configure_sdcore_pcf_is_called_then_config_file_is_not_written(  # noqa: E501
        self, add_storage, mock_default_values, nrf_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        (root / f"etc/pcf/{CONFIG_FILE_NAME}").write_text(
            self._read_file(EXPECTED_CONFIG_FILE_PATH).strip()
        )
        config_modification_time = (root / f"etc/pcf/{CONFIG_FILE_NAME}").stat().st_mtime
        self._create_database_relation_and_populate_data()
        self._create_certificates_relation()
        self.harness.charm._certificate_is_stored = Mock(return_value=True)

        self.harness.container_pebble_ready(self.container_name)

        assert (root / f"etc/pcf/{CONFIG_FILE_NAME}").stat().st_mtime == config_modification_time

    def test_given_config_file_exists_and_is_changed_when_configure_pcf_then_config_file_is_updated(  # noqa: E501
        self, add_storage, get_default_certificate, mock_default_values, nrf_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CSR_PATH).write_text(CSR)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        (root / f"etc/pcf/{CONFIG_FILE_NAME}").write_text("super different config file content")
        self._create_database_relation_and_populate_data()
        self._create_certificates_relation()

        self.harness.container_pebble_ready(self.container_name)

        expected_content = self._read_file(EXPECTED_CONFIG_FILE_PATH)
        assert (root / f"etc/pcf/{CONFIG_FILE_NAME}").read_text() == expected_content.strip()

    def test_given_config_files_and_relations_are_created_when_configure_sdcore_pcf_is_called_then_expected_plan_is_applied(  # noqa: E501
        self, add_storage, get_default_certificate, mock_default_values, nrf_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        (root / CSR_PATH).write_text(CSR)
        self._create_database_relation_and_populate_data()
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
        self, add_storage, mock_default_values, nrf_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.mock_generate_private_key.return_value = PRIVATE_KEY.encode()
        self.mock_generate_csr.return_value = CSR.encode()
        self._create_database_relation_and_populate_data()
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
        self, add_storage, mock_default_values, nrf_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        self.mock_generate_csr.return_value = CSR.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_database_relation_and_populate_data()

        self._create_certificates_relation()

        assert (root / CSR_PATH).read_text() == CSR

    def test_given_private_key_exists_and_cert_not_yet_requested_when_on_certificates_relation_joined_then_cert_is_requested(  # noqa: E501
        self, add_storage, mock_default_values, nrf_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        self.mock_generate_csr.return_value = CSR.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_database_relation_and_populate_data()

        self._create_certificates_relation()

        self.mock_request_certificate.assert_called_with(certificate_signing_request=CSR.encode())

    def test_given_cert_already_stored_when_on_certificates_relation_joined_then_cert_is_not_requested(  # noqa: E501
        self, add_storage, mock_default_values, nrf_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        (root / CSR_PATH).write_text(CSR)
        self._create_database_relation_and_populate_data()

        self._create_certificates_relation()

        self.mock_request_certificate.assert_not_called()

    def test_given_csr_matches_stored_one_when_certificate_available_then_certificate_is_pushed(
        self, add_storage, get_default_certificate, mock_default_values, nrf_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        (root / CSR_PATH).write_text(CSR)
        self._create_database_relation_and_populate_data()
        self._create_certificates_relation()

        self.harness.container_pebble_ready(self.container_name)

        assert (root / CERTIFICATE_PATH).read_text() == CERTIFICATE

    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_certificate_is_not_pushed(  # noqa: E501
        self, add_storage, nrf_relation_id
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
