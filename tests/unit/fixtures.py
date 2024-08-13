# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from typing import Generator
from unittest.mock import Mock, PropertyMock, patch

import pytest
import yaml
from charm import (
    NRF_RELATION_NAME,
    PCFOperatorCharm,
)
from charms.tls_certificates_interface.v3.tls_certificates import (
    ProviderCertificate,
)
from ops import testing

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
NMS_APPLICATION_NAME = "sdcore-nms-operator"


class PCFUnitTestFixtures:
    patcher_check_output = patch("charm.check_output")
    patcher_generate_csr = patch("charm.generate_csr")
    patcher_generate_private_key = patch("charm.generate_private_key")
    patcher_get_certificates = patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    patcher_nrf_url = patch(
        "charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock
    )
    patcher_request_certificate = patch(f"{CERTIFICATES_LIB}.request_certificate_creation")
    patcher_restart_container = patch("ops.model.Container.restart")
    patcher_webui_url = patch(
        "charms.sdcore_nms_k8s.v0.sdcore_config.SdcoreConfigRequires.webui_url",
        new_callable=PropertyMock
    )

    @pytest.fixture()
    def setUp(self):
        metadata = self._get_metadata()
        self.container_name = list(metadata["containers"].keys())[0]
        self.mock_check_output = PCFUnitTestFixtures.patcher_check_output.start()
        self.mock_generate_csr = PCFUnitTestFixtures.patcher_generate_csr.start()
        self.mock_generate_private_key = PCFUnitTestFixtures.patcher_generate_private_key.start()
        self.mock_get_certificates = PCFUnitTestFixtures.patcher_get_certificates.start()
        self.mock_nrf_url = PCFUnitTestFixtures.patcher_nrf_url.start()
        self.mock_request_certificate = PCFUnitTestFixtures.patcher_request_certificate.start()
        self.mock_restart_container = PCFUnitTestFixtures.patcher_restart_container.start()
        self.mock_webui_url = PCFUnitTestFixtures.patcher_webui_url.start()

    @staticmethod
    def tearDown() -> None:
        patch.stopall()

    @pytest.fixture()
    def mock_default_values(self) -> None:
        self.mock_nrf_url.return_value = VALID_NRF_URL
        self.mock_webui_url.return_value = WEBUI_URL
        self.mock_check_output.return_value = POD_IP
        self.mock_generate_private_key.return_value = PRIVATE_KEY.encode()
        self.mock_generate_csr.return_value = CSR.encode()

    @pytest.fixture(autouse=True)
    def setup_harness(self, setUp, request):
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

    @pytest.fixture()
    def sdcore_config_relation_id(self) -> Generator[int, None, None]:
        sdcore_config_relation_id = self.harness.add_relation(  # type:ignore
            relation_name=SDCORE_CONFIG_RELATION_NAME,
            remote_app=NMS_APPLICATION_NAME,
        )
        self.harness.add_relation_unit(  # type:ignore
            relation_id=sdcore_config_relation_id, remote_unit_name=f"{NMS_APPLICATION_NAME}/0"
        )
        self.harness.update_relation_data(  # type:ignore
            relation_id=sdcore_config_relation_id,
            app_or_unit=NMS_APPLICATION_NAME,
            key_values={
                "webui_url": WEBUI_URL,
            },
        )
        yield sdcore_config_relation_id
