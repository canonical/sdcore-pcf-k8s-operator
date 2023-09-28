#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SD-Core's PCF service."""

import logging
from ipaddress import IPv4Address
from subprocess import check_output
from typing import Optional

from charms.data_platform_libs.v0.data_interfaces import DatabaseRequires  # type: ignore[import]
from charms.observability_libs.v1.kubernetes_service_patch import (  # type: ignore[import]  # noqa: E501
    KubernetesServicePatch,
)
from charms.sdcore_nrf.v0.fiveg_nrf import NRFRequires  # type: ignore[import]
from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import]
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from jinja2 import Environment, FileSystemLoader
from lightkube.models.core_v1 import ServicePort
from ops.charm import CharmBase
from ops.framework import EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.pebble import Layer

logger = logging.getLogger(__name__)

BASE_CONFIG_PATH = "/etc/pcf"
CONFIG_FILE_NAME = "pcfcfg.yaml"
PCF_SBI_PORT = 29507
DATABASE_NAME = "free5gc"
DATABASE_RELATION_NAME = "database"
NRF_RELATION_NAME = "fiveg_nrf"
TLS_RELATION_NAME = "certificates"
CERTS_DIR_PATH = "/support/TLS"  # Certificate paths are hardcoded in PCF code
PRIVATE_KEY_NAME = "pcf.key"
CSR_NAME = "pcf.csr"
CERTIFICATE_NAME = "pcf.pem"
CERTIFICATE_COMMON_NAME = "pcf.sdcore"


class PCFOperatorCharm(CharmBase):
    """Main class to describe Juju event handling for the 5G PCF operator."""

    def __init__(self, *args):
        super().__init__(*args)
        if not self.unit.is_leader():
            raise NotImplementedError("Scaling is not implemented for this charm")
        self._container_name = self._service_name = "pcf"
        self._container = self.unit.get_container(self._container_name)

        self._database = DatabaseRequires(
            self, relation_name="database", database_name=DATABASE_NAME
        )
        self._nrf_requires = NRFRequires(charm=self, relation_name=NRF_RELATION_NAME)
        self._service_patcher = KubernetesServicePatch(
            charm=self,
            ports=[ServicePort(name="sbi", port=PCF_SBI_PORT)],
        )
        self._certificates = TLSCertificatesRequiresV2(self, "certificates")
        self.framework.observe(self.on.database_relation_joined, self._configure_sdcore_pcf)
        self.framework.observe(self._database.on.database_created, self._configure_sdcore_pcf)
        self.framework.observe(self.on.fiveg_nrf_relation_joined, self._configure_sdcore_pcf)
        self.framework.observe(self._nrf_requires.on.nrf_available, self._configure_sdcore_pcf)
        self.framework.observe(self._nrf_requires.on.nrf_broken, self._on_nrf_broken)
        self.framework.observe(self.on.pcf_pebble_ready, self._configure_sdcore_pcf)
        self.framework.observe(
            self.on.certificates_relation_created, self._on_certificates_relation_created
        )
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(
            self.on.certificates_relation_broken, self._on_certificates_relation_broken
        )
        self.framework.observe(
            self._certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self._certificates.on.certificate_expiring, self._on_certificate_expiring
        )

    def _configure_sdcore_pcf(self, event: EventBase):
        """Adds Pebble layer and manages Juju unit status.

        Args:
            event (EventBase): Juju event.
        """
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting for container to be ready")
            return
        for relation in [DATABASE_RELATION_NAME, NRF_RELATION_NAME, TLS_RELATION_NAME]:
            if not self._relation_created(relation):
                self.unit.status = BlockedStatus(
                    f"Waiting for `{relation}` relation to be created"
                )
                return
        if not self._database_is_available():
            self.unit.status = WaitingStatus(
                f"Waiting for `{DATABASE_RELATION_NAME}` relation to be available"
            )
            return
        if not self._nrf_is_available():
            self.unit.status = WaitingStatus("Waiting for NRF endpoint to be available")
            return
        if not self._storage_is_attached():
            self.unit.status = WaitingStatus("Waiting for the storage to be attached")
            event.defer()
            return
        if not _get_pod_ip():
            self.unit.status = WaitingStatus("Waiting for pod IP address to be available")
            event.defer()
            return
        if not self._certificate_is_stored():
            self.unit.status = WaitingStatus("Waiting for certificates to be stored")
            event.defer()
            return
        restart = self._update_config_file()
        self._configure_pebble(restart=restart)
        self.unit.status = ActiveStatus()

    def _on_nrf_broken(self, event: EventBase) -> None:
        """Event handler for NRF relation broken.

        Args:
            event (NRFBrokenEvent): Juju event
        """
        self.unit.status = BlockedStatus("Waiting for fiveg_nrf relation")

    def _on_certificates_relation_created(self, event: EventBase) -> None:
        """Generates Private key.

        Args:
            event (EventBase): Juju event.
        """
        if not self._container.can_connect():
            event.defer()
            return
        self._generate_private_key()

    def _on_certificates_relation_broken(self, event: EventBase) -> None:
        """Deletes TLS related artifacts and reconfigures workload.

        Args:
            event (EventBase): Juju event.
        """
        if not self._container.can_connect():
            event.defer()
            return
        self._delete_private_key()
        self._delete_csr()
        self._delete_certificate()
        self.unit.status = BlockedStatus("Waiting for certificates relation")

    def _on_certificates_relation_joined(self, event: EventBase) -> None:
        """Generates CSR and requests new certificate.

        Args:
            event (EventBase): Juju event.
        """
        if not self._container.can_connect():
            event.defer()
            return
        if not self._private_key_is_stored():
            event.defer()
            return
        self._request_new_certificate()

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Pushes certificate to workload and configures workload.

        Args:
            event (CertificateAvailableEvent): Juju event.
        """
        if not self._container.can_connect():
            event.defer()
            return
        if not self._csr_is_stored():
            logger.warning("Certificate is available but no CSR is stored")
            return
        if event.certificate_signing_request != self._get_stored_csr():
            logger.debug("Stored CSR doesn't match one in certificate available event")
            return
        self._store_certificate(event.certificate)
        self._configure_sdcore_pcf(event)

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        """Requests new certificate.

        Args:
            event (CertificateExpiringEvent): Juju event.
        """
        if not self._container.can_connect():
            event.defer()
            return
        if event.certificate != self._get_stored_certificate():
            logger.debug("Expiring certificate is not the one stored")
            return
        self._request_new_certificate()

    def _generate_private_key(self) -> None:
        """Generates and stores private key."""
        private_key = generate_private_key()
        self._store_private_key(private_key)

    def _request_new_certificate(self) -> None:
        """Generates and stores CSR, and uses it to request a new certificate."""
        private_key = self._get_stored_private_key()
        csr = generate_csr(
            private_key=private_key,
            subject=CERTIFICATE_COMMON_NAME,
            sans_dns=[CERTIFICATE_COMMON_NAME],
        )
        self._store_csr(csr)
        self._certificates.request_certificate_creation(certificate_signing_request=csr)

    def _delete_private_key(self) -> None:
        """Removes private key from workload."""
        if not self._private_key_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")
        logger.info("Removed private key from workload")

    def _delete_csr(self) -> None:
        """Deletes CSR from workload."""
        if not self._csr_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{CSR_NAME}")
        logger.info("Removed CSR from workload")

    def _delete_certificate(self) -> None:
        """Deletes certificate from workload."""
        if not self._certificate_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")
        logger.info("Removed certificate from workload")

    def _private_key_is_stored(self) -> bool:
        """Returns whether private key is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")

    def _csr_is_stored(self) -> bool:
        """Returns whether CSR is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{CSR_NAME}")

    def _get_stored_certificate(self) -> str:
        """Returns stored certificate."""
        return str(self._container.pull(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}").read())

    def _get_stored_csr(self) -> str:
        """Returns stored CSR."""
        return str(self._container.pull(path=f"{CERTS_DIR_PATH}/{CSR_NAME}").read())

    def _get_stored_private_key(self) -> bytes:
        """Returns stored private key."""
        return str(
            self._container.pull(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}").read()
        ).encode()

    def _certificate_is_stored(self) -> bool:
        """Returns whether certificate is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")

    def _store_certificate(self, certificate: str) -> None:
        """Stores certificate in workload."""
        self._container.push(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}", source=certificate)
        logger.info("Pushed certificate pushed to workload")

    def _store_private_key(self, private_key: bytes) -> None:
        """Stores private key in workload."""
        self._container.push(
            path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}",
            source=private_key.decode(),
        )
        logger.info("Pushed private key to workload")

    def _store_csr(self, csr: bytes) -> None:
        """Stores CSR in workload."""
        self._container.push(path=f"{CERTS_DIR_PATH}/{CSR_NAME}", source=csr.decode().strip())
        logger.info("Pushed CSR to workload")

    def _configure_pebble(self, restart: bool = False) -> None:
        """Configure the Pebble layer.

        Args:
            restart (bool): Whether to restart the Pebble service. Defaults to False.
        """
        self._container.add_layer(self._container_name, self._pebble_layer, combine=True)
        if restart:
            self._container.restart(self._service_name)
            logger.info("Restarted container %s", self._service_name)
            return
        self._container.replan()

    def _update_config_file(self) -> bool:
        """Updates config file.

        Writes the config file if it does not exist or
        the content does not match.

        Returns:
            bool: True if config file was updated, False otherwise.
        """
        content = self._render_config_file(
            database_name=DATABASE_NAME,
            database_url=self._get_database_data()["uris"].split(",")[0],
            nrf_url=self._nrf_requires.nrf_url,
            pcf_sbi_port=PCF_SBI_PORT,
            pod_ip=_get_pod_ip(),  # type: ignore[arg-type]
            scheme="https",
        )
        if not self._config_file_is_written() or not self._config_file_content_matches(
            content=content
        ):
            self._write_config_file(content=content)
            return True
        return False

    def _render_config_file(
        self,
        *,
        database_name: str,
        database_url: str,
        nrf_url: str,
        pcf_sbi_port: int,
        pod_ip: str,
        scheme: str,
    ) -> str:
        """Renders the config file content.

        Args:
            nrf_url (str): NRF URL.
            pcf_sbi_port (int): PCF SBI port.
            pod_ip (str): Pod IPv4.
            scheme (str): SBI interface scheme ("http" or "https")

        Returns:
            str: Config file content.
        """
        jinja2_env = Environment(loader=FileSystemLoader("src/templates"))
        template = jinja2_env.get_template("pcfcfg.yaml.j2")
        return template.render(
            database_name=database_name,
            database_url=database_url,
            nrf_url=nrf_url,
            pcf_sbi_port=pcf_sbi_port,
            pod_ip=pod_ip,
            scheme=scheme,
        )

    def _write_config_file(self, content: str) -> None:
        """Writes config file to workload.

        Args:
            content (str): Config file content.
        """
        self._container.push(
            path=f"{BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}",
            source=content,
        )
        logger.info("Pushed: %s to workload.", CONFIG_FILE_NAME)

    def _config_file_is_written(self) -> bool:
        """Returns whether the config file was written to the workload container.

        Returns:
            bool: Whether the config file was written.
        """
        return bool(self._container.exists(f"{BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}"))

    def _config_file_content_matches(self, content: str) -> bool:
        """Returns whether the config file content matches the provided content.

        Args:
            content (str): Config file content.

        Returns:
            bool: Whether the config file content matches.
        """
        existing_content = self._container.pull(path=f"{BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}")
        return existing_content.read() == content

    def _relation_created(self, relation_name: str) -> bool:
        """Returns whether a given Juju relation was crated.

        Args:
            relation_name (str): Relation name.

        Returns:
            bool: Whether the relation was created.
        """
        return bool(self.model.get_relation(relation_name))

    def _get_database_data(self) -> dict:
        """Returns the database data.

        Returns:
            dict: The database data.

        Raises:
            RuntimeError: If the database is not available.
        """
        if not self._database_is_available():
            raise RuntimeError("Database is not available")
        return self._database.fetch_relation_data()[self._database.relations[0].id]

    def _database_is_available(self) -> bool:
        """Returns whether database relation is available.

        Returns:
            bool: Whether database relation is available.
        """
        return bool(self._database.is_resource_created())

    def _nrf_is_available(self) -> bool:
        """Returns whether the NRF endpoint is available.

        Returns:
            bool: whether the NRF endpoint is available.
        """
        return bool(self._nrf_requires.nrf_url)

    def _storage_is_attached(self) -> bool:
        """Returns whether storage is attached to the workload container.

        Returns:
            bool: Whether storage is attached.
        """
        return self._container.exists(path=BASE_CONFIG_PATH)

    @property
    def _pebble_layer(self) -> Layer:
        """Returns pebble layer.

        Returns:
            Layer: Pebble Layer
        """
        return Layer(
            {
                "summary": "pcf layer",
                "description": "pebble config layer for pcf",
                "services": {
                    self._service_name: {
                        "override": "replace",
                        "startup": "enabled",
                        "command": f"/bin/pcf --pcfcfg {BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}",
                        "environment": self._environment_variables,
                    },
                },
            }
        )

    @property
    def _environment_variables(self) -> dict:
        """Returns environment variables.

        Returns:
            dict: Environment variables.
        """
        return {
            "GRPC_GO_LOG_VERBOSITY_LEVEL": "99",
            "GRPC_GO_LOG_SEVERITY_LEVEL": "info",
            "GRPC_TRACE": "all",
            "GRPC_VERBOSITY": "debug",
            "POD_IP": _get_pod_ip(),
            "MANAGED_BY_CONFIG_POD": "true",
        }


def _get_pod_ip() -> Optional[str]:
    """Returns the pod IP using juju client.

    Returns:
        str: The pod IP.
    """
    ip_address = check_output(["unit-get", "private-address"])
    return str(IPv4Address(ip_address.decode().strip())) if ip_address else None


if __name__ == "__main__":  # pragma: no cover
    main(PCFOperatorCharm)
