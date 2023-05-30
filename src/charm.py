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


class PCFOperatorCharm(CharmBase):
    """Main class to describe Juju event handling for the 5G PCF operator."""

    def __init__(self, *args):
        super().__init__(*args)
        self._container_name = self._service_name = "pcf"
        self._container = self.unit.get_container(self._container_name)

        self._database = DatabaseRequires(
            self, relation_name="database", database_name=DATABASE_NAME
        )
        self._nrf_requires = NRFRequires(charm=self, relation_name=NRF_RELATION_NAME)

        self.framework.observe(self.on.database_relation_joined, self._configure_sdcore_pcf)
        self.framework.observe(self._database.on.database_created, self._configure_sdcore_pcf)

        self.framework.observe(self.on.fiveg_nrf_relation_joined, self._configure_sdcore_pcf)
        self.framework.observe(self._nrf_requires.on.nrf_available, self._configure_sdcore_pcf)

        self.framework.observe(self.on.pcf_pebble_ready, self._configure_sdcore_pcf)

        self._service_patcher = KubernetesServicePatch(
            charm=self,
            ports=[ServicePort(name="sbi", port=PCF_SBI_PORT)],
        )

    def _configure_sdcore_pcf(self, event: EventBase):
        """Adds Pebble layer and manages Juju unit status.

        Args:
            event (EventBase): Juju event.
        """
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting for container to be ready")
            return
        for relation in [DATABASE_RELATION_NAME, NRF_RELATION_NAME]:
            if not self._relation_created(relation):
                self.unit.status = BlockedStatus(
                    f"Waiting for `{relation}` relation to be created"
                )
                return
        if not self._database_is_available():
            self.unit.status = WaitingStatus("Waiting for `database` relation to be available")
            return
        if not self._nrf_is_available():
            self.unit.status = WaitingStatus("Waiting for NRF endpoint to be available")
            return
        if not self._storage_is_attached():
            self.unit.status = WaitingStatus("Waiting for the storage to be attached")
            event.defer()
            return
        restart = self._update_config_file()
        self._configure_pebble(restart=restart)
        self.unit.status = ActiveStatus()

    def _configure_pebble(self, restart=False) -> None:
        """Configure the Pebble layer.

        Args:
            restart (bool, optional): Whether to restart the Pebble service. Defaults to False.
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
            pcf_hostname=self._pcf_hostname,
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
        pcf_hostname: str,
    ) -> str:
        """Renders the config file content.

        Args:
            nrf_url (str): NRF URL.
            pcf_sbi_port (int): PCF SBI port.
            pcf_hostname (str): PCF URL.

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
            pcf_hostname=pcf_hostname,
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
                        "command": f"./pcf --pcfcfg {BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}",
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
            "POD_IP": str(self._get_pod_ip()),
            "MANAGED_BY_CONFIG_POD": "true",
        }

    def _get_pod_ip(self) -> Optional[IPv4Address]:
        """Get the IP address of the Kubernetes pod.

        Returns:
            Optional[IPv4Address]: The IP address of the Kubernetes pod.
        """
        return IPv4Address(check_output(["unit-get", "private-address"]).decode().strip())

    @property
    def _pcf_hostname(self) -> str:
        """Returns the PCF hostname.

        Returns:
            str: The PCF hostname.
        """
        return f"{self.model.app.name}.{self.model.name}.svc.cluster.local"


if __name__ == "__main__":  # pragma: no cover
    main(PCFOperatorCharm)
