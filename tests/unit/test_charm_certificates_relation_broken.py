# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import os
import tempfile

from ops import testing

from tests.unit.fixtures import PCFUnitTestFixtures


class TestCharmCertificatesRelationBroken(PCFUnitTestFixtures):
    def test_given_certificates_are_stored_when_on_certificates_relation_broken_then_certificates_are_removed(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
            certificates_relation = testing.Relation(
                endpoint="certificates", interface="tls-certificates"
            )
            certs_mount = testing.Mount(
                location="/sdcore/certs",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/sdcore/config/",
                source=tempdir,
            )
            container = testing.Container(
                name="pcf",
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            os.mkdir(f"{tempdir}/sdcore")
            os.mkdir(f"{tempdir}/sdcore/certs")
            with open(f"{tempdir}/pcf.pem", "w") as f:
                f.write("certificate")

            with open(f"{tempdir}/pcf.key", "w") as f:
                f.write("private key")

            state_in = testing.State(
                relations=[certificates_relation],
                containers=[container],
                leader=True,
            )

            self.ctx.run(self.ctx.on.relation_broken(certificates_relation), state_in)

            assert not os.path.exists(f"{tempdir}/pcf.pem")
            assert not os.path.exists(f"{tempdir}/pcf.key")
