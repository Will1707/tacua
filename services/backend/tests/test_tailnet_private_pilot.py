# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import contextlib
import io
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = (
    ROOT
    / "services"
    / "backend"
    / "scripts"
    / "verify_tailnet_private_pilot.py"
)


def load_script():
    specification = importlib.util.spec_from_file_location(
        "tacua_tailnet_private_pilot",
        SCRIPT,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


PILOT = load_script()
DNS_NAME = "mini-pc.example-tail.ts.net"
ORIGIN = f"https://{DNS_NAME}"
REVIEWER_CAPABILITY = "auth.example.invalid/cap/tacua-reviewer"


def config(**overrides):
    values = {
        "backend_origin": ORIGIN,
        "listen_host": "0.0.0.0",
        "listen_port": 8080,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def tailscale_status():
    return {
        "BackendState": "Running",
        "CertDomains": [DNS_NAME],
        "CurrentTailnet": {
            "MagicDNSEnabled": True,
            "MagicDNSSuffix": "example-tail.ts.net",
            "Name": "synthetic-tailnet",
        },
        "MagicDNSSuffix": "example-tail.ts.net",
        "Self": {
            "DNSName": f"{DNS_NAME}.",
            "Online": True,
            "TailscaleIPs": ["100.64.0.1"],
        },
        "Version": "1.102.2-test",
    }


def serve_status(*, reviewer_app_capability=None):
    handler = {"Proxy": PILOT.EXPECTED_PROXY}
    if reviewer_app_capability is not None:
        handler["AcceptAppCaps"] = [reviewer_app_capability]
    return {
        "TCP": {"443": {"HTTPS": True}},
        "Web": {
            f"{DNS_NAME}:443": {
                "Handlers": {
                    "/": handler
                }
            }
        },
    }


def compose_document(**backend_overrides):
    backend = {
        "build": {
            "context": str(ROOT),
            "dockerfile": "services/backend/Dockerfile",
        },
        "image": "tacua-backend:local",
    }
    backend.update(backend_overrides)
    return {
        "services": {
            "backend": backend,
            "reviewer": {
                "build": {
                    "context": str(ROOT),
                    "dockerfile": "services/reviewer-web/Dockerfile",
                },
                "image": "tacua-reviewer-web:local",
            },
        }
    }


class TailnetPrivatePilotTests(unittest.TestCase):
    def validate(
        self,
        *,
        pilot_config=None,
        compose=None,
        status=None,
        serve=None,
        compose_result=None,
    ):
        with mock.patch.object(
            PILOT,
            "validate_compose_document",
            return_value=compose_result
            or {
                "topology": "loopback-ingress",
                "publisher_service": "ingress",
                "published_host": "127.0.0.1",
                "published_port": "8080",
                "reviewer_image": "tacua-reviewer-web:local",
            },
        ) as validator:
            result = PILOT.validate_tailnet_private_pilot(
                pilot_config or config(),
                compose or compose_document(),
                status or tailscale_status(),
                serve or serve_status(),
            )
        self.assertEqual(False, validator.call_args.kwargs["require_immutable_image"])
        return result

    def test_accepts_exact_private_https_loopback_topology(self):
        self.assertEqual(
            {
                "origin": ORIGIN,
                "proxy": "http://127.0.0.1:8080",
                "status": "ok",
            },
            self.validate(),
        )

    def test_ingress_preserves_reviewer_auth_headers_only_for_api_requests(self):
        ingress = (
            ROOT / "services" / "backend" / "ingress" / "haproxy.cfg"
        ).read_text(encoding="utf-8")
        backend_section, reviewer_section = ingress.split(
            "backend tacua_reviewer\n",
            maxsplit=1,
        )
        for header in ("Tailscale-App-Capabilities", "Tacua-CSRF-Token"):
            deletion = f"http-request del-header {header}"
            with self.subTest(header=header):
                self.assertNotIn(deletion, backend_section)
                self.assertEqual(1, reviewer_section.count(deletion))

    def test_accepts_only_the_configured_reviewer_app_capability(self):
        reviewer_auth = SimpleNamespace(
            mode="tailscale_capability_or_pairing",
            tailscale_app_capabilities={REVIEWER_CAPABILITY: [{}]},
        )
        pilot_config = config(reviewer_auth=reviewer_auth)
        self.assertEqual(
            "ok",
            self.validate(
                pilot_config=pilot_config,
                serve=serve_status(
                    reviewer_app_capability=REVIEWER_CAPABILITY,
                ),
            )["status"],
        )

        for candidate in (
            serve_status(),
            serve_status(reviewer_app_capability="other.invalid/cap/reviewer"),
            serve_status(reviewer_app_capability=REVIEWER_CAPABILITY),
        ):
            if "AcceptAppCaps" in candidate["Web"][f"{DNS_NAME}:443"]["Handlers"]["/"]:
                candidate["Web"][f"{DNS_NAME}:443"]["Handlers"]["/"][
                    "AcceptAppCaps"
                ].append("other.invalid/cap/reviewer")
            with self.subTest(candidate=candidate):
                with self.assertRaises(PILOT.TailnetPilotError):
                    self.validate(
                        pilot_config=pilot_config,
                        serve=candidate,
                    )

    def test_reviewer_auth_profile_requires_one_normalized_capability(self):
        for reviewer_auth in (
            SimpleNamespace(
                mode="tailscale_capability_or_pairing",
                tailscale_app_capabilities={},
            ),
            SimpleNamespace(
                mode="tailscale_capability_or_pairing",
                tailscale_app_capabilities={"-invalid": [{}]},
            ),
            SimpleNamespace(
                mode="tailscale_capability_or_pairing",
                tailscale_app_capabilities={REVIEWER_CAPABILITY: []},
            ),
            SimpleNamespace(
                mode="legacy_admin",
                tailscale_app_capabilities={REVIEWER_CAPABILITY: [{}]},
            ),
        ):
            with self.subTest(reviewer_auth=reviewer_auth):
                with self.assertRaises(PILOT.TailnetPilotError):
                    PILOT._reviewer_app_capability(
                        config(reviewer_auth=reviewer_auth)
                    )

        self.assertIsNone(PILOT._reviewer_app_capability(config()))
        self.assertIsNone(
            PILOT._reviewer_app_capability(
                config(
                    reviewer_auth=SimpleNamespace(
                        mode="legacy_admin",
                        tailscale_app_capabilities=None,
                    )
                )
            )
        )

    def test_reviewer_app_capability_requires_tailscale_1_92_or_newer(self):
        reviewer_auth = SimpleNamespace(
            mode="tailscale_capability_or_pairing",
            tailscale_app_capabilities={REVIEWER_CAPABILITY: [{}]},
        )
        pilot_config = config(reviewer_auth=reviewer_auth)
        for version in ("1.91.1", "1.92", "synthetic", 192):
            status = tailscale_status()
            status["Version"] = version
            with self.subTest(version=version):
                with self.assertRaises(PILOT.TailnetPilotError):
                    self.validate(
                        pilot_config=pilot_config,
                        status=status,
                        serve=serve_status(
                            reviewer_app_capability=REVIEWER_CAPABILITY,
                        ),
                    )

        for version in ("1.92.0", "1.102.2-t34c5306", "2.0.0"):
            status = tailscale_status()
            status["Version"] = version
            with self.subTest(version=version):
                self.assertEqual(
                    "ok",
                    self.validate(
                        pilot_config=pilot_config,
                        status=status,
                        serve=serve_status(
                            reviewer_app_capability=REVIEWER_CAPABILITY,
                        ),
                    )["status"],
                )
        self.assertIsNone(
            PILOT._reviewer_app_capability(
                config(
                    reviewer_auth=SimpleNamespace(
                        mode="pairing",
                        tailscale_app_capabilities=None,
                    )
                )
            )
        )

    def test_rejects_offline_or_uncovered_tailnet_identity(self):
        cases = []
        offline = tailscale_status()
        offline["Self"]["Online"] = False
        cases.append(offline)
        stopped = tailscale_status()
        stopped["BackendState"] = "Stopped"
        cases.append(stopped)
        no_magic_dns = tailscale_status()
        no_magic_dns["CurrentTailnet"]["MagicDNSEnabled"] = False
        cases.append(no_magic_dns)
        missing_magic_dns = tailscale_status()
        missing_magic_dns.pop("CurrentTailnet")
        cases.append(missing_magic_dns)
        missing_suffix = tailscale_status()
        missing_suffix["MagicDNSSuffix"] = ""
        cases.append(missing_suffix)
        mismatched_current_suffix = tailscale_status()
        mismatched_current_suffix["CurrentTailnet"]["MagicDNSSuffix"] = (
            "other-tail.ts.net"
        )
        cases.append(mismatched_current_suffix)
        other_suffix = tailscale_status()
        other_suffix["MagicDNSSuffix"] = "other-tail.ts.net"
        cases.append(other_suffix)
        no_certificate = tailscale_status()
        no_certificate["CertDomains"] = ["other-node.example-tail.ts.net"]
        cases.append(no_certificate)
        malformed_name = tailscale_status()
        malformed_name["Self"]["DNSName"] = "Mini_PC.example-tail.ts.net."
        cases.append(malformed_name)

        for status in cases:
            with self.subTest(status=status):
                with self.assertRaises(PILOT.TailnetPilotError):
                    self.validate(status=status)

    def test_rejects_origin_listener_or_compose_drift(self):
        configurations = [
            config(backend_origin="https://other.example-tail.ts.net"),
            config(backend_origin=f"{ORIGIN}/"),
            config(listen_host="127.0.0.1"),
            config(listen_port=8081),
        ]
        for candidate in configurations:
            with self.subTest(config=candidate):
                with self.assertRaises(PILOT.TailnetPilotError):
                    self.validate(pilot_config=candidate)

        for compose_result in [
            {
                "topology": "loopback-ingress",
                "publisher_service": "ingress",
                "published_host": "0.0.0.0",
                "published_port": "8080",
                "reviewer_image": "tacua-reviewer-web:local",
            },
            {
                "topology": "loopback-ingress",
                "publisher_service": "ingress",
                "published_host": "127.0.0.1",
                "published_port": "8081",
                "reviewer_image": "tacua-reviewer-web:local",
            },
            {
                "topology": "loopback-ingress",
                "publisher_service": "backend",
                "published_host": "127.0.0.1",
                "published_port": "8080",
                "reviewer_image": "tacua-reviewer-web:local",
            },
            {
                "topology": "direct",
                "publisher_service": "ingress",
                "published_host": "127.0.0.1",
                "published_port": "8080",
                "reviewer_image": "tacua-reviewer-web:local",
            },
        ]:
            with self.subTest(compose=compose_result):
                with self.assertRaises(PILOT.TailnetPilotError):
                    self.validate(compose_result=compose_result)

    def test_rejects_unreviewed_mutable_image_or_missing_local_build(self):
        for compose in (
            compose_document(image="example.invalid/unreviewed:latest"),
            compose_document(build=None),
            {"services": []},
        ):
            with self.subTest(compose=compose):
                with self.assertRaises(PILOT.TailnetPilotError):
                    self.validate(compose=compose)

    def test_pre_activation_proves_static_bindings_and_empty_serve(self):
        with mock.patch.object(
            PILOT,
            "validate_compose_document",
            return_value={
                "topology": "loopback-ingress",
                "publisher_service": "ingress",
                "published_host": "127.0.0.1",
                "published_port": "8080",
                "reviewer_image": "tacua-reviewer-web:local",
            },
        ):
            self.assertEqual(
                {
                    "origin": ORIGIN,
                    "serve": "empty",
                    "status": "ok",
                },
                PILOT.validate_tailnet_private_pilot_pre_activation(
                    config(),
                    compose_document(),
                    tailscale_status(),
                    {},
                ),
            )
            with self.assertRaises(PILOT.TailnetPilotError):
                PILOT.validate_tailnet_private_pilot_pre_activation(
                    config(),
                    compose_document(),
                    tailscale_status(),
                    serve_status(),
                )

    def test_rejects_funnel_extra_handlers_and_proxy_drift(self):
        funnel = serve_status()
        funnel["AllowFunnel"] = True

        extra_top_level = serve_status()
        extra_top_level["Services"] = {}

        extra_port = serve_status()
        extra_port["TCP"]["8443"] = {"HTTPS": True}

        wrong_port = serve_status()
        wrong_port["TCP"] = {"8443": {"HTTPS": True}}

        extra_handler = serve_status()
        extra_handler["Web"][f"{DNS_NAME}:443"]["Handlers"]["/debug"] = {
            "Text": "debug"
        }

        non_loopback = serve_status()
        non_loopback["Web"][f"{DNS_NAME}:443"]["Handlers"]["/"]["Proxy"] = (
            "http://192.0.2.1:8080"
        )

        wrong_backend_port = serve_status()
        wrong_backend_port["Web"][f"{DNS_NAME}:443"]["Handlers"]["/"]["Proxy"] = (
            "http://127.0.0.1:8081"
        )

        foreground_shape = serve_status()
        foreground_shape["Foreground"] = {"mini-pc": True}

        for serve in [
            funnel,
            extra_top_level,
            extra_port,
            wrong_port,
            extra_handler,
            non_loopback,
            wrong_backend_port,
            foreground_shape,
        ]:
            with self.subTest(serve=serve):
                with self.assertRaises(PILOT.TailnetPilotError):
                    self.validate(serve=serve)

    def test_status_loader_rejects_duplicate_keys_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"TCP":{},"TCP":{}}\n', encoding="utf-8")
            duplicate.chmod(0o600)
            with self.assertRaises(PILOT.TailnetPilotError):
                PILOT._load_status_json(duplicate, "status")

            target = root / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            target.chmod(0o600)
            link = root / "status.json"
            link.symlink_to(target)
            with self.assertRaises(PILOT.TailnetPilotError):
                PILOT._load_status_json(link, "status")

    def test_status_loader_normalizes_deep_or_huge_number_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, payload in (
                ("deep.json", "[" * 1100 + "]" * 1100),
                ("huge-number.json", "1" * 5000),
            ):
                with self.subTest(name=name):
                    status = root / name
                    status.write_text(payload, encoding="utf-8")
                    status.chmod(0o600)
                    with self.assertRaises(PILOT.TailnetPilotError):
                        PILOT._load_status_json(status, "status")

    def test_status_loader_requires_private_file_and_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status = root / "status.json"
            status.write_text("{}\n", encoding="utf-8")
            status.chmod(0o600)
            self.assertEqual({}, PILOT._load_status_json(status, "status"))

            status.chmod(0o644)
            with self.assertRaises(PILOT.TailnetPilotError):
                PILOT._load_status_json(status, "status")
            status.chmod(0o600)
            root.chmod(0o755)
            with self.assertRaises(PILOT.TailnetPilotError):
                PILOT._load_status_json(status, "status")

        with tempfile.TemporaryDirectory() as temporary:
            unsafe = Path(temporary) / "unsafe"
            unsafe.mkdir(mode=0o700)
            private = unsafe / "private"
            private.mkdir(mode=0o700)
            status = private / "status.json"
            status.write_text("{}\n", encoding="utf-8")
            status.chmod(0o600)
            unsafe.chmod(0o777)
            with self.assertRaises(PILOT.TailnetPilotError):
                PILOT._load_status_json(status, "status")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            safe = root / "safe"
            private = safe / "private"
            private.mkdir(parents=True, mode=0o700)
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o777)
            link = unsafe / "replaceable"
            link.symlink_to(safe)
            status = link / "private" / "status.json"
            (private / "status.json").write_text("{}\n", encoding="utf-8")
            (private / "status.json").chmod(0o600)
            with self.assertRaises(PILOT.TailnetPilotError):
                PILOT._load_status_json(status, "status")

    def test_empty_serve_guard_accepts_only_an_unoccupied_host(self):
        self.assertEqual(
            {"serve": "empty", "status": "ok"},
            PILOT.validate_empty_serve_status({}),
        )
        for occupied in (
            serve_status(),
            {"AllowFunnel": False},
            {"TCP": {}},
        ):
            with self.subTest(occupied=occupied):
                with self.assertRaises(PILOT.TailnetPilotError):
                    PILOT.validate_empty_serve_status(occupied)

    def test_identity_projection_exposes_only_the_expected_origin(self):
        self.assertEqual(
            {"origin": ORIGIN, "status": "ok"},
            PILOT.inspect_tailnet_identity(tailscale_status()),
        )

    def test_cli_binds_normal_validation_to_operator_preflight(self):
        compose_path = Path("/private/compose.json")
        config_path = Path("/private/config.json")
        secret_path = Path("/private/admin-secret")
        status_path = Path("/private/status.json")
        serve_path = Path("/private/serve.json")
        documents = iter(
            (compose_document(), tailscale_status(), serve_status())
        )
        with (
            mock.patch.object(
                PILOT,
                "_load_status_json",
                side_effect=lambda *_args: next(documents),
            ),
            mock.patch.object(
                PILOT,
                "deployment_preflight",
            ) as preflight,
            mock.patch.object(
                PILOT,
                "load_public_config",
                return_value=config(),
            ),
            mock.patch.object(
                PILOT,
                "validate_tailnet_private_pilot",
                return_value={"status": "ok"},
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                0,
                PILOT.main(
                    [
                        "--config-file",
                        str(config_path),
                        "--admin-secret-file",
                        str(secret_path),
                        "--compose-json",
                        str(compose_path),
                        "--tailscale-status-json",
                        str(status_path),
                        "--serve-status-json",
                        str(serve_path),
                    ]
                ),
            )
        preflight.assert_called_once_with(
            config_path,
            secret_path,
            compose_document(),
            require_immutable_image=False,
            check_state=False,
        )

    def test_does_not_mutate_input_documents(self):
        status = tailscale_status()
        serve = serve_status()
        status_before = copy.deepcopy(status)
        serve_before = copy.deepcopy(serve)
        self.validate(status=status, serve=serve)
        self.assertEqual(status_before, status)
        self.assertEqual(serve_before, serve)


if __name__ == "__main__":
    unittest.main()
