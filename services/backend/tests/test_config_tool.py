# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "src"
REPOSITORY = SOURCE.parents[2]
sys.path.insert(0, str(SOURCE))

from tacua_backend.config import ConfigError, parse_config_text  # noqa: E402
import tacua_backend.config_tool as config_tool  # noqa: E402
from tacua_backend.config_tool import (  # noqa: E402
    DERIVE_MARKER,
    SDK_PROFILE_CONTRACT,
    compile_config_artifacts,
    compile_config_template,
    main,
)
from tacua_backend.contracts import canonical_json, digest  # noqa: E402


TEMPLATE = REPOSITORY / "services" / "backend" / "config.template.example.json"
SEALED_EXAMPLE = REPOSITORY / "services" / "backend" / "config.example.json"
SDK_PROFILE_EXAMPLE = REPOSITORY / "services" / "backend" / "sdk-profile.example.json"


class ConfigToolTests(unittest.TestCase):
    def template_text(self) -> str:
        return TEMPLATE.read_text(encoding="utf-8")

    def template_document(self) -> dict:
        return json.loads(self.template_text())

    @staticmethod
    def render(document: dict) -> str:
        return json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2) + "\n"

    def test_example_template_reproduces_the_checked_in_sealed_config(self) -> None:
        rendered = compile_config_template(self.template_text())
        self.assertEqual(SEALED_EXAMPLE.read_text(encoding="utf-8"), rendered)
        self.assertNotIn(DERIVE_MARKER, rendered)
        config = parse_config_text(rendered)
        self.assertEqual("org_example", config.organization_id)
        self.assertEqual("build_example", config.build_id)

    def test_example_template_reproduces_one_canonical_secret_free_sdk_profile(self) -> None:
        rendered_config, rendered_profile = compile_config_artifacts(self.template_text())
        self.assertEqual(SEALED_EXAMPLE.read_text(encoding="utf-8"), rendered_config)
        self.assertEqual(SDK_PROFILE_EXAMPLE.read_text(encoding="utf-8"), rendered_profile)
        self.assertEqual(rendered_profile.rstrip("\n"), canonical_json(json.loads(rendered_profile)))
        self.assertEqual(1, rendered_profile.count("\n"))
        profile = json.loads(rendered_profile)
        self.assertEqual(SDK_PROFILE_CONTRACT, profile["contract_version"])
        self.assertEqual("https://qa.example.com", profile["backend_origin"])
        self.assertEqual(
            profile["transport_configuration_digest"],
            profile["build_identity"]["transport_configuration_digest"],
        )
        self.assertEqual(
            profile["build_identity"]["build_identity_digest"],
            profile["capture_scope_policy"]["build_identity_digest"],
        )
        self.assertEqual("org_example", profile["capture_scope_policy"]["organization_id"])
        self.assertEqual("required", profile["capture_scope_policy"]["consent"]["microphone"])
        subject = dict(profile)
        subject.pop("profile_digest")
        self.assertEqual(digest(subject), profile["profile_digest"])
        self.assertFalse(
            {"token", "secret", "password", "api_key"}
            & {key.casefold() for key in self._walk_keys(profile)}
        )

    @staticmethod
    def _walk_keys(value: object) -> list[str]:
        keys: list[str] = []
        if isinstance(value, dict):
            for key, item in value.items():
                keys.append(key)
                keys.extend(ConfigToolTests._walk_keys(item))
        elif isinstance(value, list):
            for item in value:
                keys.extend(ConfigToolTests._walk_keys(item))
        return keys

    def test_compilation_uses_startup_parser_without_creating_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "must-not-exist"
            document = self.template_document()
            document["state_directory"] = str(state)
            rendered = compile_config_template(self.render(document))
            config = parse_config_text(rendered)
            self.assertEqual(state, config.state_directory)
            self.assertFalse(state.exists())

    def test_transport_change_reseals_every_dependent_digest(self) -> None:
        original_config, original_profile_text = compile_config_artifacts(self.template_text())
        original = json.loads(original_config)
        original_profile = json.loads(original_profile_text)
        document = self.template_document()
        document["backend_origin"] = "HTTPS://Other.Example:443/"
        changed_config, changed_profile_text = compile_config_artifacts(self.render(document))
        changed = json.loads(changed_config)
        changed_profile = json.loads(changed_profile_text)
        self.assertEqual("https://other.example", changed["backend_origin"])
        transport = changed["build_identity"]["transport_configuration_digest"]
        self.assertEqual(
            transport,
            changed["approved_handoff"]["build_identity"]["sdk"][
                "configuration_digest"
            ],
        )
        self.assertNotEqual(
            original["build_identity"]["transport_configuration_digest"],
            transport,
        )
        self.assertNotEqual(
            original["build_identity"]["build_identity_digest"],
            changed["build_identity"]["build_identity_digest"],
        )
        self.assertNotEqual(
            original["approved_handoff"]["build_identity"][
                "build_identity_digest"
            ],
            changed["approved_handoff"]["build_identity"][
                "build_identity_digest"
            ],
        )
        self.assertEqual("https://other.example", changed_profile["backend_origin"])
        self.assertEqual(
            changed["build_identity"],
            changed_profile["build_identity"],
        )
        self.assertNotEqual(
            original_profile["profile_digest"],
            changed_profile["profile_digest"],
        )
        parse_config_text(self.render(changed))

    def test_native_binary_digest_reseals_only_the_handoff_projection(self) -> None:
        original_config_text, original_profile_text = compile_config_artifacts(
            self.template_text()
        )
        original_config = json.loads(original_config_text)
        document = self.template_document()
        measured_digest = "sha256:" + "9" * 64
        document["approved_handoff"]["build_identity"]["mobile"][
            "native_binary_digest"
        ] = measured_digest

        changed_config_text, changed_profile_text = compile_config_artifacts(
            self.render(document)
        )
        changed_config = json.loads(changed_config_text)

        self.assertEqual(
            measured_digest,
            changed_config["approved_handoff"]["build_identity"]["mobile"][
                "native_binary_digest"
            ],
        )
        self.assertNotEqual(
            original_config["approved_handoff"]["build_identity"][
                "build_identity_digest"
            ],
            changed_config["approved_handoff"]["build_identity"][
                "build_identity_digest"
            ],
        )
        self.assertEqual(
            original_config["build_identity"],
            changed_config["build_identity"],
        )
        self.assertEqual(original_profile_text, changed_profile_text)

    def test_scope_policy_is_an_exact_projection_of_operator_pins(self) -> None:
        document = self.template_document()
        document["organization_id"] = "org_changed"
        document["project_id"] = "project_changed"
        document["application_id"] = "app_changed"
        document["consent_contract"] = "tacua.consent-custom-v1"
        document["raw_retention_days"] = 12
        document["derived_retention_days"] = 12
        document["approved_handoff"]["build_identity"]["organization_id"] = "org_changed"
        document["approved_handoff"]["build_identity"]["project_id"] = "project_changed"
        _config, profile_text = compile_config_artifacts(self.render(document))
        policy = json.loads(profile_text)["capture_scope_policy"]
        self.assertEqual(
            {
                "application_id": "app_changed",
                "build_id": "build_example",
                "build_identity_digest": json.loads(profile_text)["build_identity"]["build_identity_digest"],
                "capture_scope": "app_only",
                "consent": {
                    "diagnostics": "required",
                    "microphone": "required",
                    "policy_version": "tacua.consent-custom-v1",
                    "raw_media_upload": "required",
                    "screen_recording": "required",
                },
                "contract_version": "tacua.capture-scope-policy@1.0.0",
                "organization_id": "org_changed",
                "project_id": "project_changed",
                "protocol_version": "tacua.sdk-backend@1.0.0",
                "retention": {
                    "derived_data_days": 12,
                    "policy_version": "tacua.retention-v1",
                    "raw_media_days": 12,
                },
            },
            policy,
        )

    def test_compilation_rejects_split_v1_retention_boundaries(self) -> None:
        document = self.template_document()
        document["raw_retention_days"] = 20
        document["derived_retention_days"] = 21
        with self.assertRaisesRegex(
            ConfigError,
            "V1 raw and derived retention periods must use one session boundary",
        ):
            compile_config_artifacts(self.render(document))

    def test_fails_closed_on_noncanonical_malformed_and_inconsistent_templates(self) -> None:
        malformed = self.template_text().replace(
            '  "organization_id": "org_example",',
            '  "organization_id": "org_example",\n  "organization_id": "org_other",',
            1,
        )
        float_value = self.template_text().replace('"listen_port": 8080', '"listen_port": 8080.5')
        unsafe_integer = self.template_text().replace(
            '"listen_port": 8080', '"listen_port": 9007199254740992'
        )
        oversized_integer_token = self.template_text().replace(
            '"listen_port": 8080', '"listen_port": ' + "9" * 5_000
        )
        excessive_nesting = self.template_text().replace(
            '"reviewer_id": "reviewer_owner"',
            '"reviewer_id": '
            + "[" * 65
            + '"reviewer_owner"'
            + "]" * 65,
        )
        non_nfc = self.template_text().replace("self-hosted-example", "Cafe\u0301")
        escaped_surrogate = self.template_text().replace(
            "self-hosted-example", r"\ud800"
        )
        stale_digest = self.template_text().replace(
            DERIVE_MARKER,
            "sha256:" + "0" * 64,
            1,
        )

        inconsistent = self.template_document()
        inconsistent["approved_handoff"]["build_identity"]["organization_id"] = (
            "org_other"
        )
        secret_bearing = self.template_document()
        secret_bearing["admin_secret"] = "must-never-be-consumed"

        for serialized in (
            malformed,
            float_value,
            unsafe_integer,
            oversized_integer_token,
            excessive_nesting,
            non_nfc,
            escaped_surrogate,
            stale_digest,
            self.render(inconsistent),
            self.render(secret_bearing),
        ):
            with self.subTest(serialized=serialized[:80]), self.assertRaises(ConfigError):
                compile_config_template(serialized)

    def test_check_mode_never_writes_and_detects_stale_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = root / "template.json"
            output = root / "config.json"
            sdk_profile = root / "sdk-profile.json"
            template.write_text(self.template_text(), encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    0,
                    main(
                        [
                            str(template),
                            "--output",
                            str(output),
                            "--sdk-profile-output",
                            str(sdk_profile),
                        ]
                    ),
                )
            self.assertEqual(0o644, os.stat(output).st_mode & 0o777)
            self.assertEqual(0o644, os.stat(sdk_profile).st_mode & 0o777)
            expected = output.read_bytes()
            expected_profile = sdk_profile.read_bytes()
            before = output.stat().st_mtime_ns
            profile_before = sdk_profile.stat().st_mtime_ns
            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    0,
                    main(
                        [
                            str(template),
                            "--output",
                            str(output),
                            "--sdk-profile-output",
                            str(sdk_profile),
                            "--check",
                        ]
                    ),
                )
            self.assertEqual(expected, output.read_bytes())
            self.assertEqual(expected_profile, sdk_profile.read_bytes())
            self.assertEqual(before, output.stat().st_mtime_ns)
            self.assertEqual(profile_before, sdk_profile.stat().st_mtime_ns)

            output.write_bytes(expected + b" ")
            stale = output.read_bytes()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    1,
                    main([str(template), "--output", str(output), "--check"]),
                )
            self.assertEqual(stale, output.read_bytes())

            output.write_bytes(expected)
            sdk_profile.write_bytes(expected_profile + b" ")
            stale_profile = sdk_profile.read_bytes()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    1,
                    main(
                        [
                            str(template),
                            "--output",
                            str(output),
                            "--sdk-profile-output",
                            str(sdk_profile),
                            "--check",
                        ]
                    ),
                )
            self.assertEqual(stale_profile, sdk_profile.read_bytes())

    def test_stdout_and_check_only_modes_do_not_require_an_output_file(self) -> None:
        with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()):
            self.assertEqual(0, main([str(TEMPLATE)]))
            parse_config_text(stdout.getvalue())
        with redirect_stderr(io.StringIO()):
            self.assertEqual(0, main([str(TEMPLATE), "--check"]))

    def test_output_cannot_overwrite_the_template_itself(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            template = Path(temporary) / "template.json"
            template.write_text(self.template_text(), encoding="utf-8")
            before = template.read_bytes()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    1,
                    main([str(template), "--output", str(template)]),
                )
            self.assertEqual(before, template.read_bytes())

            shared_output = Path(temporary) / "same-output.json"
            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    1,
                    main(
                        [
                            str(template),
                            "--output",
                            str(shared_output),
                            "--sdk-profile-output",
                            str(shared_output),
                        ]
                    ),
                )
            self.assertFalse(shared_output.exists())
            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    1,
                    main(
                        [
                            str(template),
                            "--output",
                            str(Path(temporary) / "config.json"),
                            "--sdk-profile-output",
                            str(template),
                        ]
                    ),
                )
            self.assertEqual(before, template.read_bytes())

    def test_sdk_profile_output_requires_a_separate_config_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, redirect_stderr(io.StringIO()):
            profile = Path(temporary) / "sdk-profile.json"
            self.assertEqual(
                1,
                main([str(TEMPLATE), "--sdk-profile-output", str(profile)]),
            )
            self.assertFalse(profile.exists())

    def test_output_metadata_and_contents_are_synced_before_publication(self) -> None:
        real_fchmod = os.fchmod
        real_fsync = os.fsync
        real_replace = os.replace
        calls: list[str] = []
        fsync_count = 0

        def recording_fchmod(descriptor: int, mode: int) -> None:
            calls.append("chmod")
            real_fchmod(descriptor, mode)

        def recording_fsync(descriptor: int) -> None:
            nonlocal fsync_count
            fsync_count += 1
            calls.append("file_fsync" if fsync_count == 1 else "directory_fsync")
            real_fsync(descriptor)

        def recording_replace(source: Path, destination: Path) -> None:
            calls.append("replace")
            real_replace(source, destination)

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "config.json"
            with (
                patch.object(config_tool.os, "fchmod", side_effect=recording_fchmod),
                patch.object(config_tool.os, "fsync", side_effect=recording_fsync),
                patch.object(config_tool.os, "replace", side_effect=recording_replace),
            ):
                config_tool._write_public_config(output, "{}\n")

            self.assertEqual(
                ["chmod", "file_fsync", "replace", "directory_fsync"],
                calls,
            )
            self.assertEqual(b"{}\n", output.read_bytes())
            self.assertEqual(0o644, os.stat(output).st_mode & 0o777)

    def test_directory_sync_failure_is_reported_after_atomic_publication(self) -> None:
        real_fsync = os.fsync
        fsync_count = 0

        def failing_directory_fsync(descriptor: int) -> None:
            nonlocal fsync_count
            fsync_count += 1
            if fsync_count == 2:
                raise OSError("injected directory sync failure")
            real_fsync(descriptor)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = root / "template.json"
            output = root / "config.json"
            template.write_text(self.template_text(), encoding="utf-8")
            stderr = io.StringIO()
            with (
                patch.object(
                    config_tool.os,
                    "fsync",
                    side_effect=failing_directory_fsync,
                ),
                redirect_stderr(stderr),
            ):
                self.assertEqual(
                    1,
                    main([str(template), "--output", str(output)]),
                )

            self.assertEqual(2, fsync_count)
            self.assertTrue(output.is_file())
            self.assertEqual(
                compile_config_template(self.template_text()).encode("utf-8"),
                output.read_bytes(),
            )
            self.assertIn("cannot durably publish", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
