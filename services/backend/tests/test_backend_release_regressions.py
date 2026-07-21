# SPDX-License-Identifier: Apache-2.0
"""Release-boundary regressions found during the SDK backend audit."""

from __future__ import annotations

import copy
from contextlib import closing
from dataclasses import replace
from datetime import timedelta
import io
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from test_backend import BackendHarness, fixture, instant

from tacua_backend.contracts import runtime_seal, seal
from tacua_backend.service import ApiError, PilotBackend


class BackendReleaseRegressionTests(BackendHarness):
    def test_exact_upload_replay_survives_same_second_credential_rotation(self) -> None:
        launch_request, launch_receipt, _, _ = self.start_session()
        session_id = launch_receipt["session_id"]
        segment_request, _, original_response = self.store_segment(
            session_id,
            launch_receipt["credential"]["credential_id"],
            launch_request["credential"]["secret"],
            accepted_at="2026-07-21T10:02:00Z",
        )
        self.resume_session(
            session_id,
            launch_receipt["credential"]["credential_id"],
            state="receiving",
            completion_id=None,
            credential_id="credential_same_second",
            secret="U" * 43,
            exchange_id="exchange_same_second",
            requested_at="2026-07-21T10:02:00Z",
            accepted_at="2026-07-21T10:02:00Z",
        )

        with closing(sqlite3.connect(self.backend.db_path)) as connection:
            original = connection.execute(
                "SELECT revoked_at FROM credentials WHERE credential_id = ?",
                (launch_receipt["credential"]["credential_id"],),
            ).fetchone()[0]
            rotated = connection.execute(
                "SELECT issued_at FROM credentials WHERE credential_id = ?",
                ("credential_same_second",),
            ).fetchone()[0]
        self.assertEqual("2026-07-21T10:02:01Z", original)
        self.assertEqual(original, rotated)

        # The logical one-second advance is persisted so a restart cannot make
        # the new credential temporarily not-yet-valid when wall time is still
        # on the colliding second.
        self.backend = PilotBackend(
            self.config,
            self.admin_secret,
            clock=self.clock,
        )

        recovered = self.backend.upload_segment(
            session_id,
            segment_request["sequence"],
            segment_request["segment_id"],
            "U" * 43,
            segment_request,
            io.BytesIO(b"a replay must not consume these bytes"),
        )

        self.assertEqual(200, recovered.status)
        self.assertEqual(original_response, recovered.body)

    def test_launch_rejects_consent_outside_the_grant_to_exchange_window(self) -> None:
        for index, granted_at in enumerate(
            ("2026-07-21T09:57:00Z", "2099-01-01T00:00:00Z")
        ):
            with self.subTest(granted_at=granted_at):
                grant = self.backend.create_launch_code(
                    {
                        "exchange_kind": "start_session",
                        "build_id": self.build["build_id"],
                    }
                )
                scope = copy.deepcopy(self.scope)
                scope["consent"]["granted_at"] = granted_at
                scope = seal(scope)
                request = fixture("launch-exchange-request")
                request["exchange_id"] = f"exchange_bad_consent_{index}"
                request["credential"]["credential_id"] = f"credential_bad_consent_{index}"
                request["launch_code"] = grant["launch_code"]
                request["scope"] = scope
                request = seal(request)

                with self.assertRaises(ApiError) as captured:
                    self.backend.exchange_launch_code(request)
                self.assertEqual(422, captured.exception.status)
                self.assertEqual("INVALID_CHRONOLOGY", captured.exception.code)
                self.assertEqual(
                    "consent chronology is outside the authorized launch exchange",
                    captured.exception.message,
                )

    def test_completion_rejects_manifest_retention_outside_session_policy(self) -> None:
        for index, (field, value) in enumerate(
            (
                ("policy_version", "other-policy"),
                ("raw_media_expires_at", "2026-08-20T09:57:00Z"),
                ("derived_data_expires_at", "2099-01-01T00:00:00Z"),
                ("deletion_status", "deleted"),
            )
        ):
            with self.subTest(field=field):
                self.clock.set("2026-07-21T09:57:01Z")
                credential_id = f"credential_retention_{index}"
                secret = ("S", "T", "V", "W")[index] * 43
                _, launch_receipt, _, _ = self.start_session(
                    credential_id=credential_id,
                    secret=secret,
                    exchange_id=f"exchange_retention_{index}",
                )
                session_id = launch_receipt["session_id"]
                _, segment_receipt, _ = self.store_segment(
                    session_id,
                    credential_id,
                    secret,
                )
                _, diagnostic_receipt, _ = self.store_diagnostic(
                    session_id,
                    credential_id,
                    secret,
                )
                request = self.completion_request(
                    session_id,
                    credential_id,
                    [segment_receipt],
                    [diagnostic_receipt],
                )
                request["capture_manifest"]["retention"][field] = value
                request["capture_manifest"] = runtime_seal(request["capture_manifest"])
                request = seal(request)
                self.clock.set("2026-07-21T10:02:06Z")

                with self.assertRaises(ApiError) as captured:
                    self.backend.complete_session(
                        session_id,
                        request["completion_id"],
                        secret,
                        request,
                    )
                self.assertEqual(422, captured.exception.status)
                self.assertEqual("RETENTION_BINDING_MISMATCH", captured.exception.code)

    def test_sdk_preauthorization_erases_at_the_exact_retention_boundary(self) -> None:
        launch_request, launch_receipt, _, _ = self.start_session()
        session_id = launch_receipt["session_id"]
        self.store_segment(
            session_id,
            launch_receipt["credential"]["credential_id"],
            launch_request["credential"]["secret"],
        )
        expiry = instant(
            self.backend.get_session(session_id)["retention"]["raw_media_expires_at"]
        )
        self.clock.set(expiry)

        with self.assertRaises(ApiError) as captured:
            self.backend.preauthorize_sdk_route(
                session_id,
                launch_request["credential"]["secret"],
            )
        self.assertEqual(410, captured.exception.status)
        self.assertEqual("SESSION_RETENTION_EXPIRED", captured.exception.code)
        self.assertFalse((self.backend.objects_dir / session_id).exists())
        self.assertEqual("deleted", self.backend.get_session(session_id)["state"])

    def test_admin_review_erases_before_returning_at_retention_boundary(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        self.backend.persist_candidate_bundle(
            candidate=candidate,
            evidence_manifest=manifest,
            previews=previews,
        )
        expiry = instant(
            self.backend.get_session(session_id)["retention"]["raw_media_expires_at"]
        )
        self.clock.set(expiry - timedelta(seconds=1))
        self.assertEqual([session_id], [item["session_id"] for item in self.backend.list_sessions()])
        self.assertEqual(1, len(self.backend.list_jobs()))
        self.assertEqual(1, len(self.backend.list_candidates(session_id)))

        self.clock.set(expiry)
        with self.assertRaises(ApiError) as captured:
            self.backend.list_candidates(session_id)
        self.assertEqual(410, captured.exception.status)
        self.assertEqual("SESSION_DELETED", captured.exception.code)
        self.assertEqual([], self.backend.list_sessions())
        self.assertEqual([], self.backend.list_jobs())
        self.assertFalse((self.backend.objects_dir / session_id).exists())
        self.assertEqual("deleted", self.backend.get_session(session_id)["state"])

    def test_expired_review_data_stays_hidden_when_physical_erasure_must_retry(self) -> None:
        _launch_request, launch_receipt, _, _ = self.start_session()
        session_id = launch_receipt["session_id"]
        expiry = instant(
            self.backend.get_session(session_id)["retention"]["raw_media_expires_at"]
        )
        self.clock.set(expiry)

        with patch.object(
            self.backend,
            "_erase_session_objects",
            side_effect=OSError("simulated storage outage"),
        ):
            self.assertEqual([], self.backend.list_sessions())
            with self.assertRaises(ApiError) as captured:
                self.backend.get_session(session_id)
            self.assertEqual(410, captured.exception.status)
            self.assertEqual("SESSION_DELETED", captured.exception.code)

        recovered = self.backend.sweep_expired_sessions(now=expiry)
        self.assertEqual([session_id], recovered["deleted_session_ids"])
        self.assertEqual("deleted", self.backend.get_session(session_id)["state"])

    def test_database_symlink_is_rejected_before_sqlite_connects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            state = parent / "state"
            state.mkdir()
            outside = parent / "outside.sqlite3"
            (state / "tacua.sqlite3").symlink_to(outside)
            config = replace(self.config, state_directory=state)

            with self.assertRaisesRegex(ValueError, "database path is not a regular file"):
                PilotBackend(config, self.admin_secret, clock=self.clock)
            self.assertFalse(outside.exists())

    def test_v1_rejects_split_raw_and_derived_retention_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = replace(
                self.config,
                state_directory=Path(temporary),
                derived_retention_days=self.config.raw_retention_days - 1,
            )
            with self.assertRaisesRegex(ValueError, "one session boundary"):
                PilotBackend(config, self.admin_secret, clock=self.clock)

    def test_first_object_publish_fsyncs_each_created_directory_level(self) -> None:
        launch_request, launch_receipt, _, _ = self.start_session()
        session_id = launch_receipt["session_id"]
        with patch.object(
            self.backend,
            "_fsync_directory",
            wraps=self.backend._fsync_directory,
        ) as fsync_directory:
            self.store_segment(
                session_id,
                launch_receipt["credential"]["credential_id"],
                launch_request["credential"]["secret"],
            )

        synced = [Path(call.args[0]).resolve() for call in fsync_directory.call_args_list]
        self.assertIn(self.backend.objects_dir.resolve(), synced)
        self.assertIn((self.backend.objects_dir / session_id).resolve(), synced)
        self.assertIn(
            (self.backend.objects_dir / session_id / "segments").resolve(), synced
        )
        self.assertIn(self.backend.temp_dir.resolve(), synced)


class BackendContainerRegressionTests(unittest.TestCase):
    def test_image_contains_the_runtime_ticket_candidate_contract(self) -> None:
        repository = Path(__file__).resolve().parents[3]
        dockerfile = (repository / "services/backend/Dockerfile").read_text(
            encoding="utf-8"
        )
        dockerignore = (
            repository / "services/backend/Dockerfile.dockerignore"
        ).read_text(encoding="utf-8")

        for suffix in ("src/", "schemas/"):
            contract_path = f"contracts/ticket-candidate/{suffix}"
            self.assertIn(f"COPY --chown=root:root {contract_path}", dockerfile)
            self.assertIn(f"!{contract_path}", dockerignore)


if __name__ == "__main__":
    unittest.main()
