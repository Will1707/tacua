# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from contextlib import closing
from dataclasses import replace
from email.message import Message
from hashlib import sha256
import io
import json
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from tacua_backend import CAPTURE_CONTRACT, DIAGNOSTIC_CONTRACT, PROCESSING_JOB_CONTRACT  # noqa: E402
from tacua_backend.config import ConfigError, PilotConfig, load_config  # noqa: E402
from tacua_backend.contracts import seal as seal_contract, validate as validate_contract  # noqa: E402
from tacua_backend.http_api import PilotRequestHandler  # noqa: E402
from tacua_backend.service import ApiError, PilotBackend  # noqa: E402


def digest(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


class PilotBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.admin_secret = secrets.token_urlsafe(48).encode()
        self.config = PilotConfig(
            organization_id="org_test",
            project_id="project_test",
            application_id="app_test",
            bundle_identifier="com.example.test.qa",
            build_id="build_test",
            build_identity_digest="sha256:" + "2" * 64,
            consent_contract="tacua-consent-v1",
            state_directory=Path(self.temporary.name),
            max_segment_bytes=1024,
            max_diagnostic_bytes=32768,
        )
        self.backend = PilotBackend(self.config, self.admin_secret)

    def assert_api_error(self, status: int, code: str, callback) -> ApiError:
        with self.assertRaises(ApiError) as captured:
            callback()
        self.assertEqual(status, captured.exception.status)
        self.assertEqual(code, captured.exception.code)
        return captured.exception

    def make_session(self) -> tuple[str, str, str]:
        launch = self.backend.create_launch_code(self.config.scope)
        exchanged = self.backend.exchange_launch_code(
            {"launch_code": launch["launch_code"], "scope": self.config.scope}
        )
        return exchanged["session_id"], exchanged["upload_token"], launch["launch_code"]

    def put_segment(self, session_id: str, token: str, sequence: int, content: bytes) -> dict:
        return self.backend.upload_segment(
            session_id,
            sequence,
            f"segment_{sequence}",
            token,
            io.BytesIO(content),
            len(content),
            digest(content),
        )

    def diagnostic_document(self, session_id: str, envelope_id: str) -> bytes:
        fixture = SOURCE.parents[2] / "contracts/runtime/fixtures/positive/diagnostics.json"
        document = json.loads(fixture.read_text(encoding="utf-8"))
        document.update(
            {
                "organization_id": self.config.organization_id,
                "project_id": self.config.project_id,
                "build_id": self.config.build_id,
                "build_identity_digest": self.config.build_identity_digest,
                "session_id": session_id,
                "envelope_id": envelope_id,
            }
        )
        for evidence in document["evidence"]:
            if evidence["reference"] is not None:
                locator = evidence["reference"]["locator"]
                locator["organization_id"] = self.config.organization_id
                locator["project_id"] = self.config.project_id
        document = seal_contract(document)
        validate_contract(document)
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()

    def put_diagnostic(self, session_id: str, token: str, envelope_id: str = "env_test") -> dict:
        document = self.diagnostic_document(session_id, envelope_id)
        return self.backend.upload_diagnostic(
            session_id, envelope_id, token, document, digest(document)
        )

    def completion(
        self,
        session_id: str,
        segments: list[tuple[int, bytes]],
        receipts: dict[int, dict],
        diagnostics: list[str],
    ) -> dict:
        session = self.backend.get_session(session_id)
        started_at = session["created_at"]
        contract_receipts = []
        segment_documents = []
        for sequence, content in segments:
            receipt = receipts.get(sequence)
            if receipt is None:
                receipt = {
                    "segment_id": f"segment_{sequence}",
                    "object_id": f"object_{sequence}",
                    "size_bytes": len(content),
                    "content_digest": digest(content),
                    "received_at": started_at,
                    "receipt_digest": "sha256:" + "0" * 64,
                }
            contract_receipts.append(
                {key: receipt[key] for key in (
                    "segment_id", "object_id", "size_bytes", "content_digest",
                    "received_at", "receipt_digest"
                )}
            )
            segment_documents.append(
                {
                    "segment_id": receipt["segment_id"],
                    "sequence": sequence,
                    "time_range": {
                        "start_ms": sequence * 1000,
                        "end_ms": (sequence + 1) * 1000,
                        "clock": "session_monotonic",
                    },
                    "finalized": True,
                    "availability": "available",
                    "content": {
                        "content_type": "video/quicktime",
                        "size_bytes": len(content),
                        "content_digest": digest(content),
                        "sidecar_digest": digest(f"sidecar-{sequence}".encode()),
                    },
                    "unavailable": None,
                }
            )
        duration = len(segment_documents) * 1000
        manifest = {
            "contract_version": CAPTURE_CONTRACT,
            "media_type": "application/vnd.tacua.capture-upload-manifest+json;version=1.0.0",
            "organization_id": self.config.organization_id,
            "project_id": self.config.project_id,
            "build_id": self.config.build_id,
            "build_identity_digest": self.config.build_identity_digest,
            "session_id": session_id,
            "manifest_version": 1,
            "capture_state": "complete",
            "started_at": started_at,
            "ended_at": started_at,
            "monotonic_duration_ms": duration,
            "capture_scope": "app_only",
            "streams": {
                "app_video": "enabled",
                "app_audio": "enabled",
                "microphone": "enabled",
                "diagnostics": "enabled",
            },
            "segments": segment_documents,
            "gaps": [],
            "upload": {
                "state": "complete",
                "protocol": "segmented-resumable-v1",
                "remote_session_id": session_id,
                "receipts": contract_receipts,
                "last_error": None,
                "completed_at": started_at,
            },
            "retention": {
                "policy_version": "tacua.retention@1.0.0",
                "raw_media_expires_at": session["retention"]["raw_media_expires_at"],
                "derived_data_expires_at": session["retention"]["raw_media_expires_at"],
                "deletion_status": "active",
            },
            "manifest_digest": "sha256:" + "0" * 64,
        }
        manifest = seal_contract(manifest)
        validate_contract(manifest)
        return {
            "capture_manifest": manifest,
            "diagnostic_envelope_ids": diagnostics,
        }

    def test_health_publishes_versions_and_non_production_status(self) -> None:
        health = self.backend.health()
        self.assertEqual("ok", health["status"])
        self.assertFalse(health["production_ready"])
        self.assertEqual(CAPTURE_CONTRACT, health["contracts"]["capture"])
        self.assertEqual(PROCESSING_JOB_CONTRACT, health["contracts"]["processing_job"])

    def test_launch_scope_one_time_exchange_and_hash_only_storage(self) -> None:
        wrong = dict(self.config.scope)
        wrong["build_id"] = "build_other"
        self.assert_api_error(403, "SCOPE_NOT_ALLOWED", lambda: self.backend.create_launch_code(wrong))

        launch = self.backend.create_launch_code(self.config.scope)
        wrong_exchange = {"launch_code": launch["launch_code"], "scope": wrong}
        self.assert_api_error(
            403, "SCOPE_MISMATCH", lambda: self.backend.exchange_launch_code(wrong_exchange)
        )
        exchange_body = {"launch_code": launch["launch_code"], "scope": self.config.scope}
        exchanged = self.backend.exchange_launch_code(exchange_body)
        self.assertEqual(self.config.scope, exchanged["scope"])
        self.assertEqual("raw-30d-v1", exchanged["retention_policy"])
        self.assert_api_error(
            409, "LAUNCH_CODE_CONSUMED", lambda: self.backend.exchange_launch_code(exchange_body)
        )

        with closing(sqlite3.connect(self.backend.db_path)) as conn:
            launch_hash = conn.execute("SELECT token_hash FROM launch_codes").fetchone()[0]
            upload_hash = conn.execute("SELECT token_hash FROM upload_tokens").fetchone()[0]
            launch_columns = {row[1] for row in conn.execute("PRAGMA table_info(launch_codes)")}
            token_columns = {row[1] for row in conn.execute("PRAGMA table_info(upload_tokens)")}
        self.assertTrue(launch_hash.startswith("sha256:"))
        self.assertTrue(upload_hash.startswith("sha256:"))
        self.assertNotEqual(launch["launch_code"], launch_hash)
        self.assertNotEqual(exchanged["upload_token"], upload_hash)
        self.assertNotIn("launch_code", launch_columns)
        self.assertNotIn("upload_token", token_columns)

    def test_admin_and_upload_authentication_and_cross_session_scope(self) -> None:
        self.assert_api_error(401, "ADMIN_AUTH_REQUIRED", lambda: self.backend.authenticate_admin(None))
        self.assert_api_error(
            401, "ADMIN_AUTH_REQUIRED", lambda: self.backend.authenticate_admin("not-the-secret")
        )
        self.backend.authenticate_admin(self.admin_secret.decode())

        first_session, first_token, _ = self.make_session()
        second_session, _, _ = self.make_session()
        content = b"media"
        self.assert_api_error(
            401,
            "UPLOAD_AUTH_REQUIRED",
            lambda: self.backend.upload_segment(
                first_session, 0, "segment_0", None, io.BytesIO(content), len(content), digest(content)
            ),
        )
        self.assert_api_error(
            403,
            "UPLOAD_SCOPE_MISMATCH",
            lambda: self.backend.upload_segment(
                second_session, 0, "segment_0", first_token, io.BytesIO(content), len(content), digest(content)
            ),
        )

    def test_path_traversal_and_segment_index_are_rejected(self) -> None:
        session_id, token, _ = self.make_session()
        self.assert_api_error(400, "INVALID_IDENTIFIER", lambda: self.backend.get_session("../outside"))
        self.assert_api_error(
            400,
            "INVALID_SEGMENT_INDEX",
            lambda: self.backend.upload_segment(
                session_id, 2048, "segment_2048", token, io.BytesIO(b"x"), 1, digest(b"x")
            ),
        )
        self.assertFalse((Path(self.temporary.name).parent / "outside").exists())

    def test_length_and_digest_mismatches_publish_nothing(self) -> None:
        session_id, token, _ = self.make_session()
        self.assert_api_error(
            400,
            "CONTENT_LENGTH_MISMATCH",
            lambda: self.backend.upload_segment(
                session_id, 0, "segment_0", token, io.BytesIO(b"four"), 3, digest(b"four")
            ),
        )
        self.assert_api_error(
            400,
            "CONTENT_LENGTH_MISMATCH",
            lambda: self.backend.upload_segment(
                session_id, 0, "segment_0", token, io.BytesIO(b"four"), 5, digest(b"four")
            ),
        )
        self.assert_api_error(
            422,
            "CONTENT_DIGEST_MISMATCH",
            lambda: self.backend.upload_segment(
                session_id, 0, "segment_0", token, io.BytesIO(b"four"), 4, digest(b"five")
            ),
        )
        self.assertEqual([], self.backend.get_session(session_id)["segments"])
        self.assertEqual([], list(self.backend.media_dir.rglob("*.segment")))

    def test_same_content_retry_is_idempotent_and_conflict_is_rejected(self) -> None:
        session_id, token, _ = self.make_session()
        first = self.put_segment(session_id, token, 0, b"first")
        retry = self.put_segment(session_id, token, 0, b"first")
        self.assertFalse(first["idempotent_retry"])
        self.assertTrue(retry["idempotent_retry"])
        self.assertEqual(first["receipt_digest"], retry["receipt_digest"])
        self.assertEqual(first["object_id"], retry["object_id"])
        self.assert_api_error(
            409,
            "SEGMENT_CONFLICT",
            lambda: self.put_segment(session_id, token, 0, b"different"),
        )
        self.assert_api_error(
            409,
            "SEGMENT_ID_CONFLICT",
            lambda: self.backend.upload_segment(
                session_id,
                1,
                "segment_0",
                token,
                io.BytesIO(b"second-index"),
                len(b"second-index"),
                digest(b"second-index"),
            ),
        )
        path = self.backend.media_dir / session_id / "0000.segment"
        self.assertEqual(b"first", path.read_bytes())

    def test_idempotent_retry_verifies_the_published_file(self) -> None:
        session_id, token, _ = self.make_session()
        self.put_segment(session_id, token, 0, b"first")
        path = self.backend.media_dir / session_id / "0000.segment"
        path.write_bytes(b"other")
        self.assert_api_error(
            500,
            "STORAGE_INCONSISTENT",
            lambda: self.put_segment(session_id, token, 0, b"first"),
        )

    def test_database_failure_after_publication_removes_uncommitted_media(self) -> None:
        session_id, token, _ = self.make_session()
        original_audit = self.backend._audit

        def fail_after_publish(conn, event_type, *args):
            if event_type == "segment_stored":
                raise sqlite3.OperationalError("injected commit-path failure")
            return original_audit(conn, event_type, *args)

        self.backend._audit = fail_after_publish
        with self.assertRaises(sqlite3.OperationalError):
            self.put_segment(session_id, token, 0, b"uncommitted")
        self.assertFalse((self.backend.media_dir / session_id / "0000.segment").exists())
        self.assertEqual([], self.backend.get_session(session_id)["segments"])

    def test_upload_auth_is_checked_before_stream_is_read(self) -> None:
        session_id, _, _ = self.make_session()

        class ExplodingStream:
            read_called = False

            def read(self, _size=-1):
                self.read_called = True
                raise AssertionError("unauthorized body was read")

        stream = ExplodingStream()
        self.assert_api_error(
            403,
            "UPLOAD_SCOPE_MISMATCH",
            lambda: self.backend.upload_segment(
                session_id, 0, "segment_0", "ut_" + "x" * 43,
                stream, 10, digest(b"x" * 10)
            ),
        )
        self.assertFalse(stream.read_called)

    def test_completion_rejects_missing_segment_then_enqueues_durable_job(self) -> None:
        session_id, token, _ = self.make_session()
        first = self.put_segment(session_id, token, 0, b"zero")
        diagnostic = self.put_diagnostic(session_id, token, "env_complete")
        body = self.completion(
            session_id,
            [(0, b"zero"), (1, b"one")],
            {0: first},
            ["env_complete"],
        )
        self.assert_api_error(
            409, "SEGMENT_SET_MISMATCH", lambda: self.backend.complete_session(session_id, token, body)
        )
        second = self.put_segment(session_id, token, 1, b"one")
        body = self.completion(
            session_id,
            [(0, b"zero"), (1, b"one")],
            {0: first, 1: second},
            ["env_complete"],
        )
        job = self.backend.complete_session(session_id, token, body)
        self.assertEqual("queued", job["status"])
        self.assertEqual(PROCESSING_JOB_CONTRACT, job["contract_version"])
        self.assertEqual(diagnostic["envelope_digest"], job["inputs"]["diagnostic_envelope_digests"][0])
        validate_contract(job)
        self.assertEqual(job, self.backend.get_job(job["job_id"]))
        self.assertEqual(job, self.backend.complete_session(session_id, token, body))
        conflicting_completion = json.loads(json.dumps(body))
        conflicting_completion["diagnostic_envelope_ids"] = ["env_other"]
        self.assert_api_error(
            409,
            "COMPLETION_CONFLICT",
            lambda: self.backend.complete_session(session_id, token, conflicting_completion),
        )
        manifest_path = self.backend.media_dir / session_id / "capture-manifest.json"
        self.assertTrue(manifest_path.is_file())
        self.assertEqual(body["capture_manifest"], json.loads(manifest_path.read_text()))
        self.assert_api_error(
            401,
            "UPLOAD_TOKEN_EXPIRED",
            lambda: self.put_segment(session_id, token, 2, b"late"),
        )
        original_manifest = manifest_path.read_bytes()
        manifest_path.write_bytes(b"x" * len(original_manifest))
        self.assert_api_error(
            500,
            "STORAGE_INCONSISTENT",
            lambda: self.backend.complete_session(session_id, token, body),
        )
        manifest_path.write_bytes(original_manifest)
        with self.backend._connect() as conn:
            conn.execute(
                "UPDATE upload_tokens SET expires_at = '2000-01-01T00:00:00Z' WHERE session_id = ?",
                (session_id,),
            )
        self.assert_api_error(
            401,
            "UPLOAD_TOKEN_EXPIRED",
            lambda: self.backend.complete_session(session_id, token, body),
        )
        self.backend.delete_session(session_id)
        cancelled = self.backend.get_job(job["job_id"])
        self.assertEqual("cancelled", cancelled["status"])
        self.assertEqual(2, cancelled["job_version"])
        self.assertEqual(job["job_digest"], cancelled["previous_job_digest"])
        validate_contract(cancelled)

    def test_completion_requires_the_exact_intact_diagnostic_set(self) -> None:
        session_id, token, _ = self.make_session()
        receipt = self.put_segment(session_id, token, 0, b"segment")
        self.put_diagnostic(session_id, token, "env_first")
        self.put_diagnostic(session_id, token, "env_second")
        subset = self.completion(
            session_id,
            [(0, b"segment")],
            {0: receipt},
            ["env_first"],
        )
        self.assert_api_error(
            409,
            "DIAGNOSTIC_SET_MISMATCH",
            lambda: self.backend.complete_session(session_id, token, subset),
        )
        complete = self.completion(
            session_id,
            [(0, b"segment")],
            {0: receipt},
            ["env_first", "env_second"],
        )
        diagnostic_path = self.backend.media_dir / session_id / "diagnostics/env_second.json"
        diagnostic_path.write_bytes(b"x" * diagnostic_path.stat().st_size)
        self.assert_api_error(
            500,
            "STORAGE_INCONSISTENT",
            lambda: self.backend.complete_session(session_id, token, complete),
        )

    def test_restart_preserves_session_token_and_idempotent_receipt(self) -> None:
        session_id, token, _ = self.make_session()
        first = self.put_segment(session_id, token, 0, b"persistent")
        restarted = PilotBackend(self.config, self.admin_secret)
        retry = restarted.upload_segment(
            session_id,
            0,
            "segment_0",
            token,
            io.BytesIO(b"persistent"),
            len(b"persistent"),
            digest(b"persistent"),
        )
        self.assertTrue(retry["idempotent_retry"])
        self.assertEqual(first["receipt_digest"], retry["receipt_digest"])
        self.assertEqual(1, len(restarted.get_session(session_id)["segments"]))

    def test_startup_reconciles_recognized_crash_orphans(self) -> None:
        session_id, _, _ = self.make_session()
        session_dir = self.backend.media_dir / session_id
        diagnostics_dir = session_dir / "diagnostics"
        diagnostics_dir.mkdir(parents=True)
        (session_dir / "0000.segment").write_bytes(b"orphan")
        (diagnostics_dir / "env_orphan.json").write_bytes(b"{}")
        (session_dir / "capture-manifest.json").write_bytes(b"{}")
        (self.backend.temp_dir / "upload-crash").write_bytes(b"partial")
        restarted = PilotBackend(self.config, self.admin_secret)
        self.assertFalse(session_dir.exists())
        self.assertEqual([], list(restarted.temp_dir.iterdir()))
        self.assertEqual("receiving", restarted.get_session(session_id)["state"])

    def test_startup_fails_closed_when_a_committed_session_directory_disappears(self) -> None:
        session_id, token, _ = self.make_session()
        self.put_segment(session_id, token, 0, b"committed")
        segment_path = self.backend.media_dir / session_id / "0000.segment"
        segment_path.unlink()
        segment_path.parent.rmdir()
        with self.assertRaisesRegex(ValueError, "committed segment is missing"):
            PilotBackend(self.config, self.admin_secret)

    def test_diagnostic_is_bounded_scoped_and_persistent(self) -> None:
        session_id, token, _ = self.make_session()
        envelope_id = "env_test"
        document = self.diagnostic_document(session_id, envelope_id)
        receipt = self.backend.upload_diagnostic(
            session_id, envelope_id, token, document, digest(document)
        )
        self.assertFalse(receipt["idempotent_retry"])
        retry = self.backend.upload_diagnostic(
            session_id, envelope_id, token, document, digest(document)
        )
        self.assertTrue(retry["idempotent_retry"])
        self.assertEqual(json.loads(document)["envelope_digest"], receipt["envelope_digest"])

        duplicate = b'{"contract_version":"first","contract_version":"second"}'
        self.assert_api_error(
            400,
            "INVALID_DIAGNOSTIC_JSON",
            lambda: self.backend.upload_diagnostic(
                session_id, "env_duplicate", token, duplicate, digest(duplicate)
            ),
        )
        incomplete = json.dumps(
            {
                "contract_version": DIAGNOSTIC_CONTRACT,
                "organization_id": self.config.organization_id,
                "project_id": self.config.project_id,
                "build_id": self.config.build_id,
                "build_identity_digest": self.config.build_identity_digest,
                "session_id": session_id,
                "envelope_id": "env_incomplete",
            }
        ).encode()
        self.assert_api_error(
            422,
            "DIAGNOSTIC_CONTRACT_INVALID",
            lambda: self.backend.upload_diagnostic(
                session_id, "env_incomplete", token, incomplete, digest(incomplete)
            ),
        )

        wrong = json.loads(document)
        wrong["build_id"] = "build_other"
        wrong["envelope_id"] = "env_other"
        wrong = seal_contract(wrong)
        wrong_raw = json.dumps(wrong, sort_keys=True, separators=(",", ":")).encode()
        self.assert_api_error(
            403,
            "DIAGNOSTIC_SCOPE_MISMATCH",
            lambda: self.backend.upload_diagnostic(
                session_id, "env_other", token, wrong_raw, digest(wrong_raw)
            ),
        )

        database_bytes = b"".join(
            path.read_bytes() for path in Path(self.temporary.name).glob("tacua.sqlite3*")
        )
        self.assertNotIn(b"Reviewer says the button uses the wrong copy", database_bytes)
        self.assert_api_error(
            413,
            "DIAGNOSTIC_SIZE_NOT_ALLOWED",
            lambda: self.backend.upload_diagnostic(
                session_id,
                "env_large",
                token,
                b"x" * (self.config.max_diagnostic_bytes + 1),
                digest(b"x" * (self.config.max_diagnostic_bytes + 1)),
            ),
        )

    def test_scoped_deletion_removes_raw_data_and_leaves_tombstone_job(self) -> None:
        session_id, token, _ = self.make_session()
        self.put_segment(session_id, token, 0, b"delete-me")
        envelope_id = "env_delete"
        diagnostic = self.diagnostic_document(session_id, envelope_id)
        self.backend.upload_diagnostic(session_id, envelope_id, token, diagnostic, digest(diagnostic))
        media_path = self.backend.media_dir / session_id / "0000.segment"
        self.assertTrue(media_path.exists())

        job = self.backend.delete_session(session_id)
        self.assertEqual("delete_session", job["job_type"])
        self.assertNotEqual(PROCESSING_JOB_CONTRACT, job["resource_version"])
        self.assertEqual("succeeded", job["status"])
        self.assertFalse(media_path.exists())
        tombstone = self.backend.get_session(session_id)
        self.assertEqual("deleted", tombstone["state"])
        self.assertEqual("deleted", tombstone["retention"]["deletion_status"])
        self.assertIsNone(tombstone["manifest_digest"])
        self.assertEqual([], tombstone["segments"])
        self.assertEqual([], tombstone["diagnostics"])
        self.assertEqual(job["job_id"], self.backend.delete_session(session_id)["job_id"])
        self.assert_api_error(
            401,
            "UPLOAD_TOKEN_EXPIRED",
            lambda: self.put_segment(session_id, token, 0, b"return"),
        )

        allowed_audit_columns = {
            "event_id",
            "event_type",
            "actor_kind",
            "organization_id",
            "project_id",
            "session_id",
            "outcome",
            "occurred_at",
        }
        self.assertTrue(self.backend.list_audit_events())
        self.assertTrue(all(set(event) == allowed_audit_columns for event in self.backend.list_audit_events()))

    def test_deletion_request_and_failure_are_durable_and_retryable(self) -> None:
        session_id, token, _ = self.make_session()
        self.put_segment(session_id, token, 0, b"retry-delete")
        original_delete = self.backend._delete_session_files

        def fail_delete(*_args):
            raise OSError("injected deletion failure")

        self.backend._delete_session_files = fail_delete
        self.assert_api_error(
            500,
            "STORAGE_DELETE_FAILED",
            lambda: self.backend.delete_session(session_id),
        )
        failed = next(job for job in self.backend.list_jobs() if job["job_type"] == "delete_session")
        self.assertEqual("failed", failed["status"])
        self.assertEqual(
            "deletion_requested",
            self.backend.get_session(session_id)["retention"]["deletion_status"],
        )
        self.backend._delete_session_files = original_delete
        succeeded = self.backend.delete_session(session_id)
        self.assertEqual(failed["job_id"], succeeded["job_id"])
        self.assertEqual("succeeded", succeeded["status"])

    def test_persisted_deployment_scope_fails_closed_on_config_change(self) -> None:
        self.make_session()
        changed = replace(self.config, build_id="build_other")
        with self.assertRaisesRegex(ValueError, "persisted scope"):
            PilotBackend(changed, self.admin_secret)


class PilotConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.secret_file = self.root / "admin-secret"
        self.secret_file.write_bytes(secrets.token_urlsafe(48).encode())

    def write_config(self, **overrides) -> Path:
        value = {
            "organization_id": "org_config",
            "project_id": "project_config",
            "application_id": "app_config",
            "bundle_identifier": "com.example.kuzaba.qa",
            "build_id": "build_config",
            "build_identity_digest": "sha256:" + "2" * 64,
            "consent_contract": "tacua-consent-v1",
            "state_directory": str(self.root / "state"),
            **overrides,
        }
        path = self.root / "config.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_reverse_dns_bundle_id_safe_bind_and_shorter_retention(self) -> None:
        config, _ = load_config(self.write_config(raw_retention_days=1), self.secret_file)
        self.assertEqual("app_config", config.application_id)
        self.assertEqual("com.example.kuzaba.qa", config.bundle_identifier)
        self.assertEqual("127.0.0.1", config.listen_host)
        self.assertEqual(1, config.raw_retention_days)

    def test_invalid_bundle_retention_unknown_and_duplicate_config_are_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            load_config(self.write_config(application_id="invalid.with.dot"), self.secret_file)
        with self.assertRaises(ConfigError):
            load_config(self.write_config(bundle_identifier="bundle_invalid"), self.secret_file)
        with self.assertRaises(ConfigError):
            load_config(self.write_config(raw_retention_days=31), self.secret_file)
        with self.assertRaises(ConfigError):
            load_config(self.write_config(unknown_setting=True), self.secret_file)
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            '{"organization_id":"org_config","organization_id":"org_other"}',
            encoding="utf-8",
        )
        with self.assertRaises(ConfigError):
            load_config(duplicate, self.secret_file)


class PilotHTTPAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.secret = secrets.token_urlsafe(48).encode()
        config = PilotConfig(
            organization_id="org_http",
            project_id="project_http",
            application_id="app_http",
            bundle_identifier="com.example.http.qa",
            build_id="build_http",
            build_identity_digest="sha256:" + "2" * 64,
            consent_contract="tacua-consent-v1",
            state_directory=Path(self.temporary.name),
            max_segment_bytes=1024,
            max_diagnostic_bytes=32768,
        )
        self.backend = PilotBackend(config, self.secret)
    def handler(self, path: str, authorization: str | None = None) -> PilotRequestHandler:
        handler = object.__new__(PilotRequestHandler)
        handler.path = path
        handler.server = SimpleNamespace(backend=self.backend)
        handler.headers = Message()
        handler.close_connection = False
        if authorization is not None:
            handler.headers["Authorization"] = authorization
        return handler

    def test_http_bearer_auth_adapter(self) -> None:
        with self.assertRaises(ApiError) as missing:
            self.handler("/v1/admin/sessions")._admin()
        self.assertEqual(401, missing.exception.status)
        with self.assertRaises(ApiError) as wrong:
            self.handler("/v1/admin/sessions", "Bearer invalid")._admin()
        self.assertEqual(401, wrong.exception.status)
        self.handler("/v1/admin/sessions", "Bearer " + self.secret.decode())._admin()

    def test_http_path_parser_rejects_encoded_and_plain_traversal(self) -> None:
        self.assertEqual("/healthz", self.handler("/healthz")._path())
        for path in (
            "/v1/admin/sessions/%2e%2e",
            "/v1/admin/sessions/../outside",
            "/v1//sessions",
            "/healthz?verbose=true",
            "/healthz#fragment",
            "http://example.invalid/healthz",
        ):
            with self.subTest(path=path), self.assertRaises(ApiError) as captured:
                self.handler(path)._path()
            self.assertEqual("INVALID_PATH", captured.exception.code)

    def test_duplicate_json_and_integrity_headers_are_rejected(self) -> None:
        handler = self.handler("/v1/admin/launch-codes")
        raw = b'{"scope":{},"scope":{}}'
        handler.headers["Content-Length"] = str(len(raw))
        handler.rfile = io.BytesIO(raw)
        with self.assertRaises(ApiError) as duplicate_json:
            handler._read_json()
        self.assertEqual("INVALID_JSON", duplicate_json.exception.code)

        handler = self.handler("/upload")
        handler.headers.add_header("X-Content-SHA256", digest(b"one"))
        handler.headers.add_header("X-Content-SHA256", digest(b"two"))
        with self.assertRaises(ApiError) as duplicate_digest:
            handler._single_header("X-Content-SHA256", "CONTENT_DIGEST_REQUIRED")
        self.assertEqual("CONTENT_DIGEST_REQUIRED", duplicate_digest.exception.code)

    def test_errors_close_the_connection_and_unexpected_bodies_are_rejected(self) -> None:
        handler = self.handler("/healthz")

        def fail_dispatch():
            raise ApiError(400, "TEST_ERROR", "test")

        sent = []
        handler._dispatch = fail_dispatch
        handler._send_json = lambda status, body: sent.append((status, body))
        handler._handle()
        self.assertTrue(handler.close_connection)
        self.assertEqual(400, sent[0][0])

        handler = self.handler("/healthz")
        handler.command = "GET"
        handler.headers["Content-Length"] = "1"
        with self.assertRaises(ApiError) as unexpected:
            handler._dispatch()
        self.assertEqual("UNEXPECTED_BODY", unexpected.exception.code)


if __name__ == "__main__":
    unittest.main()
