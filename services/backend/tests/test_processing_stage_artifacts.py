# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from tacua_backend.contracts import (  # noqa: E402
    canonical_json,
    digest_without,
    runtime_seal,
)
from tacua_backend.operator_tool import (  # noqa: E402
    create_backup,
    restore_backup,
    verify_backup,
)
from tacua_backend import operator_tool  # noqa: E402
from tacua_backend import processing_jobs  # noqa: E402
from tacua_backend.processing_jobs import (  # noqa: E402
    ARTIFACT_CHECKPOINT_DETAIL,
    ARTIFACT_PIPELINE_VERSION,
    MAX_TRANSCRIPT_TEXT_BYTES,
    PROCESSING_ARTIFACT_CONTRACT,
    ProcessingCheckpoint,
    _processing_artifact_id,
)
from tacua_backend.service import ApiError, PilotBackend  # noqa: E402
from test_backend import BackendHarness, instant  # noqa: E402


class ArtifactPipelineBackend(PilotBackend):
    """Test-only producer for the dormant, non-default pipeline contract."""

    def _queued_job_snapshot(self, *args, **kwargs):
        job = super()._queued_job_snapshot(*args, **kwargs)
        job["pipeline"]["pipeline_version"] = ARTIFACT_PIPELINE_VERSION
        return runtime_seal(job)


class SyntheticTranscriptEngine:
    def __init__(self, payload: dict, *, fail_once: bool = False):
        self.payload = copy.deepcopy(payload)
        self.fail_once = fail_once
        self.calls = 0

    def process_stage(self, claim):
        self.calls += 1
        if self.fail_once and self.calls == 1:
            raise RuntimeError("synthetic transcript body must stay private")
        if claim.stage_name != "transcribe":
            return ProcessingCheckpoint()
        return ProcessingCheckpoint(
            artifacts=(
                {
                    "artifact_kind": "transcript",
                    "payload": copy.deepcopy(self.payload),
                },
            ),
        )


class LegacyPipelineArtifactCompatibilityTests(BackendHarness):
    def test_pipeline_v1_remains_zero_artifact_and_adapter_compatible(self) -> None:
        lifecycle = self.full_completed_session()
        job = lifecycle["completion_receipt"]["processing_job"]
        claim = self.backend.claim_processing_job("worker_legacy_artifact_guard")
        assert claim is not None
        payload = {
            "contract_version": "tacua.transcript@1.0.0",
            "language_tag": "und",
            "speech_status": "not_detected",
            "source_segments": [],
            "spans": [],
        }
        self.assert_api_error(
            422,
            "PROCESSING_CHECKPOINT_INVALID",
            lambda: self.backend.publish_processing_checkpoint(
                job["job_id"],
                "transcribe",
                claim["lease"]["lease_token"],
                ProcessingCheckpoint(
                    artifacts=({"artifact_kind": "transcript", "payload": payload},)
                ),
            ),
        )
        running = self.backend.get_job(job["job_id"])
        self.assertEqual("running", running["status"])
        with self.backend._connect() as connection:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_artifacts"
                ).fetchone()[0],
            )


class ProcessingStageArtifactTests(BackendHarness):
    def setUp(self) -> None:
        super().setUp()
        self.backend = ArtifactPipelineBackend(
            self.config, self.admin_secret, clock=self.clock
        )

    @staticmethod
    def transcript_payload(lifecycle: dict, *, text: str = "Wrong button label.") -> dict:
        segment = lifecycle["completion_request"]["capture_manifest"]["segments"][0]
        source = {
            "segment_id": segment["segment_id"],
            "sequence": segment["sequence"],
            "content_digest": segment["content"]["content_digest"],
            "start_ms": segment["time_range"]["start_ms"],
            "end_ms": segment["time_range"]["end_ms"],
        }
        return {
            "contract_version": "tacua.transcript@1.0.0",
            "language_tag": "en-GB",
            "speech_status": "detected",
            "source_segments": [source],
            "spans": [
                {
                    "segment_id": source["segment_id"],
                    "start_ms": source["start_ms"],
                    "end_ms": source["end_ms"],
                    "text": text,
                }
            ],
        }

    def publish_transcript(self, lifecycle: dict) -> tuple[dict, dict]:
        job = lifecycle["completion_receipt"]["processing_job"]
        claim = self.backend.claim_processing_job("worker_transcript")
        assert claim is not None
        checkpoint = self.backend.publish_processing_checkpoint(
            job["job_id"],
            "transcribe",
            claim["lease"]["lease_token"],
            ProcessingCheckpoint(
                artifacts=(
                    {
                        "artifact_kind": "transcript",
                        "payload": self.transcript_payload(lifecycle),
                    },
                ),
            ),
        )
        with self.backend._connect() as connection:
            row = connection.execute(
                "SELECT * FROM tacua_processing_artifacts WHERE job_id = ?",
                (job["job_id"],),
            ).fetchone()
            assert row is not None
            artifact = json.loads(row["canonical_json"])
        return checkpoint, artifact

    def test_synthetic_engine_publishes_strict_inline_transcript_atomically(self) -> None:
        lifecycle = self.full_completed_session()
        job = lifecycle["completion_receipt"]["processing_job"]
        engine = SyntheticTranscriptEngine(self.transcript_payload(lifecycle))
        self.backend._processing_engine = engine

        checkpoint = self.backend.run_processing_once("worker_synthetic_engine")
        assert checkpoint is not None
        self.assertEqual("queued", checkpoint["status"])
        self.assertEqual("succeeded", checkpoint["pipeline"]["stages"][0]["state"])
        self.assertEqual(
            ARTIFACT_CHECKPOINT_DETAIL,
            checkpoint["pipeline"]["stages"][0]["detail"],
        )
        self.assertNotIn("Wrong button label", canonical_json(checkpoint))
        with self.backend._connect() as connection:
            row = connection.execute(
                "SELECT * FROM tacua_processing_artifacts WHERE job_id = ?",
                (job["job_id"],),
            ).fetchone()
            assert row is not None
            artifact = json.loads(row["canonical_json"])
            self.assertEqual(
                [(1,)],
                [
                    tuple(row)
                    for row in connection.execute(
                        "SELECT schema_version FROM tacua_processing_artifact_schema"
                    )
                ],
            )
            self.assertEqual(2, connection.execute("PRAGMA user_version").fetchone()[0])
        self.assertEqual(PROCESSING_ARTIFACT_CONTRACT, artifact["contract_version"])
        self.assertEqual(
            digest_without(artifact, "artifact_digest"), artifact["artifact_digest"]
        )
        self.assertEqual(
            _processing_artifact_id(job["job_id"], "transcribe", "transcript"),
            artifact["artifact_id"],
        )
        self.assertEqual(checkpoint["job_version"], artifact["checkpoint_job_version"])
        self.assertEqual(
            checkpoint["pipeline"]["stages"][0]["completed_at"],
            artifact["created_at"],
        )
        self.assertEqual(
            lifecycle["completion_request"]["capture_manifest"]["retention"]
            ["derived_data_expires_at"],
            artifact["derived_data_expires_at"],
        )
        restarted = PilotBackend(self.config, self.admin_secret, clock=self.clock)
        self.assertEqual(checkpoint, restarted.get_job(job["job_id"]))
        self.assertIsNone(
            restarted.claim_processing_job("worker_artifact_reader_not_yet_available")
        )

    def test_invalid_body_rolls_back_checkpoint_and_never_appears_in_error(self) -> None:
        lifecycle = self.full_completed_session()
        job = lifecycle["completion_receipt"]["processing_job"]
        claim = self.backend.claim_processing_job("worker_invalid_transcript")
        assert claim is not None
        private_body = "PRIVATE_TRANSCRIPT_SENTINEL"
        payload = self.transcript_payload(lifecycle, text=private_body)
        payload["source_segments"][0]["content_digest"] = "sha256:" + "f" * 64
        error = self.assert_api_error(
            422,
            "PROCESSING_CHECKPOINT_INVALID",
            lambda: self.backend.publish_processing_checkpoint(
                job["job_id"],
                "transcribe",
                claim["lease"]["lease_token"],
                ProcessingCheckpoint(
                    artifacts=(
                        {"artifact_kind": "transcript", "payload": payload},
                    )
                ),
            ),
        )
        self.assertNotIn(private_body, error.message)
        current = self.backend.get_job(job["job_id"])
        self.assertEqual("running", current["status"])
        self.assertEqual(claim["job"]["job_version"], current["job_version"])
        with self.backend._connect() as connection:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_artifacts"
                ).fetchone()[0],
            )

    def test_no_speech_transcript_keeps_exact_sources_without_spans(self) -> None:
        lifecycle = self.full_completed_session()
        job = lifecycle["completion_receipt"]["processing_job"]
        claim = self.backend.claim_processing_job("worker_no_speech")
        assert claim is not None
        payload = self.transcript_payload(lifecycle)
        payload.update(language_tag="und", speech_status="not_detected", spans=[])
        checkpoint = self.backend.publish_processing_checkpoint(
            job["job_id"],
            "transcribe",
            claim["lease"]["lease_token"],
            ProcessingCheckpoint(
                artifacts=(
                    {"artifact_kind": "transcript", "payload": payload},
                )
            ),
        )
        self.assertEqual("succeeded", checkpoint["pipeline"]["stages"][0]["state"])
        with self.backend._connect() as connection:
            body = connection.execute(
                "SELECT canonical_json FROM tacua_processing_artifacts"
            ).fetchone()[0]
        stored = json.loads(body)["payload"]
        self.assertEqual("not_detected", stored["speech_status"])
        self.assertEqual([], stored["spans"])
        self.assertEqual(payload["source_segments"], stored["source_segments"])

    def test_insert_failure_rolls_back_checkpoint_and_preserves_live_lease(self) -> None:
        lifecycle = self.full_completed_session()
        job = lifecycle["completion_receipt"]["processing_job"]
        claim = self.backend.claim_processing_job("worker_atomic_rollback")
        assert claim is not None
        original_validator = (
            processing_jobs._validate_processing_artifact_population_for_job
        )
        validation_count = 0

        def fail_after_insert(connection, job_row, history):
            nonlocal validation_count
            validation_count += 1
            if validation_count == 1:
                return original_validator(connection, job_row, history)
            raise ValueError("synthetic post-insert validation failure")

        with patch.object(
            processing_jobs,
            "_validate_processing_artifact_population_for_job",
            side_effect=fail_after_insert,
        ):
            error = self.assert_api_error(
                500,
                "PROCESSING_JOB_STORAGE_CORRUPT",
                lambda: self.backend.publish_processing_checkpoint(
                    job["job_id"],
                    "transcribe",
                    claim["lease"]["lease_token"],
                    ProcessingCheckpoint(
                        artifacts=(
                            {
                                "artifact_kind": "transcript",
                                "payload": self.transcript_payload(lifecycle),
                            },
                        )
                    ),
                ),
            )
        self.assertNotIn("Wrong button label", error.message)
        current = self.backend.get_job(job["job_id"])
        self.assertEqual(claim["job"], current)
        with self.backend._connect() as connection:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_artifacts"
                ).fetchone()[0],
            )
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_job_leases"
                ).fetchone()[0],
            )

    def test_text_and_span_bounds_fail_before_publication(self) -> None:
        lifecycle = self.full_completed_session()
        job = lifecycle["completion_receipt"]["processing_job"]
        cases = []
        oversized = self.transcript_payload(
            lifecycle, text="x" * (MAX_TRANSCRIPT_TEXT_BYTES + 1)
        )
        cases.append(oversized)
        non_nfc = self.transcript_payload(lifecycle, text="e\u0301")
        cases.append(non_nfc)
        too_many = self.transcript_payload(lifecycle)
        too_many["spans"] = too_many["spans"] * 10_001
        cases.append(too_many)
        for index, payload in enumerate(cases):
            with self.subTest(index=index):
                if index:
                    # The prior rejected publication retains the same live lease.
                    current_claim = claim
                else:
                    claim = self.backend.claim_processing_job("worker_bounds")
                    assert claim is not None
                    current_claim = claim
                self.assert_api_error(
                    422,
                    "PROCESSING_CHECKPOINT_INVALID",
                    lambda payload=payload: self.backend.publish_processing_checkpoint(
                        job["job_id"],
                        "transcribe",
                        current_claim["lease"]["lease_token"],
                        ProcessingCheckpoint(
                            artifacts=(
                                {"artifact_kind": "transcript", "payload": payload},
                            )
                        ),
                    ),
                )
        with self.backend._connect() as connection:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_artifacts"
                ).fetchone()[0],
            )

    def test_retry_failure_creates_no_artifact_then_publishes_once(self) -> None:
        lifecycle = self.full_completed_session()
        job = lifecycle["completion_receipt"]["processing_job"]
        engine = SyntheticTranscriptEngine(
            self.transcript_payload(lifecycle), fail_once=True
        )
        self.backend._processing_engine = engine
        with self.assertRaises(ApiError) as captured:
            self.backend.run_processing_once("worker_retry_artifact")
        self.assertEqual("PROCESSING_ENGINE_FAILED", captured.exception.code)
        self.assertIsNone(captured.exception.__cause__)
        self.assertNotIn("synthetic transcript body", str(captured.exception))
        with self.backend._connect() as connection:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_artifacts"
                ).fetchone()[0],
            )

        checkpoint = self.backend.run_processing_once("worker_retry_artifact")
        assert checkpoint is not None
        self.assertEqual(2, checkpoint["pipeline"]["stages"][0]["attempt_count"])
        with self.backend._connect() as connection:
            rows = connection.execute(
                "SELECT artifact_id FROM tacua_processing_artifacts"
            ).fetchall()
        self.assertEqual(
            [(_processing_artifact_id(job["job_id"], "transcribe", "transcript"),)],
            [tuple(row) for row in rows],
        )

    def test_immutable_row_and_startup_tamper_validation_fail_closed(self) -> None:
        lifecycle = self.full_completed_session()
        _checkpoint, artifact = self.publish_transcript(lifecycle)
        private_body = artifact["payload"]["spans"][0]["text"]
        with self.backend._connect() as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE tacua_processing_artifacts SET canonical_json = '{}'"
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """INSERT OR REPLACE INTO tacua_processing_artifacts
                       (artifact_id,job_id,session_id,stage_name,artifact_kind,
                        checkpoint_job_version,artifact_digest,created_at,
                        derived_data_expires_at,canonical_json)
                       SELECT artifact_id,job_id,session_id,stage_name,
                              artifact_kind,checkpoint_job_version,
                              artifact_digest,created_at,
                              derived_data_expires_at,'{}'
                         FROM tacua_processing_artifacts"""
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """INSERT OR REPLACE INTO tacua_processing_artifacts
                       (artifact_id,job_id,session_id,stage_name,artifact_kind,
                        checkpoint_job_version,artifact_digest,created_at,
                        derived_data_expires_at,canonical_json)
                       SELECT 'artifact_replacement_probe',job_id,session_id,
                              'align',artifact_kind,checkpoint_job_version,
                              artifact_digest,created_at,
                              derived_data_expires_at,'{}'
                         FROM tacua_processing_artifacts"""
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM tacua_processing_artifacts")
            connection.execute("DROP TRIGGER tacua_processing_artifacts_no_update")
            changed = copy.deepcopy(artifact)
            changed["payload"]["spans"][0]["text"] = "tampered body"
            connection.execute(
                "UPDATE tacua_processing_artifacts SET canonical_json = ?",
                (canonical_json(changed),),
            )
        with self.assertRaises(ValueError) as captured:
            PilotBackend(self.config, self.admin_secret, clock=self.clock)
        self.assertIn("persisted processing-job state failed", str(captured.exception))
        self.assertNotIn(private_body, str(captured.exception))
        self.assertNotIn("tampered body", str(captured.exception))

    def test_startup_rejects_missing_artifact_for_succeeded_stage(self) -> None:
        lifecycle = self.full_completed_session()
        self.publish_transcript(lifecycle)
        with self.backend._connect() as connection:
            connection.execute(
                "DROP TRIGGER tacua_processing_artifacts_no_direct_delete"
            )
            connection.execute("DELETE FROM tacua_processing_artifacts")
        with self.assertRaisesRegex(
            ValueError, "persisted processing-job state failed"
        ):
            PilotBackend(self.config, self.admin_secret, clock=self.clock)

    def test_startup_rejects_same_named_weakened_immutability_trigger(self) -> None:
        lifecycle = self.full_completed_session()
        self.publish_transcript(lifecycle)
        with self.backend._connect() as connection:
            connection.execute("DROP TRIGGER tacua_processing_artifacts_no_update")
            connection.execute(
                """CREATE TRIGGER tacua_processing_artifacts_no_update
                   BEFORE UPDATE ON tacua_processing_artifacts
                   BEGIN
                       SELECT 1;
                   END"""
            )
        with self.assertRaisesRegex(
            ValueError, "persisted processing-job state failed"
        ):
            PilotBackend(self.config, self.admin_secret, clock=self.clock)

    def test_startup_rejects_unexpected_artifact_trigger(self) -> None:
        self.full_completed_session()
        with self.backend._connect() as connection:
            connection.execute(
                """CREATE TRIGGER synthetic_artifact_copy_trigger
                   AFTER INSERT ON tacua_processing_artifacts
                   BEGIN
                       SELECT 1;
                   END"""
            )
        with self.assertRaisesRegex(
            ValueError, "persisted processing-job state failed"
        ):
            PilotBackend(self.config, self.admin_secret, clock=self.clock)

    def test_session_deletion_cascades_artifacts_and_counts_them(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        self.publish_transcript(lifecycle)
        tombstone = self.backend.delete_session(session_id)
        # Segment, diagnostics, completion, processing job, and transcript.
        self.assertEqual(5, tombstone["erasure"]["erased_object_count"])
        with self.backend._connect() as connection:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_artifacts"
                ).fetchone()[0],
            )

    def test_retention_expiry_cascades_inline_artifact(self) -> None:
        lifecycle = self.full_completed_session()
        self.publish_transcript(lifecycle)
        expiry = instant(
            lifecycle["completion_request"]["capture_manifest"]["retention"]
            ["derived_data_expires_at"]
        )
        report = self.backend.sweep_expired_sessions(now=expiry)
        self.assertIn(
            lifecycle["launch_receipt"]["session_id"], report["deleted_session_ids"]
        )
        with self.backend._connect() as connection:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_artifacts"
                ).fetchone()[0],
            )

    def _write_operator_configuration(self, root: Path) -> tuple[Path, Path]:
        config_file = root / "config.json"
        document = {
            "organization_id": self.config.organization_id,
            "project_id": self.config.project_id,
            "application_id": self.config.application_id,
            "reviewer_id": self.config.reviewer_id,
            "build_identity": self.config.build_identity,
            "approved_handoff": self.config.approved_handoff,
            "consent_contract": self.config.consent_contract,
            "backend_origin": self.config.backend_origin,
            "transport_policy_version": self.config.transport_policy_version,
            "state_directory": str(self.config.state_directory),
            "listen_host": self.config.listen_host,
            "listen_port": self.config.listen_port,
            "launch_code_ttl_seconds": self.config.launch_code_ttl_seconds,
            "credential_ttl_seconds": self.config.credential_ttl_seconds,
            "max_segment_bytes": self.config.max_segment_bytes,
            "max_diagnostic_bytes": self.config.max_diagnostic_bytes,
            "max_completion_bytes": self.config.max_completion_bytes,
            "raw_retention_days": self.config.raw_retention_days,
            "derived_retention_days": self.config.derived_retention_days,
            "tombstone_retention_days": self.config.tombstone_retention_days,
            "retention_sweep_interval_seconds": (
                self.config.retention_sweep_interval_seconds
            ),
        }
        config_file.write_text(canonical_json(document), encoding="utf-8")
        config_file.chmod(0o600)
        secret_file = root / "admin-secret"
        secret_file.write_bytes(self.admin_secret)
        secret_file.chmod(0o600)
        return config_file, secret_file

    def test_operator_backup_and_restore_preserve_validated_inline_artifact(self) -> None:
        lifecycle = self.full_completed_session()
        job = lifecycle["completion_receipt"]["processing_job"]
        checkpoint, artifact = self.publish_transcript(lifecycle)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_file, secret_file = self._write_operator_configuration(root)
            backup = root / "backup"
            before_expiry = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)
            with patch.object(operator_tool, "_now_utc", return_value=before_expiry):
                manifest = create_backup(config_file, secret_file, backup)
                self.assertEqual(
                    artifact["derived_data_expires_at"],
                    manifest["evidence_retention"][
                        "earliest_evidence_expires_at"
                    ],
                )
                self.assertEqual("ok", verify_backup(backup)["status"])
                restored = root / "restored"
                restore_backup(backup, restored, apply=True)

            backup_connection = sqlite3.connect(
                backup / "state" / "tacua.sqlite3"
            )
            try:
                backed_body = backup_connection.execute(
                    "SELECT canonical_json FROM tacua_processing_artifacts"
                ).fetchone()[0]
            finally:
                backup_connection.close()
            self.assertEqual(canonical_json(artifact), backed_body)

            restored_config = replace(
                self.config, state_directory=restored / "state"
            )
            restarted = PilotBackend(
                restored_config, self.admin_secret, clock=self.clock
            )
            self.assertEqual(checkpoint, restarted.get_job(job["job_id"]))


if __name__ == "__main__":
    unittest.main()
