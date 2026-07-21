# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
from datetime import datetime, timedelta
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from tacua_backend.contracts import canonical_json, runtime_seal, runtime_validate  # noqa: E402
from tacua_backend.processing_jobs import ProcessingJobStoreError  # noqa: E402
from tacua_backend.service import ApiError, PilotBackend  # noqa: E402
from test_backend import BackendHarness, instant  # noqa: E402


class ProcessingJobStateTests(BackendHarness):
    def completed_job(self) -> tuple[dict, dict]:
        lifecycle = self.full_completed_session()
        return lifecycle, lifecycle["completion_receipt"]["processing_job"]

    def assert_job_error(self, status: int, code: str, callback) -> ApiError:
        return self.assert_api_error(status, code, callback)

    def test_initial_head_is_exact_queued_default_deny_and_startup_is_inert(self) -> None:
        lifecycle, job = self.completed_job()
        restarted = PilotBackend(self.config, self.admin_secret, clock=self.clock)

        self.assertEqual(job, restarted.get_job(job["job_id"]))
        self.assertEqual([job], restarted.list_jobs())
        self.assertEqual("queued", job["status"])
        self.assertIsNone(job["started_at"])
        self.assertEqual(
            [("pending", 0, None, None, None)] * 5,
            [
                (
                    stage["state"],
                    stage["attempt_count"],
                    stage["started_at"],
                    stage["completed_at"],
                    stage["detail"],
                )
                for stage in job["pipeline"]["stages"]
            ],
        )
        self.assertEqual(
            {
                "policy": "default_deny",
                "authorized": False,
                "authorization_decision_id": None,
                "destinations": [],
            },
            job["execution"]["egress"],
        )
        with restarted._connect() as connection:
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_job_versions"
                ).fetchone()[0],
            )
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_job_leases"
                ).fetchone()[0],
            )
        session = restarted.get_session(lifecycle["launch_receipt"]["session_id"])
        self.assertEqual(
            [
                {
                    "job_id": job["job_id"],
                    "job_type": "process_session",
                    "status": "queued",
                    "requested_at": job["requested_at"],
                    "started_at": None,
                    "completed_at": None,
                    "failure_code": None,
                }
            ],
            session["jobs"],
        )

    def test_store_operations_require_one_explicit_sqlite_transaction(self) -> None:
        _lifecycle, job = self.completed_job()
        with self.backend._connect() as connection:
            self.assertFalse(connection.in_transaction)
            store = self.backend._processing_job_store(connection)
            before = (
                connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_job_versions"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_job_leases"
                ).fetchone()[0],
            )
            operations = (
                lambda: store.get(job["job_id"]),
                store.list,
                lambda: store.claim("worker_without_transaction"),
                lambda: store.put_initial(job),
                store._validate_all_leases,
            )
            for operation in operations:
                with self.assertRaises(ProcessingJobStoreError) as captured:
                    operation()
                self.assertEqual(
                    "PROCESSING_JOB_TRANSACTION_REQUIRED", captured.exception.code
                )
            after = (
                connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_job_versions"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_job_leases"
                ).fetchone()[0],
            )
            self.assertEqual(before, after)

    def test_sqlite_failures_map_to_content_free_storage_errors(self) -> None:
        _lifecycle, job = self.completed_job()
        with self.backend._connect() as connection:
            connection.execute("DROP TABLE tacua_processing_job_versions")
        self.assert_job_error(
            500,
            "PROCESSING_JOB_STORAGE_CORRUPT",
            lambda: self.backend.get_job(job["job_id"]),
        )

    def test_claim_and_checkpoint_append_exact_versions(self) -> None:
        lifecycle, job = self.completed_job()
        claim = self.backend.claim_processing_job("worker_primary")
        assert claim is not None
        self.assertEqual(2, claim["job"]["job_version"])
        self.assertEqual("running", claim["job"]["status"])
        self.assertEqual("transcribe", claim["lease"]["stage_name"])
        self.assertEqual(1, claim["job"]["pipeline"]["stages"][0]["attempt_count"])
        self.assertEqual([], claim["job"]["execution"]["egress"]["destinations"])
        replay = self.backend.complete_session(
            lifecycle["launch_receipt"]["session_id"],
            lifecycle["completion_request"]["completion_id"],
            lifecycle["secret"],
            lifecycle["completion_request"],
        )
        self.assertEqual(lifecycle["completion_bytes"], replay.body)

        self.clock.set("2026-07-21T10:03:00Z")
        checkpoint = self.backend.checkpoint_processing_stage(
            job["job_id"],
            "transcribe",
            claim["lease"]["lease_token"],
            detail="Transcript artifact was durably checkpointed.",
        )
        self.assertEqual(3, checkpoint["job_version"])
        self.assertEqual("queued", checkpoint["status"])
        self.assertIsNone(checkpoint["started_at"])
        self.assertEqual("succeeded", checkpoint["pipeline"]["stages"][0]["state"])
        self.assertEqual("pending", checkpoint["pipeline"]["stages"][1]["state"])
        runtime_validate(checkpoint)
        replay = self.backend.complete_session(
            lifecycle["launch_receipt"]["session_id"],
            lifecycle["completion_request"]["completion_id"],
            lifecycle["secret"],
            lifecycle["completion_request"],
        )
        self.assertEqual(lifecycle["completion_bytes"], replay.body)
        self.assertEqual(checkpoint, self.backend.get_job(job["job_id"]))
        self.assertEqual([checkpoint], self.backend.list_jobs())
        with self.backend._connect() as connection:
            versions = connection.execute(
                """SELECT job_version,previous_job_digest,job_digest,canonical_json
                     FROM tacua_processing_job_versions
                    WHERE job_id = ? ORDER BY job_version""",
                (job["job_id"],),
            ).fetchall()
            self.assertEqual([1, 2, 3], [row["job_version"] for row in versions])
            for index, row in enumerate(versions):
                artifact = json.loads(row["canonical_json"])
                runtime_validate(artifact)
                self.assertEqual(row["job_digest"], artifact["job_digest"])
                self.assertEqual(
                    None if index == 0 else versions[index - 1]["job_digest"],
                    row["previous_job_digest"],
                )
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_job_leases"
                ).fetchone()[0],
            )

    def test_concurrent_claims_have_one_winner_and_failed_insert_rolls_back_head(self) -> None:
        _lifecycle, job = self.completed_job()
        barrier = threading.Barrier(3)
        results: list[dict | None] = []
        errors: list[Exception] = []

        def claim(worker: str) -> None:
            try:
                barrier.wait()
                results.append(self.backend.claim_processing_job(worker))
            except Exception as error:  # pragma: no cover - asserted empty
                errors.append(error)

        threads = [
            threading.Thread(target=claim, args=("worker_one",)),
            threading.Thread(target=claim, args=("worker_two",)),
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual([], errors)
        self.assertEqual(1, sum(result is not None for result in results))
        self.assertEqual("running", self.backend.get_job(job["job_id"])["status"])

        # A fresh queued job demonstrates that an invalid token-factory result
        # rolls the running snapshot back with the lease insert transaction.
        winner = next(result for result in results if result is not None)
        self.backend.fail_processing_job(
            job["job_id"],
            winner["lease"]["stage_name"],
            winner["lease"]["lease_token"],
            code="WORK_ABORTED",
            detail="End the first job so its lease is no longer active.",
            retryable=False,
        )
        # Resetting terminal state is intentionally impossible; use a clean
        # backend to test atomic rollback of the first claim.
        clean = BackendHarness(methodName="runTest")
        clean.setUp()
        self.addCleanup(clean.doCleanups)
        _clean_lifecycle = clean.full_completed_session()
        clean_job = _clean_lifecycle["completion_receipt"]["processing_job"]
        with patch("tacua_backend.service.secrets.token_urlsafe", return_value="bad"):
            clean.assert_api_error(
                500,
                "PROCESSING_TOKEN_INVALID",
                lambda: clean.backend.claim_processing_job("worker_atomic"),
            )
        self.assertEqual(clean_job, clean.backend.get_job(clean_job["job_id"]))
        with clean.backend._connect() as connection:
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_job_versions"
                ).fetchone()[0],
            )
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_job_leases"
                ).fetchone()[0],
            )

    def test_retry_queue_is_pending_and_attempts_exhaust_terminally(self) -> None:
        _lifecycle, job = self.completed_job()
        claim = self.backend.claim_processing_job("worker_retry")
        assert claim is not None
        for attempt in (1, 2):
            self.clock.set(f"2026-07-21T10:0{2 + attempt}:00Z")
            queued = self.backend.fail_processing_job(
                job["job_id"],
                claim["lease"]["stage_name"],
                claim["lease"]["lease_token"],
                code="PROVIDER_TEMPORARY",
                detail="The local processor asked for a bounded retry.",
                retryable=True,
            )
            self.assertEqual("queued", queued["status"])
            self.assertIsNone(queued["started_at"])
            stage = queued["pipeline"]["stages"][0]
            self.assertEqual("pending", stage["state"])
            self.assertEqual(attempt, stage["attempt_count"])
            self.assertIsNone(stage["started_at"])
            self.assertIsNone(stage["completed_at"])
            self.assertIsNone(stage["detail"])
            self.assert_job_error(
                409,
                "PROCESSING_LEASE_STALE",
                lambda: self.backend.checkpoint_processing_stage(
                    job["job_id"], "transcribe", claim["lease"]["lease_token"]
                ),
            )
            claim = self.backend.claim_processing_job("worker_retry")
            assert claim is not None
            self.assertEqual(attempt + 1, claim["job"]["pipeline"]["stages"][0]["attempt_count"])

        self.clock.set("2026-07-21T10:05:00Z")
        terminal = self.backend.fail_processing_job(
            job["job_id"],
            "transcribe",
            claim["lease"]["lease_token"],
            code="PROVIDER_TEMPORARY",
            detail="A third retry was requested.",
            retryable=True,
        )
        self.assertEqual("failed", terminal["status"])
        self.assertEqual("STAGE_ATTEMPTS_EXHAUSTED", terminal["failure"]["code"])
        self.assertFalse(terminal["failure"]["retryable"])
        self.assertEqual(3, terminal["pipeline"]["stages"][0]["attempt_count"])
        self.assertIsNone(self.backend.claim_processing_job("worker_retry"))

    def test_expired_lease_is_reclaimed_after_restart_and_old_token_is_stale(self) -> None:
        _lifecycle, job = self.completed_job()
        first = self.backend.claim_processing_job("worker_before_restart")
        assert first is not None
        restarted = PilotBackend(self.config, self.admin_secret, clock=self.clock)
        self.assertEqual(first["job"], restarted.get_job(job["job_id"]))

        self.clock.set(first["lease"]["lease_expires_at"])
        reclaimed = restarted.claim_processing_job("worker_after_restart")
        assert reclaimed is not None
        self.assertEqual(5, reclaimed["job"]["job_version"])
        self.assertEqual(2, reclaimed["job"]["pipeline"]["stages"][0]["attempt_count"])
        self.assertNotEqual(
            first["lease"]["lease_token"], reclaimed["lease"]["lease_token"]
        )
        self.assert_job_error(
            409,
            "PROCESSING_LEASE_STALE",
            lambda: restarted.checkpoint_processing_stage(
                job["job_id"], "transcribe", first["lease"]["lease_token"]
            ),
        )

    def test_lease_renewal_is_live_token_bound_and_each_extension_is_bounded(self) -> None:
        lifecycle, job = self.completed_job()
        claim = self.backend.claim_processing_job("worker_heartbeat")
        assert claim is not None
        self.clock.set("2026-07-21T10:04:00Z")
        renewed = self.backend.renew_processing_lease(
            job["job_id"], "transcribe", claim["lease"]["lease_token"]
        )
        self.assertEqual("2026-07-21T10:09:00Z", renewed["lease_expires_at"])
        self.assert_job_error(
            409,
            "PROCESSING_LEASE_STALE",
            lambda: self.backend.renew_processing_lease(
                job["job_id"], "transcribe", "Z" * 43
            ),
        )
        for minute in (8, 12, 16, 20, 24, 28, 32, 36, 40):
            self.clock.set(f"2026-07-21T10:{minute:02d}:00Z")
            renewed = self.backend.renew_processing_lease(
                job["job_id"], "transcribe", claim["lease"]["lease_token"]
            )
        self.assertEqual(
            self.clock() + timedelta(minutes=5), instant(renewed["lease_expires_at"])
        )
        self.clock.set("2026-07-21T10:40:00Z")
        self.assert_job_error(
            409,
            "PROCESSING_LEASE_RENEWAL_EARLY",
            lambda: self.backend.renew_processing_lease(
                job["job_id"], "transcribe", claim["lease"]["lease_token"]
            ),
        )

        self.backend.delete_session(lifecycle["launch_receipt"]["session_id"])
        self.assert_job_error(
            404,
            "JOB_NOT_FOUND",
            lambda: self.backend.renew_processing_lease(
                job["job_id"], "transcribe", claim["lease"]["lease_token"]
            ),
        )
        with self.backend._connect() as connection:
            for table in (
                "jobs",
                "tacua_processing_job_versions",
                "tacua_processing_job_leases",
            ):
                self.assertEqual(
                    0, connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                )

    def test_heartbeat_and_checkpoint_cannot_revive_expired_or_use_naive_clock(self) -> None:
        lifecycle, job = self.completed_job()
        claim = self.backend.claim_processing_job("worker_expiry")
        assert claim is not None
        session = self.backend.get_session(lifecycle["launch_receipt"]["session_id"])
        self.clock.set(session["retention"]["raw_media_expires_at"])
        for operation in (
            lambda: self.backend.renew_processing_lease(
                job["job_id"], "transcribe", claim["lease"]["lease_token"]
            ),
            lambda: self.backend.checkpoint_processing_stage(
                job["job_id"], "transcribe", claim["lease"]["lease_token"]
            ),
        ):
            self.assert_job_error(410, "SESSION_RETENTION_EXPIRED", operation)
        with self.backend._connect() as connection:
            row = connection.execute(
                "SELECT status,job_json FROM jobs WHERE job_id = ?", (job["job_id"],)
            ).fetchone()
            self.assertEqual("running", row["status"])
            self.assertEqual(claim["job"], json.loads(row["job_json"]))

        clean = BackendHarness(methodName="runTest")
        clean.setUp()
        self.addCleanup(clean.doCleanups)
        clean_lifecycle = clean.full_completed_session()
        clean_job = clean_lifecycle["completion_receipt"]["processing_job"]
        original_clock = clean.backend._clock
        clean.backend._clock = lambda: datetime(2026, 7, 21, 10, 3, 0)
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            clean.backend.claim_processing_job("worker_naive_clock")
        clean.backend._clock = original_clock
        self.assertEqual(clean_job, clean.backend.get_job(clean_job["job_id"]))

    def test_history_head_chain_and_configuration_tampering_fail_closed(self) -> None:
        _lifecycle, job = self.completed_job()
        claim = self.backend.claim_processing_job("worker_tamper")
        assert claim is not None
        altered = copy.deepcopy(claim["job"])
        altered["inputs"]["context_sources"] = [
            {
                "source_id": "repo_tampered",
                "kind": "mobile_repository",
                "access": "read_only",
                "availability": "unavailable",
                "snapshot_digest": None,
                "unavailable": {
                    "reason": "not_configured",
                    "detail": "Tampered but structurally valid immutable input.",
                },
            }
        ]
        altered = runtime_seal(altered)
        with self.backend._connect() as connection:
            connection.execute(
                """UPDATE tacua_processing_job_versions
                      SET job_digest = ?, canonical_json = ?
                    WHERE job_id = ? AND job_version = 2""",
                (altered["job_digest"], canonical_json(altered), job["job_id"]),
            )
            connection.execute(
                "UPDATE jobs SET job_json = ? WHERE job_id = ?",
                (canonical_json(altered), job["job_id"]),
            )
        self.assert_job_error(
            500,
            "PROCESSING_JOB_STORAGE_CORRUPT",
            lambda: self.backend.get_job(job["job_id"]),
        )
        with self.assertRaisesRegex(ValueError, "failed safe schema-v2 adoption"):
            PilotBackend(self.config, self.admin_secret, clock=self.clock)

    def test_version_one_is_anchored_to_exact_durable_completion_receipt(self) -> None:
        _lifecycle, job = self.completed_job()
        altered = copy.deepcopy(job)
        altered["inputs"]["capture_manifest_digest"] = "sha256:" + "9" * 64
        altered = runtime_seal(altered)
        with self.backend._connect() as connection:
            connection.execute(
                """UPDATE tacua_processing_job_versions
                      SET job_digest = ?, canonical_json = ?
                    WHERE job_id = ? AND job_version = 1""",
                (altered["job_digest"], canonical_json(altered), job["job_id"]),
            )
            connection.execute(
                "UPDATE jobs SET job_json = ? WHERE job_id = ?",
                (canonical_json(altered), job["job_id"]),
            )
        self.assert_job_error(
            500,
            "PROCESSING_JOB_STORAGE_CORRUPT",
            lambda: self.backend.get_job(job["job_id"]),
        )
        with self.assertRaisesRegex(ValueError, "failed safe schema-v2 adoption"):
            PilotBackend(self.config, self.admin_secret, clock=self.clock)

    def test_session_retention_cannot_outlive_the_completion_anchor(self) -> None:
        lifecycle, job = self.completed_job()
        session_id = lifecycle["launch_receipt"]["session_id"]
        with self.backend._connect() as connection:
            connection.execute(
                """UPDATE sessions
                      SET raw_media_expires_at = ?, derived_data_expires_at = ?
                    WHERE session_id = ?""",
                ("2026-09-19T10:00:00Z", "2026-09-19T10:00:00Z", session_id),
            )

        self.assert_job_error(
            500,
            "PROCESSING_JOB_STORAGE_CORRUPT",
            lambda: self.backend.get_job(job["job_id"]),
        )
        self.assert_job_error(
            500,
            "PROCESSING_JOB_STORAGE_CORRUPT",
            lambda: self.backend.claim_processing_job("worker_retention_tamper"),
        )
        with self.assertRaisesRegex(ValueError, "failed safe schema-v2 adoption"):
            PilotBackend(self.config, self.admin_secret, clock=self.clock)

    def test_completed_session_requires_its_exact_durable_job(self) -> None:
        lifecycle, job = self.completed_job()
        session_id = lifecycle["launch_receipt"]["session_id"]
        with self.backend._connect() as connection:
            connection.execute("DELETE FROM jobs WHERE session_id = ?", (session_id,))

        self.assert_job_error(
            500,
            "PROCESSING_JOB_STORAGE_CORRUPT",
            lambda: self.backend.get_session(session_id),
        )
        self.assert_job_error(
            500,
            "PROCESSING_JOB_STORAGE_CORRUPT",
            lambda: self.backend.get_job(job["job_id"]),
        )
        self.assert_job_error(
            500,
            "PROCESSING_JOB_STORAGE_CORRUPT",
            self.backend.list_jobs,
        )
        self.assert_job_error(
            500,
            "PROCESSING_JOB_STORAGE_CORRUPT",
            lambda: self.backend.complete_session(
                session_id,
                lifecycle["completion_request"]["completion_id"],
                lifecycle["secret"],
                lifecycle["completion_request"],
            ),
        )
        with self.assertRaisesRegex(ValueError, "failed safe schema-v2 adoption"):
            PilotBackend(self.config, self.admin_secret, clock=self.clock)

    def test_store_owned_exhaustion_code_cannot_be_spoofed(self) -> None:
        _lifecycle, job = self.completed_job()
        claim = self.backend.claim_processing_job("worker_reserved_code")
        assert claim is not None
        self.assert_job_error(
            400,
            "PROCESSING_FAILURE_INVALID",
            lambda: self.backend.fail_processing_job(
                job["job_id"],
                "transcribe",
                claim["lease"]["lease_token"],
                code="STAGE_ATTEMPTS_EXHAUSTED",
                detail="Caller tried to forge store-owned exhaustion.",
                retryable=False,
            ),
        )
        self.assertEqual(claim["job"], self.backend.get_job(job["job_id"]))

    def test_resealed_exhausted_retry_queue_and_oversized_terminal_detail_fail_closed(self) -> None:
        _lifecycle, job = self.completed_job()
        claim = self.backend.claim_processing_job("worker_attempt_bound")
        assert claim is not None
        for minute in (3, 4):
            self.clock.set(f"2026-07-21T10:0{minute}:00Z")
            self.backend.fail_processing_job(
                job["job_id"],
                "transcribe",
                claim["lease"]["lease_token"],
                code="PROVIDER_TEMPORARY",
                detail="Retry within the declared attempt bound.",
                retryable=True,
            )
            claim = self.backend.claim_processing_job("worker_attempt_bound")
            assert claim is not None
        self.assertEqual(3, claim["job"]["pipeline"]["stages"][0]["attempt_count"])
        self.assert_job_error(
            400,
            "PROCESSING_FAILURE_INVALID",
            lambda: self.backend.fail_processing_job(
                job["job_id"],
                "transcribe",
                claim["lease"]["lease_token"],
                code="PERMANENT_FAILURE",
                detail="x" * 513,
                retryable=False,
            ),
        )
        self.assertEqual(claim["job"], self.backend.get_job(job["job_id"]))

        event_at = "2026-07-21T10:05:00Z"
        failed_attempt = copy.deepcopy(claim["job"])
        failed_stage = failed_attempt["pipeline"]["stages"][0]
        failed_stage.update(
            state="failed",
            completed_at=event_at,
            detail="Coherently resealed but exhausted retry.",
        )
        failed_attempt["job_version"] += 1
        failed_attempt["previous_job_digest"] = claim["job"]["job_digest"]
        failed_attempt = runtime_seal(failed_attempt)
        illegal_queue = copy.deepcopy(failed_attempt)
        illegal_queue["status"] = "queued"
        illegal_queue["started_at"] = None
        illegal_stage = illegal_queue["pipeline"]["stages"][0]
        illegal_stage.update(
            state="pending", started_at=None, completed_at=None, detail=None
        )
        illegal_queue["job_version"] += 1
        illegal_queue["previous_job_digest"] = failed_attempt["job_digest"]
        illegal_queue = runtime_seal(illegal_queue)
        with self.backend._connect() as connection:
            for snapshot in (failed_attempt, illegal_queue):
                connection.execute(
                    """INSERT INTO tacua_processing_job_versions
                       (job_id,job_version,previous_job_digest,job_digest,status,
                        recorded_at,canonical_json)
                       VALUES (?,?,?,?,?,?,?)""",
                    (
                        snapshot["job_id"],
                        snapshot["job_version"],
                        snapshot["previous_job_digest"],
                        snapshot["job_digest"],
                        snapshot["status"],
                        event_at,
                        canonical_json(snapshot),
                    ),
                )
            connection.execute(
                "UPDATE jobs SET status = ?, job_json = ? WHERE job_id = ?",
                ("queued", canonical_json(illegal_queue), job["job_id"]),
            )
            connection.execute(
                "DELETE FROM tacua_processing_job_leases WHERE job_id = ?",
                (job["job_id"],),
            )
        self.assert_job_error(
            500,
            "PROCESSING_JOB_STORAGE_CORRUPT",
            lambda: self.backend.get_job(job["job_id"]),
        )

    def test_missing_history_or_lease_and_projection_tampering_fail_closed(self) -> None:
        _lifecycle, job = self.completed_job()
        with self.backend._connect() as connection:
            connection.execute(
                "UPDATE jobs SET status = 'running' WHERE job_id = ?", (job["job_id"],)
            )
        self.assert_job_error(
            500,
            "PROCESSING_JOB_STORAGE_CORRUPT",
            lambda: self.backend.get_job(job["job_id"]),
        )

        clean = BackendHarness(methodName="runTest")
        clean.setUp()
        self.addCleanup(clean.doCleanups)
        _clean_lifecycle = clean.full_completed_session()
        clean_job = _clean_lifecycle["completion_receipt"]["processing_job"]
        clean_claim = clean.backend.claim_processing_job("worker_missing_lease")
        assert clean_claim is not None
        with clean.backend._connect() as connection:
            connection.execute(
                "DELETE FROM tacua_processing_job_leases WHERE job_id = ?",
                (clean_job["job_id"],),
            )
        clean.assert_api_error(
            500,
            "PROCESSING_JOB_STORAGE_CORRUPT",
            lambda: clean.backend.get_job(clean_job["job_id"]),
        )
        with self.assertRaisesRegex(ValueError, "failed safe schema-v2 adoption"):
            PilotBackend(clean.config, clean.admin_secret, clock=clean.clock)

    def test_valid_legacy_v2_head_backfills_but_corrupt_head_is_rejected(self) -> None:
        _lifecycle, job = self.completed_job()
        with self.backend._connect() as connection:
            connection.execute("DROP TABLE tacua_processing_job_leases")
            connection.execute("DROP TABLE tacua_processing_job_versions")
        restarted = PilotBackend(self.config, self.admin_secret, clock=self.clock)
        self.assertEqual(job, restarted.get_job(job["job_id"]))
        with restarted._connect() as connection:
            connection.execute("DROP TABLE tacua_processing_job_leases")
            connection.execute("DROP TABLE tacua_processing_job_versions")
            corrupt = copy.deepcopy(job)
            corrupt["job_version"] = 2
            corrupt["previous_job_digest"] = job["job_digest"]
            corrupt = runtime_seal(corrupt)
            connection.execute(
                "UPDATE jobs SET status = ?, job_json = ? WHERE job_id = ?",
                (corrupt["status"], canonical_json(corrupt), job["job_id"]),
            )
        with self.assertRaisesRegex(ValueError, "failed safe schema-v2 adoption"):
            PilotBackend(self.config, self.admin_secret, clock=self.clock)

    def test_checkpoint_delete_race_cannot_resurrect_job_or_lease(self) -> None:
        lifecycle, job = self.completed_job()
        claim = self.backend.claim_processing_job("worker_delete_race")
        assert claim is not None
        barrier = threading.Barrier(3)
        outcomes: list[tuple[str, str]] = []

        def checkpoint() -> None:
            barrier.wait()
            try:
                self.backend.checkpoint_processing_stage(
                    job["job_id"], "transcribe", claim["lease"]["lease_token"]
                )
                outcomes.append(("checkpoint", "succeeded"))
            except ApiError as error:
                outcomes.append(("checkpoint", error.code))

        def delete() -> None:
            barrier.wait()
            self.backend.delete_session(lifecycle["launch_receipt"]["session_id"])
            outcomes.append(("delete", "succeeded"))

        threads = [threading.Thread(target=checkpoint), threading.Thread(target=delete)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertIn(("delete", "succeeded"), outcomes)
        self.assertIn(
            next(value for name, value in outcomes if name == "checkpoint"),
            {"succeeded", "JOB_NOT_FOUND"},
        )
        self.assert_job_error(
            404, "JOB_NOT_FOUND", lambda: self.backend.get_job(job["job_id"])
        )
        with self.backend._connect() as connection:
            for table in (
                "jobs",
                "tacua_processing_job_versions",
                "tacua_processing_job_leases",
            ):
                self.assertEqual(
                    0, connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                )


if __name__ == "__main__":
    unittest.main()
