# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
from datetime import timedelta
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from tacua_backend.candidate_domain import TICKET_CONTRACT  # noqa: E402
from tacua_backend.candidate_store import CandidateStore  # noqa: E402
from tacua_backend.processing_jobs import (  # noqa: E402
    JOB_STAGES,
    ProcessingJobStore,
    ProcessingJobStoreError,
    ProcessingResult,
    PublicationCandidate,
)
from tacua_backend.service import ApiError, PilotBackend  # noqa: E402
from test_backend import BackendHarness, instant  # noqa: E402


class SyntheticEngine:
    def __init__(self, result_factory):
        self.result_factory = result_factory
        self.stages: list[str] = []

    def process_stage(self, claim):
        self.stages.append(claim.stage_name)
        if claim.stage_name == JOB_STAGES[-1]:
            return self.result_factory(claim)
        return None


class ProcessingPublicationTests(BackendHarness):
    def advance_to_final_stage(self) -> tuple[dict, dict]:
        lifecycle = self.full_completed_session()
        for expected in JOB_STAGES[:-1]:
            claim = self.backend.claim_processing_job("worker_publication")
            assert claim is not None
            self.assertEqual(expected, claim["lease"]["stage_name"])
            self.backend.checkpoint_processing_stage(
                claim["job"]["job_id"],
                expected,
                claim["lease"]["lease_token"],
                detail=f"Synthetic {expected} checkpoint.",
            )
        claim = self.backend.claim_processing_job("worker_publication")
        assert claim is not None
        self.assertEqual(JOB_STAGES[-1], claim["lease"]["stage_name"])
        return lifecycle, claim

    def result_for_job(
        self,
        job: dict,
        *,
        candidate_count: int = 1,
        actor_id: str = "worker_publication",
    ) -> ProcessingResult:
        candidate, manifest, previews = self.candidate_bundle(job["session_id"])
        for field in ("candidate_created_at", "version_created_at"):
            candidate[field] = job["requested_at"]
        candidate["transition"]["occurred_at"] = job["requested_at"]
        candidate["transition"]["actor"]["actor_id"] = actor_id
        candidate = TICKET_CONTRACT.seal(candidate)
        bundles = [
            PublicationCandidate(
                candidate=candidate,
                evidence_manifest=manifest,
                previews=tuple(previews),
            )
        ]
        if candidate_count == 2:
            second = copy.deepcopy(candidate)
            second["candidate_id"] = "candidate_profile_copy_second"
            second = TICKET_CONTRACT.seal(second)
            bundles.append(
                PublicationCandidate(
                    candidate=second,
                    evidence_manifest=copy.deepcopy(manifest),
                    previews=tuple(copy.deepcopy(previews)),
                )
            )
        return ProcessingResult(
            disposition="candidates_created",
            summary="Synthetic local processor found candidate issues.",
            candidates=tuple(bundles),
        )

    def test_two_candidates_publish_with_terminal_job_and_lease_in_one_commit(self) -> None:
        lifecycle, claim = self.advance_to_final_stage()
        job_id = claim["job"]["job_id"]
        result = self.result_for_job(claim["job"], candidate_count=2)

        self.assert_api_error(
            409,
            "PROCESSING_PUBLICATION_REQUIRED",
            lambda: self.backend.checkpoint_processing_stage(
                job_id,
                JOB_STAGES[-1],
                claim["lease"]["lease_token"],
            ),
        )
        succeeded = self.backend.publish_processing_result(
            job_id, claim["lease"]["lease_token"], result
        )

        self.assertEqual("succeeded", succeeded["status"])
        self.assertEqual("candidates_created", succeeded["outputs"]["disposition"])
        self.assertEqual(
            sorted(bundle.candidate["candidate_id"] for bundle in result.candidates),
            [item["candidate_id"] for item in succeeded["outputs"]["candidate_refs"]],
        )
        expected_evidence = sorted(
            {
                evidence_id
                for bundle in result.candidates
                for evidence_id in bundle.candidate["evidence_manifest"]["evidence_ids"]
            }
        )
        self.assertEqual(
            expected_evidence, succeeded["outputs"]["derived_evidence_refs"]
        )
        self.assertEqual(
            2,
            len(
                self.backend.list_candidates(
                    lifecycle["launch_receipt"]["session_id"]
                )["candidates"]
            ),
        )
        with self.backend._connect() as connection:
            self.assertEqual(
                (2, 2, 0, "succeeded"),
                (
                    connection.execute("SELECT COUNT(*) FROM candidate_versions").fetchone()[0],
                    connection.execute("SELECT COUNT(*) FROM candidate_heads").fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM tacua_processing_job_leases"
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT status FROM jobs WHERE job_id = ?", (job_id,)
                    ).fetchone()[0],
                ),
            )

        restarted = PilotBackend(self.config, self.admin_secret, clock=self.clock)
        self.assertEqual(succeeded, restarted.get_job(job_id))
        for bundle in result.candidates:
            self.assertEqual(
                bundle.candidate,
                restarted.get_candidate(bundle.candidate["candidate_id"], 1),
            )

    def test_explicit_no_issue_result_publishes_no_candidate_or_evidence_refs(self) -> None:
        lifecycle, claim = self.advance_to_final_stage()
        result = ProcessingResult(
            disposition="no_issue_detected",
            summary="Synthetic local processor found no issue.",
        )
        succeeded = self.backend.publish_processing_result(
            claim["job"]["job_id"], claim["lease"]["lease_token"], result
        )
        self.assertEqual(
            {
                "disposition": "no_issue_detected",
                "candidate_refs": [],
                "derived_evidence_refs": [],
                "summary": "Synthetic local processor found no issue.",
            },
            succeeded["outputs"],
        )
        self.assertEqual(
            [],
            self.backend.list_candidates(
                lifecycle["launch_receipt"]["session_id"]
            )["candidates"],
        )
        restarted = PilotBackend(self.config, self.admin_secret, clock=self.clock)
        self.assertEqual(succeeded, restarted.get_job(claim["job"]["job_id"]))

    def test_future_candidate_timestamps_fail_before_staging_and_remain_retryable(self) -> None:
        lifecycle, claim = self.advance_to_final_stage()
        valid = self.result_for_job(claim["job"])
        bundle = valid.candidates[0]
        candidate = copy.deepcopy(bundle.candidate)
        future = "9999-12-31T23:59:59Z"
        candidate["candidate_created_at"] = future
        candidate["transition"]["occurred_at"] = future
        candidate["version_created_at"] = future
        candidate = TICKET_CONTRACT.seal(candidate)
        invalid = ProcessingResult(
            disposition=valid.disposition,
            summary=valid.summary,
            candidates=(
                PublicationCandidate(
                    candidate=candidate,
                    evidence_manifest=bundle.evidence_manifest,
                    previews=bundle.previews,
                ),
            ),
        )

        self.assert_api_error(
            422,
            "PROCESSING_RESULT_BINDING_MISMATCH",
            lambda: self.backend.publish_processing_result(
                claim["job"]["job_id"],
                claim["lease"]["lease_token"],
                invalid,
            ),
        )

        with self.backend._connect() as connection:
            self.assertEqual(
                (0, 0, 0, 0, 0),
                tuple(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in (
                        "candidate_heads",
                        "candidate_versions",
                        "tacua_evidence_manifests",
                        "tacua_candidate_evidence_bindings",
                        "tacua_evidence_preview_revisions",
                    )
                ),
            )
        self.assertEqual(
            [],
            self.backend.list_candidates(
                lifecycle["launch_receipt"]["session_id"]
            )["candidates"],
        )
        self.assertEqual(
            "running",
            self.backend.get_job(claim["job"]["job_id"])["status"],
        )
        succeeded = self.backend.publish_processing_result(
            claim["job"]["job_id"], claim["lease"]["lease_token"], valid
        )
        self.assertEqual("succeeded", succeeded["status"])

    def test_failed_final_transaction_leaves_only_invisible_restart_safe_staging(self) -> None:
        lifecycle, claim = self.advance_to_final_stage()
        result = self.result_for_job(claim["job"])

        def fail_after_candidate_insert(store, *args, **kwargs):
            self.assertEqual(
                1,
                store.connection.execute(
                    "SELECT COUNT(*) FROM candidate_heads"
                ).fetchone()[0],
            )
            raise ProcessingJobStoreError(
                500, "SYNTHETIC_PUBLICATION_FAILURE", "synthetic publication failure"
            )

        with patch.object(ProcessingJobStore, "succeed", new=fail_after_candidate_insert):
            self.assert_api_error(
                500,
                "SYNTHETIC_PUBLICATION_FAILURE",
                lambda: self.backend.publish_processing_result(
                    claim["job"]["job_id"],
                    claim["lease"]["lease_token"],
                    result,
                ),
            )

        with self.backend._connect() as connection:
            counts = {
                table: connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
                for table in (
                    "candidate_heads",
                    "candidate_versions",
                    "tacua_evidence_manifests",
                    "tacua_candidate_evidence_bindings",
                    "tacua_evidence_preview_revisions",
                    "tacua_processing_job_leases",
                )
            }
            self.assertEqual(0, counts["candidate_heads"])
            self.assertEqual(0, counts["candidate_versions"])
            self.assertEqual(1, counts["tacua_evidence_manifests"])
            self.assertEqual(1, counts["tacua_candidate_evidence_bindings"])
            self.assertEqual(1, counts["tacua_evidence_preview_revisions"])
            self.assertEqual(1, counts["tacua_processing_job_leases"])
        self.assertEqual(
            [],
            self.backend.list_candidates(
                lifecycle["launch_receipt"]["session_id"]
            )["candidates"],
        )

        restarted = PilotBackend(self.config, self.admin_secret, clock=self.clock)
        self.assertEqual(
            "running", restarted.get_job(claim["job"]["job_id"])["status"]
        )
        succeeded = restarted.publish_processing_result(
            claim["job"]["job_id"], claim["lease"]["lease_token"], result
        )
        self.assertEqual("succeeded", succeeded["status"])

    def test_deletion_removes_unpublished_staging_after_atomic_rollback(self) -> None:
        lifecycle, claim = self.advance_to_final_stage()
        result = self.result_for_job(claim["job"])

        with patch.object(
            ProcessingJobStore,
            "succeed",
            side_effect=ProcessingJobStoreError(
                500, "SYNTHETIC_PUBLICATION_FAILURE", "synthetic publication failure"
            ),
        ):
            self.assert_api_error(
                500,
                "SYNTHETIC_PUBLICATION_FAILURE",
                lambda: self.backend.publish_processing_result(
                    claim["job"]["job_id"],
                    claim["lease"]["lease_token"],
                    result,
                ),
            )

        session_id = lifecycle["launch_receipt"]["session_id"]
        with self.backend._connect() as connection:
            relative_path = connection.execute(
                "SELECT relative_path FROM tacua_evidence_preview_revisions"
            ).fetchone()[0]
        preview_path = self.backend.derived_evidence_dir / relative_path
        self.assertTrue(preview_path.is_file())
        self.backend.delete_session(session_id)
        with self.backend._connect() as connection:
            for table in (
                "tacua_evidence_manifests",
                "tacua_evidence_items",
                "tacua_candidate_evidence_bindings",
                "tacua_evidence_preview_revisions",
            ):
                self.assertEqual(
                    0, connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                )
        self.assertFalse(preview_path.exists())

    def test_lease_expiry_after_staging_rolls_back_visibility_and_reclaims_safely(self) -> None:
        lifecycle, claim = self.advance_to_final_stage()
        result = self.result_for_job(claim["job"])
        original_stage = self.backend._persist_candidate_bundle_locked

        def stage_then_expire(**values):
            staged = original_stage(**values)
            self.clock.set(
                instant(claim["lease"]["lease_expires_at"])
                + timedelta(seconds=1)
            )
            return staged

        with patch.object(
            self.backend,
            "_persist_candidate_bundle_locked",
            side_effect=stage_then_expire,
        ):
            self.assert_api_error(
                409,
                "PROCESSING_LEASE_STALE",
                lambda: self.backend.publish_processing_result(
                    claim["job"]["job_id"],
                    claim["lease"]["lease_token"],
                    result,
                ),
            )

        with self.backend._connect() as connection:
            self.assertEqual(
                (0, 0, 1, 1),
                (
                    connection.execute(
                        "SELECT COUNT(*) FROM candidate_heads"
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM candidate_versions"
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM tacua_evidence_manifests"
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM tacua_processing_job_leases"
                    ).fetchone()[0],
                ),
            )
        self.assertEqual(
            [],
            self.backend.list_candidates(
                lifecycle["launch_receipt"]["session_id"]
            )["candidates"],
        )

        reclaimed = self.backend.claim_processing_job("worker_publication")
        assert reclaimed is not None
        self.assertEqual(JOB_STAGES[-1], reclaimed["lease"]["stage_name"])
        self.assertNotEqual(
            claim["lease"]["lease_token"], reclaimed["lease"]["lease_token"]
        )
        succeeded = self.backend.publish_processing_result(
            reclaimed["job"]["job_id"],
            reclaimed["lease"]["lease_token"],
            result,
        )
        self.assertEqual("succeeded", succeeded["status"])

    def test_second_bundle_staging_failure_keeps_first_hidden_and_retryable(self) -> None:
        lifecycle, claim = self.advance_to_final_stage()
        valid = self.result_for_job(claim["job"], candidate_count=2)
        invalid_bundles = list(valid.candidates)
        invalid_preview = copy.deepcopy(invalid_bundles[1].previews[0])
        invalid_preview["content_digest"] = "sha256:" + "0" * 64
        invalid_bundles[1] = PublicationCandidate(
            candidate=invalid_bundles[1].candidate,
            evidence_manifest=invalid_bundles[1].evidence_manifest,
            previews=(invalid_preview,),
        )
        invalid = ProcessingResult(
            disposition=valid.disposition,
            summary=valid.summary,
            candidates=tuple(invalid_bundles),
        )

        self.assert_api_error(
            500,
            "CANDIDATE_EVIDENCE_CORRUPT",
            lambda: self.backend.publish_processing_result(
                claim["job"]["job_id"],
                claim["lease"]["lease_token"],
                invalid,
            ),
        )
        with self.backend._connect() as connection:
            self.assertEqual(
                (0, 0, 2, 1),
                (
                    connection.execute(
                        "SELECT COUNT(*) FROM candidate_heads"
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM candidate_versions"
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM tacua_candidate_evidence_bindings"
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM tacua_evidence_preview_revisions"
                    ).fetchone()[0],
                ),
            )
        self.assertEqual(
            [],
            self.backend.list_candidates(
                lifecycle["launch_receipt"]["session_id"]
            )["candidates"],
        )
        succeeded = self.backend.publish_processing_result(
            claim["job"]["job_id"], claim["lease"]["lease_token"], valid
        )
        self.assertEqual(2, len(succeeded["outputs"]["candidate_refs"]))

    def test_retired_direct_candidate_publication_is_closed_without_staging(self) -> None:
        lifecycle = self.full_completed_session()
        candidate, manifest, previews = self.candidate_bundle(
            lifecycle["launch_receipt"]["session_id"]
        )

        self.assert_api_error(
            409,
            "PROCESSING_PUBLICATION_REQUIRED",
            lambda: self.backend.persist_candidate_bundle(
                candidate=candidate,
                evidence_manifest=manifest,
                previews=previews,
            ),
        )
        with self.backend._connect() as connection:
            self.assertEqual(
                (0, 0, 0, 0, 0),
                tuple(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in (
                        "candidate_heads",
                        "candidate_versions",
                        "tacua_evidence_manifests",
                        "tacua_candidate_evidence_bindings",
                        "tacua_evidence_preview_revisions",
                    )
                ),
            )

    def test_no_issue_rejects_a_preexisting_generated_head(self) -> None:
        _lifecycle, claim = self.advance_to_final_stage()
        candidate_result = self.result_for_job(claim["job"])
        candidate = candidate_result.candidates[0].candidate
        # Simulate corrupt/legacy state directly. The supported single-candidate
        # publication boundary is deliberately closed above.
        with self.backend._connect() as connection:
            CandidateStore._insert_version(connection, candidate)
            connection.execute(
                """INSERT INTO candidate_heads
                   (candidate_id,candidate_version,candidate_digest,
                    organization_id,project_id,session_id,state)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    candidate["candidate_id"],
                    candidate["candidate_version"],
                    candidate["candidate_digest"],
                    candidate["organization_id"],
                    candidate["project_id"],
                    candidate["session_id"],
                    candidate["state"],
                ),
            )
        no_issue = ProcessingResult(
            disposition="no_issue_detected",
            summary="Synthetic local processor found no issue.",
        )
        self.assert_api_error(
            409,
            "PROCESSING_PUBLICATION_CONFLICT",
            lambda: self.backend.publish_processing_result(
                claim["job"]["job_id"],
                claim["lease"]["lease_token"],
                no_issue,
            ),
        )
        self.assertEqual("running", self.backend.get_job(claim["job"]["job_id"])["status"])

    def test_each_terminal_output_population_tamper_fails_read_and_restart(self) -> None:
        mutations = (
            "candidate_head_deleted",
            "evidence_binding_deleted",
            "preview_metadata_deleted",
            "extra_generated_head",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                harness = ProcessingPublicationTests(methodName="runTest")
                harness.setUp()
                try:
                    _lifecycle, claim = harness.advance_to_final_stage()
                    result = harness.result_for_job(claim["job"])
                    harness.backend.publish_processing_result(
                        claim["job"]["job_id"],
                        claim["lease"]["lease_token"],
                        result,
                    )
                    candidate = result.candidates[0].candidate
                    with harness.backend._connect() as connection:
                        if mutation == "candidate_head_deleted":
                            connection.execute(
                                "DELETE FROM candidate_heads WHERE candidate_id = ?",
                                (candidate["candidate_id"],),
                            )
                        elif mutation == "evidence_binding_deleted":
                            connection.execute(
                                """DELETE FROM tacua_candidate_evidence_bindings
                                    WHERE candidate_id = ? AND candidate_version = 1""",
                                (candidate["candidate_id"],),
                            )
                        elif mutation == "preview_metadata_deleted":
                            connection.execute(
                                "DELETE FROM tacua_evidence_preview_revisions"
                            )
                        else:
                            extra = copy.deepcopy(candidate)
                            extra["candidate_id"] = "candidate_unexpected_extra"
                            extra = TICKET_CONTRACT.seal(extra)
                            CandidateStore._insert_version(connection, extra)
                            connection.execute(
                                """INSERT INTO candidate_heads
                                   (candidate_id,candidate_version,candidate_digest,
                                    organization_id,project_id,session_id,state)
                                   VALUES (?,?,?,?,?,?,?)""",
                                (
                                    extra["candidate_id"],
                                    extra["candidate_version"],
                                    extra["candidate_digest"],
                                    extra["organization_id"],
                                    extra["project_id"],
                                    extra["session_id"],
                                    extra["state"],
                                ),
                            )

                    harness.assert_api_error(
                        500,
                        "PROCESSING_JOB_STORAGE_CORRUPT",
                        lambda: harness.backend.get_job(claim["job"]["job_id"]),
                    )
                    with harness.assertRaises(ValueError):
                        PilotBackend(
                            harness.config,
                            harness.admin_secret,
                            clock=harness.clock,
                        )
                finally:
                    harness.doCleanups()

    def test_missing_published_preview_fails_admin_read_and_restart_closed(self) -> None:
        _lifecycle, claim = self.advance_to_final_stage()
        result = self.result_for_job(claim["job"])
        self.backend.publish_processing_result(
            claim["job"]["job_id"], claim["lease"]["lease_token"], result
        )
        with self.backend._connect() as connection:
            relative_path = connection.execute(
                "SELECT relative_path FROM tacua_evidence_preview_revisions"
            ).fetchone()[0]
        (self.backend.derived_evidence_dir / relative_path).unlink()

        self.assert_api_error(
            500,
            "PROCESSING_JOB_STORAGE_CORRUPT",
            lambda: self.backend.get_job(claim["job"]["job_id"]),
        )
        with self.assertRaisesRegex(
            ValueError, "successful processing publication failed validation"
        ):
            PilotBackend(self.config, self.admin_secret, clock=self.clock)

    def test_engine_is_default_disabled_startup_inert_and_runs_one_stage_per_call(self) -> None:
        lifecycle = self.full_completed_session()
        job = lifecycle["completion_receipt"]["processing_job"]
        self.assert_api_error(
            503,
            "PROCESSING_ENGINE_DISABLED",
            lambda: self.backend.run_processing_once("worker_engine"),
        )
        self.assertEqual("queued", self.backend.get_job(job["job_id"])["status"])

        engine = SyntheticEngine(
            lambda claim: self.result_for_job(
                claim.job, actor_id=claim.worker_id
            )
        )
        configured = PilotBackend(
            self.config,
            self.admin_secret,
            clock=self.clock,
            processing_engine=engine,
        )
        self.assertEqual([], engine.stages)
        for expected in JOB_STAGES:
            current = configured.run_processing_once("worker_engine")
            assert current is not None
            if expected == JOB_STAGES[-1]:
                self.assertEqual("succeeded", current["status"])
            else:
                self.assertEqual("queued", current["status"])
        self.assertEqual(list(JOB_STAGES), engine.stages)
        self.assertEqual("succeeded", configured.get_job(job["job_id"])["status"])

    def test_invalid_engine_result_durably_fails_instead_of_stranding_lease(self) -> None:
        lifecycle = self.full_completed_session()
        job = lifecycle["completion_receipt"]["processing_job"]

        class InvalidEngine:
            def process_stage(self, _claim):
                return ProcessingResult(
                    disposition="no_issue_detected",
                    summary="This is invalid before the final stage.",
                )

        configured = PilotBackend(
            self.config,
            self.admin_secret,
            clock=self.clock,
            processing_engine=InvalidEngine(),
        )
        self.assert_api_error(
            500,
            "PROCESSING_ENGINE_RESULT_INVALID",
            lambda: configured.run_processing_once("worker_invalid_engine"),
        )
        failed = configured.get_job(job["job_id"])
        self.assertEqual("failed", failed["status"])
        self.assertEqual(
            "PROCESSING_ENGINE_RESULT_INVALID", failed["failure"]["code"]
        )
        with configured._connect() as connection:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_job_leases"
                ).fetchone()[0],
            )


if __name__ == "__main__":
    unittest.main()
