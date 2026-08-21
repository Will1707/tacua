# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "src"
REPOSITORY = SOURCE.parents[2]
sys.path.insert(0, str(SOURCE))

from tacua_backend.candidate_domain import TICKET_CONTRACT  # noqa: E402
from tacua_backend.candidate_store import CandidateStore, CandidateStoreError  # noqa: E402
from tacua_backend.handoff_export import HANDOFF  # noqa: E402
from tacua_backend.handoff_store import HandoffStore  # noqa: E402
from tacua_backend.processing_adapter import (  # noqa: E402
    COMMAND_CONTRACT,
    _parse_result,
    _processing_input,
)
from tacua_backend.processing_jobs import (  # noqa: E402
    JOB_STAGES,
    ProcessingJobClaim,
    ProcessingJobStore,
    ProcessingJobStoreError,
    ProcessingResult,
    PublicationCandidate,
)
from tacua_backend.service import ApiError, ClosingConnection, PilotBackend  # noqa: E402
from test_backend import BackendHarness, instant  # noqa: E402


PROCESSOR_PATH = REPOSITORY / "services" / "processor" / "processor.py"
PROCESSOR_SPEC = importlib.util.spec_from_file_location(
    "tacua_grounding_regression_processor", PROCESSOR_PATH
)
assert PROCESSOR_SPEC is not None and PROCESSOR_SPEC.loader is not None
PROCESSOR = importlib.util.module_from_spec(PROCESSOR_SPEC)
PROCESSOR_SPEC.loader.exec_module(PROCESSOR)


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

    def marked_processor_result(
        self,
        claim: dict,
        *,
        transcript: str | None = (
            "The save button uses the wrong copy and should say Save profile."
        ),
    ) -> ProcessingResult:
        job = claim["job"]
        lease = claim["lease"]
        keyframe = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
            "YAAAAAYAAjCB0C8AAAAASUVORK5CYII="
        )
        created_at = instant(job["requested_at"])

        class ProcessorClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return created_at if tz is None else created_at.astimezone(tz)

        processing_claim = ProcessingJobClaim(
            job=copy.deepcopy(job),
            worker_id=lease["worker_id"],
            stage_name=lease["stage_name"],
            lease_token=lease["lease_token"],
            lease_expires_at=lease["lease_expires_at"],
        )
        with _processing_input(
            self.backend,
            processing_claim,
            command_contract_version=COMMAND_CONTRACT,
        ) as snapshot:
            source = snapshot.document
            segment_reference = source["capture"]["segments"][0]
            segment = {
                "content_digest": segment_reference["content_digest"],
                "content_type": segment_reference["content_type"],
                "end_ms": 60_000,
                "path": Path(segment_reference["read_only_path"]),
                "segment_id": segment_reference["segment_id"],
                "sequence": segment_reference["sequence"],
                "size_bytes": segment_reference["size_bytes"],
                "start_ms": 0,
            }
            with (
                patch.object(PROCESSOR, "capture_segments", return_value=[segment]),
                patch.object(PROCESSOR, "extract_keyframe", return_value=keyframe),
                patch.object(
                    PROCESSOR,
                    "extract_narration",
                    return_value=(
                        transcript,
                        (5_000, 40_000) if transcript is not None else None,
                        [segment] if transcript is not None else [],
                    ),
                ),
                patch.object(PROCESSOR, "datetime", ProcessorClock),
            ):
                processor_document, preview_bodies = PROCESSOR.generate_tickets(
                    source,
                    ffmpeg=Path("/unused/ffmpeg"),
                    ffprobe=Path("/unused/ffprobe"),
                    whisper_cli=Path("/unused/whisper-cli"),
                    model=Path("/unused/model.bin"),
                    model_id="whisper-base-en",
                    model_digest="sha256:" + "a" * 64,
                )
            self.assertEqual("terminal", processor_document["disposition"])
            terminal = processor_document["result"]
            self.assertEqual("candidates_created", terminal["disposition"])
            for name, body in preview_bodies:
                (snapshot.output_directory / name).write_bytes(body)
            parsed = _parse_result(
                PROCESSOR.canonical_bytes(processor_document), snapshot
            )
        self.assertIsInstance(parsed, ProcessingResult)
        assert isinstance(parsed, ProcessingResult)
        return parsed

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

    def test_marked_processor_candidate_approves_and_exports_without_content_edit(self) -> None:
        _lifecycle, claim = self.advance_to_final_stage()
        result = self.marked_processor_result(claim)
        generated_output = result.candidates[0]
        generated = generated_output.candidate
        claims_by_kind = {
            item["kind"]: item for item in generated["content"]["claims"]
        }
        self.assertEqual("direct", claims_by_kind["observed"]["support"])
        self.assertEqual("inferred", claims_by_kind["hypothesis"]["support"])

        succeeded = self.backend.publish_processing_result(
            claim["job"]["job_id"], claim["lease"]["lease_token"], result
        )
        self.assertEqual("succeeded", succeeded["status"])
        self.assertEqual(generated, self.backend.get_candidate(generated["candidate_id"]))

        clarification = generated["content"]["clarifications"][0]
        transcript_choice = next(
            choice
            for choice in clarification["choices"]
            if choice["label"] == "Use transcribed intent"
        )
        resolved = json.loads(
            self.backend.transition_candidate(
                generated["candidate_id"],
                if_match=generated["candidate_digest"],
                idempotency_key="candidate:processor-grounding:resolve",
                body=self.candidate_transition_body(
                    generated,
                    "resolve_clarification",
                    clarification_id=clarification["clarification_id"],
                    selected_choice_id=transcript_choice["choice_id"],
                ),
            ).body
        )
        self.assertEqual("ready_for_review", resolved["state"])
        self.clock.set("2026-07-21T10:02:08Z")
        approval_body = self.candidate_transition_body(resolved, "approve")
        approval_key = "candidate:processor-grounding:approve"
        original_handoff_put = HandoffStore.put
        handoff_put_snapshots: list[tuple[int, int]] = []
        pre_failure_snapshots: list[tuple[int, int, int, int, str]] = []

        def observe_successful_handoff_put(store, candidate, artifacts):
            original_handoff_put(store, candidate, artifacts)
            handoff_put_snapshots.append(
                (
                    store.connection.execute(
                        "SELECT COUNT(*) FROM approved_handoffs WHERE candidate_id = ?",
                        (candidate["candidate_id"],),
                    ).fetchone()[0],
                    candidate["candidate_version"],
                )
            )

        class FailAfterApprovalWritesConnection(ClosingConnection):
            def execute(self, sql, parameters=()):  # type: ignore[no-untyped-def]
                cursor = super().execute(sql, parameters)
                if (
                    "INSERT INTO candidate_operations" in sql
                    and len(parameters) > 1
                    and parameters[1] == approval_key
                ):
                    head = super().execute(
                        "SELECT candidate_version, state FROM candidate_heads "
                        "WHERE candidate_id = ?",
                        (resolved["candidate_id"],),
                    ).fetchone()
                    pre_failure_snapshots.append(
                        (
                            super().execute(
                                "SELECT COUNT(*) FROM approved_handoffs "
                                "WHERE candidate_id = ?",
                                (resolved["candidate_id"],),
                            ).fetchone()[0],
                            super().execute(
                                "SELECT COUNT(*) FROM candidate_versions WHERE candidate_id = ?",
                                (resolved["candidate_id"],),
                            ).fetchone()[0],
                            super().execute(
                                "SELECT COUNT(*) FROM candidate_operations "
                                "WHERE candidate_id = ?",
                                (resolved["candidate_id"],),
                            ).fetchone()[0],
                            head["candidate_version"],
                            head["state"],
                        )
                    )
                    raise CandidateStoreError(
                        500,
                        "SYNTHETIC_POST_HANDOFF_FAILURE",
                        "synthetic failure after all approval writes",
                    )
                return cursor

        def failing_connect():
            connection = sqlite3.connect(
                self.backend.db_path,
                timeout=10,
                factory=FailAfterApprovalWritesConnection,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 10000")
            connection.execute("PRAGMA secure_delete = ON")
            return connection

        with (
            patch.object(HandoffStore, "put", new=observe_successful_handoff_put),
            patch.object(self.backend, "_connect", side_effect=failing_connect),
        ):
            self.assert_api_error(
                500,
                "SYNTHETIC_POST_HANDOFF_FAILURE",
                lambda: self.backend.transition_candidate(
                    resolved["candidate_id"],
                    if_match=resolved["candidate_digest"],
                    idempotency_key=approval_key,
                    body=approval_body,
                ),
            )

        self.assertEqual([(1, 3)], handoff_put_snapshots)
        self.assertEqual([(1, 3, 2, 3, "approved")], pre_failure_snapshots)
        self.assertEqual(resolved, self.backend.get_candidate(resolved["candidate_id"]))
        with self.backend._connect() as connection:
            head = connection.execute(
                "SELECT candidate_version, candidate_digest, state FROM candidate_heads "
                "WHERE candidate_id = ?",
                (resolved["candidate_id"],),
            ).fetchone()
            self.assertEqual(
                (2, resolved["candidate_digest"], "ready_for_review"),
                tuple(head),
            )
            self.assertEqual(
                (2, 1, 0),
                (
                    connection.execute(
                        "SELECT COUNT(*) FROM candidate_versions WHERE candidate_id = ?",
                        (resolved["candidate_id"],),
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM candidate_operations WHERE candidate_id = ?",
                        (resolved["candidate_id"],),
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM approved_handoffs WHERE candidate_id = ?",
                        (resolved["candidate_id"],),
                    ).fetchone()[0],
                ),
            )

        approved = json.loads(
            self.backend.transition_candidate(
                resolved["candidate_id"],
                if_match=resolved["candidate_digest"],
                idempotency_key=approval_key,
                body=approval_body,
            ).body
        )
        versions = [
            self.backend.get_candidate(approved["candidate_id"], version)
            for version in (1, 2, 3)
        ]
        self.assertEqual("approved", approved["state"])
        self.assertEqual(
            ["generated", "clarification_answered", "approved"],
            [version["lineage"]["operation"] for version in versions],
        )
        self.assertEqual(
            versions[1]["candidate_content_digest"],
            versions[2]["candidate_content_digest"],
        )
        for field in set(versions[0]["content"]) - {"clarifications"}:
            self.assertEqual(
                versions[0]["content"][field], versions[1]["content"][field]
            )

        stored = self.backend.get_candidate_handoff(
            approved["candidate_id"], approved["candidate_version"]
        )
        handoff = json.loads(stored.json_bytes)
        self.assertEqual("approved", handoff["ticket"]["state"])
        self.assertEqual(
            [
                {
                    "clarification_id": clarification["clarification_id"],
                    "impact": "blocking",
                    "question": clarification["question"],
                    "resolution": "Use transcribed intent",
                    "status": "resolved",
                }
            ],
            handoff["ticket"]["clarifications"],
        )
        self.assertEqual(
            "Implement the outcome of the expected-behavior clarification.",
            handoff["ticket"]["reproduction"]["expected_result"],
        )
        semantic_export = (
            stored.json_bytes.decode("utf-8")
            + "\n"
            + stored.markdown_bytes.decode("utf-8")
        ).lower()
        self.assertNotIn("unconfirmed", semantic_export)
        self.assertNotIn("unresolved", semantic_export)
        self.assertNotIn("unapproved", semantic_export)
        self.assertEqual(
            TICKET_CONTRACT.canonical_json(approved),
            handoff["source_candidate"]["canonical_json"],
        )
        self.assertEqual(stored.json_bytes, HANDOFF.canonical_json_artifact(handoff))
        HANDOFF.validate_handoff(handoff, executable=False)
        HANDOFF.validate_markdown(handoff, stored.markdown_bytes.decode("utf-8"))

    def test_marked_processor_without_transcript_resolves_note_and_exports(self) -> None:
        _lifecycle, claim = self.advance_to_final_stage()
        result = self.marked_processor_result(claim, transcript=None)
        generated = result.candidates[0].candidate
        self.assertEqual(
            {"expected", "observed"},
            {item["kind"] for item in generated["content"]["claims"]},
        )
        clarification = generated["content"]["clarifications"][0]
        self.assertEqual(
            ["Add expected result", "Dismiss finding"],
            [choice["label"] for choice in clarification["choices"]],
        )

        succeeded = self.backend.publish_processing_result(
            claim["job"]["job_id"], claim["lease"]["lease_token"], result
        )
        self.assertEqual("succeeded", succeeded["status"])
        written_choice = next(
            choice
            for choice in clarification["choices"]
            if choice["label"] == "Add expected result"
        )
        resolution_note = "The captured screen should show Save profile."
        resolved = json.loads(
            self.backend.transition_candidate(
                generated["candidate_id"],
                if_match=generated["candidate_digest"],
                idempotency_key="candidate:processor-no-transcript:resolve",
                body=self.candidate_transition_body(
                    generated,
                    "resolve_clarification",
                    clarification_id=clarification["clarification_id"],
                    selected_choice_id=written_choice["choice_id"],
                    resolution_note=resolution_note,
                ),
            ).body
        )
        self.assertEqual("ready_for_review", resolved["state"])
        approved = json.loads(
            self.backend.transition_candidate(
                resolved["candidate_id"],
                if_match=resolved["candidate_digest"],
                idempotency_key="candidate:processor-no-transcript:approve",
                body=self.candidate_transition_body(resolved, "approve"),
            ).body
        )
        self.assertEqual("approved", approved["state"])
        self.assertEqual(
            ["generated", "clarification_answered", "approved"],
            [
                self.backend.get_candidate(approved["candidate_id"], version)[
                    "lineage"
                ]["operation"]
                for version in (1, 2, 3)
            ],
        )

        stored = self.backend.get_candidate_handoff(
            approved["candidate_id"], approved["candidate_version"]
        )
        handoff = json.loads(stored.json_bytes)
        self.assertEqual(
            [
                {
                    "clarification_id": clarification["clarification_id"],
                    "impact": "blocking",
                    "question": clarification["question"],
                    "resolution": resolution_note,
                    "status": "resolved",
                }
            ],
            handoff["ticket"]["clarifications"],
        )
        semantic_export = (
            stored.json_bytes.decode("utf-8")
            + "\n"
            + stored.markdown_bytes.decode("utf-8")
        ).lower()
        for stale_text in (
            "unconfirmed",
            "unresolved",
            "unapproved",
            "use transcribed intent",
        ):
            self.assertNotIn(stale_text, semantic_export)
        self.assertEqual(
            TICKET_CONTRACT.canonical_json(approved),
            handoff["source_candidate"]["canonical_json"],
        )
        self.assertEqual(stored.json_bytes, HANDOFF.canonical_json_artifact(handoff))
        HANDOFF.validate_handoff(handoff, executable=False)
        HANDOFF.validate_markdown(handoff, stored.markdown_bytes.decode("utf-8"))

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
