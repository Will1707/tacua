#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the synthetic, non-sensitive runtime bundle fixture."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_contract import seal, validate_bundle  # noqa: E402


D = "sha256:" + "1" * 64
BUILD = "sha256:" + "2" * 64


def main() -> None:
    capture = seal({
        "contract_version": "tacua.capture-upload-manifest@1.0.0",
        "media_type": "application/vnd.tacua.capture-upload-manifest+json;version=1.0.0",
        "organization_id": "org_synthetic", "project_id": "project_synthetic",
        "build_id": "build_synthetic", "build_identity_digest": BUILD,
        "session_id": "session_synthetic", "manifest_version": 2, "capture_state": "complete",
        "started_at": "2026-07-21T10:00:00Z", "ended_at": "2026-07-21T10:01:00Z",
        "monotonic_duration_ms": 60000, "capture_scope": "app_only",
        "streams": {"app_video": "enabled", "app_audio": "enabled", "microphone": "enabled", "diagnostics": "enabled"},
        "app_audio_accounting": {
            "version": 1, "complete": True, "append_attempts": 4,
            "reserved_through_index": 4,
            "segments": [{
                "segment_id": "segment_synthetic", "sequence": 0,
                "attempt_start_index": 1, "append_attempts": 4,
                "appended_samples": 3,
                "drops": [{"attempt_index": 3, "cause": "input_backpressure"}],
            }],
            "unknown_ranges": [],
        },
        "segments": [{
            "segment_id": "segment_synthetic", "sequence": 0,
            "time_range": {"start_ms": 0, "end_ms": 60000, "clock": "session_monotonic"},
            "finalized": True, "availability": "available",
            "content": {"content_type": "video/quicktime", "size_bytes": 2048, "content_digest": "sha256:" + "3" * 64, "sidecar_digest": "sha256:" + "4" * 64},
            "unavailable": None,
        }],
        "gaps": [{
            "gap_id": "gap_synthetic", "time_range": {"start_ms": 30000, "end_ms": 31000, "clock": "session_monotonic"},
            "reason": "app_backgrounded", "affected_streams": ["app_video", "app_audio"],
            "detail": "ReplayKit reported an explicit one-second interruption.",
        }],
        "upload": {
            "state": "complete", "protocol": "segmented-resumable-v1", "remote_session_id": "remote_synthetic",
            "receipts": [{"segment_id": "segment_synthetic", "object_id": "object_synthetic", "size_bytes": 2048, "content_digest": "sha256:" + "3" * 64, "received_at": "2026-07-21T10:02:00Z", "receipt_digest": D}],
            "last_error": None, "completed_at": "2026-07-21T10:02:00Z",
        },
        "retention": {"policy_version": "tacua.retention@1.0.0", "raw_media_expires_at": "2026-08-20T10:00:00Z", "derived_data_expires_at": "2026-08-20T10:00:00Z", "deletion_status": "active"},
        "manifest_digest": D,
    })

    redaction = {"policy_version": "tacua.redaction@1.0.0", "applied": True, "removed_field_count": 1}
    diagnostics = seal({
        "contract_version": "tacua.diagnostic-envelope@1.0.0",
        "media_type": "application/vnd.tacua.diagnostic-envelope+json;version=1.0.0",
        "organization_id": "org_synthetic", "project_id": "project_synthetic",
        "build_id": "build_synthetic", "build_identity_digest": BUILD, "session_id": "session_synthetic",
        "envelope_id": "envelope_synthetic", "envelope_version": 1, "sequence_range": {"first": 10, "last": 12},
        "events": [
            {"event_id": "event_route", "sequence": 10, "elapsed_ms": 1000, "occurred_at": "2026-07-21T10:00:01Z", "source": "mobile_sdk", "event_type": "route_transition", "data": {"from_route": None, "to_route": "Settings", "trigger": "user"}, "evidence_refs": []},
            {"event_id": "event_issue", "sequence": 11, "elapsed_ms": 20000, "occurred_at": "2026-07-21T10:00:20Z", "source": "mobile_sdk", "event_type": "issue_mark", "data": {"marker_id": "marker_synthetic", "kind": "spoken", "narration_elapsed_ms": 20000}, "evidence_refs": ["evidence_transcript", "evidence_frame"]},
            {"event_id": "event_gap", "sequence": 12, "elapsed_ms": 30000, "occurred_at": "2026-07-21T10:00:30Z", "source": "capture_extension", "event_type": "capture_gap", "data": {"gap_id": "gap_synthetic", "affected_streams": ["app_video", "app_audio"]}, "evidence_refs": []},
        ],
        "evidence": [
            {"evidence_id": "evidence_transcript", "evidence_type": "transcript_excerpt", "description": "Reviewer says the button uses the wrong copy.", "availability": "available", "time_range": {"start_ms": 19000, "end_ms": 22000, "clock": "session_monotonic"}, "source": {"component": "mobile_sdk", "source_id": "sdk_synthetic", "snapshot_revision": "1.0.0", "captured_at": "2026-07-21T10:00:22Z"}, "reference": {"locator": {"scheme": "tacua-evidence", "organization_id": "org_synthetic", "project_id": "project_synthetic", "evidence_id": "evidence_transcript", "revision_id": "revision_transcript"}, "content_type": "text/plain", "size_bytes": 64, "content_digest": "sha256:" + "5" * 64}, "unavailable": None, "redaction": redaction},
            {"evidence_id": "evidence_frame", "evidence_type": "media_keyframe", "description": "Frame showing the incorrect button label.", "availability": "available", "time_range": {"start_ms": 20000, "end_ms": 20000, "clock": "session_monotonic"}, "source": {"component": "mobile_sdk", "source_id": "sdk_synthetic", "snapshot_revision": "1.0.0", "captured_at": "2026-07-21T10:00:20Z"}, "reference": {"locator": {"scheme": "tacua-evidence", "organization_id": "org_synthetic", "project_id": "project_synthetic", "evidence_id": "evidence_frame", "revision_id": "revision_frame"}, "content_type": "image/png", "size_bytes": 1024, "content_digest": "sha256:" + "6" * 64}, "unavailable": None, "redaction": redaction},
            {"evidence_id": "evidence_sentry", "evidence_type": "sentry_event", "description": "Sentry correlation was not configured for this pilot.", "availability": "unavailable", "time_range": None, "source": {"component": "sentry", "source_id": "sentry_synthetic", "snapshot_revision": "none", "captured_at": "2026-07-21T10:03:00Z"}, "reference": None, "unavailable": {"reason": "not_configured", "detail": "The optional Sentry connector was not configured."}, "redaction": {"policy_version": "tacua.redaction@1.0.0", "applied": False, "removed_field_count": 0}},
        ],
        "collection_gaps": [{"gap_id": "diagnostic_gap", "time_range": {"start_ms": 30000, "end_ms": 31000, "clock": "session_monotonic"}, "reason": "diagnostic_collection_paused", "detail": "Collection paused while the app was backgrounded."}],
        "redaction": redaction, "envelope_digest": D,
    })

    stages = [{"name": name, "state": "succeeded", "attempt_count": 1, "started_at": "2026-07-21T10:03:00Z", "completed_at": "2026-07-21T10:04:00Z", "detail": None} for name in ["transcribe", "align", "correlate", "research", "generate_tickets"]]
    job = seal({
        "contract_version": "tacua.processing-job@1.0.0", "media_type": "application/vnd.tacua.processing-job+json;version=1.0.0",
        "organization_id": "org_synthetic", "project_id": "project_synthetic", "build_id": "build_synthetic", "build_identity_digest": BUILD, "session_id": "session_synthetic",
        "job_id": "job_synthetic", "job_version": 1, "previous_job_digest": None, "status": "succeeded",
        "requested_at": "2026-07-21T10:02:30Z", "started_at": "2026-07-21T10:03:00Z", "completed_at": "2026-07-21T10:04:00Z",
        "inputs": {"capture_manifest_digest": capture["manifest_digest"], "diagnostic_envelope_digests": [diagnostics["envelope_digest"]], "context_sources": [
            {"source_id": "repo_synthetic", "kind": "mobile_repository", "access": "read_only", "availability": "available", "snapshot_digest": "sha256:" + "7" * 64, "unavailable": None},
            {"source_id": "sentry_synthetic", "kind": "sentry", "access": "read_only", "availability": "unavailable", "snapshot_digest": None, "unavailable": {"reason": "not_configured", "detail": "The optional connector was not configured."}},
        ]},
        "pipeline": {"pipeline_version": "tacua.pipeline@1.0.0", "stages": stages},
        "execution": {"mode": "async", "max_attempts": 3, "egress": {"policy": "default_deny", "authorized": False, "authorization_decision_id": None, "destinations": []}},
        "outputs": {"disposition": "candidates_created", "candidate_refs": [{"candidate_id": "candidate_synthetic", "candidate_version": 2}], "derived_evidence_refs": ["evidence_transcript", "evidence_frame"], "summary": "One candidate was grounded in the narration and keyframe."},
        "failure": None, "job_digest": D,
    })

    ticket = seal({
        "contract_version": "tacua.runtime-ticket-candidate@1.0.0", "media_type": "application/vnd.tacua.runtime-ticket-candidate+json;version=1.0.0",
        "organization_id": "org_synthetic", "project_id": "project_synthetic", "build_id": "build_synthetic", "build_identity_digest": BUILD, "session_id": "session_synthetic",
        "candidate_id": "candidate_synthetic", "candidate_version": 2, "previous_candidate_digest": "sha256:" + "8" * 64, "state": "approved",
        "created_at": "2026-07-21T10:04:00Z", "updated_at": "2026-07-21T10:06:00Z",
        "source": {"job_id": "job_synthetic", "job_digest": job["job_digest"], "evidence_manifest_digest": diagnostics["envelope_digest"]},
        "content": {
            "title": "Settings button uses incorrect copy", "priority": "P2", "summary": "The Settings action is labelled Save instead of Continue.", "summary_claim_refs": ["claim_actual", "claim_expected"],
            "actual_behavior": {"text": "The button reads Save.", "claim_refs": ["claim_actual"], "evidence_refs": ["evidence_frame", "evidence_transcript"]},
            "expected_behavior": {"text": "The button should read Continue.", "claim_refs": ["claim_expected"], "evidence_refs": ["evidence_transcript"]},
            "claims": [
                {"claim_id": "claim_actual", "kind": "observed", "support": "direct", "confidence": "high", "statement": "The captured frame shows Save.", "evidence_refs": ["evidence_frame"]},
                {"claim_id": "claim_expected", "kind": "expected", "support": "direct", "confidence": "high", "statement": "The reviewer requested Continue.", "evidence_refs": ["evidence_transcript"]},
            ],
            "preconditions": [{"precondition_id": "precondition_settings", "text": "Open the Settings screen in the tested build.", "claim_refs": ["claim_actual"], "evidence_refs": ["evidence_frame"]}],
            "reproduction_steps": [{"step_id": "step_open", "action": "Open Settings and inspect the primary action.", "expected_result": "The action reads Continue.", "actual_result": "The action reads Save.", "claim_refs": ["claim_actual", "claim_expected"], "evidence_refs": ["evidence_frame", "evidence_transcript"], "confidence": "high"}],
            "acceptance_criteria": [{"criterion_id": "criterion_copy", "criterion": "The Settings primary action reads Continue.", "verification": "Open Settings in the QA build and compare the visible label."}],
            "scope": {"in_scope": ["Settings primary action copy"], "out_of_scope": ["Settings navigation behavior"]},
            "uncertainty": {"overall_confidence": "high", "items": [{"uncertainty_id": "uncertainty_backend", "statement": "No backend behavior is implicated by the available evidence.", "impact": "non_blocking", "evidence_refs": ["evidence_frame"]}]},
            "clarifications": [{"clarification_id": "clarification_copy", "question": "Which approved label should replace Save?", "impact": "blocking", "status": "resolved", "choices": [
                {"choice_id": "choice_continue", "label": "Continue", "consequence": "Use the reviewer-requested product copy.", "evidence_refs": ["evidence_transcript"]},
                {"choice_id": "choice_next", "label": "Next", "consequence": "Use alternative navigation copy not supported by the recording.", "evidence_refs": []}
            ], "selected_choice_id": "choice_continue", "resolution_note": "The reviewer selected Continue."}],
        },
        "transition": {"from_state": "ready_for_review", "to_state": "approved", "actor_type": "human", "actor_id": "reviewer_synthetic", "occurred_at": "2026-07-21T10:06:00Z", "reason": "Reviewer accepted the exact candidate version."},
        "review": {"status": "reviewed", "reviewer_action_required": False, "last_edited_by": "reviewer_synthetic", "last_reviewed_at": "2026-07-21T10:06:00Z", "notes": ["Confirmed the intended copy."]},
        "approval": {"approval_id": "approval_synthetic", "actor_type": "human", "actor_id": "reviewer_synthetic", "approved_at": "2026-07-21T10:06:00Z", "candidate_version": 2, "candidate_content_digest": D, "immutable": True},
        "rejection": None, "candidate_content_digest": D, "candidate_digest": D,
    })

    validate_bundle(capture, diagnostics, job, ticket)
    output = ROOT / "fixtures" / "positive"
    output.mkdir(parents=True, exist_ok=True)
    for name, value in (("capture.json", capture), ("diagnostics.json", diagnostics), ("job.json", job), ("ticket.json", ticket)):
        (output / name).write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
