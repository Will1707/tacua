#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerate deterministic, synthetic ticket-candidate conformance fixtures."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ticket_candidate_contract import canonical_json_artifact, seal  # noqa: E402


POSITIVE = ROOT / "fixtures" / "positive"
NEGATIVE = ROOT / "fixtures" / "negative"


def content() -> dict[str, Any]:
    return {
        "title": "Profile action uses the wrong label",
        "priority": "P2",
        "summary": {
            "text": "The profile action shows Save draft instead of the approved Save profile copy.",
            "claim_refs": ["claim_observed_label", "claim_expected_label"],
            "evidence_refs": ["evidence_keyframe_001", "evidence_transcript_001"],
        },
        "actual_behavior": {
            "text": "The enabled profile action is labelled Save draft.",
            "claim_refs": ["claim_observed_label"],
            "evidence_refs": ["evidence_keyframe_001"],
        },
        "expected_behavior": {
            "text": "The enabled profile action should be labelled Save profile.",
            "claim_refs": ["claim_expected_label"],
            "evidence_refs": ["evidence_transcript_001", "evidence_repository_001"],
        },
        "claims": [
            {
                "claim_id": "claim_observed_label",
                "kind": "observed",
                "support": "direct",
                "confidence": "high",
                "statement": "The tested build renders Save draft on the profile action.",
                "evidence_refs": ["evidence_keyframe_001"],
            },
            {
                "claim_id": "claim_expected_label",
                "kind": "expected",
                "support": "inferred",
                "confidence": "high",
                "statement": "The reviewer and tested repository identify Save profile as the intended copy.",
                "evidence_refs": ["evidence_transcript_001", "evidence_repository_001"],
            },
            {
                "claim_id": "claim_profile_route",
                "kind": "constraint",
                "support": "direct",
                "confidence": "high",
                "statement": "The observation occurs on the profile-edit route.",
                "evidence_refs": ["evidence_route_001"],
            },
        ],
        "reproduction": {
            "preconditions": [
                {
                    "precondition_id": "precondition_profile_editable",
                    "text": "Use an authorized QA account with an editable profile.",
                    "claim_refs": ["claim_profile_route"],
                    "evidence_refs": ["evidence_route_001"],
                }
            ],
            "steps": [
                {
                    "step_id": "step_open_profile",
                    "action": "Open Settings and select Edit profile.",
                    "expected_result": "The profile editor opens.",
                    "actual_result": "The profile editor opens.",
                    "claim_refs": ["claim_profile_route"],
                    "evidence_refs": ["evidence_route_001"],
                    "confidence": "high",
                },
                {
                    "step_id": "step_inspect_action",
                    "action": "Inspect the enabled primary action.",
                    "expected_result": "The label reads Save profile.",
                    "actual_result": "The label reads Save draft.",
                    "claim_refs": ["claim_observed_label", "claim_expected_label"],
                    "evidence_refs": ["evidence_keyframe_001", "evidence_transcript_001"],
                    "confidence": "high",
                },
            ],
            "attempts": 1,
            "reproductions": 1,
        },
        "scope": {
            "in_scope": ["Correct the profile action copy in the tested iOS build."],
            "out_of_scope": ["Do not change profile API behavior or deploy from this candidate."],
        },
        "acceptance_criteria": [
            {
                "criterion_id": "criterion_profile_copy",
                "criterion": "The enabled profile action reads Save profile in the tested locale.",
                "verification": "Run the focused profile component test and inspect the iOS QA build.",
                "claim_refs": ["claim_expected_label"],
                "evidence_refs": ["evidence_transcript_001", "evidence_repository_001"],
            }
        ],
        "uncertainty": {
            "overall_confidence": "high",
            "items": [
                {
                    "uncertainty_id": "uncertainty_other_locales",
                    "statement": "Copy for locales outside the tested English build was not inspected.",
                    "impact": "non_blocking",
                    "evidence_refs": ["evidence_repository_001"],
                }
            ],
        },
        "clarifications": [
            {
                "clarification_id": "clarification_copy_source",
                "question": "Which label should the enabled profile action use?",
                "target": "expected_behavior",
                "impact": "blocking",
                "status": "unresolved",
                "choices": [
                    {
                        "choice_id": "choice_keep_current",
                        "label": "Keep Save draft",
                        "description": "Keep the copy visible in the captured build.",
                        "consequence": "No copy change would be requested.",
                        "requires_note": False,
                        "presentation": {
                            "kind": "evidence_thumbnail",
                            "value": None,
                            "evidence_ref": "evidence_keyframe_001",
                        },
                        "evidence_refs": ["evidence_keyframe_001"],
                    },
                    {
                        "choice_id": "choice_use_approved",
                        "label": "Use Save profile",
                        "description": "Use the reviewer-stated and repository-backed copy.",
                        "consequence": "The implementation ticket requests the Save profile label.",
                        "requires_note": False,
                        "presentation": {
                            "kind": "text",
                            "value": "Save profile",
                            "evidence_ref": None,
                        },
                        "evidence_refs": ["evidence_transcript_001", "evidence_repository_001"],
                    },
                ],
                "selected_choice_id": None,
                "resolution_note": None,
            }
        ],
    }


def base_candidate() -> dict[str, Any]:
    return {
        "contract_version": "tacua.ticket-candidate@1.0.0",
        "media_type": "application/vnd.tacua.ticket-candidate+json;version=1.0.0",
        "organization_id": "org_synthetic",
        "project_id": "project_sample_mobile",
        "build_id": "build_ios_031",
        "build_identity_digest": "sha256:" + "b" * 64,
        "session_id": "session_synthetic_001",
        "evidence_manifest": {
            "manifest_id": "manifest_synthetic_001",
            "manifest_digest": "sha256:" + "a" * 64,
            "evidence_ids": [
                "evidence_keyframe_001",
                "evidence_repository_001",
                "evidence_route_001",
                "evidence_transcript_001",
            ],
        },
        "candidate_id": "candidate_profile_copy",
        "candidate_version": 1,
        "previous_candidate_digest": None,
        "state": "draft",
        "candidate_created_at": "2026-07-21T10:00:00Z",
        "version_created_at": "2026-07-21T10:00:00Z",
        "lineage": {"operation": "generated", "parents": []},
        "transition": {
            "from_state": None,
            "to_state": "draft",
            "actor": {"actor_type": "system", "actor_id": "worker_local"},
            "occurred_at": "2026-07-21T10:00:00Z",
            "reason": "processing_job_generated_candidate",
        },
        "content": content(),
        "review": {
            "status": "unreviewed",
            "reviewer_action_required": False,
            "last_human_actor_id": None,
            "last_reviewed_at": None,
            "notes": [],
        },
        "approval": None,
        "rejection": None,
        "candidate_content_digest": "sha256:" + "0" * 64,
        "candidate_digest": "sha256:" + "0" * 64,
    }


def next_version(
    previous: dict[str, Any],
    *,
    state: str,
    operation: str,
    occurred_at: str,
    actor_type: str,
    actor_id: str,
    reason: str,
) -> dict[str, Any]:
    result = copy.deepcopy(previous)
    result["candidate_version"] += 1
    result["previous_candidate_digest"] = previous["candidate_digest"]
    result["state"] = state
    result["version_created_at"] = occurred_at
    result["lineage"] = {
        "operation": operation,
        "parents": [
            {
                "candidate_id": previous["candidate_id"],
                "candidate_version": previous["candidate_version"],
                "candidate_digest": previous["candidate_digest"],
            }
        ],
    }
    result["transition"] = {
        "from_state": previous["state"],
        "to_state": state,
        "actor": {"actor_type": actor_type, "actor_id": actor_id},
        "occurred_at": occurred_at,
        "reason": reason,
    }
    result["approval"] = None
    result["rejection"] = None
    return result


def positive_chain() -> list[dict[str, Any]]:
    draft = seal(base_candidate())

    needs = next_version(
        draft,
        state="needs_clarification",
        operation="reviewed",
        occurred_at="2026-07-21T10:02:00Z",
        actor_type="human",
        actor_id="reviewer_owner",
        reason="reviewer_opened_blocking_question",
    )
    needs["review"] = {
        "status": "in_review",
        "reviewer_action_required": True,
        "last_human_actor_id": "reviewer_owner",
        "last_reviewed_at": "2026-07-21T10:02:00Z",
        "notes": [],
    }
    needs = seal(needs)

    ready = next_version(
        needs,
        state="ready_for_review",
        operation="clarification_answered",
        occurred_at="2026-07-21T10:03:00Z",
        actor_type="human",
        actor_id="reviewer_owner",
        reason="reviewer_selected_approved_copy",
    )
    clarification = ready["content"]["clarifications"][0]
    clarification["status"] = "resolved"
    clarification["selected_choice_id"] = "choice_use_approved"
    clarification["resolution_note"] = None
    ready["review"] = {
        "status": "reviewed",
        "reviewer_action_required": True,
        "last_human_actor_id": "reviewer_owner",
        "last_reviewed_at": "2026-07-21T10:03:00Z",
        "notes": ["Blocking copy choice resolved from the visual options."],
    }
    ready = seal(ready)

    approved = next_version(
        ready,
        state="approved",
        operation="approved",
        occurred_at="2026-07-21T10:04:00Z",
        actor_type="human",
        actor_id="reviewer_owner",
        reason="reviewer_approved_exact_candidate",
    )
    approved["review"]["reviewer_action_required"] = False
    approved["review"]["last_reviewed_at"] = "2026-07-21T10:04:00Z"
    approved["approval"] = {
        "approval_id": "approval_profile_copy",
        "actor_type": "human",
        "actor_id": "reviewer_owner",
        "approved_at": "2026-07-21T10:04:00Z",
        "reviewed_candidate_version": ready["candidate_version"],
        "reviewed_candidate_digest": ready["candidate_digest"],
        "approved_candidate_version": approved["candidate_version"],
        "candidate_content_digest": ready["candidate_content_digest"],
        "evidence_manifest_digest": approved["evidence_manifest"]["manifest_digest"],
        "authorized_evidence_ids": sorted(
            {
                "evidence_keyframe_001",
                "evidence_repository_001",
                "evidence_route_001",
                "evidence_transcript_001",
            }
        ),
        "immutable": True,
    }
    approved = seal(approved)
    return [draft, needs, ready, approved]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_artifact(value))


def regenerate() -> None:
    draft, needs, ready, approved = positive_chain()
    positives = {
        "version-1-draft.json": draft,
        "version-2-needs-clarification.json": needs,
        "version-3-ready.json": ready,
        "version-4-approved.json": approved,
    }
    for name, value in positives.items():
        write_json(POSITIVE / name, value)

    negatives: dict[str, tuple[dict[str, Any], str]] = {}

    value = copy.deepcopy(approved)
    value["unknown_runtime_field"] = "must be rejected"
    negatives["unknown-property.json"] = (value, "SCHEMA_ADDITIONAL_PROPERTY")

    value = copy.deepcopy(approved)
    clarification = value["content"]["clarifications"][0]
    clarification["status"] = "unresolved"
    clarification["selected_choice_id"] = None
    clarification["resolution_note"] = None
    negatives["unresolved-blocking-approved.json"] = (seal(value), "UNRESOLVED_BLOCKING_CLARIFICATION")

    value = copy.deepcopy(approved)
    value["approval"]["actor_type"] = "system"
    negatives["machine-approval.json"] = (value, "SCHEMA_CONST")

    value = copy.deepcopy(approved)
    value["content"]["title"] = "Tampered after sealing"
    negatives["tampered-content.json"] = (value, "CONTENT_DIGEST_MISMATCH")

    value = copy.deepcopy(approved)
    value["approval"]["authorized_evidence_ids"].remove("evidence_route_001")
    negatives["unauthorized-evidence.json"] = (seal(value), "APPROVAL_EVIDENCE_BINDING_MISMATCH")

    value = copy.deepcopy(approved)
    value["lineage"]["operation"] = "generated"
    negatives["invalid-lineage.json"] = (seal(value), "LINEAGE_OPERATION_MISMATCH")

    value = copy.deepcopy(ready)
    value["content"]["clarifications"][0]["selected_choice_id"] = "choice_missing"
    negatives["unknown-choice.json"] = (seal(value), "UNKNOWN_CLARIFICATION_CHOICE")

    value = copy.deepcopy(ready)
    value["content"]["clarifications"][0]["choices"][1]["presentation"]["value"] = None
    negatives["invalid-presentation.json"] = (seal(value), "INVALID_CHOICE_PRESENTATION")

    value = copy.deepcopy(ready)
    value["content"]["summary"]["text"] = "Synthetic Bearer abcdefghijklmnopqrstuvwxyz012345"
    negatives["secret-value.json"] = (seal(value), "SECRET_VALUE_DETECTED")

    expected: list[dict[str, str]] = []
    for name, (value, code) in negatives.items():
        write_json(NEGATIVE / name, value)
        expected.append({"file": name, "expected_error": code})
    write_json(NEGATIVE / "expected.json", expected)


if __name__ == "__main__":
    regenerate()
