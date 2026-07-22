#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Idempotently regenerate the synthetic positive candidate-contract fixtures."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from handoff_contract import (  # noqa: E402
    TICKET_CANDIDATE,
    canonical_json_artifact,
    load_json,
    project_source_candidate_ticket,
    render_markdown,
    seal_handoff,
    seal_registry_assertion,
    seal_trial,
    sha256_digest,
)


POSITIVE = ROOT / "fixtures" / "positive"
SYNTHETIC_KEY = bytes.fromhex("11" * 32)
SAMPLE_PROJECT_ID = "project-sample-mobile-app-synthetic"
SAMPLE_MOBILE_REPOSITORY_ID = "repo-sample-mobile-app"
SAMPLE_BACKEND_REPOSITORY_ID = "repo-sample-backend"
SAMPLE_APPLICATION_ID = "com.example.samplemobileapp.tacua.synthetic"


def _claim_evidence(ticket: dict, claim_refs: list[str]) -> list[str]:
    claims = {claim["claim_id"]: claim for claim in ticket["claims"]}
    return sorted(
        {
            evidence_id
            for claim_id in claim_refs
            for evidence_id in claims[claim_id]["evidence_refs"]
        }
    )


def build_source_candidate(handoff: dict) -> dict:
    """Build the exact synthetic approved candidate represented by the handoff."""

    ticket = handoff["ticket"]
    approval = handoff["approval"]
    manifest = handoff["evidence_manifest"]
    previous_digest = "sha256:" + "9" * 64
    expected_claim_refs = ticket["reproduction"]["expected_claim_refs"]
    observed_claim_refs = ticket["reproduction"]["observed_claim_refs"]
    summary_claim_refs = ticket["summary_claim_refs"]
    acceptance_claim_refs = [
        expected_claim_refs,
        ["claim-observed-submit"],
    ]
    content = {
        "title": ticket["title"],
        "priority": ticket["priority"],
        "summary": {
            "text": ticket["summary"],
            "claim_refs": summary_claim_refs,
            "evidence_refs": _claim_evidence(ticket, summary_claim_refs),
        },
        "actual_behavior": {
            "text": ticket["reproduction"]["observed_result"],
            "claim_refs": observed_claim_refs,
            "evidence_refs": _claim_evidence(ticket, observed_claim_refs),
        },
        "expected_behavior": {
            "text": ticket["reproduction"]["expected_result"],
            "claim_refs": expected_claim_refs,
            "evidence_refs": _claim_evidence(ticket, expected_claim_refs),
        },
        "claims": ticket["claims"],
        "reproduction": {
            "preconditions": [
                {
                    "precondition_id": f"precondition-{index}",
                    "text": text,
                    "claim_refs": [],
                    "evidence_refs": [],
                }
                for index, text in enumerate(
                    ticket["reproduction"]["preconditions"], start=1
                )
            ],
            "steps": [
                {
                    "step_id": step["step_id"],
                    "action": step["action"],
                    "expected_result": None,
                    "actual_result": None,
                    "claim_refs": step["claim_refs"],
                    "evidence_refs": step["evidence_refs"],
                    "confidence": "high",
                }
                for step in ticket["reproduction"]["steps"]
            ],
            "attempts": ticket["reproduction"]["attempts"],
            "reproductions": ticket["reproduction"]["reproductions"],
        },
        "scope": ticket["scope"],
        "acceptance_criteria": [
            {
                **criterion,
                "claim_refs": claim_refs,
                "evidence_refs": _claim_evidence(ticket, claim_refs),
            }
            for criterion, claim_refs in zip(
                ticket["acceptance_criteria"], acceptance_claim_refs, strict=True
            )
        ],
        "uncertainty": {
            "overall_confidence": "medium",
            "items": [
                {
                    "uncertainty_id": "uncertainty-sentry-correlation",
                    "statement": "The unavailable Sentry correlation remains an explicit non-blocking limitation.",
                    "impact": "non_blocking",
                    "evidence_refs": ["evidence-sentry-001"],
                }
            ],
        },
        "clarifications": [
            {
                "clarification_id": item["clarification_id"],
                "question": item["question"],
                "target": "expected_behavior",
                "impact": item["impact"],
                "status": item["status"],
                "choices": [
                    {
                        "choice_id": "choice-keep-current",
                        "label": "Keep current copy",
                        "description": "Keep the copy observed in the tested build.",
                        "consequence": "No copy correction would be requested.",
                        "requires_note": False,
                        "presentation": {
                            "kind": "text",
                            "value": "Save draft",
                            "evidence_ref": None,
                        },
                        "evidence_refs": ["evidence-keyframe-001"],
                    },
                    {
                        "choice_id": "choice-use-approved",
                        "label": "Use approved copy",
                        "description": "Use the reviewer-approved V1 copy.",
                        "consequence": "The ticket requests the approved label.",
                        "requires_note": False,
                        "presentation": {
                            "kind": "text",
                            "value": "Save profile",
                            "evidence_ref": None,
                        },
                        "evidence_refs": ["evidence-repository-001"],
                    },
                ],
                "selected_choice_id": "choice-use-approved",
                "resolution_note": item["resolution"],
            }
            for item in ticket["clarifications"]
        ],
    }
    candidate = {
        "contract_version": "tacua.ticket-candidate@1.0.0",
        "media_type": "application/vnd.tacua.ticket-candidate+json;version=1.0.0",
        "organization_id": handoff["organization_id"],
        "project_id": handoff["project_id"],
        "build_id": handoff["build_identity"]["build_id"],
        "build_identity_digest": handoff["build_identity"]["sdk"][
            "configuration_digest"
        ],
        "session_id": manifest["session_id"],
        "evidence_manifest": {
            "manifest_id": manifest["manifest_id"],
            "manifest_digest": "sha256:" + "a" * 64,
            "evidence_ids": sorted(
                item["evidence_id"] for item in manifest["items"]
            ),
        },
        "candidate_id": ticket["ticket_id"],
        "candidate_version": 4,
        "previous_candidate_digest": previous_digest,
        "state": "approved",
        "candidate_created_at": "2026-07-20T10:10:00Z",
        "version_created_at": approval["approved_at"],
        "lineage": {
            "operation": "approved",
            "parents": [
                {
                    "candidate_id": ticket["ticket_id"],
                    "candidate_version": 3,
                    "candidate_digest": previous_digest,
                }
            ],
        },
        "transition": {
            "from_state": "ready_for_review",
            "to_state": "approved",
            "actor": {
                "actor_type": "human",
                "actor_id": approval["actor_id"],
            },
            "occurred_at": approval["approved_at"],
            "reason": "Synthetic owner approved the exact reviewed candidate.",
        },
        "content": content,
        "review": {
            "status": "reviewed",
            "reviewer_action_required": False,
            "last_human_actor_id": approval["actor_id"],
            "last_reviewed_at": "2026-07-20T10:15:30Z",
            "notes": ["Synthetic fixture review only."],
        },
        "approval": {
            "approval_id": approval["approval_id"],
            "actor_type": "human",
            "actor_id": approval["actor_id"],
            "approved_at": approval["approved_at"],
            "reviewed_candidate_version": 3,
            "reviewed_candidate_digest": previous_digest,
            "approved_candidate_version": 4,
            "candidate_content_digest": "sha256:" + "0" * 64,
            "evidence_manifest_digest": "sha256:" + "0" * 64,
            "authorized_evidence_ids": sorted(
                item["evidence_id"] for item in manifest["items"]
            ),
            "immutable": True,
        },
        "rejection": None,
        "candidate_content_digest": "sha256:" + "0" * 64,
        "candidate_digest": "sha256:" + "0" * 64,
    }
    candidate = TICKET_CANDIDATE.seal(candidate)
    TICKET_CANDIDATE.validate(candidate)
    return candidate


def apply_sample_mobile_app_identity(handoff: dict) -> None:
    """Keep every integrity-bound fixture scoped to an obviously fictional app."""

    handoff["project_id"] = SAMPLE_PROJECT_ID
    handoff["approval"]["project_id"] = SAMPLE_PROJECT_ID
    handoff["authority"]["allowed_repositories"] = [
        SAMPLE_MOBILE_REPOSITORY_ID,
        SAMPLE_BACKEND_REPOSITORY_ID,
    ]

    build = handoff["build_identity"]
    build["project_id"] = SAMPLE_PROJECT_ID
    build["mobile"]["application_id"] = SAMPLE_APPLICATION_ID
    build["mobile"]["source"]["repository_id"] = SAMPLE_MOBILE_REPOSITORY_ID
    for source in build["backend"]["sources"]:
        source["repository_id"] = SAMPLE_BACKEND_REPOSITORY_ID

    manifest = handoff["evidence_manifest"]
    manifest["project_id"] = SAMPLE_PROJECT_ID
    for item in manifest["items"]:
        item["project_id"] = SAMPLE_PROJECT_ID
        if item["authorization"] is not None:
            item["authorization"]["project_id"] = SAMPLE_PROJECT_ID
        if item["reference"] is not None:
            item["reference"]["locator"]["project_id"] = SAMPLE_PROJECT_ID
        if item["source"]["component"] == "repository":
            item["source"]["source_id"] = SAMPLE_MOBILE_REPOSITORY_ID


def main() -> None:
    handoff = load_json(POSITIVE / "approved-handoff.json")
    apply_sample_mobile_app_identity(handoff)
    claims = handoff["ticket"]["claims"]
    support_by_id = {
        "claim-observed-label": ("direct", "high"),
        "claim-observed-submit": ("direct", "high"),
        "claim-diagnosis-copy": ("direct", "high"),
        "claim-constraint-sentry": ("inferred", "medium"),
        "claim-expected-behavior": ("inferred", "high"),
    }
    for claim in claims:
        claim["support"], claim["confidence"] = support_by_id[claim["claim_id"]]

    expected_id = "claim-expected-behavior"
    if not any(claim["claim_id"] == expected_id for claim in claims):
        claims.append(
            {
                "claim_id": expected_id,
                "kind": "expected",
                "support": "inferred",
                "confidence": "high",
                "statement": "The approved behavior is Save profile copy and exactly one update on the first enabled tap.",
                "evidence_refs": ["evidence-repository-001", "evidence-backend-001"],
            }
        )

    ticket = handoff["ticket"]
    ticket["summary_claim_refs"] = ["claim-observed-label", "claim-observed-submit"]
    reproduction = ticket["reproduction"]
    reproduction["observed_claim_refs"] = ["claim-observed-label", "claim-observed-submit"]
    reproduction["expected_claim_refs"] = [expected_id]
    step_claims = {
        "step-open-profile": ["claim-observed-label"],
        "step-change-name": ["claim-observed-label"],
        "step-tap-save": ["claim-observed-submit"],
    }
    for step in reproduction["steps"]:
        step["claim_refs"] = step_claims[step["step_id"]]

    source_candidate = build_source_candidate(handoff)
    handoff["contract_version"] = "tacua.approved-handoff@1.1.0"
    handoff["media_type"] = (
        "application/vnd.tacua.approved-handoff+json;version=1.1.0"
    )
    handoff["source_candidate"] = {
        "contract_version": source_candidate["contract_version"],
        "candidate_id": source_candidate["candidate_id"],
        "candidate_version": source_candidate["candidate_version"],
        "candidate_digest": source_candidate["candidate_digest"],
        "candidate_content_digest": source_candidate["candidate_content_digest"],
        "canonical_json": TICKET_CANDIDATE.canonical_json(source_candidate),
    }
    handoff["ticket"] = project_source_candidate_ticket(source_candidate)
    handoff["approval"]["ticket_id"] = source_candidate["candidate_id"]
    handoff["approval"]["ticket_version"] = source_candidate["candidate_version"]
    handoff = seal_handoff(handoff)
    ticket = handoff["ticket"]
    handoff_bytes = canonical_json_artifact(handoff)
    markdown = render_markdown(handoff)

    assertion = {
        "contract_version": "tacua.registry-assertion@1.0.0",
        "media_type": "application/vnd.tacua.registry-assertion+json;version=1.0.0",
        "assertion_id": "assertion-synthetic-001",
        "issuer_id": "registry-synthetic-001",
        "organization_id": handoff["organization_id"],
        "project_id": handoff["project_id"],
        "ticket_id": ticket["ticket_id"],
        "ticket_version": ticket["ticket_version"],
        "current_handoff_digest": handoff["handoff_digest"],
        "registry_revision": handoff["supersession"]["registry_revision"],
        "authorized_sources": sorted(
            [
                {
                    "component": item["source"]["component"],
                    "source_id": item["source"]["source_id"],
                    "snapshot_revision": item["source"]["snapshot_revision"],
                }
                for item in handoff["evidence_manifest"]["items"]
            ],
            key=lambda source: (source["component"], source["source_id"], source["snapshot_revision"]),
        ),
        "issued_at": "2026-07-20T10:16:01Z",
        "expires_at": "2026-07-21T10:16:01Z",
        "signature": {
            "algorithm": "hmac-sha256",
            "key_id": "registry-key-synthetic-001",
            "value": "hmac-sha256:" + "0" * 64,
        },
    }
    assertion = seal_registry_assertion(assertion, SYNTHETIC_KEY)
    assertion_bytes = canonical_json_artifact(assertion)

    trial = load_json(POSITIVE / "agent-trial.json")
    trial["project_id"] = SAMPLE_PROJECT_ID
    trial["ticket_id"] = ticket["ticket_id"]
    trial["ticket_version"] = ticket["ticket_version"]
    for change in trial["changes"]:
        change["repository_id"] = SAMPLE_MOBILE_REPOSITORY_ID
        change["path"] = f"apps/sample-mobile-app/src/profile/{Path(change['path']).name}"
    trial["handoff_digest"] = handoff["handoff_digest"]
    trial["ticket_content_digest"] = handoff["ticket"]["ticket_content_digest"]
    trial["json_artifact_digest"] = sha256_digest(handoff_bytes)
    trial["markdown_artifact_digest"] = sha256_digest(markdown.encode("utf-8"))
    trial["registry_assertion_digest"] = sha256_digest(assertion_bytes)
    trial["reporter_intervention"] = {
        "interaction_count": 0,
        "active_seconds": 0,
        "questions_answered": 0,
    }
    trial["acceptance"] = {
        "status": "accepted",
        "actor_id": "member-approver-001",
        "decided_at": "2026-07-20T11:07:00Z",
        "notes": "Synthetic owner acceptance for contract-fixture coverage only.",
    }
    trial = seal_trial(trial)

    (POSITIVE / "approved-handoff.json").write_bytes(handoff_bytes)
    (POSITIVE / "approved-handoff.md").write_text(markdown, encoding="utf-8")
    (POSITIVE / "source-candidate.json").write_bytes(
        TICKET_CANDIDATE.canonical_json_artifact(source_candidate)
    )
    (POSITIVE / "build-identity.json").write_bytes(canonical_json_artifact(handoff["build_identity"]))
    (POSITIVE / "evidence-manifest.json").write_bytes(canonical_json_artifact(handoff["evidence_manifest"]))
    (POSITIVE / "registry-assertion.json").write_bytes(assertion_bytes)
    (POSITIVE / "agent-trial.json").write_bytes(canonical_json_artifact(trial))


if __name__ == "__main__":
    main()
