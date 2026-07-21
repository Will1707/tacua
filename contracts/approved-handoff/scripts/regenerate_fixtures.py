#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Idempotently regenerate the synthetic positive candidate-contract fixtures."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from handoff_contract import (  # noqa: E402
    canonical_json_artifact,
    load_json,
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

    handoff = seal_handoff(handoff)
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
    (POSITIVE / "build-identity.json").write_bytes(canonical_json_artifact(handoff["build_identity"]))
    (POSITIVE / "evidence-manifest.json").write_bytes(canonical_json_artifact(handoff["evidence_manifest"]))
    (POSITIVE / "registry-assertion.json").write_bytes(assertion_bytes)
    (POSITIVE / "agent-trial.json").write_bytes(canonical_json_artifact(trial))


if __name__ == "__main__":
    main()
