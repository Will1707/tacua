# SPDX-License-Identifier: Apache-2.0
"""Deterministic adapter from an approved candidate to agent handoff artifacts."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

from .candidate_domain import ContractError as CandidateContractError, TICKET_CONTRACT
from .contracts import ContractError as ProtocolContractError, validate as validate_protocol
from .evidence_domain import EvidenceDomainError, validate_manifest


def _load_handoff_contract() -> ModuleType:
    repository_root = Path(__file__).resolve().parents[4]
    module_path = (
        repository_root
        / "contracts"
        / "approved-handoff"
        / "src"
        / "handoff_contract.py"
    )
    if not module_path.is_file():
        raise RuntimeError("Tacua approved-handoff validator is unavailable")
    specification = importlib.util.spec_from_file_location(
        "tacua_approved_handoff_contract", module_path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("Tacua approved-handoff validator cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


HANDOFF = _load_handoff_contract()


class HandoffExportError(ValueError):
    """Stable, content-free failure at the approval/export boundary."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class HandoffArtifacts:
    handoff: dict[str, Any]
    json_bytes: bytes
    markdown_bytes: bytes
    json_digest: str
    markdown_digest: str


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise HandoffExportError(
            "HANDOFF_TIME_INVALID", "handoff registry time must be timezone-aware"
        )
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _decision_id(approval_id: str, evidence_id: str) -> str:
    subject = f"{approval_id}\0{evidence_id}".encode("utf-8")
    return "decision_" + hashlib.sha256(subject).hexdigest()[:32]


def _resolved_clarification(clarification: dict[str, Any]) -> str | None:
    if clarification["status"] != "resolved":
        return None
    if clarification["resolution_note"]:
        return clarification["resolution_note"]
    selected_id = clarification["selected_choice_id"]
    for choice in clarification["choices"]:
        if choice["choice_id"] == selected_id:
            return choice["label"]
    raise HandoffExportError(
        "HANDOFF_CLARIFICATION_INVALID",
        "resolved clarification has no selected choice",
    )


def _step_action(step: dict[str, Any]) -> str:
    parts = [step["action"]]
    if step["expected_result"] is not None:
        parts.append("Expected: " + step["expected_result"])
    if step["actual_result"] is not None:
        parts.append("Observed: " + step["actual_result"])
    return "\n".join(parts)


def map_candidate_ticket(candidate: dict[str, Any]) -> dict[str, Any]:
    """Project one validated ticket candidate into the handoff ticket shape."""

    content = candidate["content"]
    return {
        "ticket_id": candidate["candidate_id"],
        "ticket_version": candidate["candidate_version"],
        "state": "approved",
        "title": content["title"],
        "priority": content["priority"],
        "summary": content["summary"]["text"],
        "summary_claim_refs": copy.deepcopy(content["summary"]["claim_refs"]),
        "claims": copy.deepcopy(content["claims"]),
        "reproduction": {
            "preconditions": [
                item["text"] for item in content["reproduction"]["preconditions"]
            ],
            "steps": [
                {
                    "step_id": item["step_id"],
                    "action": _step_action(item),
                    "claim_refs": copy.deepcopy(item["claim_refs"]),
                    "evidence_refs": copy.deepcopy(item["evidence_refs"]),
                }
                for item in content["reproduction"]["steps"]
            ],
            "observed_result": content["actual_behavior"]["text"],
            "expected_result": content["expected_behavior"]["text"],
            "observed_claim_refs": copy.deepcopy(
                content["actual_behavior"]["claim_refs"]
            ),
            "expected_claim_refs": copy.deepcopy(
                content["expected_behavior"]["claim_refs"]
            ),
            "attempts": content["reproduction"]["attempts"],
            "reproductions": content["reproduction"]["reproductions"],
        },
        "scope": copy.deepcopy(content["scope"]),
        "acceptance_criteria": [
            {
                "criterion_id": item["criterion_id"],
                "criterion": item["criterion"],
                "verification": item["verification"],
            }
            for item in content["acceptance_criteria"]
        ],
        "clarifications": [
            {
                "clarification_id": item["clarification_id"],
                "question": item["question"],
                "impact": item["impact"],
                "status": item["status"],
                "resolution": _resolved_clarification(item),
            }
            for item in content["clarifications"]
        ],
        "ticket_content_digest": "sha256:" + "0" * 64,
    }


def map_source_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    """Bind the handoff to the exact canonical approved candidate snapshot."""

    return {
        "contract_version": candidate["contract_version"],
        "candidate_id": candidate["candidate_id"],
        "candidate_version": candidate["candidate_version"],
        "candidate_digest": candidate["candidate_digest"],
        "candidate_content_digest": candidate["candidate_content_digest"],
        "canonical_json": TICKET_CONTRACT.canonical_json(candidate),
    }


def _map_evidence(
    candidate: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    approval = candidate["approval"]
    authorized_ids = set(approval["authorized_evidence_ids"])
    by_id = {item["evidence_id"]: item for item in manifest["items"]}
    if not authorized_ids or not authorized_ids <= set(by_id):
        raise HandoffExportError(
            "HANDOFF_EVIDENCE_MISMATCH",
            "approved candidate references unavailable manifest membership",
        )
    items: list[dict[str, Any]] = []
    for evidence_id in sorted(authorized_ids):
        source = by_id[evidence_id]
        authorization = None
        if source["availability"] == "available":
            authorization = {
                "authorized_for_handoff": True,
                "organization_id": candidate["organization_id"],
                "project_id": candidate["project_id"],
                "evidence_id": evidence_id,
                "decision_id": _decision_id(approval["approval_id"], evidence_id),
                "actor_id": approval["actor_id"],
                "policy_version": "tacua.egress@1.0.0",
                "approved_at": approval["approved_at"],
                "immutable": True,
            }
        items.append(
            {
                "contract_version": "tacua.evidence-item@1.0.0",
                "organization_id": source["organization_id"],
                "project_id": source["project_id"],
                "session_id": source["session_id"],
                "evidence_id": source["evidence_id"],
                "evidence_type": source["evidence_type"],
                "availability": source["availability"],
                "description": source["description"],
                "time_range": copy.deepcopy(source["time_range"]),
                "source": copy.deepcopy(source["source"]),
                "reference": copy.deepcopy(source["reference"]),
                "authorization": authorization,
                "unavailable": copy.deepcopy(source["unavailable"]),
                "evidence_item_digest": "sha256:" + "0" * 64,
            }
        )
    return {
        "contract_version": "tacua.evidence-manifest@1.0.0",
        "media_type": "application/vnd.tacua.evidence-manifest+json;version=1.0.0",
        "organization_id": candidate["organization_id"],
        "project_id": candidate["project_id"],
        "session_id": candidate["session_id"],
        "manifest_id": manifest["manifest_id"],
        "items": items,
        "evidence_manifest_digest": "sha256:" + "0" * 64,
    }


def _validate_build_mapping(
    candidate: dict[str, Any],
    sdk_build_identity: dict[str, Any],
    handoff_build_identity: dict[str, Any],
) -> None:
    try:
        validate_protocol(sdk_build_identity)
        HANDOFF.validate_build_identity(handoff_build_identity)
    except (ProtocolContractError, HANDOFF.ContractError) as error:
        raise HandoffExportError(
            "HANDOFF_BUILD_INVALID", "handoff build identity is invalid"
        ) from error
    distribution = {
        "local": "local-development",
        "internal": "internal",
        "testflight": "testflight",
    }[sdk_build_identity["distribution"]]
    mobile = handoff_build_identity["mobile"]
    mismatched = (
        sdk_build_identity["message_type"] != "build_identity"
        or sdk_build_identity["source"]["working_tree_dirty"] is not False
        or candidate["build_id"] != sdk_build_identity["build_id"]
        or candidate["build_identity_digest"]
        != sdk_build_identity["build_identity_digest"]
        or handoff_build_identity["organization_id"]
        != candidate["organization_id"]
        or handoff_build_identity["project_id"] != candidate["project_id"]
        or handoff_build_identity["build_id"] != candidate["build_id"]
        or mobile["platform"] != sdk_build_identity["platform"]
        or mobile["application_id"] != sdk_build_identity["bundle_identifier"]
        or mobile["app_version"] != sdk_build_identity["native_version"]
        or mobile["build_number"] != sdk_build_identity["native_build"]
        or mobile["distribution"] != distribution
        or mobile["source"]["revision"]
        != sdk_build_identity["source"]["git_revision"]
        or mobile["source"]["dirty"] is not False
        or handoff_build_identity["sdk"]["configuration_digest"]
        != sdk_build_identity["transport_configuration_digest"]
    )
    if mismatched:
        raise HandoffExportError(
            "HANDOFF_BUILD_MISMATCH",
            "handoff build identity does not match the captured SDK build",
        )


def export_approved_candidate(
    *,
    candidate: dict[str, Any],
    evidence_manifest: dict[str, Any],
    sdk_build_identity: dict[str, Any],
    handoff_build_identity: dict[str, Any],
    authority: dict[str, Any],
    registry_revision: str,
    checked_at: datetime,
    supersedes_handoff_digest: str | None = None,
) -> HandoffArtifacts:
    """Create structural-only JSON/Markdown from one exact approved version.

    The output intentionally carries no registry assertion and therefore does
    not authorize execution by itself. Missing binary, image, deployment, or
    repository identity must be supplied in ``handoff_build_identity``; this
    adapter never fabricates those values.
    """

    try:
        TICKET_CONTRACT.validate(candidate)
        validate_manifest(evidence_manifest)
    except (CandidateContractError, EvidenceDomainError) as error:
        raise HandoffExportError(
            "HANDOFF_INPUT_INVALID", "approved candidate input is invalid"
        ) from error
    approval = candidate.get("approval")
    if (
        candidate["state"] != "approved"
        or not isinstance(approval, dict)
        or approval["approved_candidate_version"] != candidate["candidate_version"]
        or approval["candidate_content_digest"] != candidate["candidate_content_digest"]
        or approval["evidence_manifest_digest"]
        != candidate["evidence_manifest"]["manifest_digest"]
        or evidence_manifest["manifest_id"]
        != candidate["evidence_manifest"]["manifest_id"]
        or evidence_manifest["manifest_digest"]
        != candidate["evidence_manifest"]["manifest_digest"]
        or {item["evidence_id"] for item in evidence_manifest["items"]}
        != set(candidate["evidence_manifest"]["evidence_ids"])
    ):
        raise HandoffExportError(
            "HANDOFF_APPROVAL_MISMATCH",
            "handoff input is not the exact approved candidate evidence",
        )
    _validate_build_mapping(candidate, sdk_build_identity, handoff_build_identity)

    handoff = {
        "contract_version": "tacua.approved-handoff@1.1.0",
        "media_type": "application/vnd.tacua.approved-handoff+json;version=1.1.0",
        "organization_id": candidate["organization_id"],
        "project_id": candidate["project_id"],
        "source_candidate": map_source_candidate(candidate),
        "ticket": map_candidate_ticket(candidate),
        "build_identity": copy.deepcopy(handoff_build_identity),
        "evidence_manifest": _map_evidence(candidate, evidence_manifest),
        "approval": {
            "state": "approved",
            "approval_id": approval["approval_id"],
            "actor_id": approval["actor_id"],
            "organization_id": candidate["organization_id"],
            "project_id": candidate["project_id"],
            "ticket_id": candidate["candidate_id"],
            "approved_at": approval["approved_at"],
            "ticket_version": candidate["candidate_version"],
            "ticket_content_digest": "sha256:" + "0" * 64,
            "immutable": True,
        },
        "supersession": {
            "status": "current",
            "supersedes_handoff_digest": supersedes_handoff_digest,
            "superseded_by_handoff_digest": None,
            "checked_at": _timestamp(checked_at),
            "registry_revision": registry_revision,
        },
        "authority": copy.deepcopy(authority),
        "handoff_digest": "sha256:" + "0" * 64,
    }
    try:
        handoff = HANDOFF.seal_handoff(handoff)
        HANDOFF.validate_handoff(handoff, executable=False)
        markdown = HANDOFF.render_markdown(handoff).encode("utf-8")
        json_bytes = HANDOFF.canonical_json_artifact(handoff)
        HANDOFF.validate_markdown(handoff, markdown.decode("utf-8"))
    except HANDOFF.ContractError as error:
        raise HandoffExportError(
            "HANDOFF_CONTRACT_INVALID",
            "approved candidate cannot be represented by the handoff contract",
        ) from error
    return HandoffArtifacts(
        handoff=handoff,
        json_bytes=json_bytes,
        markdown_bytes=markdown,
        json_digest=_sha256(json_bytes),
        markdown_digest=_sha256(markdown),
    )
