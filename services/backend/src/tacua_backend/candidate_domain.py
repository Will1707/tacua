"""Production ticket-candidate transitions over immutable stored chains.

This module constructs only the next version.  The canonical ticket-candidate
contract remains the validation authority for every stored and returned chain.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import re
from types import ModuleType
from typing import Any, Sequence


def _load_ticket_candidate_contract() -> ModuleType:
    repository_root = Path(__file__).resolve().parents[4]
    module_path = (
        repository_root
        / "contracts"
        / "ticket-candidate"
        / "src"
        / "ticket_candidate_contract.py"
    )
    if not module_path.is_file():
        raise RuntimeError("Tacua ticket-candidate contract validator is unavailable")
    spec = importlib.util.spec_from_file_location(
        "tacua_ticket_candidate_contract",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Tacua ticket-candidate contract validator cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TICKET_CONTRACT = _load_ticket_candidate_contract()
ContractError = TICKET_CONTRACT.ContractError

_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
_ACTIONS = {"resolve_clarification", "mark_ready", "approve", "reject"}
_COMMON_FIELDS = {
    "action",
    "actor_id",
    "expected_candidate_id",
    "expected_candidate_version",
    "expected_candidate_digest",
    "expected_candidate_content_digest",
    "expected_evidence_manifest_digest",
    "reason",
}
_ACTION_FIELDS = {
    "resolve_clarification": {
        "clarification_id",
        "choice_id",
        "resolution_note",
    },
    "mark_ready": set(),
    "approve": {"approval_id"},
    "reject": set(),
}


def _require(condition: bool, code: str, path: str, detail: str) -> None:
    if not condition:
        raise ContractError(code, path, detail)


def _require_id(value: Any, path: str) -> str:
    _require(
        isinstance(value, str) and _ID_PATTERN.fullmatch(value) is not None,
        "TRANSITION_FIELD_INVALID",
        path,
        "expected a Tacua identifier",
    )
    return value


def _require_digest(value: Any, path: str) -> str:
    _require(
        isinstance(value, str) and _DIGEST_PATTERN.fullmatch(value) is not None,
        "TRANSITION_FIELD_INVALID",
        path,
        "expected a lowercase SHA-256 digest",
    )
    return value


def _require_text(value: Any, path: str, maximum: int) -> str:
    _require(
        isinstance(value, str) and 1 <= len(value) <= maximum,
        "TRANSITION_FIELD_INVALID",
        path,
        f"expected non-empty text no longer than {maximum} characters",
    )
    return value


def _validate_body(body: Any, authenticated_reviewer_id: str) -> dict[str, Any]:
    _require(
        isinstance(body, dict),
        "TRANSITION_BODY_TYPE",
        "$",
        "transition body must be an object",
    )
    action = body.get("action")
    _require(
        isinstance(action, str) and action in _ACTIONS,
        "TRANSITION_ACTION_INVALID",
        "$.action",
        "action is outside the closed transition set",
    )
    expected_fields = _COMMON_FIELDS | _ACTION_FIELDS[action]
    _require(
        set(body) == expected_fields,
        "TRANSITION_BODY_FIELDS",
        "$",
        f"transition body must contain exactly {sorted(expected_fields)!r}",
    )

    actor_id = _require_id(body["actor_id"], "$.actor_id")
    _require_id(authenticated_reviewer_id, "$.authenticated_reviewer_id")
    _require(
        actor_id == authenticated_reviewer_id,
        "REVIEWER_MISMATCH",
        "$.actor_id",
        "body actor does not match the authenticated configured reviewer",
    )
    _require_id(body["expected_candidate_id"], "$.expected_candidate_id")
    _require(
        isinstance(body["expected_candidate_version"], int)
        and not isinstance(body["expected_candidate_version"], bool)
        and body["expected_candidate_version"] >= 1,
        "TRANSITION_FIELD_INVALID",
        "$.expected_candidate_version",
        "expected candidate version must be a positive integer",
    )
    for field in (
        "expected_candidate_digest",
        "expected_candidate_content_digest",
        "expected_evidence_manifest_digest",
    ):
        _require_digest(body[field], f"$.{field}")
    _require_text(body["reason"], "$.reason", 256)

    if action == "resolve_clarification":
        _require_id(body["clarification_id"], "$.clarification_id")
        _require_id(body["choice_id"], "$.choice_id")
        note = body["resolution_note"]
        if note is not None:
            _require_text(note, "$.resolution_note", 4096)
    elif action == "approve":
        _require_id(body["approval_id"], "$.approval_id")
    return body


def _check_expected_parent(parent: dict[str, Any], body: dict[str, Any]) -> None:
    checks = (
        (
            "expected_candidate_id",
            "candidate_id",
            "EXPECTED_CANDIDATE_ID_MISMATCH",
        ),
        (
            "expected_candidate_version",
            "candidate_version",
            "EXPECTED_CANDIDATE_VERSION_MISMATCH",
        ),
        (
            "expected_candidate_digest",
            "candidate_digest",
            "EXPECTED_CANDIDATE_DIGEST_MISMATCH",
        ),
        (
            "expected_candidate_content_digest",
            "candidate_content_digest",
            "EXPECTED_CONTENT_DIGEST_MISMATCH",
        ),
    )
    for body_field, parent_field, code in checks:
        _require(
            body[body_field] == parent[parent_field],
            code,
            f"$.{body_field}",
            f"request does not bind the stored parent {parent_field}",
        )
    _require(
        body["expected_evidence_manifest_digest"]
        == parent["evidence_manifest"]["manifest_digest"],
        "EXPECTED_EVIDENCE_DIGEST_MISMATCH",
        "$.expected_evidence_manifest_digest",
        "request does not bind the stored evidence manifest",
    )


def _next_timestamp(server_time: datetime, parent: dict[str, Any]) -> str:
    _require(
        isinstance(server_time, datetime)
        and server_time.tzinfo is not None
        and server_time.utcoffset() is not None,
        "SERVER_TIME_INVALID",
        "$.server_time",
        "server time must be a timezone-aware datetime",
    )
    supplied = server_time.astimezone(timezone.utc).replace(microsecond=0)
    parent_time = TICKET_CONTRACT.parse_time(
        parent["version_created_at"],
        "$.parent.version_created_at",
    )
    occurred = max(supplied, parent_time + timedelta(seconds=1))
    return occurred.strftime("%Y-%m-%dT%H:%M:%SZ")


def _unresolved_blocking(content: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        clarification
        for clarification in content["clarifications"]
        if clarification["impact"] == "blocking"
        and clarification["status"] == "unresolved"
    ]


def _resolve_clarification(
    candidate: dict[str, Any],
    body: dict[str, Any],
) -> str:
    _require(
        candidate["state"] == "needs_clarification",
        "ILLEGAL_TRANSITION_ACTION",
        "$.action",
        "clarification resolution requires a needs_clarification parent",
    )
    clarification = next(
        (
            item
            for item in candidate["content"]["clarifications"]
            if item["clarification_id"] == body["clarification_id"]
        ),
        None,
    )
    _require(
        clarification is not None,
        "CLARIFICATION_NOT_FOUND",
        "$.clarification_id",
        "clarification is not declared by the stored candidate",
    )
    _require(
        clarification["status"] == "unresolved",
        "CLARIFICATION_ALREADY_RESOLVED",
        "$.clarification_id",
        "clarification was already resolved",
    )
    choice = next(
        (
            item
            for item in clarification["choices"]
            if item["choice_id"] == body["choice_id"]
        ),
        None,
    )
    _require(
        choice is not None,
        "UNDECLARED_CLARIFICATION_CHOICE",
        "$.choice_id",
        "choice is not declared by the stored clarification",
    )
    if choice["requires_note"]:
        _require(
            isinstance(body["resolution_note"], str)
            and bool(body["resolution_note"]),
            "CLARIFICATION_NOTE_REQUIRED",
            "$.resolution_note",
            "selected choice requires a non-empty reviewer note",
        )
    clarification["status"] = "resolved"
    clarification["selected_choice_id"] = choice["choice_id"]
    clarification["resolution_note"] = body["resolution_note"]
    # The declared choice object, including its consequence, remains unchanged
    # in content as explicit downstream handoff context.
    return "needs_clarification" if _unresolved_blocking(candidate["content"]) else "ready_for_review"


def _target_state(candidate: dict[str, Any], body: dict[str, Any]) -> str:
    action = body["action"]
    if action == "resolve_clarification":
        return _resolve_clarification(candidate, body)
    if action == "mark_ready":
        _require(
            candidate["state"] == "draft",
            "ILLEGAL_TRANSITION_ACTION",
            "$.action",
            "mark_ready requires a draft parent",
        )
        _require(
            not _unresolved_blocking(candidate["content"]),
            "UNRESOLVED_BLOCKING_CLARIFICATION",
            "$.action",
            "mark_ready cannot bypass a blocking clarification",
        )
        return "ready_for_review"
    if action == "approve":
        _require(
            candidate["state"] == "ready_for_review",
            "ILLEGAL_TRANSITION_ACTION",
            "$.action",
            "approve requires the exact ready_for_review parent",
        )
        return "approved"
    _require(
        candidate["state"] in {"needs_clarification", "ready_for_review"},
        "ILLEGAL_TRANSITION_ACTION",
        "$.action",
        "reject requires a reviewable parent",
    )
    return "rejected"


def _assert_payload_preserved(
    parent: dict[str, Any],
    candidate: dict[str, Any],
    body: dict[str, Any],
) -> None:
    immutable_fields = (
        "contract_version",
        "media_type",
        "organization_id",
        "project_id",
        "build_id",
        "build_identity_digest",
        "session_id",
        "evidence_manifest",
        "candidate_id",
        "candidate_created_at",
    )
    for field in immutable_fields:
        _require(
            candidate[field] == parent[field],
            "INTERNAL_TRANSITION_MUTATION",
            f"$.candidate.{field}",
            "transition construction changed immutable candidate scope or evidence",
        )

    expected_content = copy.deepcopy(parent["content"])
    if body["action"] == "resolve_clarification":
        clarification = next(
            item
            for item in expected_content["clarifications"]
            if item["clarification_id"] == body["clarification_id"]
        )
        clarification.update(
            {
                "status": "resolved",
                "selected_choice_id": body["choice_id"],
                "resolution_note": body["resolution_note"],
            }
        )
    _require(
        candidate["content"] == expected_content,
        "INTERNAL_TRANSITION_MUTATION",
        "$.candidate.content",
        "transition changed semantic content outside its declared clarification",
    )


def apply_transition(
    stored_chain: Sequence[dict[str, Any]],
    authenticated_reviewer_id: str,
    body: Any,
    server_time: datetime,
) -> dict[str, Any]:
    """Return a validated immutable N+1 snapshot without mutating its inputs."""

    chain = copy.deepcopy(list(stored_chain))
    TICKET_CONTRACT.validate_chain(chain)
    request = _validate_body(body, authenticated_reviewer_id)
    parent = chain[-1]
    _check_expected_parent(parent, request)
    occurred_at = _next_timestamp(server_time, parent)

    candidate = copy.deepcopy(parent)
    candidate["candidate_version"] = parent["candidate_version"] + 1
    candidate["previous_candidate_digest"] = parent["candidate_digest"]
    candidate["version_created_at"] = occurred_at
    candidate["lineage"] = {
        "operation": {
            "resolve_clarification": "clarification_answered",
            "mark_ready": "reviewed",
            "approve": "approved",
            "reject": "rejected",
        }[request["action"]],
        "parents": [
            {
                "candidate_id": parent["candidate_id"],
                "candidate_version": parent["candidate_version"],
                "candidate_digest": parent["candidate_digest"],
            }
        ],
    }

    target_state = _target_state(candidate, request)
    _assert_payload_preserved(parent, candidate, request)
    candidate["state"] = target_state
    candidate["transition"] = {
        "from_state": parent["state"],
        "to_state": target_state,
        "actor": {
            "actor_type": "human",
            "actor_id": authenticated_reviewer_id,
        },
        "occurred_at": occurred_at,
        "reason": request["reason"],
    }
    candidate["review"] = copy.deepcopy(parent["review"])
    candidate["review"].update(
        {
            "status": (
                "in_review"
                if target_state == "needs_clarification"
                else "reviewed"
            ),
            "reviewer_action_required": target_state
            not in {"approved", "rejected"},
            "last_human_actor_id": authenticated_reviewer_id,
            "last_reviewed_at": occurred_at,
        }
    )
    candidate["approval"] = None
    candidate["rejection"] = None

    if request["action"] == "approve":
        candidate["approval"] = {
            "approval_id": request["approval_id"],
            "actor_type": "human",
            "actor_id": authenticated_reviewer_id,
            "approved_at": occurred_at,
            "reviewed_candidate_version": parent["candidate_version"],
            "reviewed_candidate_digest": parent["candidate_digest"],
            "approved_candidate_version": candidate["candidate_version"],
            "candidate_content_digest": parent["candidate_content_digest"],
            "evidence_manifest_digest": parent["evidence_manifest"]["manifest_digest"],
            "authorized_evidence_ids": sorted(
                TICKET_CONTRACT.content_evidence_refs(parent["content"])
            ),
            "immutable": True,
        }
    elif request["action"] == "reject":
        candidate["rejection"] = {
            "actor_type": "human",
            "actor_id": authenticated_reviewer_id,
            "rejected_at": occurred_at,
            "reviewed_candidate_version": parent["candidate_version"],
            "reviewed_candidate_digest": parent["candidate_digest"],
            "rejected_candidate_version": candidate["candidate_version"],
            "candidate_content_digest": parent["candidate_content_digest"],
            "reason": request["reason"],
            "immutable": True,
        }

    candidate = TICKET_CONTRACT.seal(candidate)
    TICKET_CONTRACT.validate_chain([*chain, candidate])
    return candidate
