# SPDX-License-Identifier: Apache-2.0
"""Dependency-free validation for Tacua's production draft ticket candidate."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


CONTRACT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = CONTRACT_ROOT / "schemas"
SCHEMA_FILE = "ticket-candidate.schema.json"
CONTRACT_VERSION = "tacua.ticket-candidate@1.0.0"
MAX_ARTIFACT_BYTES = 1_048_576
MAX_SAFE_INTEGER = 9_007_199_254_740_991

FORBIDDEN_KEYS = {
    "access_token",
    "api_key",
    "client_secret",
    "cookie",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "session_cookie",
    "set_cookie",
}
SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"\b(?:gh[opusr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b"),
    re.compile(r"\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,})\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(
        r"(?i)(?:[?&](?:x-amz-signature|x-goog-signature|signature|sig|access_token|token)=)"
        r"[^&#\s]{8,}"
    ),
    re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/@:]+:[^\s/@]+@"),
)


class ContractError(ValueError):
    """A stable, user-visible contract validation failure."""

    def __init__(self, code: str, path: str, detail: str):
        self.code = code
        self.path = path
        self.detail = detail
        super().__init__(f"{code} at {path}: {detail}")


def canonical_json(value: Any) -> str:
    """Return Tacua Canonical JSON v1 without an artifact trailing newline."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_json_artifact(value: Any) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def sha256_digest(value: Any) -> str:
    payload = value if isinstance(value, bytes) else canonical_json(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def digest_without(value: dict[str, Any], field: str) -> str:
    subject = copy.deepcopy(value)
    subject.pop(field, None)
    return sha256_digest(subject)


def candidate_content_subject(candidate: dict[str, Any]) -> dict[str, Any]:
    """Bind editable content to its immutable project/build/session/evidence scope."""

    return {
        "contract_version": candidate["contract_version"],
        "organization_id": candidate["organization_id"],
        "project_id": candidate["project_id"],
        "build_id": candidate["build_id"],
        "build_identity_digest": candidate["build_identity_digest"],
        "session_id": candidate["session_id"],
        "evidence_manifest": candidate["evidence_manifest"],
        "candidate_id": candidate["candidate_id"],
        "content": candidate["content"],
    }


def seal(candidate: dict[str, Any]) -> dict[str, Any]:
    """Recompute fixture/authoring digests; this never grants approval authority."""

    result = copy.deepcopy(candidate)
    result["candidate_content_digest"] = sha256_digest(candidate_content_subject(result))
    if result.get("approval") is not None:
        result["approval"]["approved_candidate_version"] = result["candidate_version"]
        result["approval"]["candidate_content_digest"] = result["candidate_content_digest"]
        result["approval"]["evidence_manifest_digest"] = result["evidence_manifest"]["manifest_digest"]
    if result.get("rejection") is not None:
        result["rejection"]["rejected_candidate_version"] = result["candidate_version"]
        result["rejection"]["candidate_content_digest"] = result["candidate_content_digest"]
    result["candidate_digest"] = digest_without(result, "candidate_digest")
    return result


class SchemaValidator:
    """Small Draft 2020-12 subset evaluator used by the bundled strict schemas."""

    def __init__(self, schema_root: Path = SCHEMA_ROOT):
        self.schema_root = schema_root.resolve()
        self._cache: dict[Path, dict[str, Any]] = {}

    def load(self, filename: str) -> tuple[dict[str, Any], Path]:
        path = (self.schema_root / filename).resolve()
        if path.parent != self.schema_root:
            raise ContractError("SCHEMA_REF_FORBIDDEN", "$", "schema escaped its directory")
        if path not in self._cache:
            self._cache[path] = json.loads(path.read_text(encoding="utf-8"))
        return self._cache[path], path

    def validate(self, instance: Any, filename: str) -> None:
        schema, path = self.load(filename)
        errors = self._errors(instance, schema, "$", schema, path)
        if errors:
            raise errors[0]

    def _resolve_ref(
        self,
        ref: str,
        root: dict[str, Any],
        root_path: Path,
    ) -> tuple[dict[str, Any], dict[str, Any], Path]:
        file_part, separator, fragment = ref.partition("#")
        if file_part:
            target_path = (root_path.parent / file_part).resolve()
            if target_path.parent != self.schema_root:
                raise ContractError("SCHEMA_REF_FORBIDDEN", "$", ref)
            if target_path not in self._cache:
                self._cache[target_path] = json.loads(target_path.read_text(encoding="utf-8"))
            target_root = self._cache[target_path]
        else:
            target_path, target_root = root_path, root
        target: Any = target_root
        if separator and fragment:
            if not fragment.startswith("/"):
                raise ContractError("SCHEMA_REF_UNSUPPORTED", "$", ref)
            for raw in fragment[1:].split("/"):
                target = target[raw.replace("~1", "/").replace("~0", "~")]
        return target, target_root, target_path

    def _errors(
        self,
        value: Any,
        schema: dict[str, Any],
        path: str,
        root: dict[str, Any],
        root_path: Path,
    ) -> list[ContractError]:
        if "$ref" in schema:
            target, target_root, target_path = self._resolve_ref(schema["$ref"], root, root_path)
            errors = self._errors(value, target, path, target_root, target_path)
            if errors:
                return errors
        if "allOf" in schema:
            for child in schema["allOf"]:
                errors = self._errors(value, child, path, root, root_path)
                if errors:
                    return errors
        if "oneOf" in schema:
            branches = [self._errors(value, child, path, root, root_path) for child in schema["oneOf"]]
            if sum(not branch for branch in branches) != 1:
                return [ContractError("SCHEMA_ONE_OF", path, "expected exactly one matching branch")]
        if "if" in schema:
            matches = not self._errors(value, schema["if"], path, root, root_path)
            selected = schema.get("then") if matches else schema.get("else")
            if selected is not None:
                errors = self._errors(value, selected, path, root, root_path)
                if errors:
                    return errors
        if "const" in schema and value != schema["const"]:
            return [ContractError("SCHEMA_CONST", path, f"expected {schema['const']!r}")]
        if "enum" in schema and value not in schema["enum"]:
            return [ContractError("SCHEMA_ENUM", path, "value is outside the closed enum")]
        expected = schema.get("type")
        if expected and not self._is_type(value, expected):
            return [ContractError("SCHEMA_TYPE", path, f"expected {expected}")]
        if isinstance(value, dict):
            for key in schema.get("required", []):
                if key not in value:
                    return [ContractError("SCHEMA_REQUIRED", path, f"missing {key!r}")]
            properties = schema.get("properties", {})
            if schema.get("additionalProperties") is False:
                extras = sorted(set(value) - set(properties))
                if extras:
                    return [ContractError("SCHEMA_ADDITIONAL_PROPERTY", path, f"unexpected {extras!r}")]
            for key, child in value.items():
                if key in properties:
                    errors = self._errors(child, properties[key], f"{path}.{key}", root, root_path)
                    if errors:
                        return errors
        if isinstance(value, list):
            if len(value) < schema.get("minItems", 0):
                return [ContractError("SCHEMA_MIN_ITEMS", path, "array is too short")]
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                return [ContractError("SCHEMA_MAX_ITEMS", path, "array is too long")]
            if schema.get("uniqueItems") and len({canonical_json(item) for item in value}) != len(value):
                return [ContractError("SCHEMA_UNIQUE_ITEMS", path, "array items must be unique")]
            if "items" in schema:
                for index, item in enumerate(value):
                    errors = self._errors(item, schema["items"], f"{path}[{index}]", root, root_path)
                    if errors:
                        return errors
        if isinstance(value, str):
            if len(value) < schema.get("minLength", 0):
                return [ContractError("SCHEMA_MIN_LENGTH", path, "string is too short")]
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                return [ContractError("SCHEMA_MAX_LENGTH", path, "string is too long")]
            if "pattern" in schema and re.search(schema["pattern"], value) is None:
                return [ContractError("SCHEMA_PATTERN", path, "string does not match pattern")]
        if self._is_integer(value):
            if value < schema.get("minimum", -MAX_SAFE_INTEGER):
                return [ContractError("SCHEMA_MINIMUM", path, "integer is too small")]
            if value > schema.get("maximum", MAX_SAFE_INTEGER):
                return [ContractError("SCHEMA_MAXIMUM", path, "integer is too large")]
        return []

    @staticmethod
    def _is_integer(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _is_type(cls, value: Any, expected: str) -> bool:
        return {
            "object": isinstance(value, dict),
            "array": isinstance(value, list),
            "string": isinstance(value, str),
            "integer": cls._is_integer(value),
            "boolean": isinstance(value, bool),
            "null": value is None,
        }.get(expected, False)


SCHEMAS = SchemaValidator()


def require(condition: bool, code: str, path: str, detail: str) -> None:
    if not condition:
        raise ContractError(code, path, detail)


def walk(value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{path}[{index}]")


def parse_time(value: str, path: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ContractError("INVALID_TIMESTAMP", path, value) from exc


def validate_basics(candidate: dict[str, Any]) -> None:
    require(isinstance(candidate, dict), "ROOT_TYPE", "$", "candidate must be an object")
    try:
        size = len(canonical_json_artifact(candidate))
    except (TypeError, ValueError) as exc:
        raise ContractError("INVALID_JSON_VALUE", "$", str(exc)) from exc
    require(size <= MAX_ARTIFACT_BYTES, "ARTIFACT_TOO_LARGE", "$", "candidate exceeds 1 MiB")
    for path, child in walk(candidate):
        if isinstance(child, float):
            raise ContractError("FLOAT_FORBIDDEN", path, "candidate contracts use integer JSON")
        if isinstance(child, int) and not isinstance(child, bool):
            require(abs(child) <= MAX_SAFE_INTEGER, "UNSAFE_INTEGER", path, "integer exceeds interoperable range")
        if isinstance(child, str):
            require(unicodedata.normalize("NFC", child) == child, "NON_NFC_STRING", path, "string must be NFC")
            for pattern in SECRET_PATTERNS:
                if pattern.search(child):
                    raise ContractError("SECRET_VALUE_DETECTED", path, "credential-like value is forbidden")
        if isinstance(child, dict):
            for key in child:
                if key.lower() in FORBIDDEN_KEYS:
                    raise ContractError("SECRET_FIELD_FORBIDDEN", f"{path}.{key}", "credential-bearing fields are forbidden")


def unique_ids(items: Sequence[dict[str, Any]], field: str, path: str) -> set[str]:
    values = [item[field] for item in items]
    require(len(values) == len(set(values)), "DUPLICATE_VALUE", path, f"{field} values must be unique")
    return set(values)


def content_evidence_refs(content: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    for _, child in walk(content):
        if isinstance(child, dict):
            evidence_refs = child.get("evidence_refs")
            if isinstance(evidence_refs, list):
                refs.update(evidence_refs)
            presentation = child.get("presentation")
            if isinstance(presentation, dict) and isinstance(presentation.get("evidence_ref"), str):
                refs.add(presentation["evidence_ref"])
    return refs


def validate_presentation(choice: dict[str, Any], path: str) -> None:
    presentation = choice["presentation"]
    kind = presentation["kind"]
    value = presentation["value"]
    evidence_ref = presentation["evidence_ref"]
    if kind == "text":
        require(isinstance(value, str) and evidence_ref is None, "INVALID_CHOICE_PRESENTATION", path, "text choice needs value only")
    elif kind == "evidence_thumbnail":
        require(value is None and isinstance(evidence_ref, str), "INVALID_CHOICE_PRESENTATION", path, "thumbnail choice needs evidence only")
        require(evidence_ref in choice["evidence_refs"], "CHOICE_EVIDENCE_MISMATCH", path, "thumbnail is not cited by its choice")
    elif kind == "color_swatch":
        require(
            isinstance(value, str) and re.fullmatch(r"#[0-9A-Fa-f]{6}", value) is not None and evidence_ref is None,
            "INVALID_CHOICE_PRESENTATION",
            path,
            "color choice needs a six-digit hex swatch",
        )
    elif kind == "sf_symbol":
        require(
            isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9.]{1,64}", value) is not None and evidence_ref is None,
            "INVALID_CHOICE_PRESENTATION",
            path,
            "SF Symbol choice needs a safe symbol name",
        )


def validate(candidate: dict[str, Any]) -> None:
    """Validate one immutable candidate-version snapshot."""

    validate_basics(candidate)
    require(candidate.get("contract_version") == CONTRACT_VERSION, "UNSUPPORTED_VERSION", "$.contract_version", str(candidate.get("contract_version")))
    SCHEMAS.validate(candidate, SCHEMA_FILE)
    require(
        candidate["candidate_content_digest"] == sha256_digest(candidate_content_subject(candidate)),
        "CONTENT_DIGEST_MISMATCH",
        "$.candidate_content_digest",
        "candidate content or its bound scope changed",
    )
    require(
        candidate["candidate_digest"] == digest_without(candidate, "candidate_digest"),
        "CANDIDATE_DIGEST_MISMATCH",
        "$.candidate_digest",
        "candidate snapshot changed",
    )

    version = candidate["candidate_version"]
    state = candidate["state"]
    lineage = candidate["lineage"]
    operation = lineage["operation"]
    parents = lineage["parents"]
    transition = candidate["transition"]
    require(transition["to_state"] == state, "STATE_TRANSITION_MISMATCH", "$.transition.to_state", "transition differs from snapshot")

    if version == 1:
        require(candidate["previous_candidate_digest"] is None, "VERSION_CHAIN_MISMATCH", "$.previous_candidate_digest", "version one has no predecessor")
        require(transition["from_state"] is None and state == "draft", "FIRST_VERSION_MUST_BE_DRAFT", "$.state", "new candidates begin unapproved")
        require(operation in {"generated", "split", "merged"}, "LINEAGE_OPERATION_MISMATCH", "$.lineage.operation", "invalid first-version operation")
        expected_parent_range = {"generated": (0, 0), "split": (1, 1), "merged": (2, 16)}[operation]
        require(expected_parent_range[0] <= len(parents) <= expected_parent_range[1], "LINEAGE_PARENT_MISMATCH", "$.lineage.parents", "first-version parent count is invalid")
    else:
        require(candidate["previous_candidate_digest"] is not None, "VERSION_CHAIN_MISMATCH", "$.previous_candidate_digest", "later versions require a predecessor")
        require(transition["from_state"] is not None, "STATE_TRANSITION_MISMATCH", "$.transition.from_state", "later versions require a prior state")
        require(operation not in {"generated", "split", "merged"}, "LINEAGE_OPERATION_MISMATCH", "$.lineage.operation", "creation operation used after version one")
        require(len(parents) == 1, "LINEAGE_PARENT_MISMATCH", "$.lineage.parents", "later versions require exactly one predecessor")
        parent = parents[0]
        require(parent["candidate_id"] == candidate["candidate_id"], "LINEAGE_PARENT_MISMATCH", "$.lineage.parents[0].candidate_id", "predecessor has another candidate ID")
        require(parent["candidate_version"] == version - 1, "LINEAGE_PARENT_MISMATCH", "$.lineage.parents[0].candidate_version", "predecessor version is not contiguous")
        require(parent["candidate_digest"] == candidate["previous_candidate_digest"], "LINEAGE_PARENT_MISMATCH", "$.lineage.parents[0].candidate_digest", "predecessor digest is inconsistent")

    allowed = {
        None: {"draft"},
        "draft": {"draft", "needs_clarification", "ready_for_review"},
        "needs_clarification": {"draft", "needs_clarification", "ready_for_review", "rejected"},
        "ready_for_review": {"draft", "needs_clarification", "ready_for_review", "approved", "rejected"},
        "approved": {"draft"},
        "rejected": {"draft"},
    }
    require(state in allowed[transition["from_state"]], "ILLEGAL_STATE_TRANSITION", "$.transition", "candidate transition is not allowed")
    actor = transition["actor"]
    if operation in {"clarification_answered", "reviewed", "approved", "rejected", "reopened"}:
        require(actor["actor_type"] == "human", "HUMAN_TRANSITION_REQUIRED", "$.transition.actor", f"{operation} requires a human")
    if operation == "approved":
        require(state == "approved", "LINEAGE_OPERATION_MISMATCH", "$.lineage.operation", "approval operation must create approved state")
    if operation == "rejected":
        require(state == "rejected", "LINEAGE_OPERATION_MISMATCH", "$.lineage.operation", "rejection operation must create rejected state")
    if operation == "reopened":
        require(transition["from_state"] in {"approved", "rejected"} and state == "draft", "LINEAGE_OPERATION_MISMATCH", "$.lineage.operation", "reopen must create a draft from a terminal state")

    content = candidate["content"]
    claim_ids = unique_ids(content["claims"], "claim_id", "$.content.claims")
    unique_ids(content["reproduction"]["preconditions"], "precondition_id", "$.content.reproduction.preconditions")
    unique_ids(content["reproduction"]["steps"], "step_id", "$.content.reproduction.steps")
    unique_ids(content["acceptance_criteria"], "criterion_id", "$.content.acceptance_criteria")
    unique_ids(content["uncertainty"]["items"], "uncertainty_id", "$.content.uncertainty.items")
    unique_ids(content["clarifications"], "clarification_id", "$.content.clarifications")

    for index, claim in enumerate(content["claims"]):
        if claim["support"] in {"direct", "inferred"}:
            require(bool(claim["evidence_refs"]), "SUPPORTED_CLAIM_REQUIRES_EVIDENCE", f"$.content.claims[{index}].evidence_refs", "supported claim must cite evidence")
    for path, child in walk(content, "$.content"):
        if isinstance(child, dict) and isinstance(child.get("claim_refs"), list):
            require(set(child["claim_refs"]) <= claim_ids, "UNKNOWN_CLAIM_REFERENCE", f"{path}.claim_refs", "claim reference is missing")

    available_evidence = set(candidate["evidence_manifest"]["evidence_ids"])
    used_evidence = content_evidence_refs(content)
    require(used_evidence <= available_evidence, "UNKNOWN_EVIDENCE_REFERENCE", "$.content", "candidate cites evidence outside the bound manifest")

    blocking: list[dict[str, Any]] = []
    for index, clarification in enumerate(content["clarifications"]):
        choice_ids = unique_ids(clarification["choices"], "choice_id", f"$.content.clarifications[{index}].choices")
        for choice_index, choice in enumerate(clarification["choices"]):
            validate_presentation(choice, f"$.content.clarifications[{index}].choices[{choice_index}].presentation")
        selected = clarification["selected_choice_id"]
        if clarification["status"] == "resolved":
            require(selected in choice_ids, "UNKNOWN_CLARIFICATION_CHOICE", f"$.content.clarifications[{index}].selected_choice_id", "resolved choice is missing")
            selected_choice = next(choice for choice in clarification["choices"] if choice["choice_id"] == selected)
            if selected_choice["requires_note"]:
                require(isinstance(clarification["resolution_note"], str), "CLARIFICATION_NOTE_REQUIRED", f"$.content.clarifications[{index}].resolution_note", "selected choice requires a note")
        if clarification["impact"] == "blocking" and clarification["status"] == "unresolved":
            blocking.append(clarification)
    if state in {"ready_for_review", "approved"}:
        require(not blocking, "UNRESOLVED_BLOCKING_CLARIFICATION", "$.content.clarifications", "blocking questions must be resolved")
    if state == "needs_clarification":
        require(bool(blocking), "CLARIFICATION_STATE_MISMATCH", "$.state", "state requires an unresolved blocking question")

    review = candidate["review"]
    if review["status"] == "unreviewed":
        require(review["last_human_actor_id"] is None and review["last_reviewed_at"] is None, "REVIEW_STATE_MISMATCH", "$.review", "unreviewed candidate cannot name a reviewer")
    else:
        require(review["last_human_actor_id"] is not None and review["last_reviewed_at"] is not None, "REVIEW_STATE_MISMATCH", "$.review", "review activity requires a human and time")
    if state in {"needs_clarification", "ready_for_review"}:
        require(review["reviewer_action_required"], "REVIEW_ACTION_MISMATCH", "$.review.reviewer_action_required", "reviewable state requires action")
    if state in {"approved", "rejected"}:
        require(not review["reviewer_action_required"], "REVIEW_ACTION_MISMATCH", "$.review.reviewer_action_required", "terminal state cannot require action")

    created = parse_time(candidate["candidate_created_at"], "$.candidate_created_at")
    version_created = parse_time(candidate["version_created_at"], "$.version_created_at")
    transitioned = parse_time(transition["occurred_at"], "$.transition.occurred_at")
    require(created <= version_created, "INVALID_CHRONOLOGY", "$.version_created_at", "version predates candidate")
    require(version_created == transitioned, "TRANSITION_CHRONOLOGY_MISMATCH", "$.transition.occurred_at", "transition must create this version")
    if review["last_reviewed_at"] is not None:
        reviewed = parse_time(review["last_reviewed_at"], "$.review.last_reviewed_at")
        require(created <= reviewed <= version_created, "INVALID_CHRONOLOGY", "$.review.last_reviewed_at", "review time is outside the snapshot")

    if state == "approved":
        approval = candidate["approval"]
        require(operation == "approved" and transition["from_state"] == "ready_for_review", "APPROVAL_TRANSITION_REQUIRED", "$.transition", "approval requires a ready candidate")
        require(actor["actor_type"] == "human" and actor["actor_id"] == approval["actor_id"], "APPROVAL_ACTOR_MISMATCH", "$.approval.actor_id", "approval actor differs from transition")
        require(approval["approved_at"] == candidate["version_created_at"], "APPROVAL_CHRONOLOGY_MISMATCH", "$.approval.approved_at", "approval time must create approved version")
        require(approval["reviewed_candidate_version"] == version - 1, "APPROVAL_BINDING_MISMATCH", "$.approval.reviewed_candidate_version", "approval did not review the predecessor")
        require(approval["reviewed_candidate_digest"] == candidate["previous_candidate_digest"], "APPROVAL_BINDING_MISMATCH", "$.approval.reviewed_candidate_digest", "approval did not bind the reviewed predecessor")
        require(approval["approved_candidate_version"] == version, "APPROVAL_BINDING_MISMATCH", "$.approval.approved_candidate_version", "approval does not bind this version")
        require(approval["candidate_content_digest"] == candidate["candidate_content_digest"], "APPROVAL_BINDING_MISMATCH", "$.approval.candidate_content_digest", "approval does not bind exact content")
        require(approval["evidence_manifest_digest"] == candidate["evidence_manifest"]["manifest_digest"], "APPROVAL_BINDING_MISMATCH", "$.approval.evidence_manifest_digest", "approval does not bind evidence manifest")
        require(set(approval["authorized_evidence_ids"]) == used_evidence, "APPROVAL_EVIDENCE_BINDING_MISMATCH", "$.approval.authorized_evidence_ids", "approval must authorize the exact referenced evidence set")
        require(review["status"] == "reviewed", "REVIEW_REQUIRED", "$.review.status", "approved candidate requires completed human review")
    if state == "rejected":
        rejection = candidate["rejection"]
        require(operation == "rejected" and transition["from_state"] in {"needs_clarification", "ready_for_review"}, "REJECTION_TRANSITION_REQUIRED", "$.transition", "rejection requires a reviewable candidate")
        require(actor["actor_type"] == "human" and actor["actor_id"] == rejection["actor_id"], "REJECTION_ACTOR_MISMATCH", "$.rejection.actor_id", "rejection actor differs from transition")
        require(rejection["rejected_at"] == candidate["version_created_at"], "REJECTION_CHRONOLOGY_MISMATCH", "$.rejection.rejected_at", "rejection time must create rejected version")
        require(rejection["reviewed_candidate_version"] == version - 1, "REJECTION_BINDING_MISMATCH", "$.rejection.reviewed_candidate_version", "rejection did not review predecessor")
        require(rejection["reviewed_candidate_digest"] == candidate["previous_candidate_digest"], "REJECTION_BINDING_MISMATCH", "$.rejection.reviewed_candidate_digest", "rejection did not bind predecessor")
        require(rejection["rejected_candidate_version"] == version, "REJECTION_BINDING_MISMATCH", "$.rejection.rejected_candidate_version", "rejection does not bind this version")
        require(rejection["candidate_content_digest"] == candidate["candidate_content_digest"], "REJECTION_BINDING_MISMATCH", "$.rejection.candidate_content_digest", "rejection does not bind exact content")


def validate_chain(candidates: Sequence[dict[str, Any]]) -> None:
    """Validate one candidate's complete, contiguous immutable version chain."""

    require(bool(candidates), "EMPTY_VERSION_CHAIN", "$", "candidate chain is empty")
    for candidate in candidates:
        validate(candidate)
    first = candidates[0]
    require(first["candidate_version"] == 1, "INCOMPLETE_VERSION_CHAIN", "$[0].candidate_version", "chain must begin at version one")
    fixed_fields = (
        "organization_id",
        "project_id",
        "build_id",
        "build_identity_digest",
        "session_id",
        "candidate_id",
        "candidate_created_at",
    )
    for index, candidate in enumerate(candidates):
        require(candidate["candidate_version"] == index + 1, "VERSION_CHAIN_MISMATCH", f"$[{index}].candidate_version", "versions must be contiguous")
        for field in fixed_fields:
            require(candidate[field] == first[field], "VERSION_SCOPE_MISMATCH", f"$[{index}].{field}", "candidate scope changed across versions")
        if index == 0:
            continue
        previous = candidates[index - 1]
        require(candidate["previous_candidate_digest"] == previous["candidate_digest"], "VERSION_CHAIN_MISMATCH", f"$[{index}].previous_candidate_digest", "predecessor digest does not match prior artifact")
        require(candidate["transition"]["from_state"] == previous["state"], "STATE_CHAIN_MISMATCH", f"$[{index}].transition.from_state", "transition does not start from prior state")
        parent = candidate["lineage"]["parents"][0]
        require(
            parent == {
                "candidate_id": previous["candidate_id"],
                "candidate_version": previous["candidate_version"],
                "candidate_digest": previous["candidate_digest"],
            },
            "LINEAGE_PARENT_MISMATCH",
            f"$[{index}].lineage.parents[0]",
            "lineage does not name the exact predecessor",
        )
        require(
            parse_time(candidate["version_created_at"], f"$[{index}].version_created_at")
            > parse_time(previous["version_created_at"], f"$[{index - 1}].version_created_at"),
            "VERSION_CHRONOLOGY_MISMATCH",
            f"$[{index}].version_created_at",
            "candidate versions must advance in time",
        )
        operation = candidate["lineage"]["operation"]
        if operation in {"approved", "rejected"}:
            require(candidate["content"] == previous["content"], "TERMINAL_CONTENT_CHANGED", f"$[{index}].content", "approval or rejection cannot silently edit reviewed content")
            require(candidate["candidate_content_digest"] == previous["candidate_content_digest"], "TERMINAL_CONTENT_CHANGED", f"$[{index}].candidate_content_digest", "terminal transition changed bound content or evidence")
        if operation == "clarification_answered":
            previous_questions = {item["clarification_id"]: item for item in previous["content"]["clarifications"]}
            newly_resolved = [
                item
                for item in candidate["content"]["clarifications"]
                if item["status"] == "resolved"
                and item["clarification_id"] in previous_questions
                and previous_questions[item["clarification_id"]]["status"] == "unresolved"
            ]
            require(bool(newly_resolved), "CLARIFICATION_ANSWER_MISMATCH", f"$[{index}].content.clarifications", "answer transition resolved no question")


def load_json(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ContractError("DUPLICATE_JSON_KEY", "$", key)
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
