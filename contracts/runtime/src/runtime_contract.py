# SPDX-License-Identifier: Apache-2.0
"""Dependency-free validation for Tacua's candidate runtime contracts."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas"
MAX_SAFE_INTEGER = 9_007_199_254_740_991


class ContractError(ValueError):
    def __init__(self, code: str, path: str, detail: str):
        self.code = code
        self.path = path
        self.detail = detail
        super().__init__(f"{code} at {path}: {detail}")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True)


def digest(value: Any) -> str:
    payload = value if isinstance(value, bytes) else canonical_json(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def digest_without(value: dict[str, Any], field: str) -> str:
    subject = copy.deepcopy(value)
    subject.pop(field, None)
    return digest(subject)


class SchemaValidator:
    """Adapted from contracts/approved-handoff's small Draft 2020-12 subset."""

    def __init__(self, schema_root: Path = SCHEMA_ROOT):
        self.schema_root = schema_root.resolve()
        self._cache: dict[Path, dict[str, Any]] = {}

    def load(self, filename: str) -> tuple[dict[str, Any], Path]:
        path = (self.schema_root / filename).resolve()
        if path.parent != self.schema_root:
            raise ContractError("SCHEMA_REF_FORBIDDEN", "$", "schema escaped the schema directory")
        if path not in self._cache:
            path.relative_to(self.schema_root)
            self._cache[path] = json.loads(path.read_text(encoding="utf-8"))
        return self._cache[path], path

    def validate(self, instance: Any, filename: str) -> None:
        schema, path = self.load(filename)
        errors = self._errors(instance, schema, "$", schema, path)
        if errors:
            raise errors[0]

    def _resolve_ref(self, ref: str, root: dict[str, Any], root_path: Path) -> tuple[dict[str, Any], dict[str, Any], Path]:
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

    def _errors(self, value: Any, schema: dict[str, Any], path: str, root: dict[str, Any], root_path: Path) -> list[ContractError]:
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
            for index, item in enumerate(value):
                if "items" in schema:
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
            "object": isinstance(value, dict), "array": isinstance(value, list),
            "string": isinstance(value, str), "integer": cls._is_integer(value),
            "boolean": isinstance(value, bool), "null": value is None,
        }.get(expected, False)


SCHEMAS = SchemaValidator()
SCHEMA_BY_VERSION = {
    "tacua.capture-upload-manifest@1.0.0": "capture-upload-manifest.schema.json",
    "tacua.diagnostic-envelope@1.0.0": "diagnostic-envelope.schema.json",
    "tacua.processing-job@1.0.0": "processing-job.schema.json",
    "tacua.ticket-candidate@1.0.0": "ticket-candidate.schema.json",
}


def require(condition: bool, code: str, path: str, detail: str) -> None:
    if not condition:
        raise ContractError(code, path, detail)


def unique(values: Iterable[Any], path: str) -> None:
    materialized = list(values)
    require(len(materialized) == len({canonical_json(v) for v in materialized}), "DUPLICATE_VALUE", path, "values must be unique")


def parse_time(value: str, path: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ContractError("INVALID_TIMESTAMP", path, value) from exc


def validate_range(value: dict[str, Any], duration: int, path: str) -> None:
    require(value["end_ms"] >= value["start_ms"], "INVALID_TIME_RANGE", path, "end precedes start")
    require(value["end_ms"] <= duration, "TIME_RANGE_OUTSIDE_SESSION", path, "range exceeds session duration")


def walk(value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{path}[{index}]")


def validate_basics(value: Any) -> None:
    for path, child in walk(value):
        require(not isinstance(child, float), "FLOAT_FORBIDDEN", path, "runtime contracts use integer JSON")
        if isinstance(child, int) and not isinstance(child, bool):
            require(abs(child) <= MAX_SAFE_INTEGER, "UNSAFE_INTEGER", path, "integer exceeds interoperable range")
        if isinstance(child, str):
            require(unicodedata.normalize("NFC", child) == child, "NON_NFC_STRING", path, "string must be NFC")


def seal(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    version = result.get("contract_version")
    if version == "tacua.capture-upload-manifest@1.0.0":
        for receipt in result["upload"]["receipts"]:
            receipt["receipt_digest"] = digest_without(receipt, "receipt_digest")
        result["manifest_digest"] = digest_without(result, "manifest_digest")
    elif version == "tacua.diagnostic-envelope@1.0.0":
        result["envelope_digest"] = digest_without(result, "envelope_digest")
    elif version == "tacua.processing-job@1.0.0":
        result["job_digest"] = digest_without(result, "job_digest")
    elif version == "tacua.ticket-candidate@1.0.0":
        result["candidate_content_digest"] = digest(result["content"])
        if result.get("approval") is not None:
            result["approval"]["candidate_content_digest"] = result["candidate_content_digest"]
        result["candidate_digest"] = digest_without(result, "candidate_digest")
    else:
        raise ContractError("UNSUPPORTED_VERSION", "$.contract_version", str(version))
    return result


def validate(value: dict[str, Any]) -> None:
    validate_basics(value)
    version = value.get("contract_version")
    require(version in SCHEMA_BY_VERSION, "UNSUPPORTED_VERSION", "$.contract_version", str(version))
    SCHEMAS.validate(value, SCHEMA_BY_VERSION[version])
    if version == "tacua.capture-upload-manifest@1.0.0":
        validate_capture(value)
    elif version == "tacua.diagnostic-envelope@1.0.0":
        validate_diagnostics(value)
    elif version == "tacua.processing-job@1.0.0":
        validate_job(value)
    else:
        validate_ticket(value)


def validate_capture(value: dict[str, Any]) -> None:
    require(value["manifest_digest"] == digest_without(value, "manifest_digest"), "DIGEST_MISMATCH", "$.manifest_digest", "manifest changed")
    duration = value["monotonic_duration_ms"]
    segments = value["segments"]
    unique([item["segment_id"] for item in segments], "$.segments")
    require([item["sequence"] for item in segments] == list(range(len(segments))), "INVALID_SEGMENT_SEQUENCE", "$.segments", "sequence must be contiguous from zero")
    previous_end = 0
    available: dict[str, dict[str, Any]] = {}
    for index, segment in enumerate(segments):
        validate_range(segment["time_range"], duration, f"$.segments[{index}].time_range")
        require(segment["time_range"]["start_ms"] >= previous_end, "OVERLAPPING_SEGMENTS", f"$.segments[{index}]", "segments overlap")
        previous_end = segment["time_range"]["end_ms"]
        if segment["availability"] == "available":
            available[segment["segment_id"]] = segment["content"]
    unique([gap["gap_id"] for gap in value["gaps"]], "$.gaps")
    for index, gap in enumerate(value["gaps"]):
        validate_range(gap["time_range"], duration, f"$.gaps[{index}].time_range")
    receipts = value["upload"]["receipts"]
    unique([item["segment_id"] for item in receipts], "$.upload.receipts")
    unique([item["object_id"] for item in receipts], "$.upload.receipts")
    unique([item["receipt_digest"] for item in receipts], "$.upload.receipts")
    for index, receipt in enumerate(receipts):
        require(receipt["receipt_digest"] == digest_without(receipt, "receipt_digest"), "DIGEST_MISMATCH", f"$.upload.receipts[{index}].receipt_digest", "receipt changed")
        content = available.get(receipt["segment_id"])
        require(content is not None, "RECEIPT_WITHOUT_CONTENT", f"$.upload.receipts[{index}]", "receipt does not reference available content")
        require(receipt["content_digest"] == content["content_digest"] and receipt["size_bytes"] == content["size_bytes"], "UPLOAD_INTEGRITY_MISMATCH", f"$.upload.receipts[{index}]", "receipt differs from local segment")
    if value["upload"]["state"] == "complete":
        require({r["segment_id"] for r in receipts} == set(available), "INCOMPLETE_UPLOAD", "$.upload.receipts", "complete upload must receipt every available segment")
    if value["capture_state"] == "complete":
        require(bool(available), "COMPLETE_CAPTURE_REQUIRES_SEGMENT", "$.segments", "complete capture requires verified media")
        require(value["streams"]["microphone"] == "enabled", "COMPLETE_NARRATION_REQUIRED", "$.streams.microphone", "complete narrated capture requires microphone evidence")
    start = parse_time(value["started_at"], "$.started_at")
    if value["ended_at"]:
        require(parse_time(value["ended_at"], "$.ended_at") >= start, "INVALID_CHRONOLOGY", "$.ended_at", "capture ended before it started")
    raw_expiry = parse_time(value["retention"]["raw_media_expires_at"], "$.retention.raw_media_expires_at")
    require(raw_expiry > start, "INVALID_RETENTION", "$.retention", "raw-media expiry must follow capture")
    require(raw_expiry <= start + timedelta(days=30), "MAX_RAW_RETENTION_EXCEEDED", "$.retention.raw_media_expires_at", "raw media may not silently exceed the 30-day V1 default")


def validate_diagnostics(value: dict[str, Any]) -> None:
    require(value["envelope_digest"] == digest_without(value, "envelope_digest"), "DIGEST_MISMATCH", "$.envelope_digest", "envelope changed")
    events = value["events"]
    sequences = [event["sequence"] for event in events]
    require(sequences == list(range(sequences[0], sequences[0] + len(sequences))), "INVALID_EVENT_SEQUENCE", "$.events", "events must be contiguous and ordered")
    require(value["sequence_range"] == {"first": sequences[0], "last": sequences[-1]}, "SEQUENCE_RANGE_MISMATCH", "$.sequence_range", "range does not match events")
    unique([event["event_id"] for event in events], "$.events")
    require([event["elapsed_ms"] for event in events] == sorted(event["elapsed_ms"] for event in events), "EVENT_TIME_REGRESSION", "$.events", "elapsed time regressed")
    evidence = {item["evidence_id"]: item for item in value["evidence"]}
    require(len(evidence) == len(value["evidence"]), "DUPLICATE_VALUE", "$.evidence", "evidence IDs must be unique")
    for index, item in enumerate(value["evidence"]):
        if item["time_range"]:
            validate_range(item["time_range"], 1_800_000, f"$.evidence[{index}].time_range")
        if item["reference"]:
            locator = item["reference"]["locator"]
            require(locator["organization_id"] == value["organization_id"] and locator["project_id"] == value["project_id"] and locator["evidence_id"] == item["evidence_id"], "EVIDENCE_SCOPE_MISMATCH", f"$.evidence[{index}].reference.locator", "locator escaped envelope scope")
    for index, event in enumerate(events):
        require(set(event["evidence_refs"]) <= set(evidence), "UNKNOWN_EVIDENCE_REFERENCE", f"$.events[{index}].evidence_refs", "event references missing evidence")
        if event["event_type"] == "custom_state":
            available = event["data"]["collection_status"] == "available"
            require(available == (event["data"]["snapshot_digest"] is not None), "AVAILABILITY_MISMATCH", f"$.events[{index}].data", "custom-state availability is not truthful")
    if not value["redaction"]["applied"]:
        require(value["redaction"]["removed_field_count"] == 0, "REDACTION_MISMATCH", "$.redaction", "removed fields require applied=true")


def validate_job(value: dict[str, Any]) -> None:
    require(value["job_digest"] == digest_without(value, "job_digest"), "DIGEST_MISMATCH", "$.job_digest", "job changed")
    require((value["job_version"] == 1) == (value["previous_job_digest"] is None), "VERSION_CHAIN_MISMATCH", "$.previous_job_digest", "only version one has no predecessor")
    expected = ["transcribe", "align", "correlate", "research", "generate_tickets"]
    require([stage["name"] for stage in value["pipeline"]["stages"]] == expected, "PIPELINE_STAGE_MISMATCH", "$.pipeline.stages", "stages must be complete and ordered")
    if value["outputs"]:
        has_candidates = bool(value["outputs"]["candidate_refs"])
        require(has_candidates == (value["outputs"]["disposition"] == "candidates_created"), "OUTPUT_DISPOSITION_MISMATCH", "$.outputs", "disposition does not match candidate list")
    if value["execution"]["egress"]["authorized"]:
        unique([d["destination_id"] for d in value["execution"]["egress"]["destinations"]], "$.execution.egress.destinations")
    requested = parse_time(value["requested_at"], "$.requested_at")
    if value["started_at"]:
        require(parse_time(value["started_at"], "$.started_at") >= requested, "INVALID_CHRONOLOGY", "$.started_at", "job started before request")
    if value["completed_at"] and value["started_at"]:
        require(parse_time(value["completed_at"], "$.completed_at") >= parse_time(value["started_at"], "$.started_at"), "INVALID_CHRONOLOGY", "$.completed_at", "job completed before start")


def all_evidence_refs(content: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    for _, child in walk(content):
        if isinstance(child, dict) and "evidence_refs" in child and isinstance(child["evidence_refs"], list):
            refs.update(child["evidence_refs"])
    return refs


def validate_ticket(value: dict[str, Any]) -> None:
    require(value["candidate_content_digest"] == digest(value["content"]), "DIGEST_MISMATCH", "$.candidate_content_digest", "ticket content changed")
    require(value["candidate_digest"] == digest_without(value, "candidate_digest"), "DIGEST_MISMATCH", "$.candidate_digest", "candidate changed")
    require((value["candidate_version"] == 1) == (value["previous_candidate_digest"] is None), "VERSION_CHAIN_MISMATCH", "$.previous_candidate_digest", "only version one has no predecessor")
    transition = value["transition"]
    if value["candidate_version"] == 1:
        require(
            value["state"] == "draft" and transition["from_state"] is None and value["approval"] is None,
            "FIRST_VERSION_MUST_BE_DRAFT",
            "$.state",
            "generation creates an unapproved draft; approval requires a later reviewed version",
        )
    require(transition["to_state"] == value["state"], "STATE_TRANSITION_MISMATCH", "$.transition.to_state", "transition does not match snapshot state")
    allowed = {
        None: {"draft"}, "draft": {"draft", "needs_clarification", "ready_for_review"},
        "needs_clarification": {"draft", "needs_clarification", "ready_for_review", "rejected"},
        "ready_for_review": {"draft", "needs_clarification", "ready_for_review", "approved", "rejected"},
        "rejected": {"draft"}, "approved": {"draft"},
    }
    require(value["state"] in allowed[transition["from_state"]], "ILLEGAL_STATE_TRANSITION", "$.transition", "candidate transition is not allowed")
    content = value["content"]
    claim_ids = {claim["claim_id"] for claim in content["claims"]}
    require(len(claim_ids) == len(content["claims"]), "DUPLICATE_VALUE", "$.content.claims", "claim IDs must be unique")
    unique([item["precondition_id"] for item in content["preconditions"]], "$.content.preconditions")
    unique([item["step_id"] for item in content["reproduction_steps"]], "$.content.reproduction_steps")
    unique([item["criterion_id"] for item in content["acceptance_criteria"]], "$.content.acceptance_criteria")
    unique([item["uncertainty_id"] for item in content["uncertainty"]["items"]], "$.content.uncertainty.items")
    unique([item["clarification_id"] for item in content["clarifications"]], "$.content.clarifications")
    for index, claim in enumerate(content["claims"]):
        if claim["support"] in {"direct", "inferred"}:
            require(bool(claim["evidence_refs"]), "SUPPORTED_CLAIM_REQUIRES_EVIDENCE", f"$.content.claims[{index}].evidence_refs", "supported claims must cite evidence")
    for path, child in walk(content, "$.content"):
        if isinstance(child, dict) and isinstance(child.get("claim_refs"), list):
            require(set(child["claim_refs"]) <= claim_ids, "UNKNOWN_CLAIM_REFERENCE", f"{path}.claim_refs", "claim reference is missing")
    for index, clarification in enumerate(content["clarifications"]):
        choices = {choice["choice_id"] for choice in clarification["choices"]}
        require(len(choices) == len(clarification["choices"]), "DUPLICATE_VALUE", f"$.content.clarifications[{index}].choices", "choice IDs must be unique")
        if clarification["selected_choice_id"]:
            require(clarification["selected_choice_id"] in choices, "UNKNOWN_CLARIFICATION_CHOICE", f"$.content.clarifications[{index}].selected_choice_id", "selected choice is missing")
    blocking = [c for c in content["clarifications"] if c["impact"] == "blocking" and c["status"] == "unresolved"]
    if value["state"] in {"ready_for_review", "approved"}:
        require(not blocking, "UNRESOLVED_BLOCKING_CLARIFICATION", "$.content.clarifications", "blocking questions must be resolved")
    if value["state"] == "needs_clarification":
        require(bool(blocking), "CLARIFICATION_STATE_MISMATCH", "$.state", "state requires an unresolved blocking question")
    if value["state"] == "approved":
        approval = value["approval"]
        require(transition["from_state"] == "ready_for_review" and transition["actor_type"] == "human", "APPROVAL_TRANSITION_REQUIRED", "$.transition", "approval requires a human ready-for-review transition")
        require(approval["candidate_version"] == value["candidate_version"] and approval["candidate_content_digest"] == value["candidate_content_digest"], "APPROVAL_BINDING_MISMATCH", "$.approval", "approval does not bind this version")
        require(approval["actor_id"] == transition["actor_id"], "APPROVAL_ACTOR_MISMATCH", "$.approval.actor_id", "approval actor differs from transition actor")
        require(value["review"]["status"] == "reviewed" and not value["review"]["reviewer_action_required"], "REVIEW_REQUIRED", "$.review", "approved candidate must be reviewed")
    created = parse_time(value["created_at"], "$.created_at")
    updated = parse_time(value["updated_at"], "$.updated_at")
    transitioned = parse_time(transition["occurred_at"], "$.transition.occurred_at")
    require(created <= transitioned <= updated, "INVALID_CHRONOLOGY", "$.transition.occurred_at", "transition must occur within the candidate snapshot window")
    reviewed_at = value["review"]["last_reviewed_at"]
    if value["review"]["status"] == "unreviewed":
        require(reviewed_at is None, "REVIEW_CHRONOLOGY_MISMATCH", "$.review.last_reviewed_at", "unreviewed candidate cannot claim a review time")
    elif value["review"]["status"] == "reviewed":
        require(reviewed_at is not None, "REVIEW_CHRONOLOGY_MISMATCH", "$.review.last_reviewed_at", "reviewed candidate requires a review time")
    if reviewed_at is not None:
        reviewed = parse_time(reviewed_at, "$.review.last_reviewed_at")
        require(created <= reviewed <= updated, "INVALID_CHRONOLOGY", "$.review.last_reviewed_at", "review time must fall within the candidate snapshot window")
    if value["state"] == "approved":
        approved = parse_time(value["approval"]["approved_at"], "$.approval.approved_at")
        require(approved == transitioned, "APPROVAL_CHRONOLOGY_MISMATCH", "$.approval.approved_at", "approval must bind the human approval transition")
    if value["state"] == "rejected":
        rejection = value["rejection"]
        require(transition["actor_type"] == "human" and transition["actor_id"] == rejection["actor_id"], "REJECTION_TRANSITION_REQUIRED", "$.transition", "rejection requires the same human actor")
        require(parse_time(rejection["rejected_at"], "$.rejection.rejected_at") == transitioned, "REJECTION_CHRONOLOGY_MISMATCH", "$.rejection.rejected_at", "rejection must bind the human rejection transition")


def validate_bundle(capture: dict[str, Any], diagnostics: dict[str, Any], job: dict[str, Any], ticket: dict[str, Any]) -> None:
    for value in (capture, diagnostics, job, ticket):
        validate(value)
    fields = ("organization_id", "project_id", "build_id", "build_identity_digest", "session_id")
    for field in fields:
        require(len({value[field] for value in (capture, diagnostics, job, ticket)}) == 1, "BUNDLE_SCOPE_MISMATCH", f"$.{field}", "runtime artifacts disagree")
    require(job["inputs"]["capture_manifest_digest"] == capture["manifest_digest"], "BUNDLE_DIGEST_MISMATCH", "$.job.inputs.capture_manifest_digest", "job does not bind capture")
    require(diagnostics["envelope_digest"] in job["inputs"]["diagnostic_envelope_digests"], "BUNDLE_DIGEST_MISMATCH", "$.job.inputs.diagnostic_envelope_digests", "job does not bind diagnostics")
    require(ticket["source"]["job_id"] == job["job_id"] and ticket["source"]["job_digest"] == job["job_digest"], "BUNDLE_DIGEST_MISMATCH", "$.ticket.source", "ticket does not bind job")
    if job["outputs"]:
        refs = {(item["candidate_id"], item["candidate_version"]) for item in job["outputs"]["candidate_refs"]}
        require((ticket["candidate_id"], ticket["candidate_version"]) in refs, "CANDIDATE_NOT_IN_JOB_OUTPUT", "$.job.outputs.candidate_refs", "job did not emit ticket")
    evidence_ids = {item["evidence_id"] for item in diagnostics["evidence"]}
    require(all_evidence_refs(ticket["content"]) <= evidence_ids, "UNKNOWN_EVIDENCE_REFERENCE", "$.ticket.content", "ticket references evidence outside its envelope")
    capture_gaps = {gap["gap_id"] for gap in capture["gaps"]}
    event_gaps = {event["data"]["gap_id"] for event in diagnostics["events"] if event["event_type"] == "capture_gap"}
    require(event_gaps <= capture_gaps, "UNKNOWN_CAPTURE_GAP", "$.diagnostics.events", "diagnostics reference an unknown capture gap")


def load_json(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ContractError("DUPLICATE_JSON_KEY", "$", key)
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
