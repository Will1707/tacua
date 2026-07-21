# SPDX-License-Identifier: Apache-2.0
"""Offline validator and deterministic renderer for the candidate Tacua handoff."""

from __future__ import annotations

import copy
import hashlib
import html
import hmac
import importlib.util
import json
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable


CONTRACT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = CONTRACT_ROOT / "schemas"
MAX_JSON_BYTES = 1_048_576
MAX_MARKDOWN_BYTES = 2_097_152
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_REGISTRY_ASSERTION_LIFETIME = timedelta(hours=24)
SYNTHETIC_FIXTURE_TIME = datetime(2026, 7, 20, 11, 0, 0, tzinfo=timezone.utc)
SYNTHETIC_FIXTURE_KEY = bytes.fromhex("11" * 32)
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
HMAC_RE = re.compile(r"^hmac-sha256:[a-f0-9]{64}$")
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
        r"(?i)(?:[?&](?:x-amz-signature|x-goog-signature|signature|sig|access_token|token)="
        r")[^&#\s]{8,}"
    ),
    re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/@:]+:[^\s/@]+@"),
)


def _load_ticket_candidate_contract() -> ModuleType:
    contracts_root = Path(__file__).resolve().parents[2]
    module_path = (
        contracts_root
        / "ticket-candidate"
        / "src"
        / "ticket_candidate_contract.py"
    )
    if not module_path.is_file():
        raise RuntimeError("Tacua ticket-candidate validator is unavailable")
    specification = importlib.util.spec_from_file_location(
        "tacua_handoff_ticket_candidate_contract", module_path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("Tacua ticket-candidate validator cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


TICKET_CANDIDATE = _load_ticket_candidate_contract()


class ContractError(ValueError):
    """A stable, user-visible contract validation failure."""

    def __init__(self, code: str, path: str, detail: str):
        self.code = code
        self.path = path
        self.detail = detail
        super().__init__(f"{code} at {path}: {detail}")


def canonical_json(value: Any) -> str:
    """Return Tacua Canonical JSON v1 (integer-only JSON, sorted UTF-8 keys)."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_json_artifact(value: Any) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def sha256_digest(payload: bytes | str) -> str:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def digest_without(value: dict[str, Any], field: str) -> str:
    subject = copy.deepcopy(value)
    subject.pop(field, None)
    return sha256_digest(canonical_json(subject))


def approval_subject(handoff: dict[str, Any]) -> dict[str, Any]:
    ticket = copy.deepcopy(handoff["ticket"])
    ticket.pop("ticket_content_digest", None)
    return {
        "contract_version": handoff["contract_version"],
        "organization_id": handoff["organization_id"],
        "project_id": handoff["project_id"],
        "source_candidate": copy.deepcopy(handoff["source_candidate"]),
        "ticket": ticket,
        "build_identity_digest": handoff["build_identity"]["build_identity_digest"],
        "evidence_manifest_digest": handoff["evidence_manifest"]["evidence_manifest_digest"],
        "authority": handoff["authority"],
    }


def seal_build_identity(build: dict[str, Any]) -> dict[str, Any]:
    build = copy.deepcopy(build)
    build["build_identity_digest"] = digest_without(build, "build_identity_digest")
    return build


def seal_evidence_item(item: dict[str, Any]) -> dict[str, Any]:
    item = copy.deepcopy(item)
    item["evidence_item_digest"] = digest_without(item, "evidence_item_digest")
    return item


def seal_evidence_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    manifest = copy.deepcopy(manifest)
    manifest["items"] = [seal_evidence_item(item) for item in manifest["items"]]
    manifest["evidence_manifest_digest"] = digest_without(manifest, "evidence_manifest_digest")
    return manifest


def seal_handoff(handoff: dict[str, Any]) -> dict[str, Any]:
    """Seal all nested digests. This does not make an unsafe document valid."""

    handoff = copy.deepcopy(handoff)
    handoff["build_identity"] = seal_build_identity(handoff["build_identity"])
    handoff["evidence_manifest"] = seal_evidence_manifest(handoff["evidence_manifest"])
    content_digest = sha256_digest(canonical_json(approval_subject(handoff)))
    handoff["ticket"]["ticket_content_digest"] = content_digest
    handoff["approval"]["ticket_content_digest"] = content_digest
    handoff["handoff_digest"] = digest_without(handoff, "handoff_digest")
    return handoff


def seal_trial(trial: dict[str, Any]) -> dict[str, Any]:
    trial = copy.deepcopy(trial)
    trial["trial_digest"] = digest_without(trial, "trial_digest")
    return trial


def registry_assertion_subject(assertion: dict[str, Any]) -> dict[str, Any]:
    subject = copy.deepcopy(assertion)
    subject["signature"].pop("value", None)
    return subject


def seal_registry_assertion(assertion: dict[str, Any], key: bytes) -> dict[str, Any]:
    """Sign a fixture assertion. Possessing this helper or an assertion does not confer trust."""

    if len(key) < 32:
        raise ContractError("REGISTRY_KEY_TOO_SHORT", "$", "registry HMAC key must be at least 32 bytes")
    assertion = copy.deepcopy(assertion)
    payload = canonical_json(registry_assertion_subject(assertion)).encode("utf-8")
    assertion["signature"]["value"] = "hmac-sha256:" + hmac.new(key, payload, hashlib.sha256).hexdigest()
    return assertion


class SchemaValidator:
    """Small Draft 2020-12 subset evaluator used by these bundled schemas."""

    def __init__(self, schema_root: Path = SCHEMA_ROOT):
        self.schema_root = schema_root.resolve()
        self._cache: dict[Path, dict[str, Any]] = {}

    def load(self, filename: str) -> tuple[dict[str, Any], Path]:
        path = (self.schema_root / filename).resolve()
        if self.schema_root not in path.parents:
            raise ContractError("SCHEMA_REF_FORBIDDEN", "$", "schema reference escaped the schema directory")
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
        root_schema: dict[str, Any],
        root_path: Path,
    ) -> tuple[dict[str, Any], dict[str, Any], Path]:
        file_part, separator, fragment = ref.partition("#")
        if file_part:
            target_path = (root_path.parent / file_part).resolve()
            if self.schema_root not in target_path.parents:
                raise ContractError("SCHEMA_REF_FORBIDDEN", "$", ref)
            if target_path not in self._cache:
                self._cache[target_path] = json.loads(target_path.read_text(encoding="utf-8"))
            target_root = self._cache[target_path]
        else:
            target_path = root_path
            target_root = root_schema
        target: Any = target_root
        if separator and fragment:
            if not fragment.startswith("/"):
                raise ContractError("SCHEMA_REF_UNSUPPORTED", "$", ref)
            for raw in fragment[1:].split("/"):
                part = raw.replace("~1", "/").replace("~0", "~")
                target = target[part]
        return target, target_root, target_path

    def _errors(
        self,
        value: Any,
        schema: dict[str, Any],
        path: str,
        root_schema: dict[str, Any],
        root_path: Path,
    ) -> list[ContractError]:
        errors: list[ContractError] = []

        if "$ref" in schema:
            target, target_root, target_path = self._resolve_ref(schema["$ref"], root_schema, root_path)
            errors.extend(self._errors(value, target, path, target_root, target_path))
            if errors:
                return errors

        if "allOf" in schema:
            for child in schema["allOf"]:
                errors.extend(self._errors(value, child, path, root_schema, root_path))
                if errors:
                    return errors

        if "oneOf" in schema:
            branch_errors = [self._errors(value, child, path, root_schema, root_path) for child in schema["oneOf"]]
            successes = sum(not branch for branch in branch_errors)
            if successes != 1:
                detail = "expected exactly one matching schema branch"
                if successes == 0:
                    first = next((branch[0] for branch in branch_errors if branch), None)
                    if first:
                        detail += f"; first failure: {first.detail}"
                return [ContractError("SCHEMA_ONE_OF", path, detail)]

        if "if" in schema:
            condition_matches = not self._errors(value, schema["if"], path, root_schema, root_path)
            selected = schema.get("then") if condition_matches else schema.get("else")
            if selected is not None:
                errors.extend(self._errors(value, selected, path, root_schema, root_path))
                if errors:
                    return errors

        if "const" in schema and value != schema["const"]:
            return [ContractError("SCHEMA_CONST", path, f"expected {schema['const']!r}")]
        if "enum" in schema and value not in schema["enum"]:
            return [ContractError("SCHEMA_ENUM", path, f"value is not in {schema['enum']!r}")]

        expected_type = schema.get("type")
        if expected_type and not self._is_type(value, expected_type):
            return [ContractError("SCHEMA_TYPE", path, f"expected {expected_type}")]

        if isinstance(value, dict):
            required = schema.get("required", [])
            for key in required:
                if key not in value:
                    return [ContractError("SCHEMA_REQUIRED", path, f"missing property {key!r}")]
            properties = schema.get("properties", {})
            if schema.get("additionalProperties") is False:
                extra = sorted(set(value) - set(properties))
                if extra:
                    return [ContractError("SCHEMA_ADDITIONAL_PROPERTY", path, f"unexpected properties {extra!r}")]
            for key, child_value in value.items():
                if key in properties:
                    errors.extend(
                        self._errors(child_value, properties[key], f"{path}.{key}", root_schema, root_path)
                    )
                    if errors:
                        return errors

        if isinstance(value, list):
            if "minItems" in schema and len(value) < schema["minItems"]:
                return [ContractError("SCHEMA_MIN_ITEMS", path, f"requires at least {schema['minItems']} items")]
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                return [ContractError("SCHEMA_MAX_ITEMS", path, f"allows at most {schema['maxItems']} items")]
            if schema.get("uniqueItems"):
                encoded = [canonical_json(item) for item in value]
                if len(encoded) != len(set(encoded)):
                    return [ContractError("SCHEMA_UNIQUE_ITEMS", path, "array items must be unique")]
            if "items" in schema:
                for index, item in enumerate(value):
                    errors.extend(self._errors(item, schema["items"], f"{path}[{index}]", root_schema, root_path))
                    if errors:
                        return errors

        if isinstance(value, str):
            if "minLength" in schema and len(value) < schema["minLength"]:
                return [ContractError("SCHEMA_MIN_LENGTH", path, "string is too short")]
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                return [ContractError("SCHEMA_MAX_LENGTH", path, "string is too long")]
            if "pattern" in schema and re.search(schema["pattern"], value) is None:
                return [ContractError("SCHEMA_PATTERN", path, f"does not match {schema['pattern']!r}")]

        if self._is_integer(value):
            if "minimum" in schema and value < schema["minimum"]:
                return [ContractError("SCHEMA_MINIMUM", path, f"must be >= {schema['minimum']}")]
            if "maximum" in schema and value > schema["maximum"]:
                return [ContractError("SCHEMA_MAXIMUM", path, f"must be <= {schema['maximum']}")]
        return errors

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


def _require(condition: bool, code: str, path: str, detail: str) -> None:
    if not condition:
        raise ContractError(code, path, detail)


def _unique(values: Iterable[str], path: str) -> None:
    materialized = list(values)
    _require(len(materialized) == len(set(materialized)), "DUPLICATE_ID", path, "IDs must be unique")


def _walk(value: Any, path: str = "$") -> Iterable[tuple[str, str | None, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            yield child_path, key, child
            yield from _walk(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            yield child_path, None, child
            yield from _walk(child, child_path)


def _validate_text_and_secrets(value: Any) -> None:
    for path, key, child in _walk(value):
        if key is not None and key.lower().replace("-", "_") in FORBIDDEN_KEYS:
            raise ContractError("SECRET_FIELD_FORBIDDEN", path, "credential-bearing fields are forbidden")
        if isinstance(child, float):
            raise ContractError("FLOAT_FORBIDDEN", path, "canonical contract permits integers, not floats")
        if isinstance(child, int) and not isinstance(child, bool):
            _require(
                -MAX_SAFE_INTEGER <= child <= MAX_SAFE_INTEGER,
                "INTEGER_OUT_OF_RANGE",
                path,
                "integers must fit the interoperable JSON safe-integer range",
            )
        if isinstance(child, str):
            _require(
                unicodedata.normalize("NFC", child) == child,
                "NON_CANONICAL_UNICODE",
                path,
                "strings must use Unicode NFC",
            )
            _require("\x00" not in child, "CONTROL_CHARACTER", path, "NUL is forbidden")
            for pattern in SECRET_PATTERNS:
                if pattern.search(child):
                    raise ContractError("SECRET_VALUE_DETECTED", path, "credential-like value is forbidden")


def validate_authority(authority: dict[str, Any]) -> None:
    """Validate a standalone approved-handoff authority object."""

    schema, schema_path = SCHEMAS.load("approved-handoff.schema.json")
    errors = SCHEMAS._errors(
        authority,
        schema["$defs"]["authority"],
        "$.authority",
        schema,
        schema_path,
    )
    if errors:
        raise errors[0]
    _validate_text_and_secrets(authority)


def _reject_source_candidate_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(
                "SOURCE_CANDIDATE_DUPLICATE_KEY",
                "$.source_candidate.canonical_json",
                "embedded candidate JSON contains a duplicate object key",
            )
        result[key] = value
    return result


def _parse_source_candidate_integer(value: str) -> int:
    parsed = int(value)
    if abs(parsed) > MAX_SAFE_INTEGER:
        raise ContractError(
            "SOURCE_CANDIDATE_UNSAFE_INTEGER",
            "$.source_candidate.canonical_json",
            "embedded candidate integer exceeds the interoperable JSON range",
        )
    return parsed


def _reject_source_candidate_float(_: str) -> Any:
    raise ContractError(
        "SOURCE_CANDIDATE_FLOAT_FORBIDDEN",
        "$.source_candidate.canonical_json",
        "embedded candidate JSON permits integers, not floats",
    )


def _reject_source_candidate_constant(_: str) -> Any:
    raise ContractError(
        "SOURCE_CANDIDATE_JSON_INVALID",
        "$.source_candidate.canonical_json",
        "embedded candidate JSON contains a non-JSON numeric constant",
    )


def parse_source_candidate(source: dict[str, Any]) -> dict[str, Any]:
    """Strictly parse and validate the exact canonical approved candidate."""

    raw = source["canonical_json"]
    try:
        candidate = json.loads(
            raw,
            object_pairs_hook=_reject_source_candidate_duplicate_keys,
            parse_int=_parse_source_candidate_integer,
            parse_float=_reject_source_candidate_float,
            parse_constant=_reject_source_candidate_constant,
        )
    except ContractError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        raise ContractError(
            "SOURCE_CANDIDATE_JSON_INVALID",
            "$.source_candidate.canonical_json",
            "embedded candidate is not valid JSON",
        ) from error
    _require(
        isinstance(candidate, dict),
        "SOURCE_CANDIDATE_ROOT_TYPE",
        "$.source_candidate.canonical_json",
        "embedded candidate must be a JSON object",
    )
    _validate_text_and_secrets(candidate)
    _require(
        canonical_json(candidate) == raw,
        "SOURCE_CANDIDATE_JSON_NOT_CANONICAL",
        "$.source_candidate.canonical_json",
        "embedded candidate must be exact Tacua Canonical JSON without a trailing newline",
    )
    try:
        TICKET_CANDIDATE.validate(candidate)
    except TICKET_CANDIDATE.ContractError as error:
        raise ContractError(
            "SOURCE_CANDIDATE_INVALID",
            "$.source_candidate.canonical_json",
            f"ticket-candidate validation failed ({error.code})",
        ) from error

    for field in (
        "contract_version",
        "candidate_id",
        "candidate_version",
        "candidate_digest",
        "candidate_content_digest",
    ):
        _require(
            source[field] == candidate[field],
            "SOURCE_CANDIDATE_METADATA_MISMATCH",
            f"$.source_candidate.{field}",
            "source metadata must exactly mirror the embedded candidate",
        )
    _require(
        candidate["state"] == "approved",
        "SOURCE_CANDIDATE_NOT_APPROVED",
        "$.source_candidate.canonical_json",
        "embedded candidate must be an approved immutable version",
    )
    return candidate


def _resolved_source_clarification(clarification: dict[str, Any]) -> str | None:
    if clarification["status"] != "resolved":
        return None
    if clarification["resolution_note"]:
        return clarification["resolution_note"]
    selected_id = clarification["selected_choice_id"]
    for choice in clarification["choices"]:
        if choice["choice_id"] == selected_id:
            return choice["label"]
    raise ContractError(
        "SOURCE_CANDIDATE_CLARIFICATION_INVALID",
        "$.source_candidate.canonical_json",
        "resolved clarification has no selected choice",
    )


def _source_step_action(step: dict[str, Any]) -> str:
    parts = [step["action"]]
    if step["expected_result"] is not None:
        parts.append("Expected: " + step["expected_result"])
    if step["actual_result"] is not None:
        parts.append("Observed: " + step["actual_result"])
    return "\n".join(parts)


def project_source_candidate_ticket(candidate: dict[str, Any]) -> dict[str, Any]:
    """Return the deterministic convenience-ticket projection for a source candidate."""

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
                    "action": _source_step_action(item),
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
                "resolution": _resolved_source_clarification(item),
            }
            for item in content["clarifications"]
        ],
        "ticket_content_digest": "sha256:" + "0" * 64,
    }


def _validate_source_candidate_binding(
    handoff: dict[str, Any], candidate: dict[str, Any]
) -> None:
    ticket = handoff["ticket"]
    approval = handoff["approval"]
    candidate_approval = candidate["approval"]
    for field in ("organization_id", "project_id"):
        _require(
            candidate[field] == handoff[field],
            "SOURCE_CANDIDATE_SCOPE_MISMATCH",
            f"$.source_candidate.canonical_json.{field}",
            "embedded candidate and handoff scope differ",
        )
    for candidate_field, ticket_field in (
        ("candidate_id", "ticket_id"),
        ("candidate_version", "ticket_version"),
    ):
        _require(
            candidate[candidate_field] == ticket[ticket_field],
            "SOURCE_CANDIDATE_TICKET_MISMATCH",
            f"$.ticket.{ticket_field}",
            "convenience ticket does not identify the embedded candidate",
        )
    _require(
        candidate["build_id"] == handoff["build_identity"]["build_id"],
        "SOURCE_CANDIDATE_BUILD_MISMATCH",
        "$.build_identity.build_id",
        "build identity does not identify the embedded candidate build",
    )
    _require(
        candidate["session_id"] == handoff["evidence_manifest"]["session_id"],
        "SOURCE_CANDIDATE_EVIDENCE_MISMATCH",
        "$.evidence_manifest.session_id",
        "evidence session does not identify the embedded candidate session",
    )
    _require(
        candidate["evidence_manifest"]["manifest_id"]
        == handoff["evidence_manifest"]["manifest_id"],
        "SOURCE_CANDIDATE_EVIDENCE_MISMATCH",
        "$.evidence_manifest.manifest_id",
        "evidence manifest does not identify the embedded candidate manifest",
    )
    handoff_evidence_ids = {
        item["evidence_id"] for item in handoff["evidence_manifest"]["items"]
    }
    _require(
        handoff_evidence_ids == set(candidate_approval["authorized_evidence_ids"]),
        "SOURCE_CANDIDATE_EVIDENCE_MISMATCH",
        "$.evidence_manifest.items",
        "handoff evidence must equal the embedded approval's authorized evidence set",
    )
    _require(
        handoff_evidence_ids <= set(candidate["evidence_manifest"]["evidence_ids"]),
        "SOURCE_CANDIDATE_EVIDENCE_MISMATCH",
        "$.evidence_manifest.items",
        "handoff evidence is absent from the embedded candidate manifest binding",
    )
    for field in ("approval_id", "actor_id", "approved_at"):
        _require(
            approval[field] == candidate_approval[field],
            "SOURCE_CANDIDATE_APPROVAL_MISMATCH",
            f"$.approval.{field}",
            "handoff approval does not match the embedded candidate approval",
        )
    _require(
        approval["ticket_version"]
        == candidate_approval["approved_candidate_version"],
        "SOURCE_CANDIDATE_APPROVAL_MISMATCH",
        "$.approval.ticket_version",
        "handoff approval does not bind the embedded approved version",
    )
    expected_ticket = project_source_candidate_ticket(candidate)
    expected_ticket["ticket_content_digest"] = ticket["ticket_content_digest"]
    _require(
        ticket == expected_ticket,
        "SOURCE_CANDIDATE_TICKET_MISMATCH",
        "$.ticket",
        "convenience ticket is not the deterministic projection of the embedded candidate",
    )


def parse_timestamp(value: str, path: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ContractError("INVALID_TIMESTAMP", path, "expected a real UTC second in RFC 3339 form") from error
    return parsed


def _require_not_after(left: tuple[str, str], right: tuple[str, str], code: str, detail: str) -> None:
    left_value, left_path = left
    right_value, right_path = right
    _require(
        parse_timestamp(left_value, left_path) <= parse_timestamp(right_value, right_path),
        code,
        right_path,
        detail,
    )


def _validate_digest(value: str, expected: str, path: str) -> None:
    _require(bool(DIGEST_RE.fullmatch(value)), "INVALID_DIGEST", path, "expected sha256:<64 lowercase hex>")
    _require(value == expected, "DIGEST_MISMATCH", path, f"expected {expected}")


def validate_build_identity(build: dict[str, Any]) -> None:
    SCHEMAS.validate(build, "build-identity.schema.json")
    _validate_text_and_secrets(build)
    if build["backend"]["availability"] == "available":
        parse_timestamp(build["backend"]["deployed_at"], "$.backend.deployed_at")
    _validate_digest(
        build["build_identity_digest"],
        digest_without(build, "build_identity_digest"),
        "$.build_identity_digest",
    )


SOURCE_PREFIX = {
    "sdk.": "mobile_sdk",
    "media.": "mobile_sdk",
    "repository.": "repository",
    "backend.": "backend",
    "observability.sentry_": "sentry",
    "observability.posthog_": "posthog",
}


def validate_evidence_item(
    item: dict[str, Any],
    organization_id: str | None = None,
    project_id: str | None = None,
    session_id: str | None = None,
) -> None:
    SCHEMAS.validate(item, "evidence-item.schema.json")
    _validate_text_and_secrets(item)
    for expected, actual, path in (
        (organization_id, item["organization_id"], "$.organization_id"),
        (project_id, item["project_id"], "$.project_id"),
        (session_id, item["session_id"], "$.session_id"),
    ):
        if expected is not None:
            _require(expected == actual, "SCOPE_MISMATCH", path, f"expected {expected!r}")

    if item["time_range"] is not None:
        _require(
            item["time_range"]["start_ms"] <= item["time_range"]["end_ms"],
            "REVERSED_TIME_RANGE",
            "$.time_range",
            "start_ms must be <= end_ms",
        )

    captured_at = parse_timestamp(item["source"]["captured_at"], "$.source.captured_at")

    source_component = item["source"]["component"]
    for prefix, expected_component in SOURCE_PREFIX.items():
        if item["evidence_type"].startswith(prefix):
            _require(
                source_component == expected_component,
                "SOURCE_TYPE_MISMATCH",
                "$.source.component",
                f"{item['evidence_type']} requires {expected_component}",
            )
            break

    if item["availability"] == "available":
        locator = item["reference"]["locator"]
        for field in ("organization_id", "project_id", "evidence_id"):
            _require(
                locator[field] == item[field],
                "REFERENCE_SCOPE_MISMATCH",
                f"$.reference.locator.{field}",
                f"must match evidence item {field}",
            )
            _require(
                item["authorization"][field] == item[field],
                "AUTHORIZATION_SCOPE_MISMATCH",
                f"$.authorization.{field}",
                f"must match evidence item {field}",
            )
        authorized_at = parse_timestamp(item["authorization"]["approved_at"], "$.authorization.approved_at")
        _require(
            captured_at <= authorized_at,
            "EVIDENCE_AUTHORIZATION_PRECEDES_CAPTURE",
            "$.authorization.approved_at",
            "evidence cannot be authorized before it was captured",
        )
    _validate_digest(
        item["evidence_item_digest"],
        digest_without(item, "evidence_item_digest"),
        "$.evidence_item_digest",
    )


def validate_evidence_manifest(manifest: dict[str, Any]) -> None:
    SCHEMAS.validate(manifest, "evidence-manifest.schema.json")
    _validate_text_and_secrets(manifest)
    _unique((item["evidence_id"] for item in manifest["items"]), "$.items")
    for item in manifest["items"]:
        validate_evidence_item(
            item,
            organization_id=manifest["organization_id"],
            project_id=manifest["project_id"],
            session_id=manifest["session_id"],
        )
    _require(
        any(item["availability"] == "available" for item in manifest["items"]),
        "NO_AVAILABLE_EVIDENCE",
        "$.items",
        "at least one authorized evidence reference is required",
    )
    _validate_digest(
        manifest["evidence_manifest_digest"],
        digest_without(manifest, "evidence_manifest_digest"),
        "$.evidence_manifest_digest",
    )


def validate_registry_assertion(
    assertion: dict[str, Any],
    key: bytes,
    handoff: dict[str, Any],
    *,
    at_time: datetime | None = None,
) -> None:
    """Verify an external registry assertion and bind it to this exact handoff.

    The HMAC mechanism is a candidate trust adapter, not an accepted signature policy.
    Callers must obtain the key through an authenticated channel outside the handoff.
    """

    _require(len(key) >= 32, "REGISTRY_KEY_TOO_SHORT", "$", "registry HMAC key must be at least 32 bytes")
    SCHEMAS.validate(assertion, "registry-assertion.schema.json")
    _validate_text_and_secrets(assertion)
    issued_at = parse_timestamp(assertion["issued_at"], "$.issued_at")
    expires_at = parse_timestamp(assertion["expires_at"], "$.expires_at")
    _require(issued_at < expires_at, "INVALID_ASSERTION_WINDOW", "$.expires_at", "expiry must follow issue time")
    _require(
        expires_at - issued_at <= MAX_REGISTRY_ASSERTION_LIFETIME,
        "ASSERTION_WINDOW_TOO_LONG",
        "$.expires_at",
        "candidate registry assertions may be valid for at most 24 hours",
    )
    checked_at = parse_timestamp(handoff["supersession"]["checked_at"], "$.supersession.checked_at")
    approved_at = parse_timestamp(handoff["approval"]["approved_at"], "$.approval.approved_at")
    _require(
        max(checked_at, approved_at) <= issued_at,
        "REGISTRY_ASSERTION_PRECEDES_HANDOFF_STATE",
        "$.issued_at",
        "trusted assertion must be issued after approval and registry observation",
    )
    now = at_time or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ContractError("INVALID_TRUST_TIME", "$", "trust evaluation time must be timezone-aware")
    now = now.astimezone(timezone.utc)
    _require(issued_at <= now <= expires_at, "REGISTRY_ASSERTION_EXPIRED", "$", "assertion is not current")

    supplied = assertion["signature"]["value"]
    _require(bool(HMAC_RE.fullmatch(supplied)), "INVALID_REGISTRY_SIGNATURE", "$.signature.value", "invalid HMAC")
    payload = canonical_json(registry_assertion_subject(assertion)).encode("utf-8")
    expected = "hmac-sha256:" + hmac.new(key, payload, hashlib.sha256).hexdigest()
    _require(
        hmac.compare_digest(supplied, expected),
        "REGISTRY_SIGNATURE_MISMATCH",
        "$.signature.value",
        "assertion was not authenticated by the trusted registry key",
    )

    ticket = handoff["ticket"]
    for field, expected_value in (
        ("organization_id", handoff["organization_id"]),
        ("project_id", handoff["project_id"]),
        ("ticket_id", ticket["ticket_id"]),
        ("ticket_version", ticket["ticket_version"]),
        ("current_handoff_digest", handoff["handoff_digest"]),
        ("registry_revision", handoff["supersession"]["registry_revision"]),
    ):
        _require(
            assertion[field] == expected_value,
            "REGISTRY_ASSERTION_SCOPE_MISMATCH",
            f"$.{field}",
            f"expected {expected_value!r}",
        )

    trusted_sources = {
        (source["component"], source["source_id"], source["snapshot_revision"])
        for source in assertion["authorized_sources"]
    }
    manifest_sources = {
        (item["source"]["component"], item["source"]["source_id"], item["source"]["snapshot_revision"])
        for item in handoff["evidence_manifest"]["items"]
    }
    _require(
        manifest_sources <= trusted_sources,
        "UNTRUSTED_EVIDENCE_SOURCE",
        "$.authorized_sources",
        f"registry does not bind sources {sorted(manifest_sources - trusted_sources)!r}",
    )


def _validate_handoff_at_time(
    handoff: dict[str, Any],
    *,
    executable: bool = False,
    registry_assertion: dict[str, Any] | None = None,
    registry_key: bytes | None = None,
    at_time: datetime | None = None,
) -> None:
    encoded_size = len(canonical_json_artifact(handoff))
    _require(encoded_size <= MAX_JSON_BYTES, "JSON_SIZE_LIMIT", "$", f"{encoded_size} > {MAX_JSON_BYTES}")
    _validate_text_and_secrets(handoff)
    SCHEMAS.validate(handoff, "approved-handoff.schema.json")
    validate_build_identity(handoff["build_identity"])
    validate_evidence_manifest(handoff["evidence_manifest"])
    source_candidate = parse_source_candidate(handoff["source_candidate"])

    organization_id = handoff["organization_id"]
    project_id = handoff["project_id"]
    for nested, path in (
        (handoff["build_identity"], "$.build_identity"),
        (handoff["evidence_manifest"], "$.evidence_manifest"),
    ):
        _require(nested["organization_id"] == organization_id, "SCOPE_MISMATCH", path, "organization mismatch")
        _require(nested["project_id"] == project_id, "SCOPE_MISMATCH", path, "project mismatch")

    ticket = handoff["ticket"]
    approval = handoff["approval"]
    approval_time = parse_timestamp(approval["approved_at"], "$.approval.approved_at")
    if handoff["build_identity"]["backend"]["availability"] == "available":
        deployed_at = parse_timestamp(
            handoff["build_identity"]["backend"]["deployed_at"],
            "$.build_identity.backend.deployed_at",
        )
        _require(
            deployed_at <= approval_time,
            "TICKET_APPROVAL_PRECEDES_BACKEND_DEPLOYMENT",
            "$.approval.approved_at",
            "ticket approval must follow the identified backend deployment",
        )
    expected_content_digest = sha256_digest(canonical_json(approval_subject(handoff)))
    _validate_digest(ticket["ticket_content_digest"], expected_content_digest, "$.ticket.ticket_content_digest")
    _require(
        approval["ticket_content_digest"] == ticket["ticket_content_digest"],
        "APPROVAL_DIGEST_MISMATCH",
        "$.approval.ticket_content_digest",
        "approval must bind the immutable approved content",
    )
    _require(
        approval["ticket_version"] == ticket["ticket_version"],
        "APPROVAL_VERSION_MISMATCH",
        "$.approval.ticket_version",
        "approval must bind this ticket version",
    )
    for field, expected in (
        ("organization_id", organization_id),
        ("project_id", project_id),
        ("ticket_id", ticket["ticket_id"]),
    ):
        _require(
            approval[field] == expected,
            "APPROVAL_SCOPE_MISMATCH",
            f"$.approval.{field}",
            f"expected {expected!r}",
        )

    items = {item["evidence_id"]: item for item in handoff["evidence_manifest"]["items"]}
    claims = ticket["claims"]
    claim_ids = {claim["claim_id"] for claim in claims}
    _unique((claim["claim_id"] for claim in claims), "$.ticket.claims")
    _unique((step["step_id"] for step in ticket["reproduction"]["steps"]), "$.ticket.reproduction.steps")
    _unique((criterion["criterion_id"] for criterion in ticket["acceptance_criteria"]), "$.ticket.acceptance_criteria")
    _unique((clarification["clarification_id"] for clarification in ticket["clarifications"]), "$.ticket.clarifications")

    for index, claim in enumerate(claims):
        for evidence_id in claim["evidence_refs"]:
            _require(
                evidence_id in items,
                "UNKNOWN_EVIDENCE_REFERENCE",
                f"$.ticket.claims[{index}].evidence_refs",
                evidence_id,
            )
        available_refs = [
            evidence_id for evidence_id in claim["evidence_refs"] if items[evidence_id]["availability"] == "available"
        ]
        if claim["support"] == "direct":
            _require(
                bool(available_refs),
                "DIRECT_CLAIM_UNGROUNDED",
                f"$.ticket.claims[{index}].evidence_refs",
                "direct support requires available authorized evidence",
            )
        elif claim["support"] == "inferred":
            _require(
                bool(claim["evidence_refs"]),
                "INFERRED_CLAIM_UNGROUNDED",
                f"$.ticket.claims[{index}].evidence_refs",
                "an inference must identify its evidence basis",
            )
        else:
            _require(
                claim["confidence"] == "unknown",
                "UNKNOWN_SUPPORT_CONFIDENCE_MISMATCH",
                f"$.ticket.claims[{index}].confidence",
                "unknown support must carry unknown confidence",
            )
        if claim["kind"] == "observed":
            _require(
                claim["support"] == "direct" and bool(available_refs),
                "OBSERVED_CLAIM_UNGROUNDED",
                f"$.ticket.claims[{index}]",
                "observed claims require direct available evidence",
            )

    for field, required_kinds in (
        ("summary_claim_refs", None),
        ("observed_claim_refs", {"observed"}),
        ("expected_claim_refs", {"expected", "constraint"}),
    ):
        refs = ticket[field] if field == "summary_claim_refs" else ticket["reproduction"][field]
        for claim_id in refs:
            _require(claim_id in claim_ids, "UNKNOWN_CLAIM_REFERENCE", f"$.ticket.{field}", claim_id)
        if required_kinds is not None:
            by_id = {claim["claim_id"]: claim for claim in claims}
            _require(
                any(by_id[claim_id]["kind"] in required_kinds for claim_id in refs),
                "CLAIM_KIND_MISMATCH",
                f"$.ticket.reproduction.{field}",
                f"requires one of {sorted(required_kinds)!r}",
            )

    for index, step in enumerate(ticket["reproduction"]["steps"]):
        _require(
            bool(step["evidence_refs"]),
            "REPRODUCTION_STEP_UNGROUNDED",
            f"$.ticket.reproduction.steps[{index}].evidence_refs",
            "every reproduction step must cite evidence",
        )
        for evidence_id in step["evidence_refs"]:
            _require(
                evidence_id in items,
                "UNKNOWN_EVIDENCE_REFERENCE",
                f"$.ticket.reproduction.steps[{index}].evidence_refs",
                evidence_id,
            )
        for claim_id in step["claim_refs"]:
            _require(
                claim_id in claim_ids,
                "UNKNOWN_CLAIM_REFERENCE",
                f"$.ticket.reproduction.steps[{index}].claim_refs",
                claim_id,
            )

    reproduction = ticket["reproduction"]
    _require(
        reproduction["reproductions"] <= reproduction["attempts"],
        "INVALID_REPRO_COUNTS",
        "$.ticket.reproduction",
        "reproductions cannot exceed attempts",
    )
    for index, clarification in enumerate(ticket["clarifications"]):
        if clarification["impact"] == "blocking" and clarification["status"] != "resolved":
            raise ContractError(
                "UNRESOLVED_BLOCKING_CLARIFICATION",
                f"$.ticket.clarifications[{index}]",
                clarification["clarification_id"],
            )

    for item in handoff["evidence_manifest"]["items"]:
        captured_time = parse_timestamp(
            item["source"]["captured_at"],
            "$.evidence_manifest.items[].source.captured_at",
        )
        _require(
            captured_time <= approval_time,
            "TICKET_APPROVAL_PRECEDES_EVIDENCE_CAPTURE",
            "$.approval.approved_at",
            "ticket approval must follow every included evidence capture",
        )
        if item["availability"] == "available":
            evidence_approval_time = parse_timestamp(
                item["authorization"]["approved_at"],
                "$.evidence_manifest.items[].authorization.approved_at",
            )
            _require(
                evidence_approval_time <= approval_time,
                "TICKET_APPROVAL_PRECEDES_EVIDENCE_AUTHORIZATION",
                "$.approval.approved_at",
                "ticket approval must follow every included evidence authorization",
            )

    source_repositories = {handoff["build_identity"]["mobile"]["source"]["repository_id"]}
    if handoff["build_identity"]["backend"]["availability"] == "available":
        source_repositories.update(
            snapshot["repository_id"] for snapshot in handoff["build_identity"]["backend"]["sources"]
        )
    allowed_repositories = set(handoff["authority"]["allowed_repositories"])
    _require(
        source_repositories <= allowed_repositories,
        "REPOSITORY_AUTHORITY_MISMATCH",
        "$.authority.allowed_repositories",
        f"missing {sorted(source_repositories - allowed_repositories)!r}",
    )
    source_revisions = {
        snapshot["repository_id"]: snapshot["revision"]
        for snapshot in [handoff["build_identity"]["mobile"]["source"]]
        + (
            handoff["build_identity"]["backend"]["sources"]
            if handoff["build_identity"]["backend"]["availability"] == "available"
            else []
        )
    }
    for index, item in enumerate(handoff["evidence_manifest"]["items"]):
        if item["source"]["component"] == "repository":
            source_id = item["source"]["source_id"]
            _require(
                source_id in source_revisions,
                "REPOSITORY_EVIDENCE_SOURCE_MISMATCH",
                f"$.evidence_manifest.items[{index}].source.source_id",
                "repository evidence must identify a tested build source",
            )
            _require(
                item["source"]["snapshot_revision"] == source_revisions[source_id],
                "REPOSITORY_EVIDENCE_REVISION_MISMATCH",
                f"$.evidence_manifest.items[{index}].source.snapshot_revision",
                "repository evidence must match the immutable tested source revision",
            )

    supersession = handoff["supersession"]
    checked_at = parse_timestamp(supersession["checked_at"], "$.supersession.checked_at")
    _require(
        approval_time <= checked_at,
        "REGISTRY_CHECK_PRECEDES_APPROVAL",
        "$.supersession.checked_at",
        "registry observation cannot precede ticket approval",
    )
    if supersession["supersedes_handoff_digest"] is not None:
        _require(
            ticket["ticket_version"] > 1,
            "INVALID_SUPERSESSION_CHAIN",
            "$.ticket.ticket_version",
            "a superseding handoff must identify a later ticket version",
        )

    _validate_source_candidate_binding(handoff, source_candidate)
    _validate_digest(handoff["handoff_digest"], digest_without(handoff, "handoff_digest"), "$.handoff_digest")
    if executable:
        _require(
            registry_assertion is not None and registry_key is not None,
            "TRUST_INPUT_REQUIRED",
            "$",
            "executable validation requires an authenticated registry assertion and external key",
        )
        _require(
            supersession["status"] == "current" and supersession["superseded_by_handoff_digest"] is None,
            "STALE_HANDOFF",
            "$.supersession",
            "only the current approved version is executable",
        )
        validate_registry_assertion(
            registry_assertion,
            registry_key,
            handoff,
            at_time=at_time,
        )


def validate_handoff(
    handoff: dict[str, Any],
    *,
    executable: bool = False,
    registry_assertion: dict[str, Any] | None = None,
    registry_key: bytes | None = None,
) -> None:
    """Validate structurally or, in executable mode, against the real current UTC clock."""

    _validate_handoff_at_time(
        handoff,
        executable=executable,
        registry_assertion=registry_assertion,
        registry_key=registry_key,
        at_time=datetime.now(timezone.utc) if executable else None,
    )


def validate_synthetic_fixture_handoff(
    handoff: dict[str, Any],
    registry_assertion: dict[str, Any],
    registry_key: bytes,
    registry_key_path: Path,
) -> None:
    """Validate only the checked-in synthetic fixture at its immutable fixture clock."""

    expected_key_path = (
        CONTRACT_ROOT / "fixtures" / "positive" / "registry-key.synthetic.hex"
    ).resolve()
    build = handoff.get("build_identity", {})
    mobile = build.get("mobile", {})
    backend = build.get("backend", {})
    checks = (
        (registry_key_path.resolve() == expected_key_path, "synthetic key path"),
        (registry_key == SYNTHETIC_FIXTURE_KEY, "synthetic key bytes"),
        (handoff.get("organization_id") == "org-synthetic", "synthetic organization"),
        (handoff.get("project_id") == "project-sample-mobile-app-synthetic", "synthetic project"),
        (handoff.get("ticket", {}).get("ticket_id") == "ticket-synthetic-001", "synthetic ticket"),
        (
            mobile.get("application_id") == "com.example.samplemobileapp.tacua.synthetic",
            "synthetic app identity",
        ),
        (backend.get("environment") == "synthetic-qa", "synthetic backend environment"),
        (registry_assertion.get("assertion_id") == "assertion-synthetic-001", "synthetic assertion ID"),
        (registry_assertion.get("issuer_id") == "registry-synthetic-001", "synthetic issuer ID"),
        (registry_assertion.get("signature", {}).get("key_id") == "registry-key-synthetic-001", "synthetic key ID"),
    )
    for condition, label in checks:
        _require(
            condition,
            "SYNTHETIC_FIXTURE_IDENTITY_REQUIRED",
            "$",
            f"fixture clock is restricted to the checked-in {label}",
        )
    _validate_handoff_at_time(
        handoff,
        executable=True,
        registry_assertion=registry_assertion,
        registry_key=registry_key,
        at_time=SYNTHETIC_FIXTURE_TIME,
    )


def _pre(value: Any, field: str | None = None) -> str:
    attribute = f' data-tacua-field="{html.escape(field, quote=True)}"' if field else ""
    return f"<pre{attribute}>{html.escape(str(value), quote=False)}</pre>"


def render_markdown(handoff: dict[str, Any]) -> str:
    validate_handoff(handoff, executable=False)
    ticket = handoff["ticket"]
    build = handoff["build_identity"]
    manifest = handoff["evidence_manifest"]
    source_candidate = handoff["source_candidate"]
    lines = [
        "<!-- SPDX-License-Identifier: Apache-2.0 -->",
        "# Tacua approved ticket",
        "",
        f"- Contract: `{handoff['contract_version']}`",
        f"- Handoff digest: `{handoff['handoff_digest']}`",
        f"- Ticket/version: `{ticket['ticket_id']}` / `{ticket['ticket_version']}`",
        f"- Approved content digest: `{ticket['ticket_content_digest']}`",
        f"- Build identity digest: `{build['build_identity_digest']}`",
        f"- Evidence manifest digest: `{manifest['evidence_manifest_digest']}`",
        f"- Supersession: `{handoff['supersession']['status']}`",
        "",
        "## Exact approved source candidate",
        "",
        f"- Candidate/version: `{source_candidate['candidate_id']}` / `{source_candidate['candidate_version']}`",
        f"- Candidate digest: `{source_candidate['candidate_digest']}`",
        f"- Candidate content digest: `{source_candidate['candidate_content_digest']}`",
        "",
        "The JSON below is the exact canonical approved ticket-candidate source, without an artifact trailing newline.",
        "",
        _pre(source_candidate["canonical_json"], "source_candidate.canonical_json"),
        "",
        "## Title",
        "",
        _pre(ticket["title"], "ticket.title"),
        "",
        "## Summary",
        "",
        _pre(ticket["summary"], "ticket.summary"),
        "",
        "Claims: " + ", ".join(f"`{reference}`" for reference in ticket["summary_claim_refs"]),
        "",
        "## Claims",
        "",
    ]
    for claim in ticket["claims"]:
        lines.extend(
            [
                f"### `{claim['claim_id']}` — `{claim['kind']}` / `{claim['support']}` / `{claim['confidence']}`",
                "",
                _pre(claim["statement"], f"claim.{claim['claim_id']}"),
                "",
                "Evidence: " + ", ".join(f"`{reference}`" for reference in claim["evidence_refs"]),
                "",
            ]
        )

    lines.extend(["## Reproduction", "", "### Preconditions", ""])
    if ticket["reproduction"]["preconditions"]:
        for precondition in ticket["reproduction"]["preconditions"]:
            lines.extend([_pre(precondition, "reproduction.precondition"), ""])
    else:
        lines.extend(["None.", ""])
    lines.extend(["### Steps", ""])
    for index, step in enumerate(ticket["reproduction"]["steps"], 1):
        refs = ", ".join(f"`{reference}`" for reference in step["evidence_refs"]) or "none"
        claim_refs = ", ".join(f"`{reference}`" for reference in step["claim_refs"])
        lines.extend(
            [
                f"{index}. `{step['step_id']}` (claims: {claim_refs}; evidence: {refs})",
                "",
                _pre(step["action"], f"reproduction.{step['step_id']}"),
                "",
            ]
        )
    lines.extend(
        [
            "### Observed result",
            "",
            _pre(ticket["reproduction"]["observed_result"], "reproduction.observed_result"),
            "",
            "Claims: " + ", ".join(f"`{reference}`" for reference in ticket["reproduction"]["observed_claim_refs"]),
            "",
            "### Expected result",
            "",
            _pre(ticket["reproduction"]["expected_result"], "reproduction.expected_result"),
            "",
            "Claims: " + ", ".join(f"`{reference}`" for reference in ticket["reproduction"]["expected_claim_refs"]),
            "",
            f"Attempts/reproductions: `{ticket['reproduction']['attempts']}` / `{ticket['reproduction']['reproductions']}`",
            "",
            "## Scope",
            "",
            "### In scope",
            "",
        ]
    )
    for value in ticket["scope"]["in_scope"]:
        lines.extend([_pre(value, "scope.in_scope"), ""])
    lines.extend(["### Out of scope", ""])
    if ticket["scope"]["out_of_scope"]:
        for value in ticket["scope"]["out_of_scope"]:
            lines.extend([_pre(value, "scope.out_of_scope"), ""])
    else:
        lines.extend(["None declared.", ""])

    lines.extend(["## Acceptance criteria", ""])
    for criterion in ticket["acceptance_criteria"]:
        lines.extend(
            [
                f"### `{criterion['criterion_id']}`",
                "",
                _pre(criterion["criterion"], f"acceptance.{criterion['criterion_id']}.criterion"),
                "",
                "Verification:",
                "",
                _pre(criterion["verification"], f"acceptance.{criterion['criterion_id']}.verification"),
                "",
            ]
        )

    lines.extend(["## Clarifications and open questions", ""])
    if ticket["clarifications"]:
        for clarification in ticket["clarifications"]:
            lines.extend(
                [
                    f"### `{clarification['clarification_id']}` — `{clarification['impact']}` / `{clarification['status']}`",
                    "",
                    _pre(clarification["question"], f"clarification.{clarification['clarification_id']}.question"),
                    "",
                    _pre(clarification["resolution"], f"clarification.{clarification['clarification_id']}.resolution"),
                    "",
                ]
            )
    else:
        lines.extend(["None.", ""])

    lines.extend(
        [
            "## Build snapshots",
            "",
            f"- Mobile: `{build['mobile']['platform']}` / `{build['mobile']['application_id']}` / "
            f"`{build['mobile']['app_version']} ({build['mobile']['build_number']})`",
            f"- Mobile source: `{build['mobile']['source']['repository_id']}@{build['mobile']['source']['revision']}`",
        ]
    )
    backend = build["backend"]
    if backend["availability"] == "available":
        lines.append(f"- Backend: `{backend['deployment_id']}` / `{backend['image_digest']}`")
        for source in backend["sources"]:
            lines.append(f"- Backend source: `{source['repository_id']}@{source['revision']}`")
    else:
        lines.append(f"- Backend unavailable: `{backend['unavailable_reason']}`")
    lines.extend(["", "## Authorized evidence references", ""])
    for item in manifest["items"]:
        lines.append(f"### `{item['evidence_id']}` — `{item['evidence_type']}` / `{item['availability']}`")
        lines.extend(["", _pre(item["description"], f"evidence.{item['evidence_id']}.description"), ""])
        if item["availability"] == "available":
            reference = item["reference"]
            lines.extend(
                [
                    f"- Revision: `{reference['locator']['revision_id']}`",
                    f"- Content: `{reference['content_type']}` / `{reference['size_bytes']}` bytes / `{reference['content_digest']}`",
                    f"- Authorization: `{item['authorization']['decision_id']}` / `{item['authorization']['policy_version']}`",
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    f"- Unavailable reason: `{item['unavailable']['reason']}`",
                    "",
                    _pre(item["unavailable"]["detail"], f"evidence.{item['evidence_id']}.unavailable"),
                    "",
                ]
            )

    lines.extend(
        [
            "## Structural scope — not execution authority",
            "",
            "- This file is not execution authorization. Before acting, obtain and verify a current trusted registry assertion for this exact handoff digest.",
            "- Only after that independent authorization, the requested scope permits reading the authorized evidence references, modifying code in the listed repositories, and running tests.",
            "- This structural scope never permits external writes, merge, or deploy.",
            "- Repositories: " + ", ".join(f"`{repo}`" for repo in handoff["authority"]["allowed_repositories"]),
            "",
            "## Canonical JSON",
            "",
            "The escaped canonical JSON below is the complete machine-equivalent representation.",
            "",
            '<pre><code class="language-json">' + html.escape(canonical_json(handoff), quote=False) + "</code></pre>",
            "",
        ]
    )
    rendered = "\n".join(lines)
    _require(
        len(rendered.encode("utf-8")) <= MAX_MARKDOWN_BYTES,
        "MARKDOWN_SIZE_LIMIT",
        "$",
        f"rendered Markdown exceeds {MAX_MARKDOWN_BYTES} bytes",
    )
    return rendered


def validate_markdown(handoff: dict[str, Any], markdown: str) -> None:
    expected = render_markdown(handoff)
    _require(
        markdown == expected,
        "MARKDOWN_EQUIVALENCE_MISMATCH",
        "$",
        "Markdown must exactly equal the deterministic render of the approved JSON",
    )


def validate_trial(
    trial: dict[str, Any],
    handoff: dict[str, Any],
    markdown: str,
    *,
    registry_assertion: dict[str, Any],
    registry_key: bytes,
    json_artifact_bytes: bytes,
) -> None:
    SCHEMAS.validate(trial, "agent-trial.schema.json")
    _validate_text_and_secrets(trial)
    started_at = parse_timestamp(trial["started_at"], "$.started_at")
    completed_at = parse_timestamp(trial["completed_at"], "$.completed_at")
    _require(started_at <= completed_at, "TRIAL_TIME_REVERSED", "$.completed_at", "completion precedes start")
    _validate_handoff_at_time(
        handoff,
        executable=True,
        registry_assertion=registry_assertion,
        registry_key=registry_key,
        at_time=started_at,
    )
    validate_markdown(handoff, markdown)
    for field in ("organization_id", "project_id"):
        _require(trial[field] == handoff[field], "TRIAL_SCOPE_MISMATCH", f"$.{field}", "trial and handoff differ")
    _require(trial["ticket_id"] == handoff["ticket"]["ticket_id"], "TRIAL_TICKET_MISMATCH", "$.ticket_id", "wrong ticket")
    _require(trial["ticket_version"] == handoff["ticket"]["ticket_version"], "TRIAL_TICKET_MISMATCH", "$.ticket_version", "wrong version")
    _require(trial["handoff_digest"] == handoff["handoff_digest"], "TRIAL_HANDOFF_MISMATCH", "$.handoff_digest", "wrong handoff")
    _require(
        trial["ticket_content_digest"] == handoff["ticket"]["ticket_content_digest"],
        "TRIAL_HANDOFF_MISMATCH",
        "$.ticket_content_digest",
        "wrong approved content",
    )
    _validate_digest(
        trial["json_artifact_digest"],
        sha256_digest(json_artifact_bytes),
        "$.json_artifact_digest",
    )
    _require(
        json_artifact_bytes == canonical_json_artifact(handoff),
        "TRIAL_JSON_ARTIFACT_MISMATCH",
        "$.json_artifact_digest",
        "trial bytes must be the canonical artifact for the validated handoff",
    )
    _validate_digest(
        trial["markdown_artifact_digest"],
        sha256_digest(markdown.encode("utf-8")),
        "$.markdown_artifact_digest",
    )
    _validate_digest(
        trial["registry_assertion_digest"],
        sha256_digest(canonical_json_artifact(registry_assertion)),
        "$.registry_assertion_digest",
    )
    evidence_ids = {item["evidence_id"] for item in handoff["evidence_manifest"]["items"]}
    _require(
        set(trial["evidence_used"]) <= evidence_ids,
        "TRIAL_UNKNOWN_EVIDENCE",
        "$.evidence_used",
        "trial cites evidence outside the handoff",
    )
    allowed_repositories = set(handoff["authority"]["allowed_repositories"])
    _require(
        all(change["repository_id"] in allowed_repositories for change in trial["changes"]),
        "TRIAL_REPOSITORY_FORBIDDEN",
        "$.changes",
        "trial changed a repository outside the handoff authority",
    )
    approved_at = parse_timestamp(handoff["approval"]["approved_at"], "$.approval.approved_at")
    assertion_issued_at = parse_timestamp(registry_assertion["issued_at"], "$.registry_assertion.issued_at")
    assertion_expires_at = parse_timestamp(registry_assertion["expires_at"], "$.registry_assertion.expires_at")
    _require(
        approved_at <= assertion_issued_at <= started_at,
        "TRIAL_PRECEDES_EXECUTION_AUTHORIZATION",
        "$.started_at",
        "trial must start after approval and trusted execution authorization",
    )
    _require(
        completed_at <= assertion_expires_at,
        "TRIAL_OUTLIVES_EXECUTION_AUTHORIZATION",
        "$.completed_at",
        "trial must complete before execution authorization expires",
    )

    acceptance = trial["acceptance"]
    decided_at = (
        parse_timestamp(acceptance["decided_at"], "$.acceptance.decided_at")
        if acceptance["decided_at"] is not None
        else None
    )
    if acceptance["status"] == "pending":
        _require(
            acceptance["actor_id"] is None and decided_at is None,
            "TRIAL_PENDING_ACCEPTANCE_INVALID",
            "$.acceptance",
            "pending acceptance cannot claim a decision actor or time",
        )
    else:
        _require(
            acceptance["actor_id"] is not None and decided_at is not None,
            "TRIAL_ACCEPTANCE_DECISION_MISSING",
            "$.acceptance",
            "a decided outcome requires actor and time",
        )
        _require(
            completed_at <= decided_at,
            "TRIAL_ACCEPTANCE_PRECEDES_COMPLETION",
            "$.acceptance.decided_at",
            "acceptance decision must follow agent completion",
        )

    human_questions = sum(question["answer_source"] == "human" for question in trial["agent_questions"])
    intervention = trial["reporter_intervention"]
    _require(
        intervention["questions_answered"] == human_questions,
        "TRIAL_INTERVENTION_MISMATCH",
        "$.reporter_intervention.questions_answered",
        "human-answer count must match the question records",
    )
    _require(
        intervention["interaction_count"] >= human_questions,
        "TRIAL_INTERVENTION_MISMATCH",
        "$.reporter_intervention.interaction_count",
        "interaction count cannot be lower than human-answer count",
    )

    if trial["result"] == "fixed":
        _require(bool(trial["changes"]), "TRIAL_FIXED_WITHOUT_CHANGES", "$.changes", "fixed requires changes")
        _require(bool(trial["tests"]), "TRIAL_FIXED_WITHOUT_TESTS", "$.tests", "fixed requires tests")
        _require(
            all(test["status"] == "passed" for test in trial["tests"]),
            "TRIAL_FIXED_WITH_FAILED_TESTS",
            "$.tests",
            "fixed requires every declared test to pass",
        )
        _require(bool(trial["evidence_used"]), "TRIAL_FIXED_WITHOUT_EVIDENCE", "$.evidence_used", "fixed requires evidence")
        _require(
            acceptance["status"] == "accepted",
            "TRIAL_FIXED_NOT_ACCEPTED",
            "$.acceptance.status",
            "fixed is reserved for an owner-accepted first-pass result",
        )
    elif trial["result"] in {"partial", "failed"}:
        _require(
            acceptance["status"] != "accepted",
            "TRIAL_RESULT_ACCEPTANCE_MISMATCH",
            "$.acceptance.status",
            "partial or failed work cannot be accepted",
        )
    else:
        _require(
            not trial["changes"] and not trial["tests"] and not trial["evidence_used"],
            "TRIAL_NOT_STARTED_HAS_ACTIVITY",
            "$",
            "not_started cannot contain changes, tests, or used evidence",
        )
    _validate_digest(trial["trial_digest"], digest_without(trial, "trial_digest"), "$.trial_digest")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("DUPLICATE_JSON_KEY", "$", f"duplicate property {key!r}")
        result[key] = value
    return result


def load_json(path: Path, *, require_canonical: bool = False) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except ContractError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError("INVALID_JSON", str(path), str(error)) from error
    _require(isinstance(value, dict), "SCHEMA_TYPE", "$", "top-level JSON must be an object")
    if require_canonical:
        _require(
            raw == canonical_json_artifact(value),
            "NON_CANONICAL_JSON_ARTIFACT",
            str(path),
            "downloaded/executable JSON must exactly equal Tacua Canonical JSON v1 bytes",
        )
    return value


def load_registry_key(path: Path) -> bytes:
    try:
        encoded = path.read_text(encoding="ascii").strip()
        key = bytes.fromhex(encoded)
    except (OSError, UnicodeError, ValueError) as error:
        raise ContractError("INVALID_REGISTRY_KEY", str(path), "expected an external hex-encoded key") from error
    _require(len(key) >= 32, "REGISTRY_KEY_TOO_SHORT", str(path), "registry HMAC key must be at least 32 bytes")
    return key
