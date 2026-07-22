# SPDX-License-Identifier: Apache-2.0
"""Strict portable validation for atomic reviewer split/merge operations."""

from __future__ import annotations

import unicodedata
from typing import Any

from ticket_candidate_contract import (
    ContractError,
    FORBIDDEN_KEYS,
    MAX_ARTIFACT_BYTES,
    MAX_SAFE_INTEGER,
    SCHEMAS,
    SECRET_PATTERNS,
    canonical_json,
    canonical_json_artifact,
    validate as validate_candidate,
    walk,
)


REQUEST_SCHEMA_FILE = "candidate-replacement-request.schema.json"
RESPONSE_SCHEMA_FILE = "candidate-replacement-response.schema.json"
MAX_REPLACEMENT_BYTES = 16_777_216


def _require(condition: bool, code: str, path: str, detail: str) -> None:
    if not condition:
        raise ContractError(code, path, detail)


def _validate_payload_basics(value: Any) -> None:
    _require(isinstance(value, dict), "ROOT_TYPE", "$", "replacement payload must be an object")
    try:
        size = len(canonical_json_artifact(value))
    except (TypeError, ValueError) as exc:
        raise ContractError("INVALID_JSON_VALUE", "$", str(exc)) from exc
    _require(
        size <= MAX_REPLACEMENT_BYTES,
        "ARTIFACT_TOO_LARGE",
        "$",
        "replacement payload exceeds 16 MiB",
    )
    for path, child in walk(value):
        if isinstance(child, float):
            raise ContractError("FLOAT_FORBIDDEN", path, "replacement contracts use integer JSON")
        if isinstance(child, int) and not isinstance(child, bool):
            _require(
                abs(child) <= MAX_SAFE_INTEGER,
                "UNSAFE_INTEGER",
                path,
                "integer exceeds interoperable range",
            )
        if isinstance(child, str):
            _require(
                unicodedata.normalize("NFC", child) == child,
                "NON_NFC_STRING",
                path,
                "string must be NFC",
            )
            _require("\x00" not in child, "CONTROL_CHARACTER", path, "NUL is forbidden")
            for pattern in SECRET_PATTERNS:
                if pattern.search(child):
                    raise ContractError(
                        "SECRET_VALUE_DETECTED",
                        path,
                        "credential-like value is forbidden",
                    )
        if isinstance(child, dict):
            for key in child:
                if key.lower() in FORBIDDEN_KEYS:
                    raise ContractError(
                        "SECRET_FIELD_FORBIDDEN",
                        f"{path}.{key}",
                        "credential-bearing fields are forbidden",
                    )


def _validate_cardinality(operation: str, sources: list[Any], results: list[Any]) -> None:
    expected = (len(sources) == 1 and 2 <= len(results) <= 16) if operation == "split" else (
        2 <= len(sources) <= 16 and len(results) == 1
    )
    _require(
        expected,
        "REPLACEMENT_CARDINALITY",
        "$",
        "split requires 1→2..16 and merge requires 2..16→1",
    )


def _require_unique_ids(items: list[dict[str, Any]], path: str) -> set[str]:
    identifiers = [item["candidate_id"] for item in items]
    _require(
        len(identifiers) == len(set(identifiers)),
        "DUPLICATE_CANDIDATE_ID",
        path,
        "candidate IDs must be unique",
    )
    return set(identifiers)


def validate_replacement_request(request: dict[str, Any]) -> None:
    """Validate one exact, human-authored atomic replacement request body."""

    _validate_payload_basics(request)
    SCHEMAS.validate(request, REQUEST_SCHEMA_FILE)
    operation = request["operation"]
    sources = request["sources"]
    results = request["results"]
    _validate_cardinality(operation, sources, results)
    source_ids = _require_unique_ids(sources, "$.sources")
    result_ids = _require_unique_ids(results, "$.results")
    _require(
        source_ids.isdisjoint(result_ids),
        "SOURCE_RESULT_ID_COLLISION",
        "$.results",
        "replacement results must use new candidate IDs",
    )
    source_digests = [item["candidate_digest"] for item in sources]
    _require(
        len(source_digests) == len(set(source_digests)),
        "DUPLICATE_SOURCE_DIGEST",
        "$.sources",
        "source candidate digests must be unique",
    )
    result_content = [canonical_json(item["content"]) for item in results]
    _require(
        len(result_content) == len(set(result_content)),
        "DUPLICATE_RESULT_CONTENT",
        "$.results",
        "replacement result content must be distinct",
    )
    for index, content in enumerate(result_content):
        _require(
            len(content.encode("utf-8")) + 1 <= MAX_ARTIFACT_BYTES,
            "RESULT_CONTENT_TOO_LARGE",
            f"$.results[{index}].content",
            "one result content document exceeds 1 MiB",
        )


def validate_replacement_response(
    response: dict[str, Any],
    *,
    request: dict[str, Any] | None = None,
) -> None:
    """Validate a committed operation record and its exact new candidate heads."""

    _validate_payload_basics(response)
    SCHEMAS.validate(response, RESPONSE_SCHEMA_FILE)
    operation = response["operation"]
    candidates = response["candidates"]
    sources = operation["sources"]
    results = operation["results"]
    _validate_cardinality(operation["operation"], sources, results)
    source_ids = _require_unique_ids(sources, "$.operation.sources")
    result_ids = _require_unique_ids(results, "$.operation.results")
    _require(
        source_ids.isdisjoint(result_ids),
        "SOURCE_RESULT_ID_COLLISION",
        "$.operation.results",
        "replacement results must use new candidate IDs",
    )
    _require(
        len(candidates) == len(results),
        "RESULT_CANDIDATE_MISMATCH",
        "$.candidates",
        "operation results and candidate snapshots differ in count",
    )
    _require(
        [candidate["candidate_id"] for candidate in candidates]
        == [result["candidate_id"] for result in results],
        "RESULT_CANDIDATE_MISMATCH",
        "$.candidates",
        "candidate snapshots must preserve operation result order",
    )

    parent_refs = [
        {
            "candidate_id": source["candidate_id"],
            "candidate_version": source["candidate_version"],
            "candidate_digest": source["candidate_digest"],
        }
        for source in sources
    ]
    lineage_operation = "split" if operation["operation"] == "split" else "merged"
    common_scope: tuple[Any, ...] | None = None
    for index, (binding, candidate) in enumerate(zip(results, candidates, strict=True)):
        validate_candidate(candidate)
        expected_binding = {
            "candidate_id": candidate["candidate_id"],
            "candidate_version": candidate["candidate_version"],
            "candidate_digest": candidate["candidate_digest"],
            "candidate_content_digest": candidate["candidate_content_digest"],
            "evidence_manifest_digest": candidate["evidence_manifest"]["manifest_digest"],
        }
        _require(
            binding == expected_binding,
            "RESULT_BINDING_MISMATCH",
            f"$.operation.results[{index}]",
            "result binding differs from its candidate snapshot",
        )
        _require(
            candidate["candidate_version"] == 1
            and candidate["previous_candidate_digest"] is None
            and candidate["state"] == "draft",
            "RESULT_NOT_NEW_DRAFT",
            f"$.candidates[{index}]",
            "replacement result must be a first-version draft",
        )
        _require(
            candidate["lineage"]
            == {"operation": lineage_operation, "parents": parent_refs},
            "REPLACEMENT_LINEAGE_MISMATCH",
            f"$.candidates[{index}].lineage",
            "candidate lineage differs from the operation sources",
        )
        transition = candidate["transition"]
        _require(
            transition["actor"]
            == {"actor_type": "human", "actor_id": operation["actor_id"]}
            and transition["occurred_at"] == operation["occurred_at"],
            "REPLACEMENT_ACTOR_MISMATCH",
            f"$.candidates[{index}].transition",
            "candidate creation actor/time differs from the operation",
        )
        _require(
            candidate["candidate_created_at"] == operation["occurred_at"]
            and candidate["version_created_at"] == operation["occurred_at"],
            "REPLACEMENT_TIME_MISMATCH",
            f"$.candidates[{index}]",
            "candidate creation time differs from the operation",
        )
        if operation["operation"] == "split":
            _require(
                candidate["evidence_manifest"]["manifest_digest"]
                == sources[0]["evidence_manifest_digest"],
                "SPLIT_EVIDENCE_MISMATCH",
                f"$.candidates[{index}].evidence_manifest",
                "split result must reuse the source evidence manifest",
            )
        scope = (
            candidate["organization_id"],
            candidate["project_id"],
            candidate["build_id"],
            candidate["build_identity_digest"],
            candidate["session_id"],
        )
        if common_scope is None:
            common_scope = scope
        _require(
            scope == common_scope,
            "RESULT_SCOPE_MISMATCH",
            f"$.candidates[{index}]",
            "replacement results must share one capture/build scope",
        )

    if request is not None:
        validate_replacement_request(request)
        _require(
            operation["operation"] == request["operation"]
            and operation["actor_id"] == request["actor_id"]
            and sources == request["sources"],
            "REQUEST_RESPONSE_BINDING_MISMATCH",
            "$.operation",
            "committed operation differs from the exact request",
        )
        _require(
            [result["candidate_id"] for result in request["results"]]
            == [result["candidate_id"] for result in results],
            "REQUEST_RESPONSE_BINDING_MISMATCH",
            "$.operation.results",
            "committed result IDs differ from the request",
        )
        for index, (requested, candidate) in enumerate(
            zip(request["results"], candidates, strict=True)
        ):
            _require(
                candidate["transition"]["reason"] == request["reason"],
                "REQUEST_RESPONSE_BINDING_MISMATCH",
                f"$.candidates[{index}].transition.reason",
                "committed candidate reason differs from the request",
            )
            _require(
                requested["content"] == candidate["content"],
                "REQUEST_RESPONSE_CONTENT_MISMATCH",
                f"$.candidates[{index}].content",
                "committed candidate content differs from the request",
            )


def canonical_replacement_artifact(value: dict[str, Any]) -> bytes:
    """Return the canonical on-disk form after validation by the caller."""

    return canonical_json_artifact(value)
