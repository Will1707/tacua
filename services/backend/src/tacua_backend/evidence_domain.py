# SPDX-License-Identifier: Apache-2.0
"""Immutable pre-approval evidence and bounded derived image previews.

Candidate evidence is visible to an authenticated reviewer, but is not yet
authorized for agent handoff. This contract therefore has no authorization
field. Approval/export must create and seal a separate authorized evidence
manifest. The caller owns the SQLite connection; this module never owns global
database lifecycle.
"""

from __future__ import annotations

import copy
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import unicodedata
import uuid
from typing import Any, Callable, Iterator, Mapping


MANIFEST_VERSION = "tacua.candidate-evidence-manifest@1.0.0"
MANIFEST_MEDIA_TYPE = (
    "application/vnd.tacua.candidate-evidence-manifest+json;version=1.0.0"
)
ITEM_VERSION = "tacua.candidate-evidence-item@1.0.0"
MAX_MANIFEST_BYTES = 1_048_576
MAX_PREVIEW_BYTES = 2_097_152
PREVIEW_MIME_TYPES = frozenset({"image/png", "image/jpeg", "image/webp"})
_JOURNAL_DISCARD_PREVIEW = "discard_uncommitted_preview"
_JOURNAL_DELETE_PREVIEW = "delete_committed_preview"
_JOURNAL_PRUNE_SESSION_TREE = "prune_session_tree"

_ID = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_TYPES = frozenset(
    {
        "sdk.route_transition",
        "sdk.user_interaction",
        "sdk.runtime_error",
        "sdk.network_metadata",
        "sdk.trace_correlation",
        "sdk.app_state_provider",
        "sdk.capture_gap",
        "media.keyframe",
        "media.clip",
        "media.transcript_excerpt",
        "repository.commit_snapshot",
        "backend.deployment_snapshot",
        "backend.log_snapshot",
        "backend.trace_snapshot",
        "observability.sentry_snapshot",
        "observability.posthog_snapshot",
    }
)
_SOURCE_FOR_PREFIX = {
    "sdk.": "mobile_sdk",
    "media.": "mobile_sdk",
    "repository.": "repository",
    "backend.": "backend",
    "observability.sentry_": "sentry",
    "observability.posthog_": "posthog",
}
_SOURCES = frozenset({"mobile_sdk", "backend", "repository", "sentry", "posthog"})
_REFERENCE_TYPES = frozenset(
    {
        "application/json",
        "text/plain",
        "image/png",
        "video/quicktime",
        "application/vnd.tacua.sdk-event+json",
        "application/vnd.tacua.connector-snapshot+json",
    }
)
_UNAVAILABLE = frozenset(
    {
        "capture_gap",
        "collection_disabled",
        "permission_denied",
        "provider_unavailable",
        "connector_revoked",
        "redacted_by_policy",
        "not_configured",
        "outside_retention",
        "correlation_missing",
    }
)
_SECRET_KEYS = frozenset(
    {
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
)
_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"\b(?:gh[opusr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
_MANIFEST_FIELDS = frozenset(
    {
        "contract_version",
        "media_type",
        "organization_id",
        "project_id",
        "session_id",
        "manifest_id",
        "items",
        "manifest_digest",
    }
)
_ITEM_FIELDS = frozenset(
    {
        "contract_version",
        "organization_id",
        "project_id",
        "session_id",
        "evidence_id",
        "evidence_type",
        "availability",
        "description",
        "time_range",
        "source",
        "reference",
        "unavailable",
        "evidence_item_digest",
    }
)
_SOURCE_FIELDS = frozenset(
    {"component", "source_id", "snapshot_revision", "captured_at"}
)
_RANGE_FIELDS = frozenset({"start_ms", "end_ms", "clock"})
_REFERENCE_FIELDS = frozenset(
    {"locator", "content_type", "size_bytes", "content_digest"}
)
_LOCATOR_FIELDS = frozenset(
    {"scheme", "organization_id", "project_id", "evidence_id", "revision_id"}
)
_UNAVAILABLE_FIELDS = frozenset({"reason", "detail"})


class EvidenceDomainError(ValueError):
    """Stable failure suitable for translation at the HTTP boundary."""

    def __init__(self, code: str, path: str, detail: str):
        self.code = code
        self.path = path
        self.detail = detail
        super().__init__(f"{code} at {path}: {detail}")


def _require(condition: bool, code: str, path: str, detail: str) -> None:
    if not condition:
        raise EvidenceDomainError(code, path, detail)


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise EvidenceDomainError(
            "NON_CANONICAL_JSON", "$", "value is not finite canonical JSON"
        ) from error


def sha256_digest(payload: bytes | str) -> str:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def digest_without(value: Mapping[str, Any], field: str) -> str:
    subject = copy.deepcopy(dict(value))
    subject.pop(field, None)
    return sha256_digest(canonical_json(subject))


def seal_item(item: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(item))
    result["evidence_item_digest"] = digest_without(result, "evidence_item_digest")
    return result


def seal_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(manifest))
    _require(
        isinstance(result.get("items"), list),
        "FIELDS_INVALID",
        "$.items",
        "items must be an array",
    )
    result["items"] = [seal_item(item) for item in result["items"]]
    result["manifest_digest"] = digest_without(result, "manifest_digest")
    return result


def _object(value: Any, fields: frozenset[str], path: str) -> dict[str, Any]:
    _require(isinstance(value, dict), "FIELD_TYPE_INVALID", path, "expected an object")
    _require(
        set(value) == fields,
        "FIELDS_INVALID",
        path,
        f"expected exactly {sorted(fields)!r}",
    )
    return value


def _identifier(value: Any, path: str) -> str:
    _require(
        isinstance(value, str) and _ID.fullmatch(value) is not None,
        "IDENTIFIER_INVALID",
        path,
        "expected a lowercase Tacua identifier",
    )
    return value


def _digest(value: Any, path: str) -> str:
    _require(
        isinstance(value, str) and _DIGEST.fullmatch(value) is not None,
        "DIGEST_INVALID",
        path,
        "expected sha256:<64 lowercase hexadecimal characters>",
    )
    return value


def _integer(value: Any, path: str, minimum: int, maximum: int) -> int:
    _require(
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum,
        "INTEGER_INVALID",
        path,
        f"expected an integer from {minimum} through {maximum}",
    )
    return value


def _text(value: Any, path: str, minimum: int, maximum: int) -> str:
    _require(
        isinstance(value, str) and minimum <= len(value) <= maximum,
        "TEXT_INVALID",
        path,
        f"expected text from {minimum} through {maximum} characters",
    )
    _require(
        unicodedata.normalize("NFC", value) == value,
        "NON_CANONICAL_UNICODE",
        path,
        "text must use Unicode NFC",
    )
    _require("\x00" not in value, "CONTROL_CHARACTER", path, "NUL is forbidden")
    for pattern in _SECRET_PATTERNS:
        _require(
            pattern.search(value) is None,
            "SECRET_VALUE_DETECTED",
            path,
            "credential-like text is forbidden",
        )
    return value


def _no_secrets(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            _require(
                normalized not in _SECRET_KEYS,
                "SECRET_FIELD_FORBIDDEN",
                f"{path}.{key}",
                "credential-bearing fields are forbidden",
            )
            _no_secrets(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _no_secrets(child, f"{path}[{index}]")
    elif isinstance(value, str):
        _text(value, path, 0, max(1, len(value)))


def _timestamp(value: Any, path: str) -> str:
    _require(
        isinstance(value, str) and _TIMESTAMP.fullmatch(value) is not None,
        "TIMESTAMP_INVALID",
        path,
        "expected a whole-second UTC RFC 3339 timestamp",
    )
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise EvidenceDomainError(
            "TIMESTAMP_INVALID", path, "timestamp is not a real UTC second"
        ) from error
    return value


def validate_item(
    item: Any,
    *,
    organization_id: str | None = None,
    project_id: str | None = None,
    session_id: str | None = None,
) -> None:
    item = _object(item, _ITEM_FIELDS, "$")
    _no_secrets(item)
    _require(
        item["contract_version"] == ITEM_VERSION,
        "CONTRACT_VERSION_INVALID",
        "$.contract_version",
        "expected the pre-approval item contract",
    )
    for field, expected in (
        ("organization_id", organization_id),
        ("project_id", project_id),
        ("session_id", session_id),
    ):
        actual = _identifier(item[field], f"$.{field}")
        if expected is not None:
            _require(
                actual == expected,
                "EVIDENCE_SCOPE_MISMATCH",
                f"$.{field}",
                "item is outside the manifest scope",
            )
    evidence_id = _identifier(item["evidence_id"], "$.evidence_id")
    evidence_type = item["evidence_type"]
    _require(
        isinstance(evidence_type, str) and evidence_type in _TYPES,
        "EVIDENCE_TYPE_INVALID",
        "$.evidence_type",
        "evidence type is outside the closed candidate-review set",
    )
    availability = item["availability"]
    _require(
        availability in {"available", "unavailable"},
        "AVAILABILITY_INVALID",
        "$.availability",
        "expected available or unavailable",
    )
    _text(item["description"], "$.description", 1, 2048)

    time_range = item["time_range"]
    if time_range is not None:
        time_range = _object(time_range, _RANGE_FIELDS, "$.time_range")
        start = _integer(
            time_range["start_ms"], "$.time_range.start_ms", 0, 9_007_199_254_740_991
        )
        end = _integer(
            time_range["end_ms"], "$.time_range.end_ms", 0, 9_007_199_254_740_991
        )
        _require(
            start <= end,
            "TIME_RANGE_REVERSED",
            "$.time_range",
            "start_ms must not exceed end_ms",
        )
        _require(
            time_range["clock"] == "session_monotonic",
            "CLOCK_INVALID",
            "$.time_range.clock",
            "expected the session monotonic clock",
        )

    source = _object(item["source"], _SOURCE_FIELDS, "$.source")
    _require(
        source["component"] in _SOURCES,
        "SOURCE_COMPONENT_INVALID",
        "$.source.component",
        "unknown source component",
    )
    _identifier(source["source_id"], "$.source.source_id")
    _text(source["snapshot_revision"], "$.source.snapshot_revision", 1, 128)
    _timestamp(source["captured_at"], "$.source.captured_at")
    for prefix, expected_component in _SOURCE_FOR_PREFIX.items():
        if evidence_type.startswith(prefix):
            _require(
                source["component"] == expected_component,
                "SOURCE_TYPE_MISMATCH",
                "$.source.component",
                "source component does not match the evidence type",
            )
            break

    if availability == "available":
        reference = _object(item["reference"], _REFERENCE_FIELDS, "$.reference")
        locator = _object(reference["locator"], _LOCATOR_FIELDS, "$.reference.locator")
        _require(
            locator["scheme"] == "tacua-evidence",
            "LOCATOR_SCHEME_INVALID",
            "$.reference.locator.scheme",
            "expected a Tacua evidence locator",
        )
        for field in ("organization_id", "project_id", "evidence_id"):
            _identifier(locator[field], f"$.reference.locator.{field}")
            _require(
                locator[field] == item[field],
                "REFERENCE_SCOPE_MISMATCH",
                f"$.reference.locator.{field}",
                "locator scope must match the evidence item",
            )
        _identifier(locator["revision_id"], "$.reference.locator.revision_id")
        _require(
            reference["content_type"] in _REFERENCE_TYPES,
            "REFERENCE_CONTENT_TYPE_INVALID",
            "$.reference.content_type",
            "unsupported reference content type",
        )
        _integer(reference["size_bytes"], "$.reference.size_bytes", 0, 104_857_600)
        _digest(reference["content_digest"], "$.reference.content_digest")
        _require(
            item["unavailable"] is None,
            "AVAILABILITY_FIELDS_INVALID",
            "$.unavailable",
            "available evidence cannot have an unavailable reason",
        )
    else:
        _require(
            item["reference"] is None,
            "AVAILABILITY_FIELDS_INVALID",
            "$.reference",
            "unavailable evidence cannot expose a reference",
        )
        unavailable = _object(
            item["unavailable"], _UNAVAILABLE_FIELDS, "$.unavailable"
        )
        _require(
            unavailable["reason"] in _UNAVAILABLE,
            "UNAVAILABLE_REASON_INVALID",
            "$.unavailable.reason",
            "unknown unavailability reason",
        )
        _text(unavailable["detail"], "$.unavailable.detail", 1, 512)

    item_digest = _digest(item["evidence_item_digest"], "$.evidence_item_digest")
    _require(
        item_digest == digest_without(item, "evidence_item_digest"),
        "EVIDENCE_ITEM_DIGEST_MISMATCH",
        "$.evidence_item_digest",
        "item metadata changed after sealing",
    )


def validate_manifest(manifest: Any) -> None:
    manifest = _object(manifest, _MANIFEST_FIELDS, "$")
    _no_secrets(manifest)
    _require(
        manifest["contract_version"] == MANIFEST_VERSION,
        "CONTRACT_VERSION_INVALID",
        "$.contract_version",
        "expected the pre-approval manifest contract",
    )
    _require(
        manifest["media_type"] == MANIFEST_MEDIA_TYPE,
        "MEDIA_TYPE_INVALID",
        "$.media_type",
        "expected the pre-approval manifest media type",
    )
    organization_id = _identifier(manifest["organization_id"], "$.organization_id")
    project_id = _identifier(manifest["project_id"], "$.project_id")
    session_id = _identifier(manifest["session_id"], "$.session_id")
    _identifier(manifest["manifest_id"], "$.manifest_id")
    items = manifest["items"]
    _require(
        isinstance(items, list) and 1 <= len(items) <= 100,
        "MANIFEST_ITEMS_INVALID",
        "$.items",
        "expected from 1 through 100 evidence items",
    )
    evidence_ids: set[str] = set()
    for index, item in enumerate(items):
        try:
            validate_item(
                item,
                organization_id=organization_id,
                project_id=project_id,
                session_id=session_id,
            )
        except EvidenceDomainError as error:
            suffix = error.path[1:] if error.path.startswith("$") else "." + error.path
            raise EvidenceDomainError(
                error.code, f"$.items[{index}]{suffix}", error.detail
            ) from error
        evidence_id = item["evidence_id"]
        _require(
            evidence_id not in evidence_ids,
            "DUPLICATE_EVIDENCE_ID",
            f"$.items[{index}].evidence_id",
            "evidence IDs must be unique",
        )
        evidence_ids.add(evidence_id)
    _require(
        any(item["availability"] == "available" for item in items),
        "NO_AVAILABLE_EVIDENCE",
        "$.items",
        "candidate review requires at least one available reference",
    )
    manifest_digest = _digest(manifest["manifest_digest"], "$.manifest_digest")
    _require(
        manifest_digest == digest_without(manifest, "manifest_digest"),
        "MANIFEST_DIGEST_MISMATCH",
        "$.manifest_digest",
        "manifest metadata changed after sealing",
    )
    _require(
        len(canonical_json(manifest).encode("utf-8")) <= MAX_MANIFEST_BYTES,
        "MANIFEST_TOO_LARGE",
        "$",
        "canonical manifest exceeds 1 MiB",
    )


@contextmanager
def _savepoint(connection: sqlite3.Connection) -> Iterator[None]:
    name = "tacua_evidence_" + uuid.uuid4().hex
    connection.execute(f"SAVEPOINT {name}")
    try:
        yield
    except BaseException:
        connection.execute(f"ROLLBACK TO SAVEPOINT {name}")
        connection.execute(f"RELEASE SAVEPOINT {name}")
        raise
    else:
        connection.execute(f"RELEASE SAVEPOINT {name}")


@contextmanager
def _durable_transaction(connection: sqlite3.Connection) -> Iterator[None]:
    """Own one SQLite commit boundary for a filesystem-coordinated phase.

    A caller transaction cannot be safely composed with a filesystem mutation:
    rolling it back after a file was created or removed would resurrect the
    opposite half of the operation. Filesystem methods therefore use explicit,
    top-level phases and reject nesting.
    """

    _require(
        not connection.in_transaction,
        "EVIDENCE_TRANSACTION_ACTIVE",
        "$",
        "filesystem evidence operations require a standalone database boundary",
    )
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Create evidence tables on a caller-owned SQLite connection."""

    statements = (
        """
        CREATE TABLE IF NOT EXISTS tacua_evidence_schema (
            schema_version INTEGER PRIMARY KEY CHECK (schema_version = 1)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS tacua_evidence_manifests (
            manifest_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            manifest_id TEXT NOT NULL,
            manifest_digest TEXT NOT NULL,
            manifest_json TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            UNIQUE (organization_id, project_id, session_id, manifest_id),
            UNIQUE (organization_id, project_id, session_id, manifest_digest)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS tacua_evidence_items (
            item_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            revision_id TEXT NOT NULL,
            item_digest TEXT NOT NULL,
            item_json TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            UNIQUE (organization_id, project_id, session_id, evidence_id, revision_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS tacua_evidence_manifest_items (
            manifest_row_id INTEGER NOT NULL,
            position INTEGER NOT NULL,
            item_row_id INTEGER NOT NULL,
            PRIMARY KEY (manifest_row_id, position),
            UNIQUE (manifest_row_id, item_row_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS tacua_candidate_evidence_bindings (
            binding_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            candidate_id TEXT NOT NULL,
            candidate_version INTEGER NOT NULL CHECK (candidate_version >= 1),
            candidate_digest TEXT NOT NULL,
            manifest_row_id INTEGER NOT NULL,
            manifest_digest TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            UNIQUE (organization_id, project_id, session_id, candidate_id, candidate_version),
            UNIQUE (organization_id, project_id, session_id, candidate_digest)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS tacua_evidence_preview_revisions (
            preview_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
            manifest_row_id INTEGER NOT NULL,
            item_row_id INTEGER NOT NULL,
            preview_revision_id TEXT NOT NULL,
            availability TEXT NOT NULL CHECK (availability IN ('available', 'unavailable')),
            content_type TEXT,
            size_bytes INTEGER,
            content_digest TEXT,
            relative_path TEXT,
            unavailable_reason TEXT,
            unavailable_detail TEXT,
            recorded_at TEXT NOT NULL,
            UNIQUE (manifest_row_id, item_row_id, preview_revision_id),
            CHECK (
                (availability = 'available' AND content_type IS NOT NULL AND
                 size_bytes IS NOT NULL AND content_digest IS NOT NULL AND
                 relative_path IS NOT NULL AND unavailable_reason IS NULL AND
                 unavailable_detail IS NULL)
                OR
                (availability = 'unavailable' AND content_type IS NULL AND
                 size_bytes IS NULL AND content_digest IS NULL AND
                 relative_path IS NULL AND unavailable_reason IS NOT NULL AND
                 unavailable_detail IS NOT NULL)
            )
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS tacua_evidence_file_journal (
            journal_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
            operation_id TEXT NOT NULL,
            disposition TEXT NOT NULL CHECK (
                disposition IN (
                    'discard_uncommitted_preview',
                    'delete_committed_preview'
                )
            ),
            relative_path TEXT NOT NULL UNIQUE,
            staging_relative_path TEXT,
            content_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL CHECK (
                size_bytes >= 1 AND size_bytes <= 2097152
            ),
            content_digest TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            UNIQUE (operation_id, relative_path)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS tacua_evidence_directory_journal (
            journal_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
            operation_id TEXT NOT NULL,
            disposition TEXT NOT NULL CHECK (
                disposition = 'prune_session_tree'
            ),
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            relative_path TEXT NOT NULL UNIQUE,
            recorded_at TEXT NOT NULL,
            UNIQUE (operation_id, relative_path)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS tacua_evidence_audit (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            occurred_at TEXT NOT NULL,
            action TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            candidate_id TEXT,
            candidate_version INTEGER,
            candidate_digest TEXT,
            manifest_digest TEXT,
            evidence_id TEXT,
            item_digest TEXT,
            preview_digest TEXT,
            reason_code TEXT
        )
        """,
        "CREATE INDEX IF NOT EXISTS tacua_evidence_bindings_session_idx ON tacua_candidate_evidence_bindings (organization_id, project_id, session_id)",
        "CREATE INDEX IF NOT EXISTS tacua_evidence_previews_item_idx ON tacua_evidence_preview_revisions (manifest_row_id, item_row_id, preview_row_id)",
        "CREATE INDEX IF NOT EXISTS tacua_evidence_file_journal_operation_idx ON tacua_evidence_file_journal (operation_id, journal_row_id)",
        "CREATE INDEX IF NOT EXISTS tacua_evidence_directory_journal_operation_idx ON tacua_evidence_directory_journal (operation_id, journal_row_id)",
    )
    with _savepoint(connection):
        for statement in statements:
            connection.execute(statement)
        connection.execute(
            "INSERT OR IGNORE INTO tacua_evidence_schema (schema_version) VALUES (1)"
        )
        versions = connection.execute(
            "SELECT schema_version FROM tacua_evidence_schema ORDER BY schema_version"
        ).fetchall()
        _require(
            [tuple(row) for row in versions] == [(1,)],
            "EVIDENCE_SCHEMA_VERSION_INVALID",
            "$",
            "unsupported evidence schema version",
        )


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _item_revision(item: Mapping[str, Any]) -> str:
    if item["reference"] is not None:
        return "reference:" + item["reference"]["locator"]["revision_id"]
    return "source:" + item["source"]["snapshot_revision"]


def _signature(content_type: str, body: bytes) -> None:
    valid = False
    if content_type == "image/png":
        valid = body.startswith(b"\x89PNG\r\n\x1a\n")
    elif content_type == "image/jpeg":
        valid = (
            len(body) >= 4
            and body.startswith(b"\xff\xd8\xff")
            and body.endswith(b"\xff\xd9")
        )
    elif content_type == "image/webp":
        valid = (
            len(body) >= 12
            and body.startswith(b"RIFF")
            and body[8:12] == b"WEBP"
        )
    _require(
        valid,
        "PREVIEW_SIGNATURE_MISMATCH",
        "$.body",
        "image signature does not match the declared MIME type",
    )


class EvidenceStore:
    """Append-only candidate evidence with integration-ready read methods."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        derived_evidence_root: str | os.PathLike[str],
    ):
        self.connection = connection
        requested = Path(derived_evidence_root)
        if requested.exists() and requested.is_symlink():
            raise EvidenceDomainError(
                "EVIDENCE_ROOT_SYMLINK",
                "$.derived_evidence_root",
                "derived evidence root cannot be a symbolic link",
            )
        requested.mkdir(mode=0o700, parents=True, exist_ok=True)
        _require(
            requested.is_dir() and not requested.is_symlink(),
            "EVIDENCE_ROOT_INVALID",
            "$.derived_evidence_root",
            "derived evidence root must be a real directory",
        )
        self.root = requested.resolve(strict=True)

    def _schema(self) -> None:
        try:
            row = self.connection.execute(
                "SELECT schema_version FROM tacua_evidence_schema"
            ).fetchone()
        except sqlite3.Error as error:
            raise EvidenceDomainError(
                "EVIDENCE_SCHEMA_MISSING", "$", "call initialize_schema first"
            ) from error
        _require(
            row is not None and tuple(row) == (1,),
            "EVIDENCE_SCHEMA_VERSION_INVALID",
            "$",
            "unsupported evidence schema version",
        )

    def _audit(
        self,
        action: str,
        *,
        organization_id: str,
        project_id: str,
        session_id: str,
        candidate_id: str | None = None,
        candidate_version: int | None = None,
        candidate_digest: str | None = None,
        manifest_digest: str | None = None,
        evidence_id: str | None = None,
        item_digest: str | None = None,
        preview_digest: str | None = None,
        reason_code: str | None = None,
    ) -> None:
        # Fixed content-free columns only: never bodies, descriptions, paths,
        # connector values, unavailable details, credentials, or secrets.
        self.connection.execute(
            """
            INSERT INTO tacua_evidence_audit (
                occurred_at, action, organization_id, project_id, session_id,
                candidate_id, candidate_version, candidate_digest,
                manifest_digest, evidence_id, item_digest, preview_digest,
                reason_code
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _now(),
                action,
                organization_id,
                project_id,
                session_id,
                candidate_id,
                candidate_version,
                candidate_digest,
                manifest_digest,
                evidence_id,
                item_digest,
                preview_digest,
                reason_code,
            ),
        )

    @staticmethod
    def _binding_values(
        organization_id: Any,
        project_id: Any,
        session_id: Any,
        candidate_id: Any,
        candidate_version: Any,
        candidate_digest: Any,
        manifest_digest: Any,
    ) -> None:
        _identifier(organization_id, "$.organization_id")
        _identifier(project_id, "$.project_id")
        _identifier(session_id, "$.session_id")
        _identifier(candidate_id, "$.candidate_id")
        _integer(candidate_version, "$.candidate_version", 1, 9_007_199_254_740_991)
        _digest(candidate_digest, "$.candidate_digest")
        _digest(manifest_digest, "$.manifest_digest")

    def put_manifest(
        self,
        *,
        organization_id: str,
        project_id: str,
        session_id: str,
        candidate_id: str,
        candidate_version: int,
        candidate_digest: str,
        manifest: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Append a full pre-approval manifest and bind one exact candidate."""

        self._schema()
        validate_manifest(manifest)
        manifest_json = canonical_json(manifest)
        manifest_digest = manifest["manifest_digest"]
        self._binding_values(
            organization_id,
            project_id,
            session_id,
            candidate_id,
            candidate_version,
            candidate_digest,
            manifest_digest,
        )
        for field, expected in (
            ("organization_id", organization_id),
            ("project_id", project_id),
            ("session_id", session_id),
        ):
            _require(
                manifest[field] == expected,
                "EVIDENCE_SCOPE_MISMATCH",
                f"$.manifest.{field}",
                "manifest does not match the candidate binding",
            )

        created_manifest = False
        created_binding = False
        with _savepoint(self.connection):
            row = self.connection.execute(
                """
                SELECT manifest_row_id, manifest_digest, manifest_json
                  FROM tacua_evidence_manifests
                 WHERE organization_id = ? AND project_id = ? AND session_id = ?
                   AND manifest_id = ?
                """,
                (
                    organization_id,
                    project_id,
                    session_id,
                    manifest["manifest_id"],
                ),
            ).fetchone()
            if row is None:
                cursor = self.connection.execute(
                    """
                    INSERT INTO tacua_evidence_manifests (
                        organization_id, project_id, session_id, manifest_id,
                        manifest_digest, manifest_json, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        organization_id,
                        project_id,
                        session_id,
                        manifest["manifest_id"],
                        manifest_digest,
                        manifest_json,
                        _now(),
                    ),
                )
                manifest_row_id = int(cursor.lastrowid)
                created_manifest = True
                for position, item in enumerate(manifest["items"]):
                    item_json = canonical_json(item)
                    revision_id = _item_revision(item)
                    existing = self.connection.execute(
                        """
                        SELECT item_row_id, item_digest, item_json
                          FROM tacua_evidence_items
                         WHERE organization_id = ? AND project_id = ?
                           AND session_id = ? AND evidence_id = ?
                           AND revision_id = ?
                        """,
                        (
                            organization_id,
                            project_id,
                            session_id,
                            item["evidence_id"],
                            revision_id,
                        ),
                    ).fetchone()
                    if existing is None:
                        item_cursor = self.connection.execute(
                            """
                            INSERT INTO tacua_evidence_items (
                                organization_id, project_id, session_id,
                                evidence_id, revision_id, item_digest,
                                item_json, recorded_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                organization_id,
                                project_id,
                                session_id,
                                item["evidence_id"],
                                revision_id,
                                item["evidence_item_digest"],
                                item_json,
                                _now(),
                            ),
                        )
                        item_row_id = int(item_cursor.lastrowid)
                    else:
                        item_row_id = int(existing[0])
                        _require(
                            existing[1] == item["evidence_item_digest"]
                            and existing[2] == item_json,
                            "EVIDENCE_ITEM_REVISION_COLLISION",
                            f"$.manifest.items[{position}]",
                            "immutable item revision already has different metadata",
                        )
                    self.connection.execute(
                        """
                        INSERT INTO tacua_evidence_manifest_items
                            (manifest_row_id, position, item_row_id)
                        VALUES (?, ?, ?)
                        """,
                        (manifest_row_id, position, item_row_id),
                    )
                self._audit(
                    "manifest_appended",
                    organization_id=organization_id,
                    project_id=project_id,
                    session_id=session_id,
                    manifest_digest=manifest_digest,
                )
            else:
                manifest_row_id = int(row[0])
                _require(
                    row[1] == manifest_digest and row[2] == manifest_json,
                    "EVIDENCE_MANIFEST_REVISION_COLLISION",
                    "$.manifest",
                    "immutable manifest ID already has different metadata",
                )
                self._verify_membership(manifest_row_id, manifest)

            binding = self.connection.execute(
                """
                SELECT candidate_digest, manifest_row_id, manifest_digest
                  FROM tacua_candidate_evidence_bindings
                 WHERE organization_id = ? AND project_id = ? AND session_id = ?
                   AND candidate_id = ? AND candidate_version = ?
                """,
                (
                    organization_id,
                    project_id,
                    session_id,
                    candidate_id,
                    candidate_version,
                ),
            ).fetchone()
            if binding is None:
                try:
                    self.connection.execute(
                        """
                        INSERT INTO tacua_candidate_evidence_bindings (
                            organization_id, project_id, session_id, candidate_id,
                            candidate_version, candidate_digest, manifest_row_id,
                            manifest_digest, recorded_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            organization_id,
                            project_id,
                            session_id,
                            candidate_id,
                            candidate_version,
                            candidate_digest,
                            manifest_row_id,
                            manifest_digest,
                            _now(),
                        ),
                    )
                except sqlite3.IntegrityError as error:
                    raise EvidenceDomainError(
                        "CANDIDATE_EVIDENCE_COLLISION",
                        "$.candidate_digest",
                        "candidate digest is already bound in this session",
                    ) from error
                created_binding = True
                self._audit(
                    "candidate_evidence_bound",
                    organization_id=organization_id,
                    project_id=project_id,
                    session_id=session_id,
                    candidate_id=candidate_id,
                    candidate_version=candidate_version,
                    candidate_digest=candidate_digest,
                    manifest_digest=manifest_digest,
                )
            else:
                _require(
                    tuple(binding)
                    == (candidate_digest, manifest_row_id, manifest_digest),
                    "CANDIDATE_EVIDENCE_COLLISION",
                    "$.candidate_version",
                    "candidate version is already bound to different evidence",
                )

        return {
            "manifest_id": manifest["manifest_id"],
            "manifest_digest": manifest_digest,
            "evidence_ids": sorted(
                item["evidence_id"] for item in manifest["items"]
            ),
            "created_manifest": created_manifest,
            "created_binding": created_binding,
            "authorized_for_handoff": False,
        }

    def _verify_membership(
        self, manifest_row_id: int, manifest: Mapping[str, Any]
    ) -> None:
        rows = self.connection.execute(
            """
            SELECT mi.position, i.evidence_id, i.revision_id,
                   i.item_digest, i.item_json
              FROM tacua_evidence_manifest_items AS mi
              JOIN tacua_evidence_items AS i ON i.item_row_id = mi.item_row_id
             WHERE mi.manifest_row_id = ?
             ORDER BY mi.position
            """,
            (manifest_row_id,),
        ).fetchall()
        _require(
            len(rows) == len(manifest["items"]),
            "STORED_MANIFEST_TAMPERED",
            "$.items",
            "stored item membership count changed",
        )
        for position, row in enumerate(rows):
            item = manifest["items"][position]
            _require(
                tuple(row)
                == (
                    position,
                    item["evidence_id"],
                    _item_revision(item),
                    item["evidence_item_digest"],
                    canonical_json(item),
                ),
                "STORED_MANIFEST_TAMPERED",
                f"$.items[{position}]",
                "stored item membership or metadata changed",
            )

    def _resolve(
        self,
        *,
        organization_id: str,
        project_id: str,
        session_id: str,
        candidate_id: str,
        candidate_version: int,
        candidate_digest: str,
        manifest_digest: str,
    ) -> tuple[int, dict[str, Any]]:
        self._binding_values(
            organization_id,
            project_id,
            session_id,
            candidate_id,
            candidate_version,
            candidate_digest,
            manifest_digest,
        )
        row = self.connection.execute(
            """
            SELECT m.manifest_row_id, m.organization_id, m.project_id,
                   m.session_id, m.manifest_digest, m.manifest_json
              FROM tacua_candidate_evidence_bindings AS b
              JOIN tacua_evidence_manifests AS m
                ON m.manifest_row_id = b.manifest_row_id
             WHERE b.organization_id = ? AND b.project_id = ? AND b.session_id = ?
               AND b.candidate_id = ? AND b.candidate_version = ?
               AND b.candidate_digest = ? AND b.manifest_digest = ?
            """,
            (
                organization_id,
                project_id,
                session_id,
                candidate_id,
                candidate_version,
                candidate_digest,
                manifest_digest,
            ),
        ).fetchone()
        _require(
            row is not None,
            "EVIDENCE_BINDING_NOT_FOUND",
            "$",
            "no evidence exists for the exact candidate and manifest binding",
        )
        _require(
            tuple(row[1:5])
            == (organization_id, project_id, session_id, manifest_digest),
            "STORED_BINDING_TAMPERED",
            "$",
            "stored manifest scope no longer matches its binding",
        )
        raw = row[5]
        _require(
            isinstance(raw, str),
            "STORED_MANIFEST_TAMPERED",
            "$",
            "stored manifest is not canonical text",
        )
        try:
            manifest = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as error:
            raise EvidenceDomainError(
                "STORED_MANIFEST_TAMPERED", "$", "stored manifest is not JSON"
            ) from error
        try:
            _require(
                canonical_json(manifest) == raw,
                "STORED_MANIFEST_TAMPERED",
                "$",
                "stored manifest is not canonical JSON",
            )
            validate_manifest(manifest)
        except EvidenceDomainError as error:
            if error.code == "STORED_MANIFEST_TAMPERED":
                raise
            raise EvidenceDomainError(
                "STORED_MANIFEST_TAMPERED", error.path, error.detail
            ) from error
        _require(
            manifest["manifest_digest"] == manifest_digest,
            "STORED_MANIFEST_TAMPERED",
            "$.manifest_digest",
            "stored digest does not match its binding",
        )
        self._verify_membership(int(row[0]), manifest)
        return int(row[0]), manifest

    def get_manifest(self, **binding: Any) -> dict[str, Any]:
        """Return verified candidate-evidence-view metadata for an exact binding."""

        self._schema()
        _, manifest = self._resolve(**binding)
        return copy.deepcopy(manifest)

    def inherit_latest_previews(
        self,
        *,
        source_bindings: list[Mapping[str, Any]],
        target_binding: Mapping[str, Any],
    ) -> int:
        """Bind canonical source preview snapshots to a merged manifest.

        Preview files are immutable session artifacts. A merged manifest can
        therefore reference the exact verified source file rather than copying
        bytes during the candidate transaction. Retirement remains fail closed:
        the journal will not remove a path while another manifest's latest
        revision still references it.
        """

        self._schema()
        _require(
            isinstance(source_bindings, list) and 2 <= len(source_bindings) <= 16,
            "PREVIEW_INHERITANCE_INVALID",
            "$.source_bindings",
            "merge preview inheritance requires 2 through 16 sources",
        )
        _require(
            isinstance(target_binding, Mapping),
            "PREVIEW_INHERITANCE_INVALID",
            "$.target_binding",
            "target binding must be an object",
        )
        target_row_id, target_manifest = self._resolve(**dict(target_binding))
        source_manifests = [
            self._resolve(**dict(binding)) for binding in source_bindings
        ]
        inherited = 0
        with _savepoint(self.connection):
            for target_item in target_manifest["items"]:
                if target_item["evidence_type"] != "media.keyframe":
                    continue
                target_item_row_id, _ = self._item(
                    target_row_id, target_manifest, target_item["evidence_id"]
                )
                snapshots: list[tuple[Any, ...]] = []
                for source_row_id, source_manifest in source_manifests:
                    matches = [
                        item
                        for item in source_manifest["items"]
                        if item["evidence_id"] == target_item["evidence_id"]
                    ]
                    if not matches:
                        continue
                    _require(
                        len(matches) == 1
                        and matches[0]["evidence_item_digest"]
                        == target_item["evidence_item_digest"]
                        and canonical_json(matches[0]) == canonical_json(target_item),
                        "MERGE_EVIDENCE_ID_CONFLICT",
                        "$.source_bindings",
                        "merged keyframe identity differs across source manifests",
                    )
                    source_item_row_id, _ = self._item(
                        source_row_id,
                        source_manifest,
                        target_item["evidence_id"],
                    )
                    latest = self.connection.execute(
                        """SELECT preview_revision_id, availability, content_type,
                                  size_bytes, content_digest, relative_path,
                                  unavailable_reason, unavailable_detail
                             FROM tacua_evidence_preview_revisions
                            WHERE manifest_row_id = ? AND item_row_id = ?
                            ORDER BY preview_row_id DESC LIMIT 1""",
                        (source_row_id, source_item_row_id),
                    ).fetchone()
                    if latest is not None:
                        snapshots.append(tuple(latest))
                if not snapshots:
                    continue
                # Revision IDs identify append history, not preview content. Two
                # source manifests may legitimately bind the same verified bytes
                # under different revision IDs, while every content-bearing or
                # availability field must still agree before inheritance.
                canonical_snapshots = {
                    (
                        snapshot[1],
                        snapshot[2],
                        snapshot[3],
                        snapshot[4],
                        snapshot[6],
                        snapshot[7],
                    )
                    for snapshot in snapshots
                }
                _require(
                    len(canonical_snapshots) == 1,
                    "MERGE_PREVIEW_CONFLICT",
                    "$.source_bindings",
                    "merged sources disagree on the latest keyframe preview",
                )
                chosen = min(
                    snapshots,
                    # Keep the target independent of caller/source ordering.
                    key=lambda snapshot: (
                        snapshot[0],
                        "" if snapshot[5] is None else snapshot[5],
                    ),
                )
                if chosen[1] == "available":
                    self._require_bound_preview_reference(
                        target_item,
                        content_type=chosen[2],
                        size_bytes=chosen[3],
                        content_digest=chosen[4],
                        stored=True,
                    )
                    self._read(chosen[5], chosen[2], chosen[3], chosen[4])
                existing = self.connection.execute(
                    """SELECT availability, content_type, size_bytes,
                              content_digest, relative_path, unavailable_reason,
                              unavailable_detail
                         FROM tacua_evidence_preview_revisions
                        WHERE manifest_row_id = ? AND item_row_id = ?
                          AND preview_revision_id = ?""",
                    (target_row_id, target_item_row_id, chosen[0]),
                ).fetchone()
                expected = tuple(chosen[1:8])
                if existing is None:
                    self.connection.execute(
                        """INSERT INTO tacua_evidence_preview_revisions (
                               manifest_row_id, item_row_id, preview_revision_id,
                               availability, content_type, size_bytes,
                               content_digest, relative_path, unavailable_reason,
                               unavailable_detail, recorded_at
                           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            target_row_id,
                            target_item_row_id,
                            chosen[0],
                            chosen[1],
                            chosen[2],
                            chosen[3],
                            chosen[4],
                            chosen[5],
                            chosen[6],
                            chosen[7],
                            _now(),
                        ),
                    )
                    self._audit(
                        "preview_inherited",
                        organization_id=target_binding["organization_id"],
                        project_id=target_binding["project_id"],
                        session_id=target_binding["session_id"],
                        candidate_id=target_binding["candidate_id"],
                        candidate_version=target_binding["candidate_version"],
                        candidate_digest=target_binding["candidate_digest"],
                        manifest_digest=target_binding["manifest_digest"],
                        evidence_id=target_item["evidence_id"],
                        item_digest=target_item["evidence_item_digest"],
                        preview_digest=chosen[4],
                    )
                    inherited += 1
                else:
                    _require(
                        tuple(existing) == expected,
                        "PREVIEW_REVISION_COLLISION",
                        "$.target_binding",
                        "merged manifest already has different preview metadata",
                    )
        return inherited

    def _item(
        self, manifest_row_id: int, manifest: Mapping[str, Any], evidence_id: str
    ) -> tuple[int, dict[str, Any]]:
        _identifier(evidence_id, "$.evidence_id")
        matches = [
            item for item in manifest["items"] if item["evidence_id"] == evidence_id
        ]
        _require(
            len(matches) == 1,
            "EVIDENCE_ITEM_NOT_FOUND",
            "$.evidence_id",
            "manifest has no item with that evidence ID",
        )
        row = self.connection.execute(
            """
            SELECT i.item_row_id, i.item_digest, i.item_json
              FROM tacua_evidence_manifest_items AS mi
              JOIN tacua_evidence_items AS i ON i.item_row_id = mi.item_row_id
             WHERE mi.manifest_row_id = ? AND i.evidence_id = ?
            """,
            (manifest_row_id, evidence_id),
        ).fetchone()
        item = matches[0]
        _require(
            row is not None
            and row[1] == item["evidence_item_digest"]
            and row[2] == canonical_json(item),
            "STORED_MANIFEST_TAMPERED",
            "$.items",
            "stored item membership changed",
        )
        return int(row[0]), item

    def get_item(self, *, evidence_id: str, **binding: Any) -> dict[str, Any]:
        """Return one verified evidence metadata item for a reviewer route."""

        self._schema()
        manifest_row_id, manifest = self._resolve(**binding)
        _, item = self._item(manifest_row_id, manifest, evidence_id)
        return copy.deepcopy(item)

    @staticmethod
    def _extension(content_type: str) -> str:
        return {
            "image/png": "png",
            "image/jpeg": "jpg",
            "image/webp": "webp",
        }[content_type]

    def _relative_path(
        self,
        session_id: str,
        manifest_digest: str,
        evidence_id: str,
        preview_revision_id: str,
        content_type: str,
    ) -> Path:
        return Path(
            "sessions",
            session_id,
            "manifests",
            manifest_digest.removeprefix("sha256:"),
            "items",
            evidence_id,
            f"{preview_revision_id}.{self._extension(content_type)}",
        )

    @staticmethod
    def _session_relative_path(session_id: str) -> Path:
        _identifier(session_id, "$.session_id")
        return Path("sessions", session_id)

    def _path(self, relative_path: str | Path, *, create_parents: bool) -> Path:
        relative = Path(relative_path)
        _require(
            not relative.is_absolute()
            and bool(relative.parts)
            and all(part not in {"", ".", ".."} for part in relative.parts),
            "PREVIEW_PATH_ESCAPE",
            "$.relative_path",
            "preview path must be confined beneath the evidence root",
        )
        current = self.root
        parent_parts = relative.parts[:-1]
        for part in parent_parts:
            current = current / part
            if current.exists() or current.is_symlink():
                try:
                    metadata = current.lstat()
                except OSError as error:
                    raise EvidenceDomainError(
                        "PREVIEW_PATH_INVALID",
                        "$.relative_path",
                        "preview path cannot be inspected",
                    ) from error
                _require(
                    not stat.S_ISLNK(metadata.st_mode),
                    "PREVIEW_PATH_SYMLINK",
                    "$.relative_path",
                    "symbolic links are forbidden beneath the evidence root",
                )
                _require(
                    stat.S_ISDIR(metadata.st_mode),
                    "PREVIEW_PATH_INVALID",
                    "$.relative_path",
                    "preview parent must be a directory",
                )
            elif create_parents:
                try:
                    current.mkdir(mode=0o700)
                except OSError as error:
                    raise EvidenceDomainError(
                        "PREVIEW_PATH_INVALID",
                        "$.relative_path",
                        "preview directory cannot be created",
                    ) from error
                metadata = current.lstat()
                _require(
                    stat.S_ISDIR(metadata.st_mode)
                    and not stat.S_ISLNK(metadata.st_mode),
                    "PREVIEW_PATH_SYMLINK",
                    "$.relative_path",
                    "preview directory was replaced by a symbolic link",
                )
            else:
                raise EvidenceDomainError(
                    "PREVIEW_FILE_MISSING",
                    "$.relative_path",
                    "preview file is missing",
                )
        target = self.root.joinpath(*relative.parts)
        try:
            target.parent.resolve(strict=True).relative_to(self.root)
        except (OSError, ValueError) as error:
            raise EvidenceDomainError(
                "PREVIEW_PATH_ESCAPE",
                "$.relative_path",
                "preview path escapes the evidence root",
            ) from error
        return target

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        try:
            descriptor = os.open(directory, flags)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as error:
            raise EvidenceDomainError(
                "PREVIEW_DIRECTORY_SYNC_FAILED",
                "$.relative_path",
                "preview directory state could not be made durable",
            ) from error

    def _write(
        self, relative_path: Path, staging_relative_path: Path, body: bytes
    ) -> Path:
        target = self._path(relative_path, create_parents=True)
        temporary = self._path(staging_relative_path, create_parents=True)
        _require(
            not target.exists() and not target.is_symlink(),
            "PREVIEW_PATH_COLLISION",
            "$.relative_path",
            "preview path already exists",
        )
        _require(
            temporary.parent == target.parent,
            "PREVIEW_PATH_ESCAPE",
            "$.staging_relative_path",
            "preview staging path must share the committed file directory",
        )
        _require(
            not temporary.exists() and not temporary.is_symlink(),
            "PREVIEW_PATH_COLLISION",
            "$.staging_relative_path",
            "preview staging path already exists",
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(temporary, flags, 0o600)
            view = memoryview(body)
            written = 0
            while written < len(view):
                written += os.write(descriptor, view[written:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.link(temporary, target, follow_symlinks=False)
            temporary.unlink()
            self._fsync_directory(target.parent)
        except FileExistsError as error:
            raise EvidenceDomainError(
                "PREVIEW_PATH_COLLISION",
                "$.relative_path",
                "preview path already exists",
            ) from error
        except OSError as error:
            raise EvidenceDomainError(
                "PREVIEW_WRITE_FAILED",
                "$.body",
                "preview bytes could not be stored",
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        return target

    def _journal_file(
        self,
        *,
        operation_id: str,
        disposition: str,
        relative_path: str | Path,
        staging_relative_path: str | Path | None,
        content_type: str,
        size_bytes: int,
        content_digest: str,
    ) -> None:
        _identifier(operation_id, "$.operation_id")
        _require(
            disposition in {_JOURNAL_DISCARD_PREVIEW, _JOURNAL_DELETE_PREVIEW},
            "FILE_JOURNAL_INVALID",
            "$.disposition",
            "unknown evidence file disposition",
        )
        relative = Path(relative_path).as_posix()
        self._path(relative, create_parents=True)
        staging = (
            None
            if staging_relative_path is None
            else Path(staging_relative_path).as_posix()
        )
        if staging is not None:
            self._path(staging, create_parents=False)
        _require(
            content_type in PREVIEW_MIME_TYPES,
            "FILE_JOURNAL_INVALID",
            "$.content_type",
            "journal MIME type is invalid",
        )
        _integer(size_bytes, "$.size_bytes", 1, MAX_PREVIEW_BYTES)
        _digest(content_digest, "$.content_digest")
        try:
            self.connection.execute(
                """
                INSERT INTO tacua_evidence_file_journal (
                    operation_id, disposition, relative_path,
                    staging_relative_path, content_type, size_bytes,
                    content_digest, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation_id,
                    disposition,
                    relative,
                    staging,
                    content_type,
                    size_bytes,
                    content_digest,
                    _now(),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise EvidenceDomainError(
                "EVIDENCE_FILE_OPERATION_CONFLICT",
                "$.relative_path",
                "another durable file operation already owns this preview path",
            ) from error

    def _journal_session_tree(
        self,
        *,
        operation_id: str,
        organization_id: str,
        project_id: str,
        session_id: str,
    ) -> None:
        _identifier(operation_id, "$.operation_id")
        _identifier(organization_id, "$.organization_id")
        _identifier(project_id, "$.project_id")
        relative_path = self._session_relative_path(session_id).as_posix()
        try:
            self.connection.execute(
                """
                INSERT INTO tacua_evidence_directory_journal (
                    operation_id, disposition, organization_id, project_id,
                    session_id, relative_path, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation_id,
                    _JOURNAL_PRUNE_SESSION_TREE,
                    organization_id,
                    project_id,
                    session_id,
                    relative_path,
                    _now(),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise EvidenceDomainError(
                "EVIDENCE_DIRECTORY_OPERATION_CONFLICT",
                "$.session_id",
                "another durable operation already owns this session evidence tree",
            ) from error

    def _clear_journal_row(self, journal_row_id: int) -> None:
        with _durable_transaction(self.connection):
            self.connection.execute(
                "DELETE FROM tacua_evidence_file_journal WHERE journal_row_id = ?",
                (journal_row_id,),
            )

    def _clear_directory_journal_row(self, journal_row_id: int) -> None:
        with _durable_transaction(self.connection):
            self.connection.execute(
                "DELETE FROM tacua_evidence_directory_journal WHERE journal_row_id = ?",
                (journal_row_id,),
            )

    def _drain_file_journal(self, operation_id: str | None = None) -> dict[str, int]:
        parameters: tuple[Any, ...] = ()
        where = ""
        if operation_id is not None:
            _identifier(operation_id, "$.operation_id")
            where = " WHERE operation_id = ?"
            parameters = (operation_id,)
        rows = self.connection.execute(
            """
            SELECT journal_row_id, disposition, relative_path,
                   staging_relative_path, content_type, size_bytes,
                   content_digest
              FROM tacua_evidence_file_journal
            """
            + where
            + " ORDER BY journal_row_id",
            parameters,
        ).fetchall()
        report = {
            "journal_entries": len(rows),
            "preview_files_removed": 0,
            "staging_files_removed": 0,
            "committed_previews_preserved": 0,
        }
        for row in rows:
            (
                journal_row_id,
                disposition,
                relative_path,
                staging_relative_path,
                content_type,
                size_bytes,
                content_digest,
            ) = tuple(row)
            if disposition == _JOURNAL_DISCARD_PREVIEW:
                committed = self.connection.execute(
                    """
                    SELECT availability, content_type, size_bytes, content_digest
                      FROM tacua_evidence_preview_revisions
                     WHERE relative_path = ?
                    """,
                    (relative_path,),
                ).fetchall()
                if committed:
                    _require(
                        len(committed) == 1
                        and tuple(committed[0])
                        == ("available", content_type, size_bytes, content_digest),
                        "STORED_PREVIEW_TAMPERED",
                        "$.relative_path",
                        "journal path is bound to conflicting preview metadata",
                    )
                    self._read(
                        relative_path, content_type, size_bytes, content_digest
                    )
                    report["committed_previews_preserved"] += 1
                elif self._unlink(relative_path):
                    report["preview_files_removed"] += 1
            elif disposition == _JOURNAL_DELETE_PREVIEW:
                referenced = self.connection.execute(
                    """
                    SELECT p.availability, p.content_type, p.size_bytes,
                           p.content_digest,
                           (
                               SELECT latest.availability
                                 FROM tacua_evidence_preview_revisions AS latest
                                WHERE latest.manifest_row_id = p.manifest_row_id
                                  AND latest.item_row_id = p.item_row_id
                                ORDER BY latest.preview_row_id DESC LIMIT 1
                           ) AS latest_availability
                      FROM tacua_evidence_preview_revisions AS p
                     WHERE p.relative_path = ?
                    """,
                    (relative_path,),
                ).fetchall()
                _require(
                    all(
                        tuple(item)
                        == (
                            "available",
                            content_type,
                            size_bytes,
                            content_digest,
                            "unavailable",
                        )
                        for item in referenced
                    ),
                    "FILE_JOURNAL_INVALID",
                    "$.relative_path",
                    "cleanup journal cannot delete an active preview revision",
                )
                if self._unlink(relative_path):
                    report["preview_files_removed"] += 1
            else:  # The table check is defense in depth against a disabled schema.
                raise EvidenceDomainError(
                    "FILE_JOURNAL_INVALID",
                    "$.disposition",
                    "stored evidence file disposition is invalid",
                )
            if staging_relative_path is not None and self._unlink(
                staging_relative_path
            ):
                report["staging_files_removed"] += 1
            self._clear_journal_row(int(journal_row_id))
        return report

    def _prune_session_tree(self, session_id: str) -> bool:
        relative_path = self._session_relative_path(session_id)
        sessions_root = self.root / relative_path.parts[0]
        try:
            sessions_metadata = sessions_root.lstat()
        except FileNotFoundError:
            return False
        except OSError as error:
            raise EvidenceDomainError(
                "SESSION_TREE_PATH_INVALID",
                "$.session_id",
                "session evidence root cannot be inspected",
            ) from error
        _require(
            stat.S_ISDIR(sessions_metadata.st_mode)
            and not stat.S_ISLNK(sessions_metadata.st_mode),
            "SESSION_TREE_PATH_SYMLINK",
            "$.session_id",
            "symbolic links are forbidden in the session evidence path",
        )
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )

        def prune_contents(descriptor: int) -> None:
            try:
                names = os.listdir(descriptor)
            except OSError as error:
                raise EvidenceDomainError(
                    "SESSION_TREE_PATH_INVALID",
                    "$.session_id",
                    "session evidence directory cannot be listed",
                ) from error
            for name in names:
                try:
                    child_metadata = os.stat(
                        name, dir_fd=descriptor, follow_symlinks=False
                    )
                except OSError as error:
                    raise EvidenceDomainError(
                        "SESSION_TREE_PATH_INVALID",
                        "$.session_id",
                        "session evidence path cannot be inspected",
                    ) from error
                _require(
                    not stat.S_ISLNK(child_metadata.st_mode),
                    "SESSION_TREE_PATH_SYMLINK",
                    "$.session_id",
                    "symbolic links are forbidden in the session evidence tree",
                )
                if stat.S_ISREG(child_metadata.st_mode):
                    try:
                        os.unlink(name, dir_fd=descriptor)
                        os.fsync(descriptor)
                    except OSError as error:
                        raise EvidenceDomainError(
                            "SESSION_TREE_DELETE_FAILED",
                            "$.session_id",
                            "session evidence file could not be removed",
                        ) from error
                    continue
                _require(
                    stat.S_ISDIR(child_metadata.st_mode),
                    "SESSION_TREE_PATH_INVALID",
                    "$.session_id",
                    "session evidence tree contains a non-file path",
                )
                try:
                    child_descriptor = os.open(
                        name, flags, dir_fd=descriptor
                    )
                except OSError as error:
                    raise EvidenceDomainError(
                        "SESSION_TREE_PATH_INVALID",
                        "$.session_id",
                        "session evidence directory cannot be opened safely",
                    ) from error
                try:
                    prune_contents(child_descriptor)
                finally:
                    os.close(child_descriptor)
                try:
                    os.rmdir(name, dir_fd=descriptor)
                    os.fsync(descriptor)
                except OSError as error:
                    raise EvidenceDomainError(
                        "SESSION_TREE_DELETE_FAILED",
                        "$.session_id",
                        "session evidence directory could not be removed",
                    ) from error

        sessions_descriptor: int | None = None
        session_descriptor: int | None = None
        try:
            sessions_descriptor = os.open(sessions_root, flags)
            try:
                session_metadata = os.stat(
                    session_id,
                    dir_fd=sessions_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return False
            _require(
                stat.S_ISDIR(session_metadata.st_mode)
                and not stat.S_ISLNK(session_metadata.st_mode),
                "SESSION_TREE_PATH_SYMLINK",
                "$.session_id",
                "session evidence path must be a real directory",
            )
            session_descriptor = os.open(
                session_id, flags, dir_fd=sessions_descriptor
            )
            prune_contents(session_descriptor)
            os.close(session_descriptor)
            session_descriptor = None
            os.rmdir(session_id, dir_fd=sessions_descriptor)
            os.fsync(sessions_descriptor)
            return True
        except EvidenceDomainError:
            raise
        except OSError as error:
            raise EvidenceDomainError(
                "SESSION_TREE_DELETE_FAILED",
                "$.session_id",
                "session evidence tree could not be removed safely",
            ) from error
        finally:
            if session_descriptor is not None:
                os.close(session_descriptor)
            if sessions_descriptor is not None:
                os.close(sessions_descriptor)

    def _drain_directory_journal(
        self, operation_id: str | None = None
    ) -> dict[str, int]:
        parameters: tuple[Any, ...] = ()
        where = ""
        if operation_id is not None:
            _identifier(operation_id, "$.operation_id")
            where = " WHERE operation_id = ?"
            parameters = (operation_id,)
        rows = self.connection.execute(
            """
            SELECT journal_row_id, disposition, organization_id, project_id,
                   session_id, relative_path
              FROM tacua_evidence_directory_journal
            """
            + where
            + " ORDER BY journal_row_id",
            parameters,
        ).fetchall()
        report = {
            "directory_journal_entries": len(rows),
            "session_trees_pruned": 0,
        }
        for row in rows:
            (
                journal_row_id,
                disposition,
                organization_id,
                project_id,
                session_id,
                relative_path,
            ) = tuple(row)
            _require(
                disposition == _JOURNAL_PRUNE_SESSION_TREE,
                "DIRECTORY_JOURNAL_INVALID",
                "$.disposition",
                "stored directory disposition is invalid",
            )
            _identifier(organization_id, "$.organization_id")
            _identifier(project_id, "$.project_id")
            expected_path = self._session_relative_path(session_id).as_posix()
            _require(
                relative_path == expected_path,
                "DIRECTORY_JOURNAL_INVALID",
                "$.relative_path",
                "stored session directory is not exactly scope-bound",
            )
            for table in (
                "tacua_evidence_manifests",
                "tacua_evidence_items",
                "tacua_candidate_evidence_bindings",
            ):
                remaining = self.connection.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE session_id = ?",
                    (session_id,),
                ).fetchone()[0]
                _require(
                    remaining == 0,
                    "DIRECTORY_JOURNAL_INVALID",
                    "$.session_id",
                    "session evidence metadata still references the directory",
                )
            pending_files = self.connection.execute(
                """
                SELECT COUNT(*) FROM tacua_evidence_file_journal
                 WHERE relative_path = ? OR instr(relative_path, ? || '/') = 1
                """,
                (relative_path, relative_path),
            ).fetchone()[0]
            _require(
                pending_files == 0,
                "DIRECTORY_JOURNAL_INVALID",
                "$.session_id",
                "session preview cleanup must finish before directory pruning",
            )
            active_previews = self.connection.execute(
                """
                SELECT COUNT(*) FROM tacua_evidence_preview_revisions
                 WHERE relative_path IS NOT NULL
                   AND (relative_path = ? OR instr(relative_path, ? || '/') = 1)
                """,
                (relative_path, relative_path),
            ).fetchone()[0]
            _require(
                active_previews == 0,
                "DIRECTORY_JOURNAL_INVALID",
                "$.session_id",
                "preview metadata still references the session directory",
            )
            if self._prune_session_tree(session_id):
                report["session_trees_pruned"] += 1
            self._clear_directory_journal_row(int(journal_row_id))
        return report

    def recover_file_journal(self) -> dict[str, int]:
        """Reconcile durable filesystem phases before accepting evidence writes.

        Call this once during process startup, before concurrent request handling.
        Uncommitted preview bytes are discarded; deletion intents and session
        directory pruning are completed; an already committed, byte-verified
        preview is preserved.
        """

        self._schema()
        _require(
            not self.connection.in_transaction,
            "EVIDENCE_TRANSACTION_ACTIVE",
            "$",
            "file recovery requires a standalone database boundary",
        )
        report = self._drain_file_journal()
        report.update(self._drain_directory_journal())
        return report

    def _read(
        self,
        relative_path: str,
        content_type: str,
        size_bytes: int,
        content_digest: str,
    ) -> bytes:
        _require(
            content_type in PREVIEW_MIME_TYPES,
            "STORED_PREVIEW_TAMPERED",
            "$.content_type",
            "stored preview MIME type is invalid",
        )
        _require(
            isinstance(size_bytes, int) and 1 <= size_bytes <= MAX_PREVIEW_BYTES,
            "STORED_PREVIEW_TAMPERED",
            "$.size_bytes",
            "stored preview size is invalid",
        )
        _digest(content_digest, "$.content_digest")
        target = self._path(relative_path, create_parents=False)
        try:
            metadata = target.lstat()
        except OSError as error:
            raise EvidenceDomainError(
                "PREVIEW_FILE_MISSING", "$.relative_path", "preview file is missing"
            ) from error
        _require(
            stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
            "PREVIEW_PATH_SYMLINK",
            "$.relative_path",
            "preview must be a regular non-symlink file",
        )
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(target, flags)
            try:
                opened = os.fstat(descriptor)
                _require(
                    stat.S_ISREG(opened.st_mode),
                    "STORED_PREVIEW_TAMPERED",
                    "$.relative_path",
                    "opened preview is not a regular file",
                )
                chunks: list[bytes] = []
                total = 0
                while total <= MAX_PREVIEW_BYTES:
                    chunk = os.read(
                        descriptor, min(65_536, MAX_PREVIEW_BYTES + 1 - total)
                    )
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                body = b"".join(chunks)
            finally:
                os.close(descriptor)
        except OSError as error:
            raise EvidenceDomainError(
                "PREVIEW_READ_FAILED",
                "$.relative_path",
                "preview file could not be read safely",
            ) from error
        _require(
            len(body) <= MAX_PREVIEW_BYTES,
            "STORED_PREVIEW_TAMPERED",
            "$.size_bytes",
            "stored preview exceeds the limit",
        )
        _require(
            len(body) == size_bytes,
            "STORED_PREVIEW_TAMPERED",
            "$.size_bytes",
            "stored preview size no longer matches metadata",
        )
        _require(
            sha256_digest(body) == content_digest,
            "STORED_PREVIEW_TAMPERED",
            "$.content_digest",
            "stored preview digest no longer matches bytes",
        )
        try:
            _signature(content_type, body)
        except EvidenceDomainError as error:
            raise EvidenceDomainError(
                "STORED_PREVIEW_TAMPERED", "$.body", error.detail
            ) from error
        return body

    @staticmethod
    def _require_bound_preview_reference(
        item: Mapping[str, Any],
        *,
        content_type: str,
        size_bytes: int,
        content_digest: str,
        stored: bool = False,
    ) -> None:
        reference = item["reference"]
        _require(
            isinstance(reference, dict)
            and (
                reference["content_type"],
                reference["size_bytes"],
                reference["content_digest"],
            )
            == (content_type, size_bytes, content_digest),
            "STORED_PREVIEW_TAMPERED" if stored else "PREVIEW_REFERENCE_MISMATCH",
            "$.body",
            "stored preview no longer matches the sealed keyframe reference"
            if stored
            else "preview bytes and metadata must exactly match the sealed keyframe reference",
        )

    def put_preview(
        self,
        *,
        evidence_id: str,
        preview_revision_id: str,
        content_type: str,
        size_bytes: int,
        content_digest: str,
        body: bytes,
        transaction_guard: Callable[[sqlite3.Connection], None] | None = None,
        **binding: Any,
    ) -> dict[str, Any]:
        """Append one immutable, manifest-bound media.keyframe preview.

        When supplied, ``transaction_guard`` is the first callback in each of
        the two durable database phases around the filesystem gap. It receives
        only the active SQLite connection and must not commit or roll it back.
        A failure rolls back that phase; a process failure in phase two leaves
        the phase-one file intent for startup recovery.
        """

        self._schema()
        _identifier(preview_revision_id, "$.preview_revision_id")
        _require(
            content_type in PREVIEW_MIME_TYPES,
            "PREVIEW_MIME_TYPE_INVALID",
            "$.content_type",
            "preview must be PNG, JPEG, or WebP",
        )
        _integer(size_bytes, "$.size_bytes", 1, MAX_PREVIEW_BYTES)
        _digest(content_digest, "$.content_digest")
        _require(
            isinstance(body, bytes),
            "PREVIEW_BODY_INVALID",
            "$.body",
            "preview body must be immutable bytes",
        )
        _require(
            len(body) <= MAX_PREVIEW_BYTES,
            "PREVIEW_TOO_LARGE",
            "$.body",
            "preview exceeds 2 MiB",
        )
        _require(
            len(body) == size_bytes,
            "PREVIEW_SIZE_MISMATCH",
            "$.size_bytes",
            "declared size does not match bytes",
        )
        _require(
            sha256_digest(body) == content_digest,
            "PREVIEW_DIGEST_MISMATCH",
            "$.content_digest",
            "declared digest does not match bytes",
        )
        _signature(content_type, body)
        _require(
            transaction_guard is None or callable(transaction_guard),
            "TRANSACTION_GUARD_INVALID",
            "$.transaction_guard",
            "transaction guard must be callable",
        )

        _require(
            not self.connection.in_transaction,
            "EVIDENCE_TRANSACTION_ACTIVE",
            "$",
            "preview writes require a standalone database boundary",
        )
        operation_id = "preview_put_" + uuid.uuid4().hex
        relative_path: Path | None = None
        staging_relative_path: Path | None = None
        try:
            with _durable_transaction(self.connection):
                if transaction_guard is not None:
                    transaction_guard(self.connection)
                manifest_row_id, manifest = self._resolve(**binding)
                item_row_id, item = self._item(
                    manifest_row_id, manifest, evidence_id
                )
                _require(
                    item["evidence_type"] == "media.keyframe",
                    "PREVIEW_EVIDENCE_TYPE_INVALID",
                    "$.evidence_id",
                    "only media.keyframe evidence can have an image preview",
                )
                _require(
                    item["availability"] == "available",
                    "PREVIEW_EVIDENCE_UNAVAILABLE",
                    "$.evidence_id",
                    "unavailable keyframe evidence cannot have a preview",
                )
                existing = self.connection.execute(
                    """
                    SELECT availability, content_type, size_bytes,
                           content_digest, relative_path
                      FROM tacua_evidence_preview_revisions
                     WHERE manifest_row_id = ? AND item_row_id = ?
                       AND preview_revision_id = ?
                    """,
                    (manifest_row_id, item_row_id, preview_revision_id),
                ).fetchone()
                if existing is not None:
                    _require(
                        existing[:4]
                        == ("available", content_type, size_bytes, content_digest),
                        "PREVIEW_REVISION_COLLISION",
                        "$.preview_revision_id",
                        "immutable preview revision has different metadata",
                    )
                self._require_bound_preview_reference(
                    item,
                    content_type=content_type,
                    size_bytes=size_bytes,
                    content_digest=content_digest,
                )
                if existing is not None:
                    self._read(
                        existing[4], content_type, size_bytes, content_digest
                    )
                    return {
                        "evidence_id": evidence_id,
                        "preview_revision_id": preview_revision_id,
                        "content_type": content_type,
                        "size_bytes": size_bytes,
                        "content_digest": content_digest,
                        "created": False,
                        "authorized_for_handoff": False,
                    }
                relative_path = self._relative_path(
                    binding["session_id"],
                    binding["manifest_digest"],
                    evidence_id,
                    preview_revision_id,
                    content_type,
                )
                staging_relative_path = relative_path.parent / (
                    ".tacua-preview-" + operation_id
                )
                self._journal_file(
                    operation_id=operation_id,
                    disposition=_JOURNAL_DISCARD_PREVIEW,
                    relative_path=relative_path,
                    staging_relative_path=staging_relative_path,
                    content_type=content_type,
                    size_bytes=size_bytes,
                    content_digest=content_digest,
                )

            assert relative_path is not None and staging_relative_path is not None
            self._write(relative_path, staging_relative_path, body)
            self._read(
                relative_path.as_posix(), content_type, size_bytes, content_digest
            )
            with _durable_transaction(self.connection):
                if transaction_guard is not None:
                    transaction_guard(self.connection)
                manifest_row_id, manifest = self._resolve(**binding)
                item_row_id, item = self._item(
                    manifest_row_id, manifest, evidence_id
                )
                _require(
                    item["evidence_type"] == "media.keyframe",
                    "PREVIEW_EVIDENCE_TYPE_INVALID",
                    "$.evidence_id",
                    "only media.keyframe evidence can have an image preview",
                )
                _require(
                    item["availability"] == "available",
                    "PREVIEW_EVIDENCE_UNAVAILABLE",
                    "$.evidence_id",
                    "unavailable keyframe evidence cannot have a preview",
                )
                self._require_bound_preview_reference(
                    item,
                    content_type=content_type,
                    size_bytes=size_bytes,
                    content_digest=content_digest,
                )
                journal = self.connection.execute(
                    """
                    SELECT disposition, relative_path, staging_relative_path,
                           content_type, size_bytes, content_digest
                      FROM tacua_evidence_file_journal
                     WHERE operation_id = ?
                    """,
                    (operation_id,),
                ).fetchone()
                _require(
                    journal is not None
                    and tuple(journal)
                    == (
                        _JOURNAL_DISCARD_PREVIEW,
                        relative_path.as_posix(),
                        staging_relative_path.as_posix(),
                        content_type,
                        size_bytes,
                        content_digest,
                    ),
                    "FILE_JOURNAL_INVALID",
                    "$.operation_id",
                    "durable preview intent changed before commit",
                )
                self.connection.execute(
                    """
                    INSERT INTO tacua_evidence_preview_revisions (
                        manifest_row_id, item_row_id, preview_revision_id,
                        availability, content_type, size_bytes, content_digest,
                        relative_path, unavailable_reason, unavailable_detail,
                        recorded_at
                    ) VALUES (?, ?, ?, 'available', ?, ?, ?, ?, NULL, NULL, ?)
                    """,
                    (
                        manifest_row_id,
                        item_row_id,
                        preview_revision_id,
                        content_type,
                        size_bytes,
                        content_digest,
                        relative_path.as_posix(),
                        _now(),
                    ),
                )
                self._audit(
                    "preview_appended",
                    organization_id=binding["organization_id"],
                    project_id=binding["project_id"],
                    session_id=binding["session_id"],
                    candidate_id=binding["candidate_id"],
                    candidate_version=binding["candidate_version"],
                    candidate_digest=binding["candidate_digest"],
                    manifest_digest=binding["manifest_digest"],
                    evidence_id=evidence_id,
                    item_digest=item["evidence_item_digest"],
                    preview_digest=content_digest,
                )
                self.connection.execute(
                    "DELETE FROM tacua_evidence_file_journal WHERE operation_id = ?",
                    (operation_id,),
                )
        except Exception:
            # Ordinary failures are cleaned synchronously. A process death or
            # BaseException leaves the durable row for startup recovery.
            try:
                if not self.connection.in_transaction:
                    self._drain_file_journal(operation_id)
            except Exception:
                pass
            raise
        return {
            "evidence_id": evidence_id,
            "preview_revision_id": preview_revision_id,
            "content_type": content_type,
            "size_bytes": size_bytes,
            "content_digest": content_digest,
            "created": True,
            "authorized_for_handoff": False,
        }

    def _latest_preview(
        self, manifest_row_id: int, item_row_id: int
    ) -> tuple[Any, ...] | None:
        return self.connection.execute(
            """
            SELECT preview_revision_id, availability, content_type, size_bytes,
                   content_digest, relative_path, unavailable_reason
              FROM tacua_evidence_preview_revisions
             WHERE manifest_row_id = ? AND item_row_id = ?
             ORDER BY preview_row_id DESC LIMIT 1
            """,
            (manifest_row_id, item_row_id),
        ).fetchone()

    def get_preview(self, *, evidence_id: str, **binding: Any) -> dict[str, Any]:
        """Read and re-verify the latest preview for an exact binding."""

        self._schema()
        manifest_row_id, manifest = self._resolve(**binding)
        item_row_id, item = self._item(manifest_row_id, manifest, evidence_id)
        _require(
            item["evidence_type"] == "media.keyframe",
            "PREVIEW_EVIDENCE_TYPE_INVALID",
            "$.evidence_id",
            "only media.keyframe evidence has image previews",
        )
        row = self._latest_preview(manifest_row_id, item_row_id)
        _require(
            row is not None,
            "PREVIEW_NOT_FOUND",
            "$.evidence_id",
            "no derived preview exists for this keyframe",
        )
        if row[1] == "unavailable":
            raise EvidenceDomainError(
                "PREVIEW_UNAVAILABLE",
                "$.evidence_id",
                f"preview is unavailable: {row[6]}",
            )
        self._require_bound_preview_reference(
            item,
            content_type=row[2],
            size_bytes=row[3],
            content_digest=row[4],
            stored=True,
        )
        body = self._read(row[5], row[2], row[3], row[4])
        return {
            "evidence_id": evidence_id,
            "preview_revision_id": row[0],
            "content_type": row[2],
            "size_bytes": row[3],
            "content_digest": row[4],
            "body": body,
            "authorized_for_handoff": False,
        }

    def get_verified_keyframes_for_approval(
        self, *, evidence_ids: list[str], **binding: Any
    ) -> dict[str, Any]:
        """Return exact verified keyframe bytes to an approval integration.

        This method deliberately grants no handoff authority. The approval
        layer must consume these returned bytes (not a later path lookup), bind
        their digests into its separately sealed authorization artifact, and
        fail if any requested keyframe is absent, unavailable, or changed. It
        should call this inside the same SQLite ``BEGIN IMMEDIATE`` transaction
        that persists approval so retirement/deletion cannot commit between
        verification and authorization.
        """

        self._schema()
        _require(
            isinstance(evidence_ids, list) and 1 <= len(evidence_ids) <= 256,
            "APPROVAL_KEYFRAMES_INVALID",
            "$.evidence_ids",
            "approval must request from 1 through 256 keyframe evidence IDs",
        )
        for index, evidence_id in enumerate(evidence_ids):
            _identifier(evidence_id, f"$.evidence_ids[{index}]")
        _require(
            len(set(evidence_ids)) == len(evidence_ids),
            "APPROVAL_KEYFRAMES_INVALID",
            "$.evidence_ids",
            "approval keyframe evidence IDs must be unique",
        )
        manifest_row_id, manifest = self._resolve(**binding)
        verified: list[dict[str, Any]] = []
        for index, evidence_id in enumerate(evidence_ids):
            item_row_id, item = self._item(
                manifest_row_id, manifest, evidence_id
            )
            _require(
                item["evidence_type"] == "media.keyframe"
                and item["availability"] == "available",
                "APPROVAL_KEYFRAME_INVALID",
                f"$.evidence_ids[{index}]",
                "approval references must name available media.keyframe evidence",
            )
            row = self._latest_preview(manifest_row_id, item_row_id)
            _require(
                row is not None,
                "PREVIEW_NOT_FOUND",
                f"$.evidence_ids[{index}]",
                "approval keyframe has no derived preview",
            )
            if row[1] == "unavailable":
                raise EvidenceDomainError(
                    "PREVIEW_UNAVAILABLE",
                    f"$.evidence_ids[{index}]",
                    f"approval keyframe preview is unavailable: {row[6]}",
                )
            self._require_bound_preview_reference(
                item,
                content_type=row[2],
                size_bytes=row[3],
                content_digest=row[4],
                stored=True,
            )
            body = self._read(row[5], row[2], row[3], row[4])
            verified.append(
                {
                    "evidence_id": evidence_id,
                    "evidence_item_digest": item["evidence_item_digest"],
                    "preview_revision_id": row[0],
                    "content_type": row[2],
                    "size_bytes": row[3],
                    "content_digest": row[4],
                    "body": body,
                }
            )
        return {
            "candidate_id": binding["candidate_id"],
            "candidate_version": binding["candidate_version"],
            "candidate_digest": binding["candidate_digest"],
            "evidence_manifest_digest": binding["manifest_digest"],
            "verified_keyframes": verified,
            "authorized_for_handoff": False,
        }

    def get_candidate_evidence_view(
        self, *, diagnostic_events: list[dict[str, Any]], **binding: Any
    ) -> dict[str, Any]:
        """Project storage into the reviewer candidate-evidence-view contract.

        Diagnostic events are already runtime-validated and candidate-filtered
        by the integration layer; this domain only supplies immutable evidence
        metadata and preview status.
        """

        self._schema()
        _require(
            isinstance(diagnostic_events, list) and len(diagnostic_events) <= 512,
            "DIAGNOSTIC_EVENTS_INVALID",
            "$.diagnostic_events",
            "integration must supply at most 512 validated diagnostic events",
        )
        manifest_row_id, manifest = self._resolve(**binding)
        projected: list[dict[str, Any]] = []
        for item in manifest["items"]:
            item_row_id, _ = self._item(
                manifest_row_id, manifest, item["evidence_id"]
            )
            preview = {
                "status": "not_applicable",
                "content_type": None,
                "size_bytes": None,
                "content_digest": None,
            }
            if item["evidence_type"] == "media.keyframe":
                row = self._latest_preview(manifest_row_id, item_row_id)
                if row is None or row[1] == "unavailable":
                    preview["status"] = "unavailable"
                else:
                    preview = {
                        "status": "available",
                        "content_type": row[2],
                        "size_bytes": row[3],
                        "content_digest": row[4],
                    }
            reference = item["reference"]
            projected.append(
                {
                    "evidence_id": item["evidence_id"],
                    "evidence_type": item["evidence_type"],
                    "availability": item["availability"],
                    "description": item["description"],
                    "time_range": copy.deepcopy(item["time_range"]),
                    "source": copy.deepcopy(item["source"]),
                    "reference": None
                    if reference is None
                    else {
                        "content_type": reference["content_type"],
                        "size_bytes": reference["size_bytes"],
                        "content_digest": reference["content_digest"],
                    },
                    "unavailable": copy.deepcopy(item["unavailable"]),
                    "preview": preview,
                }
            )
        return {
            "contract_version": "tacua.candidate-evidence-view@1.0.0",
            "candidate_id": binding["candidate_id"],
            "candidate_version": binding["candidate_version"],
            "candidate_digest": binding["candidate_digest"],
            "evidence_manifest_digest": binding["manifest_digest"],
            "items": projected,
            "diagnostic_events": copy.deepcopy(diagnostic_events),
        }

    def _unlink(self, relative_path: str) -> bool:
        try:
            target = self._path(relative_path, create_parents=False)
        except EvidenceDomainError as error:
            if error.code == "PREVIEW_FILE_MISSING":
                return False
            raise
        try:
            metadata = target.lstat()
        except FileNotFoundError:
            self._fsync_directory(target.parent)
            return False
        _require(
            stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
            "PREVIEW_PATH_SYMLINK",
            "$.relative_path",
            "refusing to remove a non-regular preview path",
        )
        try:
            target.unlink()
        except OSError as error:
            raise EvidenceDomainError(
                "PREVIEW_DELETE_FAILED",
                "$.relative_path",
                "preview file could not be removed",
            ) from error
        self._fsync_directory(target.parent)
        return True

    def mark_preview_unavailable(
        self,
        *,
        evidence_id: str,
        preview_revision_id: str,
        reason: str,
        detail: str,
        **binding: Any,
    ) -> dict[str, Any]:
        """Append unavailability without rewriting manifest metadata or digest."""

        self._schema()
        _identifier(preview_revision_id, "$.preview_revision_id")
        _require(
            reason in _UNAVAILABLE,
            "UNAVAILABLE_REASON_INVALID",
            "$.reason",
            "unknown preview unavailability reason",
        )
        _text(detail, "$.detail", 1, 512)
        _require(
            not self.connection.in_transaction,
            "EVIDENCE_TRANSACTION_ACTIVE",
            "$",
            "preview retirement requires a standalone database boundary",
        )
        operation_id = "preview_retire_" + uuid.uuid4().hex
        with _durable_transaction(self.connection):
            manifest_row_id, manifest = self._resolve(**binding)
            item_row_id, item = self._item(
                manifest_row_id, manifest, evidence_id
            )
            _require(
                item["evidence_type"] == "media.keyframe",
                "PREVIEW_EVIDENCE_TYPE_INVALID",
                "$.evidence_id",
                "only media.keyframe evidence has preview lifecycle",
            )
            existing = self.connection.execute(
                """
                SELECT availability, unavailable_reason, unavailable_detail
                  FROM tacua_evidence_preview_revisions
                 WHERE manifest_row_id = ? AND item_row_id = ?
                   AND preview_revision_id = ?
                """,
                (manifest_row_id, item_row_id, preview_revision_id),
            ).fetchone()
            created = existing is None
            if existing is None:
                self.connection.execute(
                    """
                    INSERT INTO tacua_evidence_preview_revisions (
                        manifest_row_id, item_row_id, preview_revision_id,
                        availability, content_type, size_bytes, content_digest,
                        relative_path, unavailable_reason, unavailable_detail,
                        recorded_at
                    ) VALUES (?, ?, ?, 'unavailable', NULL, NULL, NULL, NULL, ?, ?, ?)
                    """,
                    (
                        manifest_row_id,
                        item_row_id,
                        preview_revision_id,
                        reason,
                        detail,
                        _now(),
                    ),
                )
                self._audit(
                    "preview_unavailable",
                    organization_id=binding["organization_id"],
                    project_id=binding["project_id"],
                    session_id=binding["session_id"],
                    candidate_id=binding["candidate_id"],
                    candidate_version=binding["candidate_version"],
                    candidate_digest=binding["candidate_digest"],
                    manifest_digest=binding["manifest_digest"],
                    evidence_id=evidence_id,
                    item_digest=item["evidence_item_digest"],
                    reason_code=reason,
                )
            else:
                _require(
                    tuple(existing) == ("unavailable", reason, detail),
                    "PREVIEW_REVISION_COLLISION",
                    "$.preview_revision_id",
                    "immutable preview revision has different availability",
                )
            preview_files = {
                tuple(row)
                for row in self.connection.execute(
                    """
                    SELECT relative_path, content_type, size_bytes, content_digest
                      FROM tacua_evidence_preview_revisions
                     WHERE manifest_row_id = ? AND item_row_id = ?
                       AND availability = 'available'
                    """,
                    (manifest_row_id, item_row_id),
                ).fetchall()
            }
            for path, stored_type, stored_size, stored_digest in preview_files:
                self._journal_file(
                    operation_id=operation_id,
                    disposition=_JOURNAL_DELETE_PREVIEW,
                    relative_path=path,
                    staging_relative_path=None,
                    content_type=stored_type,
                    size_bytes=stored_size,
                    content_digest=stored_digest,
                )
        report = self._drain_file_journal(operation_id)
        return {
            "evidence_id": evidence_id,
            "preview_revision_id": preview_revision_id,
            "availability": "unavailable",
            "reason": reason,
            "created": created,
            "removed_preview_files": report["preview_files_removed"],
            "authorized_for_handoff": False,
        }

    def delete_session(
        self, *, organization_id: str, project_id: str, session_id: str
    ) -> dict[str, int]:
        """Delete all derived evidence for one exact session, idempotently."""

        self._schema()
        _identifier(organization_id, "$.organization_id")
        _identifier(project_id, "$.project_id")
        _identifier(session_id, "$.session_id")
        _require(
            not self.connection.in_transaction,
            "EVIDENCE_TRANSACTION_ACTIVE",
            "$",
            "session evidence deletion requires a standalone database boundary",
        )
        operation_id = "session_delete_" + uuid.uuid4().hex
        with _durable_transaction(self.connection):
            scope = (organization_id, project_id, session_id)
            manifest_count = self.connection.execute(
                """
                SELECT COUNT(*) FROM tacua_evidence_manifests
                 WHERE organization_id = ? AND project_id = ? AND session_id = ?
                """,
                scope,
            ).fetchone()[0]
            item_count = self.connection.execute(
                """
                SELECT COUNT(*) FROM tacua_evidence_items
                 WHERE organization_id = ? AND project_id = ? AND session_id = ?
                """,
                scope,
            ).fetchone()[0]
            preview_rows = self.connection.execute(
                """
                SELECT previews.relative_path, previews.content_type,
                       previews.size_bytes, previews.content_digest
                  FROM tacua_evidence_preview_revisions AS previews
                  JOIN tacua_evidence_manifests AS manifests
                    ON manifests.manifest_row_id = previews.manifest_row_id
                 WHERE manifests.organization_id = ?
                   AND manifests.project_id = ? AND manifests.session_id = ?
                """,
                scope,
            ).fetchall()
            membership_count = self.connection.execute(
                """
                SELECT COUNT(*)
                  FROM tacua_evidence_manifest_items AS membership
                  JOIN tacua_evidence_manifests AS manifests
                    ON manifests.manifest_row_id = membership.manifest_row_id
                 WHERE manifests.organization_id = ?
                   AND manifests.project_id = ? AND manifests.session_id = ?
                """,
                scope,
            ).fetchone()[0]
            binding_count = self.connection.execute(
                """
                SELECT COUNT(*) FROM tacua_candidate_evidence_bindings
                 WHERE organization_id = ? AND project_id = ? AND session_id = ?
                """,
                scope,
            ).fetchone()[0]
            session_path = self._session_relative_path(session_id).as_posix()
            pending_file_operations = self.connection.execute(
                """
                SELECT COUNT(*) FROM tacua_evidence_file_journal
                 WHERE relative_path = ? OR instr(relative_path, ? || '/') = 1
                """,
                (session_path, session_path),
            ).fetchone()[0]
            _require(
                pending_file_operations == 0,
                "EVIDENCE_FILE_OPERATION_CONFLICT",
                "$.session_id",
                "session has an unfinished preview publication or retirement",
            )
            preview_files = {
                tuple(row)
                for row in preview_rows
                if row[0] is not None
            }
            for path, stored_type, stored_size, stored_digest in preview_files:
                self._journal_file(
                    operation_id=operation_id,
                    disposition=_JOURNAL_DELETE_PREVIEW,
                    relative_path=path,
                    staging_relative_path=None,
                    content_type=stored_type,
                    size_bytes=stored_size,
                    content_digest=stored_digest,
                )
            self._journal_session_tree(
                operation_id=operation_id,
                organization_id=organization_id,
                project_id=project_id,
                session_id=session_id,
            )
            self.connection.execute(
                """
                DELETE FROM tacua_evidence_preview_revisions
                 WHERE manifest_row_id IN (
                     SELECT manifest_row_id FROM tacua_evidence_manifests
                      WHERE organization_id = ? AND project_id = ?
                        AND session_id = ?
                 )
                """,
                scope,
            )
            self.connection.execute(
                """
                DELETE FROM tacua_evidence_manifest_items
                 WHERE manifest_row_id IN (
                     SELECT manifest_row_id FROM tacua_evidence_manifests
                      WHERE organization_id = ? AND project_id = ?
                        AND session_id = ?
                 )
                """,
                scope,
            )
            self.connection.execute(
                """
                DELETE FROM tacua_candidate_evidence_bindings
                 WHERE organization_id = ? AND project_id = ? AND session_id = ?
                """,
                scope,
            )
            self.connection.execute(
                """
                DELETE FROM tacua_evidence_manifests
                 WHERE organization_id = ? AND project_id = ? AND session_id = ?
                """,
                scope,
            )
            self.connection.execute(
                """
                DELETE FROM tacua_evidence_items
                 WHERE organization_id = ? AND project_id = ? AND session_id = ?
                """,
                scope,
            )
            if manifest_count or item_count or binding_count or preview_rows:
                self._audit(
                    "session_evidence_deleted",
                    organization_id=organization_id,
                    project_id=project_id,
                    session_id=session_id,
                    reason_code="session_deletion",
                )
        report = self._drain_file_journal(operation_id)
        self._drain_directory_journal(operation_id)
        return {
            "candidate_bindings": int(binding_count),
            "manifests": int(manifest_count),
            "manifest_items": int(membership_count),
            "items": int(item_count),
            "preview_revisions": len(preview_rows),
            "preview_files": int(report["preview_files_removed"]),
        }
