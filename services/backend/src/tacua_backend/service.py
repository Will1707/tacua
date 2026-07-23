# SPDX-License-Identifier: Apache-2.0

"""Durable SDK/backend protocol service for one self-hosted Tacua deployment."""

from __future__ import annotations

import base64
import binascii
import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import tempfile
import threading
import unicodedata
from typing import Any, BinaryIO, Callable, Protocol

from . import PROCESSING_JOB_CONTRACT, __version__
from .candidate_domain import ContractError as CandidateContractError, TICKET_CONTRACT
from .candidate_store import (
    CandidateReplacementResponse,
    CandidateStore,
    CandidateStoreError,
    CandidateTransitionResponse,
)
from .config import (
    BUNDLE_ID_PATTERN,
    DIGEST_PATTERN,
    ID_PATTERN,
    TRANSPORT_POLICY_VERSION,
    PilotConfig,
    normalize_backend_origin,
    validate_approved_handoff_config,
)
from .contracts import (
    ContractError,
    PROTOCOL,
    PROTOCOL_VERSION,
    canonical_json,
    digest,
    digest_without,
    runtime_seal,
    runtime_validate,
    seal,
    validate,
    validate_authenticated_exact_replay,
    validate_new_upload_authentication,
    validate_operation_pair,
)
from .evidence_domain import (
    EvidenceDomainError,
    EvidenceStore,
    initialize_schema as initialize_evidence_schema,
    seal_manifest as seal_evidence_manifest,
    sha256_digest as evidence_sha256_digest,
)
from .handoff_export import HandoffExportError, export_approved_candidate
from .handoff_store import (
    HandoffStore,
    HandoffStoreError,
    StoredHandoff,
    initialize_schema as initialize_handoff_schema,
)
from .processing_jobs import (
    JOB_STAGES,
    ProcessingCheckpoint,
    ProcessingResult,
    PublicationCandidate,
    ProcessingJobClaim,
    ProcessingJobStore,
    ProcessingJobStoreError,
    initialize_processing_job_schema,
)
from .processing_bridge import WORKER_ERROR_CODE


MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_JSON_NESTING_DEPTH = 64
MAX_SEGMENTS = 2048
MAX_SESSION_CREDENTIALS = 64
CREDENTIAL_ORDINAL_CHECK_SQL = (
    "ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 63)"
)
MAX_CANDIDATE_EVIDENCE_VIEW_BYTES = 1_572_864
MAX_HANDOFF_ARTIFACT_BYTES = 2_097_152
LIST_PAGE_SIZE = 50
MAX_PAGE_CURSOR_LENGTH = 512
PAGE_CURSOR_VERSION = 1
SCHEMA_VERSION = 2
INTERNAL_DELETION_RESOURCE = "tacua.internal-deletion-job@1.0.0"
SCOPE_POLICY_CONTRACT = "tacua.capture-scope-policy@1.0.0"
RETENTION_POLICY_VERSION = "tacua.retention-v1"
MANIFEST_RETENTION_POLICY_VERSION = "tacua.retention@1.0.0"
SDK_BACKEND_ERROR_CONTRACT = "tacua.sdk-backend-error@1.0.0"
SDK_BACKEND_ERROR_MEDIA_TYPE = (
    "application/vnd.tacua.sdk-backend-error+json;version=1.0.0"
)
SDK_BACKEND_ERROR_MAX_BYTES = 4_096
HISTORICAL_OPERATION_NOT_FOUND = "historical_operation_not_found"
OPERATION_NOT_AUTHORIZED_MESSAGE = (
    "new upload requires the current active credential"
)
COMPLETION_NOT_AUTHORIZED_MESSAGE = (
    "first completion requires the current active credential"
)
CREDENTIAL_ROTATION_LIMIT_MESSAGE = (
    "session credential recovery limit was reached; delete this session and start a new capture"
)


class ClosingConnection(sqlite3.Connection):
    """Commit or roll back a context, then close its SQLite handle."""

    def __exit__(self, exc_type, exc_value, traceback):  # type: ignore[no-untyped-def]
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


@dataclass(frozen=True)
class SDKReconciliationBinding:
    """Content-free binding for one authoritative historical-operation lookup miss."""

    session_id: str
    operation_kind: str
    operation_id: str
    request_digest: str
    request_credential_id: str
    authenticated_credential_id: str

    def __post_init__(self) -> None:
        identifiers = (
            self.session_id,
            self.operation_id,
            self.request_credential_id,
            self.authenticated_credential_id,
        )
        if (
            self.operation_kind not in {"segment", "diagnostic", "completion"}
            or any(ID_PATTERN.fullmatch(value) is None for value in identifiers)
            or DIGEST_PATTERN.fullmatch(self.request_digest) is None
            or self.request_credential_id == self.authenticated_credential_id
        ):
            raise ValueError("invalid SDK reconciliation binding")

    def as_dict(self) -> dict[str, str]:
        return {
            "outcome": HISTORICAL_OPERATION_NOT_FOUND,
            "session_id": self.session_id,
            "operation_kind": self.operation_kind,
            "operation_id": self.operation_id,
            "request_digest": self.request_digest,
            "request_credential_id": self.request_credential_id,
            "authenticated_credential_id": self.authenticated_credential_id,
        }


class ApiError(Exception):
    """A content-free error safe to serialize to an API client."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        sdk_reconciliation: SDKReconciliationBinding | None = None,
        details: dict[str, Any] | None = None,
    ):
        if sdk_reconciliation is not None:
            expected_message = (
                COMPLETION_NOT_AUTHORIZED_MESSAGE
                if sdk_reconciliation.operation_kind == "completion"
                else OPERATION_NOT_AUTHORIZED_MESSAGE
            )
            if (
                status != 403
                or code != "OPERATION_NOT_AUTHORIZED"
                or message != expected_message
            ):
                raise ValueError(
                    "SDK reconciliation is only valid for historical operation denial"
                )
        if details is not None and code != "CANDIDATE_SUPERSEDED":
            raise ValueError("structured API error details are not allowed for this code")
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.sdk_reconciliation = sdk_reconciliation
        self.details = copy.deepcopy(details)


class _ProcessingEngineFailure(ApiError):
    """Generic public failure with one content-free worker-only code."""

    def __init__(self, worker_code: object):
        selected = (
            worker_code
            if isinstance(worker_code, str)
            and WORKER_ERROR_CODE.fullmatch(worker_code) is not None
            else "PROCESSING_ENGINE_FAILED"
        )
        super().__init__(
            500,
            "PROCESSING_ENGINE_FAILED",
            "configured processing engine failed",
        )
        self.worker_code = selected


@dataclass(frozen=True)
class StoredResponse:
    status: int
    body: bytes

    def json(self) -> dict[str, Any]:
        value = strict_json_loads(self.body)
        if not isinstance(value, dict):
            raise ValueError("stored protocol response is not an object")
        return value


class DuplicateJSONKey(ValueError):
    pass


class InvalidJSONValue(ValueError):
    pass


class ProcessingEngine(Protocol):
    """Opt-in internal processor; no engine is configured by default."""

    def process_stage(
        self, claim: ProcessingJobClaim
    ) -> ProcessingCheckpoint | ProcessingResult | None:
        """Process one lease-owned stage without receiving backend authority."""


def strict_json_loads(value: bytes | str) -> Any:
    """Decode duplicate-free, integer-only, NFC, interoperable JSON."""

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            try:
                key.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise InvalidJSONValue("JSON object key contains invalid Unicode") from exc
            if unicodedata.normalize("NFC", key) != key:
                raise InvalidJSONValue("JSON object keys must be NFC-normalized")
            if key in result:
                raise DuplicateJSONKey("JSON object contains a duplicate key")
            result[key] = item
        return result

    def reject_float(_value: str) -> float:
        raise InvalidJSONValue("floating-point JSON values are forbidden")

    def checked_int(raw: str) -> int:
        digits = raw[1:] if raw.startswith("-") else raw
        if len(digits) > 16:
            raise InvalidJSONValue("JSON integer exceeds the interoperable range")
        parsed = int(raw)
        if abs(parsed) > MAX_SAFE_INTEGER:
            raise InvalidJSONValue("JSON integer exceeds the interoperable range")
        return parsed

    def reject_constant(_value: str) -> None:
        raise InvalidJSONValue("non-finite JSON values are forbidden")

    if isinstance(value, bytes):
        value = value.decode("utf-8")
    try:
        result = json.loads(
            value,
            object_pairs_hook=reject_duplicates,
            parse_float=reject_float,
            parse_int=checked_int,
            parse_constant=reject_constant,
        )
    except RecursionError as exc:
        raise InvalidJSONValue("JSON nesting exceeds the safe depth") from exc

    stack: list[tuple[str, Any, int]] = [("$", result, 0)]
    while stack:
        path, child, depth = stack.pop()
        if depth > MAX_JSON_NESTING_DEPTH:
            raise InvalidJSONValue("JSON nesting exceeds the safe depth")
        if isinstance(child, str):
            try:
                child.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise InvalidJSONValue(f"invalid Unicode string at {path}") from exc
            if unicodedata.normalize("NFC", child) != child:
                raise InvalidJSONValue(f"non-NFC string at {path}")
        elif isinstance(child, list):
            stack.extend(
                (f"{path}[{index}]", item, depth + 1)
                for index, item in enumerate(child)
            )
        elif isinstance(child, dict):
            stack.extend(
                (f"{path}.{key}", item, depth + 1)
                for key, item in child.items()
            )
    return result


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value: str) -> datetime:
    return PROTOCOL.parse_time(value, "$.timestamp")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


def _canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def _encode_page_cursor(value: dict[str, Any]) -> str:
    encoded = base64.urlsafe_b64encode(_canonical_bytes(value)).rstrip(b"=").decode("ascii")
    if not encoded or len(encoded) > MAX_PAGE_CURSOR_LENGTH:
        raise RuntimeError("internal page cursor exceeds its wire bound")
    return encoded


def _decode_page_cursor(
    value: str | None,
    *,
    kind: str,
    session_id: str | None = None,
) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= MAX_PAGE_CURSOR_LENGTH
            or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
            or len(value) % 4 == 1
        ):
            raise ValueError("cursor encoding is invalid")
        padding = "=" * ((4 - len(value) % 4) % 4)
        raw = base64.b64decode(value + padding, altchars=b"-_", validate=True)
        document = strict_json_loads(raw)
        if not isinstance(document, dict) or _encode_page_cursor(document) != value:
            raise ValueError("cursor is not canonical")
        expected_keys_by_kind = {
            "sessions": {"version", "kind", "created_at", "session_id"},
            "candidates": {"version", "kind", "session_id", "candidate_id"},
            "jobs": {"version", "kind", "requested_at", "job_id"},
            "audit_events": {"version", "kind", "occurred_at", "event_id"},
        }
        expected_keys = expected_keys_by_kind.get(kind)
        if expected_keys is None:  # pragma: no cover - callers pin a known kind
            raise RuntimeError("unsupported internal page cursor kind")
        if (
            set(document) != expected_keys
            or document["version"] != PAGE_CURSOR_VERSION
            or document["kind"] != kind
        ):
            raise ValueError("cursor scope is invalid")
        if kind == "sessions":
            created_at = document["created_at"]
            cursor_session_id = document["session_id"]
            if (
                not isinstance(created_at, str)
                or timestamp(_parse_timestamp(created_at)) != created_at
                or not isinstance(cursor_session_id, str)
                or ID_PATTERN.fullmatch(cursor_session_id) is None
            ):
                raise ValueError("session cursor position is invalid")
        elif kind == "candidates":
            cursor_session_id = document["session_id"]
            candidate_id = document["candidate_id"]
            if (
                session_id is None
                or cursor_session_id != session_id
                or not isinstance(cursor_session_id, str)
                or ID_PATTERN.fullmatch(cursor_session_id) is None
                or not isinstance(candidate_id, str)
                or ID_PATTERN.fullmatch(candidate_id) is None
            ):
                raise ValueError("candidate cursor position is invalid")
        elif kind == "jobs":
            requested_at = document["requested_at"]
            job_id = document["job_id"]
            if (
                not isinstance(requested_at, str)
                or timestamp(_parse_timestamp(requested_at)) != requested_at
                or not isinstance(job_id, str)
                or ID_PATTERN.fullmatch(job_id) is None
            ):
                raise ValueError("job cursor position is invalid")
        elif kind == "audit_events":
            occurred_at = document["occurred_at"]
            event_id = document["event_id"]
            if (
                not isinstance(occurred_at, str)
                or timestamp(_parse_timestamp(occurred_at)) != occurred_at
                or not isinstance(event_id, str)
                or ID_PATTERN.fullmatch(event_id) is None
            ):
                raise ValueError("audit-event cursor position is invalid")
        return document
    except (
        binascii.Error,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        DuplicateJSONKey,
        InvalidJSONValue,
    ) as error:
        raise ApiError(400, "PAGE_CURSOR_INVALID", "Tacua-Page-Cursor is invalid") from error


def _require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        raise ApiError(400, "INVALID_IDENTIFIER", f"{field} is invalid")
    return value


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not DIGEST_PATTERN.fullmatch(value):
        raise ApiError(400, "INVALID_DIGEST", f"{field} must be a lowercase SHA-256 digest")
    return value


def _secret_bytes(value: Any) -> bytes | None:
    if not isinstance(value, str) or not 43 <= len(value) <= 128:
        return None
    if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        return None
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except ValueError:
        return None
    if len(decoded) != 32:
        return None
    return decoded


class PilotBackend:
    """SQLite/filesystem implementation of ``tacua.sdk-backend@1.0.0``."""

    def __init__(
        self,
        config: PilotConfig,
        admin_secret: bytes,
        *,
        clock: Callable[[], datetime] = utc_now,
        retention_wait: Callable[[threading.Event, float], bool] | None = None,
        processing_engine: ProcessingEngine | None = None,
    ):
        if not 32 <= len(admin_secret) <= 4096:
            raise ValueError("admin secret must contain from 32 through 4096 bytes")
        for name in ("organization_id", "project_id", "application_id", "reviewer_id"):
            if not ID_PATTERN.fullmatch(getattr(config, name)):
                raise ValueError(f"{name} is invalid")
        if not isinstance(config.build_identity, dict):
            raise ValueError("build_identity must be the full sealed SDK protocol artifact")
        try:
            validate(config.build_identity)
        except ContractError as exc:
            raise ValueError("build_identity is not a valid sealed SDK protocol artifact") from exc
        if config.build_identity.get("message_type") != "build_identity":
            raise ValueError("build_identity must have message_type build_identity")
        if not BUNDLE_ID_PATTERN.fullmatch(config.bundle_identifier):
            raise ValueError("bundle_identifier is invalid")
        if not ID_PATTERN.fullmatch(config.build_id):
            raise ValueError("build_identity.build_id is invalid")
        if not DIGEST_PATTERN.fullmatch(config.build_identity_digest):
            raise ValueError("build_identity_digest is invalid")
        if normalize_backend_origin(config.backend_origin) != config.backend_origin:
            raise ValueError("backend_origin is not normalized")
        if config.transport_policy_version != TRANSPORT_POLICY_VERSION:
            raise ValueError("transport_policy_version is unsupported")
        if (
            config.build_identity["transport_configuration_digest"]
            != config.transport_configuration_digest
        ):
            raise ValueError("build_identity transport configuration differs from deployment")
        validate_approved_handoff_config(config)
        if not all(
            1 <= value <= 30
            for value in (
                config.raw_retention_days,
                config.derived_retention_days,
                config.tombstone_retention_days,
            )
        ):
            raise ValueError("retention periods must be from 1 through 30 days")
        if config.raw_retention_days != config.derived_retention_days:
            raise ValueError(
                "V1 raw and derived retention periods must use one session boundary"
            )
        if not 300 <= config.credential_ttl_seconds <= 2_592_000:
            raise ValueError("credential_ttl_seconds is outside the V1 bound")
        if not 30 <= config.retention_sweep_interval_seconds <= 3600:
            raise ValueError("retention_sweep_interval_seconds is outside the V1 bound")
        if not callable(clock):
            raise ValueError("clock must be callable")
        if processing_engine is not None and not callable(
            getattr(processing_engine, "process_stage", None)
        ):
            raise ValueError("processing_engine must implement process_stage")
        self.config = config
        self._registered_build_identity = strict_json_loads(canonical_json(config.build_identity))
        self._registered_build_identity_json = canonical_json(self._registered_build_identity)
        self._approved_handoff = strict_json_loads(
            canonical_json(config.approved_handoff)
        )
        if not isinstance(self._approved_handoff, dict):  # pragma: no cover - startup validation invariant
            raise ValueError("approved_handoff configuration is invalid")
        self._admin_secret = bytes(admin_secret)
        self._verifier_key = hmac.new(
            self._admin_secret,
            b"tacua sdk credential verifier root v1",
            hashlib.sha256,
        ).digest()
        self._clock = clock
        self._retention_wait = retention_wait or self._wait_for_retention_interval
        self._processing_engine = processing_engine
        self.state_dir = config.state_directory
        if not self.state_dir.is_absolute() or self.state_dir == Path(self.state_dir.anchor):
            raise ValueError("state_directory must be an absolute non-root path")
        self.objects_dir = self.state_dir / "objects"
        self.temp_dir = self.state_dir / "tmp"
        self.derived_evidence_dir = self.state_dir / "derived-evidence"
        self.db_path = self.state_dir / "tacua.sqlite3"
        self._lock = threading.RLock()
        self._authoritative_time_lock = threading.Lock()
        self._authoritative_time_floor: datetime | None = None
        self._retention_worker_lock = threading.Lock()
        self._retention_stop = threading.Event()
        self._retention_thread: threading.Thread | None = None
        self._last_retention_sweep: dict[str, Any] | None = None
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.objects_dir.mkdir(exist_ok=True, mode=0o700)
        self.temp_dir.mkdir(exist_ok=True, mode=0o700)
        self.derived_evidence_dir.mkdir(exist_ok=True, mode=0o700)
        for directory in (
            self.state_dir,
            self.objects_dir,
            self.temp_dir,
            self.derived_evidence_dir,
        ):
            metadata = directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"backend state path is not a real directory: {directory}")
            if metadata.st_uid != os.geteuid():
                raise ValueError(
                    f"backend state path is not owned by the service user: {directory}"
                )
            directory.chmod(0o700)
        try:
            database_metadata = self.db_path.lstat()
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(database_metadata.st_mode) or stat.S_ISLNK(
                database_metadata.st_mode
            ):
                raise ValueError(
                    f"backend database path is not a regular file: {self.db_path}"
                )
            if database_metadata.st_uid != os.geteuid():
                raise ValueError("backend database is not owned by the service user")
        self._initialize_database()
        self.db_path.chmod(0o600)
        self._restore_authoritative_time_floor()
        self._initialize_review_storage()
        self._recover_pending_deletions()
        self._validate_persisted_credential_histories()
        self._reconcile_storage()
        self._validate_processing_publications_on_startup()

    @staticmethod
    def _wait_for_retention_interval(stop_event: threading.Event, seconds: float) -> bool:
        return stop_event.wait(seconds)

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        normalized = value.astimezone(timezone.utc).replace(microsecond=0)
        with self._authoritative_time_lock:
            if (
                self._authoritative_time_floor is not None
                and normalized < self._authoritative_time_floor
            ):
                return self._authoritative_time_floor
        return normalized

    def _advance_authoritative_time_floor(self, value: datetime) -> None:
        normalized = value.astimezone(timezone.utc).replace(microsecond=0)
        with self._authoritative_time_lock:
            if (
                self._authoritative_time_floor is None
                or self._authoritative_time_floor < normalized
            ):
                self._authoritative_time_floor = normalized

    def _restore_authoritative_time_floor(self) -> None:
        """Keep protocol timestamps monotonic after a same-second rotation or restart."""

        with self._connect() as conn:
            row = conn.execute(
                """SELECT MAX(event_at) AS event_at FROM (
                       SELECT created_at AS event_at FROM sessions
                       UNION ALL SELECT issued_at FROM credentials
                       UNION ALL SELECT created_at FROM launch_grants
                       UNION ALL SELECT accepted_at FROM segments
                       UNION ALL SELECT accepted_at FROM diagnostics
                       UNION ALL SELECT accepted_at FROM completions
                       UNION ALL SELECT recorded_at FROM tacua_processing_job_versions
                       UNION ALL SELECT acquired_at FROM tacua_processing_job_leases
                       UNION ALL SELECT renewed_at FROM tacua_processing_job_leases
                       UNION ALL SELECT accepted_at FROM pending_deletions
                       UNION ALL SELECT deleted_at FROM tombstones
                       UNION ALL SELECT occurred_at FROM audit_events
                   )"""
            ).fetchone()
        if row is not None and row["event_at"] is not None:
            self._advance_authoritative_time_floor(_parse_timestamp(row["event_at"]))

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, factory=ClosingConnection)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        conn.execute("PRAGMA secure_delete = ON")
        return conn

    def _initialize_database(self) -> None:
        if self.db_path.exists():
            with self._connect() as conn:
                version = conn.execute("PRAGMA user_version").fetchone()[0]
                tables = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
                credential_schema = conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'credentials'"
                ).fetchone()
            if version not in {0, SCHEMA_VERSION}:
                raise ValueError(
                    "persisted backend schema is incompatible with the frozen SDK protocol; "
                    "back up and start with an empty state directory"
                )
            if version == 0 and tables:
                raise ValueError("unversioned backend state is not safe to adopt")
            if version == SCHEMA_VERSION and (
                credential_schema is None
                or not isinstance(credential_schema["sql"], str)
                or CREDENTIAL_ORDINAL_CHECK_SQL not in credential_schema["sql"]
            ):
                raise ValueError(
                    "persisted backend schema-v2 credential constraint is incompatible; "
                    "back up and start with an empty state directory"
                )

        schema = """
        CREATE TABLE IF NOT EXISTS deployment_pin (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            pin_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            state TEXT NOT NULL CHECK (state IN ('receiving','completed','deleting')),
            scope_digest TEXT NOT NULL,
            scope_json TEXT NOT NULL,
            build_identity_digest TEXT NOT NULL,
            build_identity_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            raw_media_expires_at TEXT NOT NULL,
            derived_data_expires_at TEXT NOT NULL,
            completion_id TEXT
        );
        CREATE TABLE IF NOT EXISTS credentials (
            credential_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 63),
            verifier TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            issued_session_state TEXT NOT NULL,
            issued_state TEXT NOT NULL,
            current_state TEXT NOT NULL,
            replay_completion_id TEXT,
            UNIQUE (session_id, ordinal)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS one_current_credential
            ON credentials(session_id) WHERE revoked_at IS NULL;
        CREATE TABLE IF NOT EXISTS launch_grants (
            launch_id TEXT PRIMARY KEY,
            code_verifier TEXT NOT NULL UNIQUE,
            exchange_kind TEXT NOT NULL,
            pinned_session_id TEXT,
            pinned_previous_credential_id TEXT,
            build_identity_json TEXT NOT NULL,
            scope_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            exchange_id TEXT UNIQUE,
            request_digest TEXT,
            response_bytes BLOB
        );
        CREATE TABLE IF NOT EXISTS segments (
            session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
            upload_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            segment_id TEXT NOT NULL,
            source_credential_id TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            request_json TEXT NOT NULL,
            response_bytes BLOB NOT NULL,
            object_id TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            content_type TEXT NOT NULL,
            content_digest TEXT NOT NULL,
            sidecar_digest TEXT NOT NULL,
            accepted_at TEXT NOT NULL,
            PRIMARY KEY (session_id, upload_id),
            UNIQUE (session_id, sequence),
            UNIQUE (session_id, segment_id),
            UNIQUE (object_id)
        );
        CREATE TABLE IF NOT EXISTS diagnostics (
            session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
            upload_id TEXT NOT NULL,
            envelope_id TEXT NOT NULL,
            source_credential_id TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            request_json TEXT NOT NULL,
            response_bytes BLOB NOT NULL,
            object_id TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            content_digest TEXT NOT NULL,
            accepted_at TEXT NOT NULL,
            PRIMARY KEY (session_id, upload_id),
            UNIQUE (session_id, envelope_id),
            UNIQUE (object_id)
        );
        CREATE TABLE IF NOT EXISTS completions (
            session_id TEXT PRIMARY KEY REFERENCES sessions(session_id) ON DELETE CASCADE,
            completion_id TEXT NOT NULL,
            source_credential_id TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            request_json TEXT NOT NULL,
            response_bytes BLOB NOT NULL,
            relative_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            content_digest TEXT NOT NULL,
            accepted_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            status TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            job_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pending_deletions (
            session_id TEXT PRIMARY KEY REFERENCES sessions(session_id) ON DELETE CASCADE,
            deletion_id TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            request_json TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            replay_verifier TEXT NOT NULL,
            accepted_at TEXT NOT NULL,
            erased_object_count INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tombstones (
            session_id TEXT PRIMARY KEY,
            deletion_id TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            scope_digest TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            replay_verifier TEXT NOT NULL,
            response_bytes BLOB NOT NULL,
            accepted_at TEXT NOT NULL,
            deleted_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            actor_kind TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            session_id TEXT,
            outcome TEXT NOT NULL,
            occurred_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS sessions_retention_idx ON sessions(raw_media_expires_at, state);
        CREATE INDEX IF NOT EXISTS sessions_admin_list_idx ON sessions(created_at DESC, session_id DESC);
        CREATE INDEX IF NOT EXISTS audit_session_idx ON audit_events(session_id, occurred_at);
        CREATE INDEX IF NOT EXISTS audit_admin_list_idx
            ON audit_events(occurred_at DESC, event_id DESC);
        CREATE INDEX IF NOT EXISTS jobs_status_idx ON jobs(status, requested_at);
        CREATE INDEX IF NOT EXISTS jobs_admin_list_idx
            ON jobs(requested_at DESC, job_id DESC);
        """
        pin_json = canonical_json(self.config.deployment_pin)
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(schema)
            pinned = conn.execute("SELECT pin_json FROM deployment_pin WHERE singleton = 1").fetchone()
            if pinned is None:
                conn.execute("INSERT INTO deployment_pin(singleton, pin_json) VALUES (1, ?)", (pin_json,))
            elif pinned["pin_json"] != pin_json:
                raise ValueError("configured deployment pin differs from persisted state")
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        with self._connect() as conn:
            try:
                initialize_processing_job_schema(conn)
            except (ContractError, ProcessingJobStoreError, sqlite3.Error, ValueError) as error:
                raise ValueError(
                    "persisted processing-job state failed safe schema-v2 adoption"
                ) from error

    def _validate_persisted_credential_histories(self) -> None:
        """Fail closed when durable credential state cannot satisfy the V1 bound.

        Pending deletions are recovered before this check because their durable
        crash boundary legitimately revokes every credential. Any session still
        present here must have one bounded, contiguous credential chain.
        """

        invalid_message = (
            "persisted backend credential history failed safe schema-v2 adoption; "
            "back up and start with an empty state directory"
        )
        with self._connect() as conn:
            orphan = conn.execute(
                """SELECT 1 FROM credentials
                   LEFT JOIN sessions ON sessions.session_id = credentials.session_id
                   WHERE sessions.session_id IS NULL LIMIT 1"""
            ).fetchone()
            if orphan is not None:
                raise ValueError(invalid_message)

            sessions = conn.execute(
                "SELECT session_id,state,completion_id FROM sessions ORDER BY session_id"
            )
            for session in sessions:
                credentials = conn.execute(
                    """SELECT ordinal,revoked_at,issued_session_state,issued_state,
                              current_state,replay_completion_id
                         FROM credentials WHERE session_id = ?
                         ORDER BY ordinal LIMIT ?""",
                    (session["session_id"], MAX_SESSION_CREDENTIALS + 1),
                ).fetchall()
                if (
                    not 1 <= len(credentials) <= MAX_SESSION_CREDENTIALS
                    or [row["ordinal"] for row in credentials]
                    != list(range(len(credentials)))
                ):
                    raise ValueError(invalid_message)

                current = [row for row in credentials if row["revoked_at"] is None]
                if len(current) != 1 or current[0]["ordinal"] != len(credentials) - 1:
                    raise ValueError(invalid_message)

                session_state = session["state"]
                completion_id = session["completion_id"]
                if (
                    (session_state == "receiving" and completion_id is not None)
                    or (session_state == "completed" and completion_id is None)
                    or session_state not in {"receiving", "completed"}
                ):
                    raise ValueError(invalid_message)

                for credential in credentials:
                    issued_session_state = credential["issued_session_state"]
                    expected_issued_state = {
                        "receiving": "active",
                        "completed": "completion_replay_or_delete_only",
                    }.get(issued_session_state)
                    replay_completion_id = credential["replay_completion_id"]
                    if (
                        expected_issued_state is None
                        or credential["issued_state"] != expected_issued_state
                        or (
                            issued_session_state == "completed"
                            and (
                                session_state != "completed"
                                or replay_completion_id != completion_id
                            )
                        )
                        or (
                            replay_completion_id is not None
                            and (
                                session_state != "completed"
                                or replay_completion_id != completion_id
                            )
                        )
                    ):
                        raise ValueError(invalid_message)

                    if credential["revoked_at"] is not None:
                        if credential["current_state"] != "revoked":
                            raise ValueError(invalid_message)
                        continue
                    expected_current_state = (
                        "active"
                        if session_state == "receiving"
                        else "completion_replay_or_delete_only"
                    )
                    if (
                        credential["current_state"] != expected_current_state
                        or (
                            session_state == "receiving"
                            and replay_completion_id is not None
                        )
                        or (
                            session_state == "completed"
                            and replay_completion_id != completion_id
                        )
                    ):
                        raise ValueError(invalid_message)

    def _initialize_review_storage(self) -> None:
        """Initialize append-only review state before serving concurrent requests."""

        self._candidate_store().initialize_schema()
        with self._connect() as conn:
            initialize_evidence_schema(conn)
            initialize_handoff_schema(conn)
            EvidenceStore(conn, self.derived_evidence_dir).recover_file_journal()

    def _candidate_store(self) -> CandidateStore:
        return CandidateStore(
            self._connect,
            organization_id=self.config.organization_id,
            project_id=self.config.project_id,
            reviewer_id=self.config.reviewer_id,
            clock=self._clock,
            approval_guard=self._verify_candidate_approval_evidence,
            generated_insert_guard=self._verify_generated_candidate_publication,
            version_append_guard=self._append_candidate_evidence_version,
            replacement_manifest_factory=self._replacement_manifest,
            replacement_result_guard=self._bind_replacement_results,
        )

    def _evidence_store(self, connection: sqlite3.Connection) -> EvidenceStore:
        return EvidenceStore(connection, self.derived_evidence_dir)

    def _handoff_store(self, connection: sqlite3.Connection) -> HandoffStore:
        return HandoffStore(
            connection,
            organization_id=self.config.organization_id,
            project_id=self.config.project_id,
        )

    def _processing_job_store(self, connection: sqlite3.Connection) -> ProcessingJobStore:
        return ProcessingJobStore(
            connection,
            organization_id=self.config.organization_id,
            project_id=self.config.project_id,
            now=self._now,
            token_verifier=lambda job_id, version, token: self._verifier(
                "processing_lease", f"{job_id}:{version}", token
            ),
            token_factory=lambda: secrets.token_urlsafe(32),
            successful_output_validator=self._validate_processing_result_publication,
        )

    @staticmethod
    def _raise_processing_job_error(error: ProcessingJobStoreError) -> None:
        raise ApiError(error.status, error.code, error.message) from error

    def _validate_processing_result_publication(
        self,
        connection: sqlite3.Connection,
        job: dict[str, Any],
    ) -> None:
        """Resolve every successful output back to exact durable artifacts."""

        outputs = job.get("outputs")
        if job.get("status") != "succeeded" or not isinstance(outputs, dict):
            raise ValueError("processing publication validator requires a successful job")
        candidate_refs = outputs["candidate_refs"]
        evidence_refs = outputs["derived_evidence_refs"]
        published_candidate_ids = [
            row["candidate_id"]
            for row in connection.execute(
                """SELECT candidate_id FROM candidate_versions
                    WHERE organization_id = ? AND project_id = ?
                      AND session_id = ? AND candidate_version = 1
                    ORDER BY candidate_id""",
                (job["organization_id"], job["project_id"], job["session_id"]),
            )
        ]
        if outputs["disposition"] == "no_issue_detected":
            if candidate_refs or evidence_refs or published_candidate_ids:
                raise ValueError("no-issue result references published artifacts")
            return

        expected_refs: list[dict[str, Any]] = []
        expected_evidence: set[str] = set()
        publication_actors: set[str] = set()
        evidence = self._evidence_store(connection)
        for reference in candidate_refs:
            if reference["candidate_version"] != 1:
                raise ValueError("processing output must reference generated version one")
            candidate = self._candidate_from_connection(
                connection, reference["candidate_id"], reference["candidate_version"]
            )
            if (
                candidate["candidate_version"] != 1
                or candidate["previous_candidate_digest"] is not None
                or candidate["lineage"] != {"operation": "generated", "parents": []}
                or candidate["state"] != "draft"
                or candidate["transition"]["actor"]["actor_type"] != "system"
                or candidate["organization_id"] != job["organization_id"]
                or candidate["project_id"] != job["project_id"]
                or candidate["session_id"] != job["session_id"]
                or candidate["build_id"] != job["build_id"]
                or candidate["build_identity_digest"]
                != job["build_identity_digest"]
            ):
                raise ValueError("processing output candidate binding changed")
            binding = self._candidate_binding(candidate)
            manifest = evidence.get_manifest(**binding)
            if (
                manifest["manifest_id"]
                != candidate["evidence_manifest"]["manifest_id"]
                or manifest["manifest_digest"]
                != candidate["evidence_manifest"]["manifest_digest"]
                or sorted(item["evidence_id"] for item in manifest["items"])
                != sorted(candidate["evidence_manifest"]["evidence_ids"])
            ):
                raise ValueError("processing output evidence binding changed")
            keyframes = [
                item["evidence_id"]
                for item in manifest["items"]
                if item["evidence_type"] == "media.keyframe"
                and item["availability"] == "available"
            ]
            if not keyframes:
                raise ValueError("processing output has no available screenshot")
            verified = evidence.get_verified_keyframes_for_approval(
                evidence_ids=keyframes,
                **binding,
            )
            if len(verified["verified_keyframes"]) != len(keyframes):
                raise ValueError("processing output screenshot population changed")
            expected_refs.append(
                {
                    "candidate_id": candidate["candidate_id"],
                    "candidate_version": candidate["candidate_version"],
                }
            )
            expected_evidence.update(candidate["evidence_manifest"]["evidence_ids"])
            publication_actors.add(candidate["transition"]["actor"]["actor_id"])

        if (
            candidate_refs
            != sorted(expected_refs, key=lambda item: item["candidate_id"])
            or [item["candidate_id"] for item in candidate_refs]
            != published_candidate_ids
            or evidence_refs != sorted(expected_evidence)
            or len(publication_actors) != 1
        ):
            raise ValueError("processing output references differ from published artifacts")

    def _validate_processing_publications_on_startup(self) -> None:
        """Fail closed before serving if a successful output cannot be resolved."""

        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                self._processing_job_store(connection).list()
        except (ApiError, EvidenceDomainError, ProcessingJobStoreError, sqlite3.Error) as error:
            raise ValueError(
                "persisted successful processing publication failed validation"
            ) from error

    def _verified_candidate_publication_manifest(
        self,
        connection: sqlite3.Connection,
        candidate: dict[str, Any],
    ) -> tuple[EvidenceStore, dict[str, Any]]:
        """Recheck the complete session/build/evidence publication boundary.

        Callers invoke this only while their own ``BEGIN IMMEDIATE`` is
        active.  That makes the checks and the guarded evidence/candidate
        write one SQLite serialization point, independently of the V1
        process-wide lock.
        """

        session = self._require_review_session(
            connection,
            candidate["session_id"],
            require_completed=True,
        )
        now = self._now()
        try:
            raw_expires = _parse_timestamp(session["raw_media_expires_at"])
            derived_expires = _parse_timestamp(session["derived_data_expires_at"])
            scope_raw = session["scope_json"]
            build_raw = session["build_identity_json"]
            scope = self._decode_protocol_object(scope_raw)
            build = self._decode_protocol_object(build_raw)
            validate(scope)
            validate(build)
        except (KeyError, TypeError, ValueError, ContractError) as error:
            raise ApiError(
                500,
                "CANDIDATE_SESSION_BINDING_CORRUPT",
                "stored candidate session binding failed validation",
            ) from error

        if raw_expires != derived_expires:
            raise ApiError(
                500,
                "CANDIDATE_SESSION_BINDING_CORRUPT",
                "stored candidate session retention boundaries differ",
            )
        if derived_expires <= now:
            raise ApiError(
                410,
                "SESSION_RETENTION_EXPIRED",
                "session retention has expired",
            )
        if connection.execute(
            "SELECT 1 FROM pending_deletions WHERE session_id = ?",
            (candidate["session_id"],),
        ).fetchone() is not None:
            raise ApiError(410, "SESSION_DELETED", "session deletion is in progress")

        scope_text = scope_raw.decode("utf-8") if isinstance(scope_raw, bytes) else scope_raw
        build_text = build_raw.decode("utf-8") if isinstance(build_raw, bytes) else build_raw
        if (
            not isinstance(scope_text, str)
            or not isinstance(build_text, str)
            or canonical_json(scope) != scope_text
            or canonical_json(build) != build_text
            or canonical_json(build) != self._registered_build_identity_json
            or scope["scope_digest"] != session["scope_digest"]
            or build["build_identity_digest"] != session["build_identity_digest"]
            or candidate["organization_id"] != self.config.organization_id
            or candidate["project_id"] != self.config.project_id
            or candidate["build_id"] != self.config.build_id
            or candidate["build_identity_digest"] != self.config.build_identity_digest
            or candidate["build_id"] != build["build_id"]
            or candidate["build_identity_digest"] != build["build_identity_digest"]
            or scope["organization_id"] != candidate["organization_id"]
            or scope["project_id"] != candidate["project_id"]
            or scope["application_id"] != self.config.application_id
            or scope["build_id"] != candidate["build_id"]
            or scope["build_identity_digest"] != candidate["build_identity_digest"]
        ):
            raise ApiError(
                500,
                "CANDIDATE_SESSION_BINDING_CORRUPT",
                "stored candidate session binding changed",
            )

        evidence = self._evidence_store(connection)
        manifest = evidence.get_manifest(**self._candidate_binding(candidate))
        if (
            manifest["organization_id"] != candidate["organization_id"]
            or manifest["project_id"] != candidate["project_id"]
            or manifest["session_id"] != candidate["session_id"]
            or manifest["manifest_id"]
            != candidate["evidence_manifest"]["manifest_id"]
            or manifest["manifest_digest"]
            != candidate["evidence_manifest"]["manifest_digest"]
            or {item["evidence_id"] for item in manifest["items"]}
            != set(candidate["evidence_manifest"]["evidence_ids"])
        ):
            raise ApiError(
                409,
                "CANDIDATE_EVIDENCE_MISMATCH",
                "candidate evidence binding changed during publication",
            )
        return evidence, manifest

    def _verify_generated_candidate_publication(
        self,
        connection: sqlite3.Connection,
        candidate: dict[str, Any],
    ) -> None:
        """Final fail-closed check inside the generated-head transaction."""

        evidence, manifest = self._verified_candidate_publication_manifest(
            connection, candidate
        )
        processing = connection.execute(
            "SELECT status FROM jobs WHERE session_id = ?", (candidate["session_id"],)
        ).fetchone()
        if processing is None or processing["status"] == "succeeded":
            raise ApiError(
                409,
                "PROCESSING_PUBLICATION_CLOSED",
                "processing output candidate publication is closed",
            )
        keyframe_ids = [
            item["evidence_id"]
            for item in manifest["items"]
            if item["evidence_type"] == "media.keyframe"
            and item["availability"] == "available"
        ]
        if not keyframe_ids:
            raise ApiError(
                409,
                "CANDIDATE_SCREENSHOT_REQUIRED",
                "candidate publication requires a bound available screenshot",
            )
        evidence.get_verified_keyframes_for_approval(
            evidence_ids=keyframe_ids,
            **self._candidate_binding(candidate),
        )

    def _candidate_preview_transaction_guard(
        self, candidate: dict[str, Any]
    ) -> Callable[[sqlite3.Connection], None]:
        """Create a closed guard from an already contract-validated candidate.

        ``EvidenceStore.put_preview`` receives this callback explicitly; none
        of the preview/request fields can replace or influence the callback.
        """

        snapshot = strict_json_loads(canonical_json(candidate))
        if not isinstance(snapshot, dict):  # pragma: no cover - validated caller invariant
            raise ApiError(500, "CANDIDATE_STORAGE_CORRUPT", "candidate snapshot is invalid")

        def guard(connection: sqlite3.Connection) -> None:
            self._verified_candidate_publication_manifest(connection, snapshot)

        return guard

    def _verify_candidate_approval_evidence(
        self,
        connection: sqlite3.Connection,
        parent: dict[str, Any],
    ) -> None:
        self._require_review_session(connection, parent["session_id"])
        evidence = self._evidence_store(connection)
        binding = self._candidate_binding(parent)
        manifest = evidence.get_manifest(**binding)
        candidate_ids = set(parent["evidence_manifest"]["evidence_ids"])
        if candidate_ids != {item["evidence_id"] for item in manifest["items"]}:
            raise CandidateStoreError(
                409,
                "CANDIDATE_EVIDENCE_MISMATCH",
                "candidate evidence membership changed",
            )
        referenced_ids = TICKET_CONTRACT.content_evidence_refs(parent["content"])
        keyframe_ids = [
            item["evidence_id"]
            for item in manifest["items"]
            if item["evidence_id"] in referenced_ids
            and item["evidence_type"] == "media.keyframe"
            and item["availability"] == "available"
        ]
        if not keyframe_ids:
            raise CandidateStoreError(
                409,
                "CANDIDATE_SCREENSHOT_REQUIRED",
                "approval requires an available screenshot referenced by ticket content",
            )
        verified = evidence.get_verified_keyframes_for_approval(
            evidence_ids=keyframe_ids,
            **binding,
        )
        if verified["authorized_for_handoff"] is not False:
            raise CandidateStoreError(
                500,
                "CANDIDATE_EVIDENCE_CORRUPT",
                "review evidence cannot grant handoff authority",
            )
        for keyframe in verified["verified_keyframes"]:
            if evidence_sha256_digest(keyframe["body"]) != keyframe["content_digest"]:
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_EVIDENCE_CORRUPT",
                    "verified screenshot bytes changed during approval",
                )

    def _append_candidate_evidence_version(
        self,
        connection: sqlite3.Connection,
        parent: dict[str, Any],
        candidate: dict[str, Any],
    ) -> None:
        self._require_review_session(connection, parent["session_id"])
        evidence = self._evidence_store(connection)
        manifest = evidence.get_manifest(**self._candidate_binding(parent))
        if (
            candidate["session_id"] != parent["session_id"]
            or candidate["evidence_manifest"] != parent["evidence_manifest"]
        ):
            raise CandidateStoreError(
                409,
                "CANDIDATE_EVIDENCE_MISMATCH",
                "review transition changed immutable evidence binding",
            )
        binding = self._candidate_binding(candidate)
        binding.pop("manifest_digest")
        evidence.put_manifest(manifest=manifest, **binding)
        if candidate["state"] == "approved":
            _, approved_manifest = self._verified_candidate_publication_manifest(
                connection, candidate
            )
            self._persist_approved_candidate_handoff(
                connection,
                candidate=candidate,
                evidence_manifest=approved_manifest,
            )

    def _replacement_manifest(
        self,
        connection: sqlite3.Connection,
        operation: str,
        sources: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Verify source evidence and construct the canonical merge union."""

        if operation not in {"split", "merge"} or not sources:
            raise CandidateStoreError(
                500,
                "CANDIDATE_REPLACEMENT_INVALID",
                "candidate replacement evidence request is invalid",
            )
        evidence = self._evidence_store(connection)
        manifests: list[dict[str, Any]] = []
        for source in sources:
            self._require_review_session(connection, source["session_id"])
            manifest = evidence.get_manifest(**self._candidate_binding(source))
            if (
                manifest["manifest_id"]
                != source["evidence_manifest"]["manifest_id"]
                or manifest["manifest_digest"]
                != source["evidence_manifest"]["manifest_digest"]
                or {item["evidence_id"] for item in manifest["items"]}
                != set(source["evidence_manifest"]["evidence_ids"])
            ):
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_EVIDENCE_CORRUPT",
                    "candidate replacement evidence binding changed",
                )
            manifests.append(manifest)
        if operation == "split":
            return copy.deepcopy(manifests[0])

        items_by_id: dict[str, dict[str, Any]] = {}
        for manifest in manifests:
            for item in manifest["items"]:
                existing = items_by_id.get(item["evidence_id"])
                if existing is not None and canonical_json(existing) != canonical_json(item):
                    raise CandidateStoreError(
                        409,
                        "MERGE_EVIDENCE_ID_CONFLICT",
                        "merge sources contain conflicting immutable evidence identities",
                    )
                items_by_id[item["evidence_id"]] = copy.deepcopy(item)
        if len(items_by_id) > 100:
            raise CandidateStoreError(
                409,
                "MERGE_EVIDENCE_LIMIT_EXCEEDED",
                "merged evidence union exceeds 100 items",
            )
        ordered_items = [items_by_id[key] for key in sorted(items_by_id)]
        identity_digest = evidence_sha256_digest(
            canonical_json(
                {
                    "operation": "merge",
                    "organization_id": sources[0]["organization_id"],
                    "project_id": sources[0]["project_id"],
                    "session_id": sources[0]["session_id"],
                    "items": [
                        {
                            "evidence_id": item["evidence_id"],
                            "evidence_item_digest": item["evidence_item_digest"],
                        }
                        for item in ordered_items
                    ],
                }
            )
        )
        return seal_evidence_manifest(
            {
                "contract_version": manifests[0]["contract_version"],
                "media_type": manifests[0]["media_type"],
                "organization_id": sources[0]["organization_id"],
                "project_id": sources[0]["project_id"],
                "session_id": sources[0]["session_id"],
                "manifest_id": "manifest_merge_"
                + identity_digest.removeprefix("sha256:")[:40],
                "items": ordered_items,
                "manifest_digest": "sha256:" + "0" * 64,
            }
        )

    def _bind_replacement_results(
        self,
        connection: sqlite3.Connection,
        operation: str,
        sources: list[dict[str, Any]],
        results: list[dict[str, Any]],
        manifest: dict[str, Any],
    ) -> None:
        """Bind every result to evidence inside the replacement transaction."""

        _ = (operation, sources)
        evidence = self._evidence_store(connection)
        for candidate in results:
            binding = self._candidate_binding(candidate)
            binding.pop("manifest_digest")
            stored = evidence.put_manifest(manifest=manifest, **binding)
            if (
                stored["manifest_id"] != candidate["evidence_manifest"]["manifest_id"]
                or stored["manifest_digest"]
                != candidate["evidence_manifest"]["manifest_digest"]
                or set(stored["evidence_ids"])
                != set(candidate["evidence_manifest"]["evidence_ids"])
                or stored["authorized_for_handoff"] is not False
            ):
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_EVIDENCE_CORRUPT",
                    "replacement result evidence binding changed",
                )
        if operation == "merge":
            evidence.inherit_latest_previews(
                source_bindings=[self._candidate_binding(source) for source in sources],
                target_binding=self._candidate_binding(results[0]),
            )

    def _persist_approved_candidate_handoff(
        self,
        connection: sqlite3.Connection,
        *,
        candidate: dict[str, Any],
        evidence_manifest: dict[str, Any],
    ) -> None:
        """Export and store a handoff in the candidate approval transaction."""

        store = self._handoff_store(connection)
        try:
            try:
                current = store.get(candidate["candidate_id"])
            except HandoffStoreError as error:
                if error.code != "HANDOFF_NOT_FOUND":
                    raise
                current = None
            session = self._require_review_session(
                connection,
                candidate["session_id"],
                require_completed=True,
            )
            sdk_build = self._decode_protocol_object(session["build_identity_json"])
            approved_at = _parse_timestamp(candidate["approval"]["approved_at"])
            artifacts = export_approved_candidate(
                candidate=candidate,
                evidence_manifest=evidence_manifest,
                sdk_build_identity=sdk_build,
                handoff_build_identity=self._approved_handoff["build_identity"],
                authority=self._approved_handoff["authority"],
                registry_revision=self._approved_handoff["registry_revision"],
                checked_at=max(approved_at, self._now()),
                supersedes_handoff_digest=(
                    None if current is None else current.handoff_digest
                ),
            )
            store.put(candidate, artifacts)
        except HandoffStoreError as error:
            status = 409 if error.code in {
                "HANDOFF_VERSION_COLLISION",
                "HANDOFF_SUPERSESSION_MISMATCH",
                "HANDOFF_STORAGE_CONFLICT",
            } else 500
            raise CandidateStoreError(
                status,
                error.code,
                "approved handoff could not be persisted",
            ) from error
        except (HandoffExportError, sqlite3.Error) as error:
            raise CandidateStoreError(
                500,
                "HANDOFF_EXPORT_FAILED",
                "approved handoff could not be exported",
            ) from error

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _file_digest(path: Path) -> tuple[int, str] | None:
        """Hash one exact non-linked file without following its final component."""

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != os.geteuid()
            ):
                raise ValueError("state object is not one service-owned regular file")
            hasher = hashlib.sha256()
            size = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                hasher.update(chunk)
                size += len(chunk)
            after = os.fstat(descriptor)
            if (
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                or size != before.st_size
            ):
                raise ValueError("state object changed while it was verified")
            return size, "sha256:" + hasher.hexdigest()
        finally:
            os.close(descriptor)

    def _object_path(
        self,
        relative_path: str,
        *,
        expected_session_id: str | None = None,
        expected_category: str | None = None,
    ) -> Path:
        """Resolve only Tacua's closed object layout without following links."""

        if not isinstance(relative_path, str):
            raise ValueError("persisted object path is not text")
        relative = Path(relative_path)
        parts = relative.parts
        suffixes = {
            "segments": "media",
            "diagnostics": "json",
            "completion": "json",
        }
        if (
            relative.is_absolute()
            or len(parts) != 4
            or parts[0] != "objects"
            or any(part in {"", ".", ".."} for part in parts)
            or ID_PATTERN.fullmatch(parts[1]) is None
            or parts[2] not in suffixes
            or (
                expected_session_id is not None
                and parts[1] != expected_session_id
            )
            or (
                expected_category is not None
                and parts[2] != expected_category
            )
        ):
            raise ValueError("persisted object path escaped its closed storage scope")
        stem, separator, suffix = parts[3].rpartition(".")
        if (
            separator != "."
            or ID_PATTERN.fullmatch(stem) is None
            or suffix != suffixes[parts[2]]
        ):
            raise ValueError("persisted object file name is invalid")

        candidate = self.state_dir.joinpath(*parts)
        current = self.state_dir
        for part in parts[:-1]:
            current = current / part
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                break
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ValueError("persisted object parent is not a real directory")
        try:
            final_metadata = candidate.lstat()
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(final_metadata.st_mode) or stat.S_ISLNK(
                final_metadata.st_mode
            ):
                raise ValueError("persisted object is not a regular file")
        return candidate

    def _reconcile_storage(self) -> None:
        """Remove crash orphans and fail closed if committed bytes disappeared."""

        changed = False
        for entry in self.temp_dir.iterdir():
            if entry.name.startswith("processing-"):
                if entry.is_symlink():
                    entry.unlink()
                    changed = True
                    continue
                if not entry.is_dir():
                    raise ValueError(
                        f"unrecognized processing temporary path: {entry.name}"
                    )
                for root, directories, files in os.walk(
                    entry, topdown=False, followlinks=False
                ):
                    root_path = Path(root)
                    for name in files:
                        (root_path / name).unlink()
                    for name in directories:
                        child = root_path / name
                        if child.is_symlink():
                            child.unlink()
                        else:
                            child.rmdir()
                entry.rmdir()
                changed = True
                continue
            if entry.is_symlink() or not entry.is_file():
                raise ValueError(f"unrecognized backend temporary path: {entry.name}")
            if not entry.name.startswith(("segment-", "diagnostic-", "completion-")):
                raise ValueError(f"unrecognized backend temporary file: {entry.name}")
            entry.unlink()
            changed = True
        if changed:
            self._fsync_directory(self.temp_dir)

        with self._connect() as conn:
            expected_rows = []
            for table, category in (
                ("segments", "segments"),
                ("diagnostics", "diagnostics"),
                ("completions", "completion"),
            ):
                expected_rows.extend(
                    (
                        row["relative_path"],
                        row["size_bytes"],
                        row["content_digest"],
                        row["session_id"],
                        category,
                    )
                    for row in conn.execute(
                        f"SELECT relative_path,size_bytes,content_digest,session_id FROM {table}"
                    )
                )
        expected = {relative for relative, _, _, _, _ in expected_rows}
        for relative, size, content_digest, session_id, category in expected_rows:
            path = self._object_path(
                relative,
                expected_session_id=session_id,
                expected_category=category,
            )
            if self._file_digest(path) != (size, content_digest):
                raise ValueError(f"committed backend object is unavailable or changed: {relative}")

        for entry in sorted(self.objects_dir.rglob("*"), reverse=True):
            if entry.is_symlink():
                raise ValueError(f"symlink is forbidden in backend object storage: {entry}")
            if entry.is_file():
                relative = str(entry.relative_to(self.state_dir))
                if relative not in expected:
                    entry.unlink()
            elif entry.is_dir() and entry != self.objects_dir:
                try:
                    entry.rmdir()
                except OSError:
                    pass
        self._fsync_directory(self.objects_dir)

    def _verifier(self, domain: str, identifier: str, secret: str) -> str:
        subject = f"{domain}\0{identifier}\0{secret}".encode("utf-8")
        return "hmac-sha256:" + hmac.new(self._verifier_key, subject, hashlib.sha256).hexdigest()

    def _credential_verifier(self, credential_id: str, secret: str) -> str:
        return self._verifier("credential", credential_id, secret)

    def _launch_verifier(self, launch_code: str) -> str:
        return self._verifier("launch", "launch_code", launch_code)

    @staticmethod
    def _decode_protocol_object(raw: bytes | str) -> dict[str, Any]:
        value = strict_json_loads(raw)
        if not isinstance(value, dict):
            raise ValueError("stored protocol artifact is not an object")
        return value

    @staticmethod
    def _validate_protocol(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ApiError(422, "PROTOCOL_INVALID", "protocol request must be a JSON object")
        try:
            validate(value)
        except ContractError as exc:
            raise ApiError(422, "PROTOCOL_INVALID", "request does not satisfy the frozen protocol") from exc
        return value

    def _validate_pins(self, build: dict[str, Any], scope: dict[str, Any]) -> None:
        try:
            validate(build)
            validate(scope)
        except ContractError as exc:
            raise ApiError(422, "PROTOCOL_INVALID", "build identity or capture scope is invalid") from exc
        if (
            canonical_json(build) != self._registered_build_identity_json
        ):
            raise ApiError(403, "BUILD_NOT_AUTHORIZED", "build identity is outside the deployment pin")
        if (
            scope["organization_id"] != self.config.organization_id
            or scope["project_id"] != self.config.project_id
            or scope["application_id"] != self.config.application_id
            or scope["build_id"] != self.config.build_id
            or scope["build_identity_digest"] != self.config.build_identity_digest
            or scope["consent"]["policy_version"] != self.config.consent_contract
            or scope["retention"]["policy_version"] != RETENTION_POLICY_VERSION
            or scope["retention"]["raw_media_days"] != self.config.raw_retention_days
            or scope["retention"]["derived_data_days"] != self.config.derived_retention_days
        ):
            raise ApiError(403, "SCOPE_NOT_AUTHORIZED", "capture scope is outside the deployment pin")

    def _capture_scope_policy(self) -> dict[str, Any]:
        """Return the launch-time policy, excluding post-consent dynamic fields."""

        return {
            "contract_version": SCOPE_POLICY_CONTRACT,
            "protocol_version": PROTOCOL_VERSION,
            "organization_id": self.config.organization_id,
            "project_id": self.config.project_id,
            "application_id": self.config.application_id,
            "build_id": self.config.build_id,
            "build_identity_digest": self.config.build_identity_digest,
            "capture_scope": "app_only",
            "consent": {
                "policy_version": self.config.consent_contract,
                "screen_recording": "required",
                "microphone": "required",
                "diagnostics": "required",
                "raw_media_upload": "required",
            },
            "retention": {
                "policy_version": RETENTION_POLICY_VERSION,
                "raw_media_days": self.config.raw_retention_days,
                "derived_data_days": self.config.derived_retention_days,
            },
        }

    def authenticate_admin(self, credential: str | None) -> None:
        if credential is None or not hmac.compare_digest(
            credential.encode("utf-8", "surrogatepass"), self._admin_secret
        ):
            raise ApiError(401, "ADMIN_AUTHENTICATION_FAILED", "administrator authentication failed")

    @staticmethod
    def _require_credential_rotation_capacity(
        connection: sqlite3.Connection,
        session_id: str,
        current: sqlite3.Row,
    ) -> None:
        """Keep the V1 credential history bounded before issuing a rotation."""

        population = connection.execute(
            """SELECT COUNT(*) AS credential_count,
                      MIN(ordinal) AS minimum_ordinal,
                      MAX(ordinal) AS maximum_ordinal
                 FROM credentials WHERE session_id = ?""",
            (session_id,),
        ).fetchone()
        ordinal = current["ordinal"]
        if (
            population is None
            or not isinstance(ordinal, int)
            or ordinal < 0
            or population["credential_count"] < 1
            or population["minimum_ordinal"] != 0
            or population["maximum_ordinal"] != ordinal
            or population["credential_count"] != ordinal + 1
            or population["credential_count"] > MAX_SESSION_CREDENTIALS
        ):
            raise ApiError(
                500,
                "STORAGE_INCONSISTENT",
                "session credential history is inconsistent",
            )
        if population["credential_count"] == MAX_SESSION_CREDENTIALS:
            raise ApiError(
                409,
                "CREDENTIAL_ROTATION_LIMIT_REACHED",
                CREDENTIAL_ROTATION_LIMIT_MESSAGE,
            )

    def _audit(
        self,
        conn: sqlite3.Connection,
        event_type: str,
        actor_kind: str,
        outcome: str,
        session_id: str | None,
        occurred_at: str | None = None,
    ) -> None:
        conn.execute(
            """INSERT INTO audit_events
               (event_id,event_type,actor_kind,organization_id,project_id,session_id,outcome,occurred_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                _new_id("audit"),
                event_type,
                actor_kind,
                self.config.organization_id,
                self.config.project_id,
                session_id,
                outcome,
                occurred_at or timestamp(self._now()),
            ),
        )

    def create_launch_code(self, body: Any) -> dict[str, Any]:
        if not isinstance(body, dict) or body.get("exchange_kind") not in {
            "start_session",
            "resume_session",
        }:
            raise ApiError(400, "INVALID_LAUNCH_GRANT", "launch grant fields are invalid")
        kind = body["exchange_kind"]
        if kind == "start_session":
            if set(body) != {"exchange_kind", "build_id"}:
                raise ApiError(400, "INVALID_LAUNCH_GRANT", "start grant fields are invalid")
            build_id = _require_id(body["build_id"], "build_id")
            if build_id != self.config.build_id:
                raise ApiError(403, "BUILD_NOT_AUTHORIZED", "build is outside the deployment pin")
            build = self._registered_build_identity
            scope_authorization = self._capture_scope_policy()
            session_id = None
            previous_id = None
        else:
            if set(body) != {"exchange_kind", "session_id"}:
                raise ApiError(400, "INVALID_LAUNCH_GRANT", "resume grant fields are invalid")
            session_id = _require_id(body["session_id"], "session_id")
            if self._expire_session_if_due(session_id, self._now()):
                raise ApiError(
                    410,
                    "SESSION_RETENTION_EXPIRED",
                    "session retention has expired",
                )
            with self._connect() as conn:
                session = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
                if session is None:
                    if conn.execute("SELECT 1 FROM tombstones WHERE session_id = ?", (session_id,)).fetchone():
                        raise ApiError(410, "SESSION_DELETED", "session was deleted")
                    raise ApiError(404, "SESSION_NOT_FOUND", "session was not found")
                if session["state"] == "deleting":
                    raise ApiError(410, "SESSION_DELETED", "session deletion is in progress")
                current = conn.execute(
                    "SELECT * FROM credentials WHERE session_id = ? AND revoked_at IS NULL",
                    (session_id,),
                ).fetchone()
                if current is None:
                    raise ApiError(500, "STORAGE_INCONSISTENT", "session has no current credential")
                self._require_credential_rotation_capacity(conn, session_id, current)
                build = self._decode_protocol_object(session["build_identity_json"])
                scope_authorization = self._decode_protocol_object(session["scope_json"])
                previous_id = current["credential_id"]

        code = secrets.token_urlsafe(32)
        launch_id = _new_id("launch")
        now = self._now()
        expires = now + timedelta(seconds=self.config.launch_code_ttl_seconds)
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT INTO launch_grants
                   (launch_id,code_verifier,exchange_kind,pinned_session_id,
                    pinned_previous_credential_id,build_identity_json,scope_json,created_at,expires_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    launch_id,
                    self._launch_verifier(code),
                    kind,
                    session_id,
                    previous_id,
                    canonical_json(build),
                    canonical_json(scope_authorization),
                    timestamp(now),
                    timestamp(expires),
                ),
            )
            self._audit(conn, "launch_grant_created", "admin", "succeeded", session_id, timestamp(now))
        response = {
            "launch_id": launch_id,
            "launch_code": code,
            "exchange_kind": kind,
            "session_id": session_id,
            "build_identity_digest": build["build_identity_digest"],
            "expires_at": timestamp(expires),
        }
        if kind == "start_session":
            response["scope_policy_digest"] = digest(scope_authorization)
        else:
            response["scope_digest"] = scope_authorization["scope_digest"]
        return response

    def exchange_launch_code(self, body: Any) -> StoredResponse:
        received = self._now()
        request = self._validate_protocol(body)
        if request.get("message_type") != "launch_exchange_request":
            raise ApiError(422, "PROTOCOL_INVALID", "expected a launch exchange request")
        launch_code = request["launch_code"]
        credential = request["credential"]
        if _secret_bytes(launch_code) is None:
            raise ApiError(401, "LAUNCH_AUTHENTICATION_FAILED", "launch authentication failed")
        if _secret_bytes(credential["secret"]) is None:
            raise ApiError(422, "CREDENTIAL_SECRET_INVALID", "credential secret must encode 32 random bytes")
        code_verifier = self._launch_verifier(launch_code)
        now_text = timestamp(received)
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if request["exchange_kind"] == "resume_session" and conn.execute(
                "SELECT 1 FROM tombstones WHERE session_id = ?",
                (request["expected_session_id"],),
            ).fetchone():
                raise ApiError(410, "SESSION_DELETED", "session was deleted")
            grant = conn.execute(
                "SELECT * FROM launch_grants WHERE code_verifier = ?", (code_verifier,)
            ).fetchone()
            if grant is None:
                raise ApiError(401, "LAUNCH_AUTHENTICATION_FAILED", "launch authentication failed")
            build = self._decode_protocol_object(grant["build_identity_json"])
            scope_authorization = self._decode_protocol_object(grant["scope_json"])
            self._validate_pins(request["build_identity"], request["scope"])
            grant_mismatch = (
                request["exchange_kind"] != grant["exchange_kind"]
                or canonical_json(request["build_identity"]) != canonical_json(build)
            )
            if grant["exchange_kind"] == "start_session":
                grant_mismatch = grant_mismatch or canonical_json(
                    scope_authorization
                ) != canonical_json(self._capture_scope_policy())
            else:
                grant_mismatch = grant_mismatch or canonical_json(
                    request["scope"]
                ) != canonical_json(scope_authorization)
            if grant_mismatch:
                raise ApiError(403, "LAUNCH_GRANT_MISMATCH", "launch request differs from its authorization")
            if request["exchange_kind"] == "start_session":
                consent_granted_at = _parse_timestamp(
                    request["scope"]["consent"]["granted_at"]
                )
                if not (
                    _parse_timestamp(grant["created_at"])
                    <= consent_granted_at
                    <= received
                ):
                    raise ApiError(
                        422,
                        "INVALID_CHRONOLOGY",
                        "consent chronology is outside the authorized launch exchange",
                    )
            if grant["consumed_at"] is not None:
                if (
                    grant["exchange_id"] == request["exchange_id"]
                    and grant["request_digest"] == request["request_digest"]
                ):
                    return StoredResponse(200, bytes(grant["response_bytes"]))
                raise ApiError(409, "IDEMPOTENCY_CONFLICT", "launch grant was already consumed")
            if _parse_timestamp(grant["expires_at"]) <= received:
                raise ApiError(410, "LAUNCH_GRANT_EXPIRED", "launch grant expired")
            if conn.execute(
                "SELECT 1 FROM launch_grants WHERE exchange_id = ?", (request["exchange_id"],)
            ).fetchone():
                raise ApiError(409, "IDEMPOTENCY_CONFLICT", "exchange ID was already used")
            new_credential_id = request["credential"]["credential_id"]
            if conn.execute(
                "SELECT 1 FROM credentials WHERE credential_id = ?", (new_credential_id,)
            ).fetchone() or conn.execute(
                "SELECT 1 FROM tombstones WHERE credential_id = ?", (new_credential_id,)
            ).fetchone():
                raise ApiError(409, "CREDENTIAL_ID_CONFLICT", "credential ID was already used")

            scope = request["scope"]
            if request["exchange_kind"] == "start_session":
                session_id = _new_id("session")
                session_state = "receiving"
                completion_id = None
                previous_revocation = None
                ordinal = 0
                raw_expires = received + timedelta(days=scope["retention"]["raw_media_days"])
                derived_expires = received + timedelta(days=scope["retention"]["derived_data_days"])
                conn.execute(
                    """INSERT INTO sessions
                       (session_id,state,scope_digest,scope_json,build_identity_digest,
                        build_identity_json,created_at,raw_media_expires_at,derived_data_expires_at)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        session_id,
                        session_state,
                        scope["scope_digest"],
                        canonical_json(scope),
                        build["build_identity_digest"],
                        canonical_json(build),
                        now_text,
                        timestamp(raw_expires),
                        timestamp(derived_expires),
                    ),
                )
                issued_state = "active"
            else:
                session_id = grant["pinned_session_id"]
                session = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
                if session is None:
                    if conn.execute("SELECT 1 FROM tombstones WHERE session_id = ?", (session_id,)).fetchone():
                        raise ApiError(410, "SESSION_DELETED", "session was deleted")
                    raise ApiError(404, "SESSION_NOT_FOUND", "session was not found")
                if session["state"] == "deleting":
                    raise ApiError(410, "SESSION_DELETED", "session deletion is in progress")
                if _parse_timestamp(session["raw_media_expires_at"]) <= received:
                    raise ApiError(
                        410,
                        "SESSION_RETENTION_EXPIRED",
                        "session retention has expired",
                    )
                current = conn.execute(
                    "SELECT * FROM credentials WHERE session_id = ? AND revoked_at IS NULL",
                    (session_id,),
                ).fetchone()
                if current is None:
                    raise ApiError(500, "STORAGE_INCONSISTENT", "session has no current credential")
                # Recheck inside this BEGIN IMMEDIATE transaction. Multiple
                # resume grants may have been issued against the same current
                # credential before one of them consumed the final V1 slot.
                self._require_credential_rotation_capacity(conn, session_id, current)
                session_state = session["state"]
                completion_id = session["completion_id"]
                if (
                    request["expected_session_id"] != session_id
                    or request["expected_session_state"] != session_state
                    or request["expected_completion_id"] != completion_id
                    or request["previous_credential_id"] != current["credential_id"]
                    or grant["pinned_previous_credential_id"] != current["credential_id"]
                ):
                    raise ApiError(409, "RESUME_STATE_CONFLICT", "session changed after resume authorization")
                last_authorized = _parse_timestamp(current["issued_at"])
                for table in ("segments", "diagnostics", "completions"):
                    accepted = conn.execute(
                        f"""SELECT MAX(accepted_at) FROM {table}
                            WHERE session_id = ? AND source_credential_id = ?""",
                        (session_id, current["credential_id"]),
                    ).fetchone()[0]
                    if accepted is not None:
                        last_authorized = max(
                            last_authorized,
                            _parse_timestamp(accepted),
                        )
                if received <= last_authorized:
                    received = last_authorized + timedelta(seconds=1)
                    now_text = timestamp(received)
                    self._advance_authoritative_time_floor(received)
                conn.execute(
                    "UPDATE credentials SET revoked_at = ?, current_state = 'revoked' WHERE credential_id = ?",
                    (now_text, current["credential_id"]),
                )
                previous_revocation = {
                    "credential_id": current["credential_id"],
                    "state": "revoked",
                    "revoked_at": now_text,
                }
                ordinal = current["ordinal"] + 1
                issued_state = (
                    "active" if session_state == "receiving" else "completion_replay_or_delete_only"
                )

            expires_at = received + timedelta(seconds=self.config.credential_ttl_seconds)
            conn.execute(
                """INSERT INTO credentials
                   (credential_id,session_id,ordinal,verifier,issued_at,expires_at,
                    issued_session_state,issued_state,current_state,replay_completion_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    new_credential_id,
                    session_id,
                    ordinal,
                    self._credential_verifier(new_credential_id, credential["secret"]),
                    now_text,
                    timestamp(expires_at),
                    session_state,
                    issued_state,
                    issued_state,
                    completion_id,
                ),
            )
            receipt = seal(
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "message_type": "launch_exchange_receipt",
                    "exchange_kind": request["exchange_kind"],
                    "exchange_id": request["exchange_id"],
                    "request_digest": request["request_digest"],
                    "session_id": session_id,
                    "session_state": session_state,
                    "scope": scope,
                    "credential": {
                        "credential_id": new_credential_id,
                        "authentication_scheme": "Bearer",
                        "state": issued_state,
                        "replay_completion_id": completion_id,
                        "expires_at": timestamp(expires_at),
                    },
                    "previous_credential_revocation": previous_revocation,
                    "received_at": now_text,
                    "issued_at": now_text,
                    "exchange_receipt_digest": "sha256:" + "0" * 64,
                }
            )
            try:
                validate_operation_pair(request, receipt)
            except ContractError as exc:
                raise ApiError(500, "PROTOCOL_IMPLEMENTATION_ERROR", "launch receipt could not be sealed") from exc
            response = _canonical_bytes(receipt)
            conn.execute(
                """UPDATE launch_grants SET consumed_at = ?, pinned_session_id = ?, exchange_id = ?,
                   request_digest = ?, response_bytes = ? WHERE launch_id = ?""",
                (now_text, session_id, request["exchange_id"], request["request_digest"], response, grant["launch_id"]),
            )
            self._audit(conn, "launch_exchanged", "sdk", "succeeded", session_id, now_text)
            return StoredResponse(201, response)

    def _credential_history(self, conn: sqlite3.Connection, session_id: str) -> dict[str, dict[str, Any]]:
        history: dict[str, dict[str, Any]] = {}
        for row in conn.execute(
            "SELECT * FROM credentials WHERE session_id = ? ORDER BY ordinal", (session_id,)
        ):
            history[row["credential_id"]] = {
                "session_id": session_id,
                "scope_digest": conn.execute(
                    "SELECT scope_digest FROM sessions WHERE session_id = ?", (session_id,)
                ).fetchone()[0],
                "issued_at": _parse_timestamp(row["issued_at"]),
                "expires_at": _parse_timestamp(row["expires_at"]),
                "revoked_at": _parse_timestamp(row["revoked_at"]) if row["revoked_at"] else None,
                "session_state": row["issued_session_state"],
                "credential_state": row["issued_state"],
                "replay_completion_id": row["replay_completion_id"],
            }
        return history

    def _authenticate_current(
        self,
        conn: sqlite3.Connection,
        session_id: str,
        bearer_secret: str | None,
        authenticated_at: datetime,
    ) -> tuple[sqlite3.Row, sqlite3.Row]:
        _require_id(session_id, "session_id")
        session = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        if session is None:
            if conn.execute("SELECT 1 FROM tombstones WHERE session_id = ?", (session_id,)).fetchone():
                raise ApiError(410, "SESSION_DELETED", "session was deleted")
            raise ApiError(404, "SESSION_NOT_FOUND", "session was not found")
        if session["state"] == "deleting":
            raise ApiError(410, "SESSION_DELETED", "session deletion is in progress")
        if _parse_timestamp(session["raw_media_expires_at"]) <= authenticated_at:
            raise ApiError(
                410,
                "SESSION_RETENTION_EXPIRED",
                "session retention has expired",
            )
        current = conn.execute(
            "SELECT * FROM credentials WHERE session_id = ? AND revoked_at IS NULL", (session_id,)
        ).fetchone()
        if current is None or bearer_secret is None or _secret_bytes(bearer_secret) is None:
            raise ApiError(401, "SDK_AUTHENTICATION_FAILED", "SDK authentication failed")
        expected = self._credential_verifier(current["credential_id"], bearer_secret)
        if not hmac.compare_digest(expected, current["verifier"]):
            raise ApiError(401, "SDK_AUTHENTICATION_FAILED", "SDK authentication failed")
        if not (
            _parse_timestamp(current["issued_at"]) <= authenticated_at
            and authenticated_at < _parse_timestamp(current["expires_at"])
        ):
            raise ApiError(401, "SDK_CREDENTIAL_EXPIRED", "SDK credential is not currently valid")
        return session, current

    def _expire_session_if_due(self, session_id: str, boundary: datetime) -> bool:
        """Synchronously attempt policy erasure without entering from a DB transaction."""

        with self._connect() as conn:
            row = conn.execute(
                "SELECT raw_media_expires_at FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None or _parse_timestamp(row["raw_media_expires_at"]) > boundary:
            return False
        self.sweep_expired_sessions(now=boundary)
        return True

    def preauthorize_sdk_route(self, session_id: str, bearer_secret: str | None) -> str:
        """Authenticate a route before the HTTP adapter reads a request body."""

        _require_id(session_id, "session_id")
        authenticated_at = self._now()
        if self._expire_session_if_due(session_id, authenticated_at):
            raise ApiError(
                410,
                "SESSION_RETENTION_EXPIRED",
                "session retention has expired",
            )
        with self._connect() as conn:
            _session, credential = self._authenticate_current(
                conn,
                session_id,
                bearer_secret,
                authenticated_at,
            )
            return credential["credential_id"]

    @staticmethod
    def _check_route_scope(request: dict[str, Any], session: sqlite3.Row, session_id: str) -> None:
        if request.get("session_id") != session_id:
            raise ApiError(403, "ROUTE_SCOPE_MISMATCH", "request names another session")
        if request.get("scope_digest") != session["scope_digest"]:
            raise ApiError(403, "ROUTE_SCOPE_MISMATCH", "request escaped immutable session scope")

    def _authorize_exact_replay(
        self,
        conn: sqlite3.Connection,
        session: sqlite3.Row,
        current: sqlite3.Row,
        original_request_raw: str | bytes,
        original_response_raw: bytes,
        replay_request: dict[str, Any],
        authenticated_at: datetime,
    ) -> None:
        original_request = self._decode_protocol_object(original_request_raw)
        original_response = self._decode_protocol_object(original_response_raw)
        try:
            validate_authenticated_exact_replay(
                original_request,
                original_response,
                replay_request,
                original_response,
                current["credential_id"],
                timestamp(authenticated_at),
                self._credential_history(conn, session["session_id"]),
                session["state"],
            )
        except ContractError as exc:
            raise ApiError(403, "REPLAY_NOT_AUTHORIZED", "durable response cannot be recovered by this credential") from exc

    def _authorize_new_upload(
        self,
        conn: sqlite3.Connection,
        session: sqlite3.Row,
        current: sqlite3.Row,
        request: dict[str, Any],
        accepted_at: datetime,
    ) -> None:
        history = self._credential_history(conn, session["session_id"])
        try:
            validate_new_upload_authentication(
                request,
                current["credential_id"],
                timestamp(accepted_at),
                history,
                session["state"],
            )
        except ContractError as exc:
            reconciliation = self._historical_operation_miss_binding(
                session,
                current,
                request,
                history,
            )
            if reconciliation is not None:
                raise ApiError(
                    403,
                    "OPERATION_NOT_AUTHORIZED",
                    OPERATION_NOT_AUTHORIZED_MESSAGE,
                    sdk_reconciliation=reconciliation,
                ) from exc
            raise ApiError(
                403,
                "OPERATION_NOT_AUTHORIZED",
                OPERATION_NOT_AUTHORIZED_MESSAGE,
            ) from exc

    def _historical_operation_miss_binding(
        self,
        session: sqlite3.Row,
        current: sqlite3.Row,
        request: dict[str, Any],
        history: dict[str, dict[str, Any]],
    ) -> SDKReconciliationBinding | None:
        operation_fields = {
            "segment_upload_intent": ("segment", "upload_id", "intent_digest"),
            "diagnostic_upload_request": ("diagnostic", "upload_id", "request_digest"),
            "completion_request": ("completion", "completion_id", "request_digest"),
        }
        operation = operation_fields.get(request.get("message_type"))
        request_credential_id = request.get("credential_id")
        historical = (
            history.get(request_credential_id)
            if isinstance(request_credential_id, str)
            else None
        )
        if (
            operation is None
            or historical is None
            or historical["revoked_at"] is None
            or session["state"] != "receiving"
            or current["current_state"] != "active"
            or request_credential_id == current["credential_id"]
        ):
            return None
        operation_kind, operation_id_field, request_digest_field = operation
        return SDKReconciliationBinding(
            session_id=session["session_id"],
            operation_kind=operation_kind,
            operation_id=request[operation_id_field],
            request_digest=request[request_digest_field],
            request_credential_id=request_credential_id,
            authenticated_credential_id=current["credential_id"],
        )

    def _relative_object_path(self, session_id: str, category: str, object_id: str, suffix: str) -> str:
        for value, field in ((session_id, "session_id"), (object_id, "object_id")):
            _require_id(value, field)
        if category not in {"segments", "diagnostics", "completion"}:
            raise ValueError("unknown object category")
        return str(Path("objects") / session_id / category / f"{object_id}.{suffix}")

    def _write_bytes_temp(self, prefix: str, payload: bytes) -> Path:
        descriptor, name = tempfile.mkstemp(prefix=prefix, dir=self.temp_dir)
        path = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            return path
        except Exception:
            path.unlink(missing_ok=True)
            raise

    def _write_verified_stream(
        self,
        source: BinaryIO,
        expected_size: int,
        expected_digest: str,
    ) -> Path:
        descriptor, name = tempfile.mkstemp(prefix="segment-", dir=self.temp_dir)
        path = Path(name)
        hasher = hashlib.sha256()
        written = 0
        try:
            with os.fdopen(descriptor, "wb") as handle:
                while written < expected_size:
                    chunk = source.read(min(1024 * 1024, expected_size - written))
                    if not chunk:
                        break
                    written += len(chunk)
                    hasher.update(chunk)
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            actual = "sha256:" + hasher.hexdigest()
            if written != expected_size:
                raise ApiError(400, "CONTENT_LENGTH_MISMATCH", "segment body ended before Content-Length")
            if not hmac.compare_digest(actual, expected_digest):
                raise ApiError(422, "CONTENT_DIGEST_MISMATCH", "segment bytes do not match Tacua-Content-Digest")
            return path
        except Exception:
            path.unlink(missing_ok=True)
            raise

    def _ensure_object_parent(self, final: Path) -> None:
        # Keep the same lexical root used by ``_object_path``. On macOS,
        # resolving an ancestor rewrites /var to /private/var and would make an
        # otherwise in-scope child fail ``relative_to``.
        root = self.objects_dir
        try:
            relative_parent = final.parent.relative_to(root)
        except ValueError as exc:
            raise ValueError("persisted object parent escaped backend storage") from exc
        current = root
        for part in relative_parent.parts:
            child = current / part
            created = False
            try:
                metadata = child.lstat()
            except FileNotFoundError:
                try:
                    child.mkdir(mode=0o700)
                    created = True
                except FileExistsError:
                    metadata = child.lstat()
                else:
                    metadata = child.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"backend object path is not a real directory: {child}")
            child.chmod(0o700)
            if created:
                self._fsync_directory(child)
                self._fsync_directory(current)
            current = child

    def _publish(self, temporary: Path, relative_path: str) -> Path:
        final = self._object_path(relative_path)
        self._ensure_object_parent(final)
        os.replace(temporary, final)
        self._fsync_directory(final.parent)
        self._fsync_directory(self.objects_dir)
        self._fsync_directory(self.temp_dir)
        return final

    def _checkpoint_wal(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()

    def _verify_row_object(self, row: sqlite3.Row) -> None:
        try:
            path = self._object_path(
                row["relative_path"], expected_session_id=row["session_id"]
            )
            verified = self._file_digest(path)
        except (OSError, ValueError) as error:
            raise ApiError(
                500, "STORAGE_INCONSISTENT", "durable object failed safe verification"
            ) from error
        if verified != (row["size_bytes"], row["content_digest"]):
            raise ApiError(500, "STORAGE_INCONSISTENT", "durable object digest changed")

    @staticmethod
    def _require_client_not_before_credential(requested_at: str, credential: sqlite3.Row) -> None:
        if _parse_timestamp(requested_at) < _parse_timestamp(credential["issued_at"]):
            raise ApiError(422, "INVALID_CHRONOLOGY", "request timestamp predates credential issue")

    @staticmethod
    def _require_server_not_before_request(accepted_at: datetime, requested_at: str) -> None:
        if accepted_at < _parse_timestamp(requested_at):
            raise ApiError(422, "INVALID_CHRONOLOGY", "request timestamp is ahead of server acceptance")

    def upload_segment(
        self,
        session_id: str,
        sequence: int,
        segment_id: str,
        bearer_secret: str | None,
        intent: Any,
        source: BinaryIO,
    ) -> StoredResponse:
        """Authenticate before streaming, then atomically publish one segment."""

        _require_id(session_id, "session_id")
        _require_id(segment_id, "segment_id")
        request = self._validate_protocol(intent)
        if request.get("message_type") != "segment_upload_intent":
            raise ApiError(422, "PROTOCOL_INVALID", "expected a segment upload intent")
        if request["session_id"] != session_id or request["sequence"] != sequence or request["segment_id"] != segment_id:
            raise ApiError(403, "ROUTE_SCOPE_MISMATCH", "segment route differs from its canonical intent")
        if request["transport"]["size_bytes"] > self.config.max_segment_bytes:
            raise ApiError(413, "CONTENT_SIZE_NOT_ALLOWED", "segment exceeds the configured limit")
        preflight_at = self._now()
        with self._lock, self._connect() as conn:
            session, current = self._authenticate_current(conn, session_id, bearer_secret, preflight_at)
            self._check_route_scope(request, session, session_id)
            existing = conn.execute(
                "SELECT * FROM segments WHERE session_id = ? AND upload_id = ?",
                (session_id, request["upload_id"]),
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != request["intent_digest"]:
                    raise ApiError(409, "IDEMPOTENCY_CONFLICT", "upload ID was reused for another intent")
                self._authorize_exact_replay(
                    conn,
                    session,
                    current,
                    existing["request_json"],
                    bytes(existing["response_bytes"]),
                    request,
                    preflight_at,
                )
                self._verify_row_object(existing)
                return StoredResponse(200, bytes(existing["response_bytes"]))
            self._authorize_new_upload(conn, session, current, request, preflight_at)
            self._require_client_not_before_credential(request["requested_at"], current)

        temporary = self._write_verified_stream(
            source,
            request["transport"]["size_bytes"],
            request["transport"]["content_digest"],
        )
        published: Path | None = None
        try:
            accepted_at = self._now()
            self._require_server_not_before_request(accepted_at, request["requested_at"])
            accepted_text = timestamp(accepted_at)
            with self._lock, self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                session, current = self._authenticate_current(conn, session_id, bearer_secret, accepted_at)
                self._check_route_scope(request, session, session_id)
                existing = conn.execute(
                    "SELECT * FROM segments WHERE session_id = ? AND upload_id = ?",
                    (session_id, request["upload_id"]),
                ).fetchone()
                if existing is not None:
                    if existing["request_digest"] != request["intent_digest"]:
                        raise ApiError(409, "IDEMPOTENCY_CONFLICT", "upload ID was reused for another intent")
                    self._authorize_exact_replay(
                        conn,
                        session,
                        current,
                        existing["request_json"],
                        bytes(existing["response_bytes"]),
                        request,
                        accepted_at,
                    )
                    self._verify_row_object(existing)
                    return StoredResponse(200, bytes(existing["response_bytes"]))
                self._authorize_new_upload(conn, session, current, request, accepted_at)
                self._require_client_not_before_credential(request["requested_at"], current)
                conflict = conn.execute(
                    """SELECT 1 FROM segments WHERE session_id = ?
                       AND (sequence = ? OR segment_id = ?)""",
                    (session_id, sequence, segment_id),
                ).fetchone()
                if conflict:
                    raise ApiError(409, "SEGMENT_CONFLICT", "segment sequence or ID is already bound")

                object_id = _new_id("object")
                runtime_receipt = {
                    "segment_id": segment_id,
                    "object_id": object_id,
                    "size_bytes": request["transport"]["size_bytes"],
                    "content_digest": request["transport"]["content_digest"],
                    "received_at": accepted_text,
                    "receipt_digest": "sha256:" + "0" * 64,
                }
                runtime_receipt["receipt_digest"] = digest_without(runtime_receipt, "receipt_digest")
                receipt = seal(
                    {
                        "protocol_version": PROTOCOL_VERSION,
                        "message_type": "segment_upload_receipt",
                        "upload_id": request["upload_id"],
                        "intent_digest": request["intent_digest"],
                        "session_id": session_id,
                        "scope_digest": request["scope_digest"],
                        "credential_id": request["credential_id"],
                        "sequence": sequence,
                        "segment_id": segment_id,
                        "content_type": request["transport"]["content_type"],
                        "sidecar_digest": request["sidecar_digest"],
                        "runtime_receipt": runtime_receipt,
                        "transport_digest": request["transport"]["content_digest"],
                        "segment_receipt_digest": "sha256:" + "0" * 64,
                    }
                )
                try:
                    validate_operation_pair(request, receipt)
                except ContractError as exc:
                    raise ApiError(500, "PROTOCOL_IMPLEMENTATION_ERROR", "segment receipt could not be sealed") from exc
                response = _canonical_bytes(receipt)
                relative = self._relative_object_path(session_id, "segments", object_id, "media")
                published = self._publish(temporary, relative)
                temporary = None  # type: ignore[assignment]
                conn.execute(
                    """INSERT INTO segments
                       (session_id,upload_id,sequence,segment_id,source_credential_id,
                        request_digest,request_json,response_bytes,object_id,relative_path,
                        size_bytes,content_type,content_digest,sidecar_digest,accepted_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        session_id,
                        request["upload_id"],
                        sequence,
                        segment_id,
                        request["credential_id"],
                        request["intent_digest"],
                        canonical_json(request),
                        response,
                        object_id,
                        relative,
                        request["transport"]["size_bytes"],
                        request["transport"]["content_type"],
                        request["transport"]["content_digest"],
                        request["sidecar_digest"],
                        accepted_text,
                    ),
                )
                self._audit(conn, "segment_stored", "sdk", "succeeded", session_id, accepted_text)
            published = None
            return StoredResponse(201, response)
        except Exception:
            if published is not None:
                published.unlink(missing_ok=True)
                self._fsync_directory(published.parent)
            raise
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def upload_diagnostic(
        self,
        session_id: str,
        upload_id: str,
        bearer_secret: str | None,
        body: Any,
    ) -> StoredResponse:
        _require_id(session_id, "session_id")
        _require_id(upload_id, "upload_id")
        request = self._validate_protocol(body)
        if request.get("message_type") != "diagnostic_upload_request":
            raise ApiError(422, "PROTOCOL_INVALID", "expected a diagnostic upload request")
        if request["session_id"] != session_id or request["upload_id"] != upload_id:
            raise ApiError(403, "ROUTE_SCOPE_MISMATCH", "diagnostic route differs from its request")
        envelope_bytes = _canonical_bytes(request["envelope"])
        if len(envelope_bytes) > self.config.max_diagnostic_bytes:
            raise ApiError(413, "CONTENT_SIZE_NOT_ALLOWED", "diagnostic envelope exceeds the configured limit")
        accepted_at = self._now()
        self._require_server_not_before_request(accepted_at, request["requested_at"])
        with self._lock, self._connect() as conn:
            session, current = self._authenticate_current(conn, session_id, bearer_secret, accepted_at)
            self._check_route_scope(request, session, session_id)
            scope = self._decode_protocol_object(session["scope_json"])
            envelope = request["envelope"]
            for field in ("organization_id", "project_id", "build_id", "build_identity_digest"):
                if envelope[field] != scope[field]:
                    raise ApiError(403, "ROUTE_SCOPE_MISMATCH", "diagnostic envelope escaped immutable scope")
            existing = conn.execute(
                "SELECT * FROM diagnostics WHERE session_id = ? AND upload_id = ?",
                (session_id, upload_id),
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != request["request_digest"]:
                    raise ApiError(409, "IDEMPOTENCY_CONFLICT", "upload ID was reused for another diagnostic")
                self._authorize_exact_replay(
                    conn,
                    session,
                    current,
                    existing["request_json"],
                    bytes(existing["response_bytes"]),
                    request,
                    accepted_at,
                )
                self._verify_row_object(existing)
                return StoredResponse(200, bytes(existing["response_bytes"]))
            self._authorize_new_upload(conn, session, current, request, accepted_at)
            self._require_client_not_before_credential(request["requested_at"], current)

        temporary = self._write_bytes_temp("diagnostic-", envelope_bytes)
        published: Path | None = None
        try:
            accepted_at = self._now()
            self._require_server_not_before_request(accepted_at, request["requested_at"])
            accepted_text = timestamp(accepted_at)
            with self._lock, self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                session, current = self._authenticate_current(conn, session_id, bearer_secret, accepted_at)
                self._check_route_scope(request, session, session_id)
                scope = self._decode_protocol_object(session["scope_json"])
                envelope = request["envelope"]
                for field in ("organization_id", "project_id", "build_id", "build_identity_digest"):
                    if envelope[field] != scope[field]:
                        raise ApiError(403, "ROUTE_SCOPE_MISMATCH", "diagnostic envelope escaped immutable scope")
                existing = conn.execute(
                    "SELECT * FROM diagnostics WHERE session_id = ? AND upload_id = ?",
                    (session_id, upload_id),
                ).fetchone()
                if existing is not None:
                    if existing["request_digest"] != request["request_digest"]:
                        raise ApiError(409, "IDEMPOTENCY_CONFLICT", "upload ID was reused for another diagnostic")
                    self._authorize_exact_replay(
                        conn,
                        session,
                        current,
                        existing["request_json"],
                        bytes(existing["response_bytes"]),
                        request,
                        accepted_at,
                    )
                    self._verify_row_object(existing)
                    return StoredResponse(200, bytes(existing["response_bytes"]))
                self._authorize_new_upload(conn, session, current, request, accepted_at)
                self._require_client_not_before_credential(request["requested_at"], current)
                envelope_id = request["envelope"]["envelope_id"]
                if conn.execute(
                    "SELECT 1 FROM diagnostics WHERE session_id = ? AND envelope_id = ?",
                    (session_id, envelope_id),
                ).fetchone():
                    raise ApiError(409, "DIAGNOSTIC_CONFLICT", "envelope ID is already bound")
                object_id = _new_id("object")
                receipt_id = _new_id("receipt")
                receipt = seal(
                    {
                        "protocol_version": PROTOCOL_VERSION,
                        "message_type": "diagnostic_upload_receipt",
                        "receipt_id": receipt_id,
                        "upload_id": upload_id,
                        "request_digest": request["request_digest"],
                        "session_id": session_id,
                        "scope_digest": request["scope_digest"],
                        "credential_id": request["credential_id"],
                        "object_id": object_id,
                        "size_bytes": len(envelope_bytes),
                        "transport_digest": digest(envelope_bytes),
                        "envelope_id": envelope_id,
                        "envelope_digest": request["envelope"]["envelope_digest"],
                        "received_at": accepted_text,
                        "diagnostic_receipt_digest": "sha256:" + "0" * 64,
                    }
                )
                try:
                    validate_operation_pair(request, receipt)
                except ContractError as exc:
                    raise ApiError(500, "PROTOCOL_IMPLEMENTATION_ERROR", "diagnostic receipt could not be sealed") from exc
                response = _canonical_bytes(receipt)
                relative = self._relative_object_path(session_id, "diagnostics", object_id, "json")
                published = self._publish(temporary, relative)
                temporary = None  # type: ignore[assignment]
                conn.execute(
                    """INSERT INTO diagnostics
                       (session_id,upload_id,envelope_id,source_credential_id,request_digest,
                        request_json,response_bytes,object_id,relative_path,size_bytes,
                        content_digest,accepted_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        session_id,
                        upload_id,
                        envelope_id,
                        request["credential_id"],
                        request["request_digest"],
                        canonical_json(request),
                        response,
                        object_id,
                        relative,
                        len(envelope_bytes),
                        digest(envelope_bytes),
                        accepted_text,
                    ),
                )
                self._audit(conn, "diagnostic_stored", "sdk", "succeeded", session_id, accepted_text)
            published = None
            return StoredResponse(201, response)
        except Exception:
            if published is not None:
                published.unlink(missing_ok=True)
                self._fsync_directory(published.parent)
            raise
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _queued_job_snapshot(
        self,
        job_id: str,
        manifest: dict[str, Any],
        accepted_at: str,
        diagnostic_digests: list[str],
    ) -> dict[str, Any]:
        stages = [
            {
                "name": name,
                "state": "pending",
                "attempt_count": 0,
                "started_at": None,
                "completed_at": None,
                "detail": None,
            }
            for name in ("transcribe", "align", "correlate", "research", "generate_tickets")
        ]
        job = {
            "contract_version": PROCESSING_JOB_CONTRACT,
            "media_type": "application/vnd.tacua.processing-job+json;version=1.0.0",
            "organization_id": manifest["organization_id"],
            "project_id": manifest["project_id"],
            "build_id": manifest["build_id"],
            "build_identity_digest": manifest["build_identity_digest"],
            "session_id": manifest["session_id"],
            "job_id": job_id,
            "job_version": 1,
            "previous_job_digest": None,
            "status": "queued",
            "requested_at": accepted_at,
            "started_at": None,
            "completed_at": None,
            "inputs": {
                "capture_manifest_digest": manifest["manifest_digest"],
                "diagnostic_envelope_digests": diagnostic_digests,
                "context_sources": [],
            },
            "pipeline": {"pipeline_version": "tacua.pipeline@1.0.0", "stages": stages},
            "execution": {
                "mode": "async",
                "max_attempts": 3,
                "egress": {
                    "policy": "default_deny",
                    "authorized": False,
                    "authorization_decision_id": None,
                    "destinations": [],
                },
            },
            "outputs": None,
            "failure": None,
            "job_digest": "sha256:" + "0" * 64,
        }
        job = runtime_seal(job)
        runtime_validate(job)
        return job

    def complete_session(
        self,
        session_id: str,
        completion_id: str,
        bearer_secret: str | None,
        body: Any,
    ) -> StoredResponse:
        _require_id(session_id, "session_id")
        _require_id(completion_id, "completion_id")
        request = self._validate_protocol(body)
        if request.get("message_type") != "completion_request":
            raise ApiError(422, "PROTOCOL_INVALID", "expected a completion request")
        if request["session_id"] != session_id or request["completion_id"] != completion_id:
            raise ApiError(403, "ROUTE_SCOPE_MISMATCH", "completion route differs from its request")
        request_bytes = _canonical_bytes(request)
        if len(request_bytes) > self.config.max_completion_bytes:
            raise ApiError(413, "CONTENT_SIZE_NOT_ALLOWED", "completion request exceeds the configured limit")
        accepted_at = self._now()
        self._require_server_not_before_request(accepted_at, request["requested_at"])
        accepted_text = timestamp(accepted_at)
        temporary: Path | None = None
        published: Path | None = None
        try:
            with self._lock, self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                session, current = self._authenticate_current(conn, session_id, bearer_secret, accepted_at)
                self._check_route_scope(request, session, session_id)
                existing = conn.execute(
                    "SELECT * FROM completions WHERE session_id = ?", (session_id,)
                ).fetchone()
                if existing is not None:
                    if (
                        existing["completion_id"] != completion_id
                        or existing["request_digest"] != request["request_digest"]
                    ):
                        raise ApiError(409, "IDEMPOTENCY_CONFLICT", "session already has another completion")
                    self._authorize_exact_replay(
                        conn,
                        session,
                        current,
                        existing["request_json"],
                        bytes(existing["response_bytes"]),
                        request,
                        accepted_at,
                    )
                    self._verify_row_object(existing)
                    try:
                        durable_jobs = self._processing_job_store(conn).list(
                            session_id=session_id
                        )
                    except ProcessingJobStoreError as error:
                        self._raise_processing_job_error(error)
                    if len(durable_jobs) != 1:
                        raise ApiError(
                            500,
                            "PROCESSING_JOB_STORAGE_CORRUPT",
                            "stored processing-job state failed validation",
                        )
                    return StoredResponse(200, bytes(existing["response_bytes"]))
                if (
                    session["state"] != "receiving"
                    or current["current_state"] != "active"
                    or request["credential_id"] != current["credential_id"]
                ):
                    raise ApiError(
                        403,
                        "OPERATION_NOT_AUTHORIZED",
                        COMPLETION_NOT_AUTHORIZED_MESSAGE,
                        sdk_reconciliation=self._historical_operation_miss_binding(
                            session,
                            current,
                            request,
                            self._credential_history(conn, session_id),
                        ),
                    )
                self._require_client_not_before_credential(request["requested_at"], current)
                if _parse_timestamp(request["capture_manifest"]["started_at"]) < _parse_timestamp(
                    session["created_at"]
                ):
                    raise ApiError(422, "INVALID_CHRONOLOGY", "capture predates the session credential chain")

                stored_segments = list(
                    conn.execute("SELECT * FROM segments WHERE session_id = ?", (session_id,))
                )
                stored_diagnostics = list(
                    conn.execute("SELECT * FROM diagnostics WHERE session_id = ?", (session_id,))
                )
                expected_segments = {
                    row["upload_id"]: canonical_json(self._decode_protocol_object(bytes(row["response_bytes"])))
                    for row in stored_segments
                }
                supplied_segments = {
                    item["upload_id"]: canonical_json(item) for item in request["segment_receipts"]
                }
                expected_diagnostics = {
                    row["upload_id"]: canonical_json(self._decode_protocol_object(bytes(row["response_bytes"])))
                    for row in stored_diagnostics
                }
                supplied_diagnostics = {
                    item["upload_id"]: canonical_json(item) for item in request["diagnostic_receipts"]
                }
                if expected_segments != supplied_segments or expected_diagnostics != supplied_diagnostics:
                    raise ApiError(409, "RECEIPT_SET_MISMATCH", "completion does not contain every exact durable receipt")
                for row in [*stored_segments, *stored_diagnostics]:
                    self._verify_row_object(row)

                manifest = request["capture_manifest"]
                scope = self._decode_protocol_object(session["scope_json"])
                for field in ("organization_id", "project_id", "build_id", "build_identity_digest"):
                    if manifest[field] != scope[field]:
                        raise ApiError(403, "ROUTE_SCOPE_MISMATCH", "capture manifest escaped immutable scope")
                expected_retention = {
                    "policy_version": MANIFEST_RETENTION_POLICY_VERSION,
                    "raw_media_expires_at": session["raw_media_expires_at"],
                    "derived_data_expires_at": session["derived_data_expires_at"],
                    "deletion_status": "active",
                }
                if canonical_json(manifest["retention"]) != canonical_json(
                    expected_retention
                ):
                    raise ApiError(
                        422,
                        "RETENTION_BINDING_MISMATCH",
                        "capture manifest retention differs from the persisted session policy",
                    )
                job_id = _new_id("job")
                job = self._queued_job_snapshot(
                    job_id,
                    manifest,
                    accepted_text,
                    [item["envelope_digest"] for item in request["diagnostic_receipts"]],
                )
                receipt = seal(
                    {
                        "protocol_version": PROTOCOL_VERSION,
                        "message_type": "completion_receipt",
                        "completion_id": completion_id,
                        "request_digest": request["request_digest"],
                        "session_id": session_id,
                        "scope_digest": request["scope_digest"],
                        "accepted_at": accepted_text,
                        "processing_job": job,
                        "credential": {
                            "credential_id": current["credential_id"],
                            "state": "completion_replay_or_delete_only",
                            "replay_completion_id": completion_id,
                            "expires_at": current["expires_at"],
                        },
                        "local_cleanup": {
                            "state": "authorized_after_durable_receipt",
                            "manifest_digest": manifest["manifest_digest"],
                            "segment_receipt_digests": [
                                item["segment_receipt_digest"] for item in request["segment_receipts"]
                            ],
                            "diagnostic_receipt_digests": [
                                item["diagnostic_receipt_digest"] for item in request["diagnostic_receipts"]
                            ],
                        },
                        "completion_receipt_digest": "sha256:" + "0" * 64,
                    }
                )
                try:
                    validate_operation_pair(request, receipt)
                except ContractError as exc:
                    raise ApiError(500, "PROTOCOL_IMPLEMENTATION_ERROR", "completion receipt could not be sealed") from exc
                response = _canonical_bytes(receipt)
                object_id = _new_id("completion")
                relative = self._relative_object_path(session_id, "completion", object_id, "json")
                temporary = self._write_bytes_temp("completion-", request_bytes)
                published = self._publish(temporary, relative)
                temporary = None
                conn.execute(
                    """INSERT INTO completions
                       (session_id,completion_id,source_credential_id,request_digest,request_json,
                        response_bytes,relative_path,size_bytes,content_digest,accepted_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        session_id,
                        completion_id,
                        current["credential_id"],
                        request["request_digest"],
                        canonical_json(request),
                        response,
                        relative,
                        len(request_bytes),
                        digest(request_bytes),
                        accepted_text,
                    ),
                )
                conn.execute(
                    """INSERT INTO jobs
                       (job_id,session_id,organization_id,project_id,status,requested_at,job_json)
                       VALUES (?,?,?,?,?,?,?)""",
                    (
                        job_id,
                        session_id,
                        self.config.organization_id,
                        self.config.project_id,
                        "queued",
                        accepted_text,
                        canonical_json(job),
                    ),
                )
                # The initial job validates the complete durable completion
                # anchor inside this same write transaction. Publish the
                # session projection first; any later failure rolls all rows
                # and the projection back together.
                conn.execute(
                    "UPDATE sessions SET state = 'completed', completed_at = ?, completion_id = ? WHERE session_id = ?",
                    (accepted_text, completion_id, session_id),
                )
                try:
                    self._processing_job_store(conn).put_initial(job)
                except ProcessingJobStoreError as error:
                    self._raise_processing_job_error(error)
                conn.execute(
                    """UPDATE credentials SET current_state = 'completion_replay_or_delete_only',
                       replay_completion_id = ? WHERE credential_id = ?""",
                    (completion_id, current["credential_id"]),
                )
                self._audit(conn, "session_completed", "sdk", "succeeded", session_id, accepted_text)
            published = None
            return StoredResponse(201, response)
        except Exception:
            if published is not None:
                published.unlink(missing_ok=True)
                self._fsync_directory(published.parent)
            raise
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _authenticate_replay_verifier(
        self,
        credential_id: str,
        stored_verifier: str,
        bearer_secret: str | None,
    ) -> None:
        if bearer_secret is None or _secret_bytes(bearer_secret) is None:
            raise ApiError(401, "SDK_AUTHENTICATION_FAILED", "SDK authentication failed")
        candidate = self._credential_verifier(credential_id, bearer_secret)
        if not hmac.compare_digest(candidate, stored_verifier):
            raise ApiError(401, "SDK_AUTHENTICATION_FAILED", "SDK authentication failed")

    def preauthorize_deletion_route(self, session_id: str, bearer_secret: str | None) -> str:
        """Authenticate live, pending, or bounded tombstone deletion routes."""

        _require_id(session_id, "session_id")
        now = self._now()
        with self._lock, self._connect() as conn:
            session = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            if session is not None and session["state"] != "deleting":
                _session, current = self._authenticate_current(conn, session_id, bearer_secret, now)
                return current["credential_id"]
            if session is not None:
                pending = conn.execute(
                    "SELECT * FROM pending_deletions WHERE session_id = ?", (session_id,)
                ).fetchone()
                if pending is None:
                    raise ApiError(410, "SESSION_DELETED", "session deletion is in progress")
                self._authenticate_replay_verifier(
                    pending["credential_id"], pending["replay_verifier"], bearer_secret
                )
                return pending["credential_id"]
            tombstone = conn.execute(
                "SELECT * FROM tombstones WHERE session_id = ?", (session_id,)
            ).fetchone()
            if tombstone is None:
                raise ApiError(404, "SESSION_NOT_FOUND", "session was not found")
            if _parse_timestamp(tombstone["expires_at"]) <= now:
                conn.execute("DELETE FROM tombstones WHERE session_id = ?", (session_id,))
                conn.commit()
                raise ApiError(410, "DELETION_REPLAY_EXPIRED", "deletion replay window expired")
            self._authenticate_replay_verifier(
                tombstone["credential_id"], tombstone["replay_verifier"], bearer_secret
            )
            return tombstone["credential_id"]

    def _authorize_live_deletion(
        self,
        session: sqlite3.Row,
        current: sqlite3.Row,
        request: dict[str, Any],
        accepted_at: datetime,
        *,
        internal: bool,
    ) -> None:
        self._check_route_scope(request, session, session["session_id"])
        if request["credential_id"] != current["credential_id"]:
            raise ApiError(403, "OPERATION_NOT_AUTHORIZED", "deletion must name the current credential")
        self._require_client_not_before_credential(request["requested_at"], current)
        self._require_server_not_before_request(accepted_at, request["requested_at"])
        if session["completed_at"] is not None and _parse_timestamp(request["requested_at"]) < _parse_timestamp(
            session["completed_at"]
        ):
            raise ApiError(422, "INVALID_CHRONOLOGY", "deletion request predates completion")
        if not internal and (
            session["state"] != "completed"
            or current["current_state"] != "completion_replay_or_delete_only"
            or current["replay_completion_id"] != session["completion_id"]
        ):
            raise ApiError(
                403,
                "OPERATION_NOT_AUTHORIZED",
                "first SDK deletion requires the current completion replay-or-delete credential",
            )

    def _begin_deletion(
        self,
        request: dict[str, Any],
        *,
        bearer_secret: str | None,
        internal: bool,
        accepted_at_override: datetime | None = None,
    ) -> StoredResponse:
        session_id = request["session_id"]
        accepted_at = accepted_at_override or self._now()
        if accepted_at.tzinfo is None or accepted_at.utcoffset() is None:
            raise ValueError("deletion acceptance override must be timezone-aware")
        accepted_at = accepted_at.astimezone(timezone.utc).replace(microsecond=0)
        accepted_text = timestamp(accepted_at)
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            tombstone = conn.execute(
                "SELECT * FROM tombstones WHERE session_id = ?", (session_id,)
            ).fetchone()
            if tombstone is not None:
                if _parse_timestamp(tombstone["expires_at"]) <= accepted_at:
                    conn.execute("DELETE FROM tombstones WHERE session_id = ?", (session_id,))
                    conn.commit()
                    self._checkpoint_wal()
                    raise ApiError(410, "DELETION_REPLAY_EXPIRED", "deletion replay window expired")
                if not internal:
                    self._authenticate_replay_verifier(
                        tombstone["credential_id"], tombstone["replay_verifier"], bearer_secret
                    )
                if (
                    tombstone["deletion_id"] == request["deletion_id"]
                    and tombstone["request_digest"] == request["request_digest"]
                    and tombstone["scope_digest"] == request["scope_digest"]
                    and tombstone["credential_id"] == request["credential_id"]
                ):
                    response = bytes(tombstone["response_bytes"])
                    try:
                        validate_operation_pair(request, self._decode_protocol_object(response))
                    except ContractError as exc:
                        raise ApiError(500, "STORAGE_INCONSISTENT", "stored tombstone is invalid") from exc
                    return StoredResponse(200, response)
                if tombstone["deletion_id"] == request["deletion_id"]:
                    raise ApiError(409, "IDEMPOTENCY_CONFLICT", "deletion ID was reused")
                raise ApiError(410, "SESSION_DELETED", "session was deleted")

            session = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            if session is None:
                raise ApiError(404, "SESSION_NOT_FOUND", "session was not found")
            pending = conn.execute(
                "SELECT * FROM pending_deletions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if pending is not None:
                if not internal:
                    self._authenticate_replay_verifier(
                        pending["credential_id"], pending["replay_verifier"], bearer_secret
                    )
                if pending["deletion_id"] == request["deletion_id"] and pending[
                    "request_digest"
                ] != request["request_digest"]:
                    raise ApiError(409, "IDEMPOTENCY_CONFLICT", "deletion ID was reused")
                if pending["deletion_id"] != request["deletion_id"]:
                    raise ApiError(410, "SESSION_DELETED", "another deletion is already durable")
            else:
                current = conn.execute(
                    "SELECT * FROM credentials WHERE session_id = ? AND revoked_at IS NULL",
                    (session_id,),
                ).fetchone()
                if current is None:
                    raise ApiError(500, "STORAGE_INCONSISTENT", "session has no current credential")
                if not internal:
                    _session, current = self._authenticate_current(
                        conn, session_id, bearer_secret, accepted_at
                    )
                self._authorize_live_deletion(
                    session, current, request, accepted_at, internal=internal
                )
                object_count = conn.execute(
                    """SELECT
                       (SELECT COUNT(*) FROM segments WHERE session_id = ?) +
                       (SELECT COUNT(*) FROM diagnostics WHERE session_id = ?) +
                       (SELECT COUNT(*) FROM completions WHERE session_id = ?) +
                       (SELECT COUNT(*) FROM jobs WHERE session_id = ?) +
                       (SELECT COUNT(*) FROM tacua_processing_artifacts
                          WHERE session_id = ?) +
                       (SELECT COUNT(*) FROM tacua_processing_artifact_consumptions
                          WHERE session_id = ?) +
                       (SELECT 2 * COUNT(*) FROM approved_handoffs
                          WHERE organization_id = ? AND project_id = ?
                            AND session_id = ?) +
                       (SELECT COUNT(*) FROM tacua_evidence_preview_revisions
                          WHERE manifest_row_id IN (
                              SELECT manifest_row_id FROM tacua_evidence_manifests
                               WHERE organization_id = ? AND project_id = ?
                                 AND session_id = ?
                          ) AND relative_path IS NOT NULL)""",
                    (
                        session_id,
                        session_id,
                        session_id,
                        session_id,
                        session_id,
                        session_id,
                        self.config.organization_id,
                        self.config.project_id,
                        session_id,
                        self.config.organization_id,
                        self.config.project_id,
                        session_id,
                    ),
                ).fetchone()[0]
                conn.execute("DELETE FROM jobs WHERE session_id = ?", (session_id,))
                conn.execute(
                    "UPDATE credentials SET revoked_at = COALESCE(revoked_at, ?), current_state = 'revoked' WHERE session_id = ?",
                    (accepted_text, session_id),
                )
                conn.execute("UPDATE sessions SET state = 'deleting' WHERE session_id = ?", (session_id,))
                conn.execute(
                    """INSERT INTO pending_deletions
                       (session_id,deletion_id,request_digest,request_json,credential_id,
                        replay_verifier,accepted_at,erased_object_count)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (
                        session_id,
                        request["deletion_id"],
                        request["request_digest"],
                        canonical_json(request),
                        current["credential_id"],
                        current["verifier"],
                        accepted_text,
                        object_count,
                    ),
                )
                self._audit(
                    conn,
                    "session_deletion_requested",
                    "backend" if internal else "sdk",
                    "succeeded",
                    session_id,
                    accepted_text,
                )
        return self._finish_pending_deletion(session_id)

    def _erase_session_objects(self, conn: sqlite3.Connection, session_id: str) -> None:
        paths = [
            self._object_path(
                row["relative_path"],
                expected_session_id=session_id,
                expected_category=category,
            )
            for table, category in (
                ("segments", "segments"),
                ("diagnostics", "diagnostics"),
                ("completions", "completion"),
            )
            for row in conn.execute(
                f"SELECT relative_path FROM {table} WHERE session_id = ?", (session_id,)
            )
        ]
        for path in paths:
            path.unlink(missing_ok=True)
        session_dir = self.objects_dir / session_id
        if session_dir.exists():
            for child in sorted(session_dir.rglob("*"), reverse=True):
                if child.is_symlink() or child.is_file():
                    raise OSError("unexpected object remained during scoped erasure")
                child.rmdir()
            session_dir.rmdir()
        self._fsync_directory(self.objects_dir)

    def _finish_pending_deletion(self, session_id: str) -> StoredResponse:
        with self._lock:
            with self._connect() as conn:
                pending = conn.execute(
                    "SELECT * FROM pending_deletions WHERE session_id = ?", (session_id,)
                ).fetchone()
                if pending is None:
                    tombstone = conn.execute(
                        "SELECT response_bytes FROM tombstones WHERE session_id = ?", (session_id,)
                    ).fetchone()
                    if tombstone is not None:
                        return StoredResponse(200, bytes(tombstone["response_bytes"]))
                    raise ApiError(404, "SESSION_NOT_FOUND", "pending deletion was not found")
                request = self._decode_protocol_object(pending["request_json"])

            # Review state is erased before the session tombstone can claim
            # derived-data deletion. Each operation is idempotent, so a crash
            # between these boundaries is completed on startup recovery.
            try:
                self._candidate_store().delete_session(session_id)
                with self._connect() as conn:
                    self._evidence_store(conn).delete_session(
                        organization_id=self.config.organization_id,
                        project_id=self.config.project_id,
                        session_id=session_id,
                    )
                with self._connect() as conn:
                    conn.execute(
                        "DELETE FROM tacua_evidence_audit WHERE session_id = ?",
                        (session_id,),
                    )
            except (CandidateStoreError, EvidenceDomainError, sqlite3.Error) as exc:
                raise ApiError(
                    500,
                    "STORAGE_DELETE_FAILED",
                    "derived session evidence could not be erased",
                ) from exc

            with self._connect() as conn:
                try:
                    self._erase_session_objects(conn, session_id)
                except (OSError, ValueError) as exc:
                    raise ApiError(
                        500,
                        "STORAGE_DELETE_FAILED",
                        "session objects could not be erased",
                    ) from exc

            deleted_at = max(self._now(), _parse_timestamp(pending["accepted_at"]))
            deleted_text = timestamp(deleted_at)
            expires = deleted_at + timedelta(days=self.config.tombstone_retention_days)
            expires_text = timestamp(expires)
            tombstone_document = seal(
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "message_type": "deletion_tombstone",
                    "deletion_id": pending["deletion_id"],
                    "deletion_request_digest": pending["request_digest"],
                    "session_id": session_id,
                    "scope_digest": request["scope_digest"],
                    "credential": {
                        "credential_id": pending["credential_id"],
                        "state": "deletion_replay_only",
                        "replay_deletion_id": pending["deletion_id"],
                        "verifier_retained_until": expires_text,
                    },
                    "session_access": {
                        "evidence": "revoked",
                        "uploads": "revoked",
                        "completion": "revoked",
                        "processing": "revoked",
                    },
                    "erasure": {
                        "raw_media": "deleted",
                        "diagnostics": "deleted",
                        "derived_data": "deleted",
                        "session_metadata": "deleted_except_tombstone_and_replay_verifier",
                        "erased_object_count": pending["erased_object_count"],
                    },
                    "local_credential_cleanup": "authorized_after_durable_tombstone",
                    "accepted_at": pending["accepted_at"],
                    "deleted_at": deleted_text,
                    "tombstone_expires_at": expires_text,
                    "tombstone_digest": "sha256:" + "0" * 64,
                }
            )
            try:
                validate_operation_pair(request, tombstone_document)
            except ContractError as exc:
                raise ApiError(500, "PROTOCOL_IMPLEMENTATION_ERROR", "deletion tombstone could not be sealed") from exc
            response = _canonical_bytes(tombstone_document)
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                durable = conn.execute(
                    "SELECT * FROM pending_deletions WHERE session_id = ?", (session_id,)
                ).fetchone()
                if durable is None or durable["request_digest"] != pending["request_digest"]:
                    raise ApiError(409, "DELETION_STATE_CONFLICT", "durable deletion state changed")
                conn.execute("DELETE FROM audit_events WHERE session_id = ?", (session_id,))
                conn.execute("DELETE FROM launch_grants WHERE pinned_session_id = ?", (session_id,))
                conn.execute(
                    """INSERT INTO tombstones
                       (session_id,deletion_id,request_digest,scope_digest,credential_id,
                        replay_verifier,response_bytes,accepted_at,deleted_at,expires_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        session_id,
                        durable["deletion_id"],
                        durable["request_digest"],
                        request["scope_digest"],
                        durable["credential_id"],
                        durable["replay_verifier"],
                        response,
                        durable["accepted_at"],
                        deleted_text,
                        expires_text,
                    ),
                )
                conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            self._checkpoint_wal()
            return StoredResponse(201, response)

    def delete_session_sdk(
        self,
        session_id: str,
        deletion_id: str,
        bearer_secret: str | None,
        body: Any,
    ) -> StoredResponse:
        _require_id(session_id, "session_id")
        _require_id(deletion_id, "deletion_id")
        request = self._validate_protocol(body)
        if request.get("message_type") != "deletion_request":
            raise ApiError(422, "PROTOCOL_INVALID", "expected a deletion request")
        if request["session_id"] != session_id or request["deletion_id"] != deletion_id:
            raise ApiError(403, "ROUTE_SCOPE_MISMATCH", "deletion route differs from its request")
        return self._begin_deletion(request, bearer_secret=bearer_secret, internal=False)

    def _internal_deletion_request(
        self,
        conn: sqlite3.Connection,
        session: sqlite3.Row,
        reason: str,
        requested_at: datetime,
    ) -> dict[str, Any]:
        current = conn.execute(
            "SELECT * FROM credentials WHERE session_id = ? AND revoked_at IS NULL",
            (session["session_id"],),
        ).fetchone()
        if current is None:
            raise ApiError(500, "STORAGE_INCONSISTENT", "session has no current credential")
        request = seal(
            {
                "protocol_version": PROTOCOL_VERSION,
                "message_type": "deletion_request",
                "deletion_id": _new_id("deletion"),
                "session_id": session["session_id"],
                "scope_digest": session["scope_digest"],
                "credential_id": current["credential_id"],
                "target": "session_all_data",
                "reason": reason,
                "requested_at": timestamp(requested_at),
                "request_digest": "sha256:" + "0" * 64,
            }
        )
        validate(request)
        return request

    def delete_session(self, session_id: str) -> dict[str, Any]:
        """Administrator-triggered scoped erasure, retaining only a tombstone."""

        _require_id(session_id, "session_id")
        with self._lock, self._connect() as conn:
            tombstone = conn.execute(
                "SELECT response_bytes FROM tombstones WHERE session_id = ?", (session_id,)
            ).fetchone()
            if tombstone is not None:
                return self._decode_protocol_object(bytes(tombstone["response_bytes"]))
            pending = conn.execute(
                "SELECT request_json FROM pending_deletions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if pending is not None:
                request = self._decode_protocol_object(pending["request_json"])
            else:
                session = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
                if session is None:
                    raise ApiError(404, "SESSION_NOT_FOUND", "session was not found")
                request = self._internal_deletion_request(conn, session, "operator_requested", self._now())
        return self._begin_deletion(request, bearer_secret=None, internal=True).json()

    def _recover_pending_deletions(self) -> None:
        with self._connect() as conn:
            session_ids = [row["session_id"] for row in conn.execute("SELECT session_id FROM pending_deletions")]
        for session_id in session_ids:
            try:
                self._finish_pending_deletion(session_id)
            except ApiError as exc:
                raise ValueError("durable session erasure could not be recovered") from exc

    @property
    def retention_policy(self) -> str:
        return "tacua.retention-v1"

    def sweep_expired_sessions(self, *, now: datetime | None = None) -> dict[str, Any]:
        boundary = (now or self._now()).astimezone(timezone.utc).replace(microsecond=0)
        boundary_text = timestamp(boundary)
        deleted: list[str] = []
        failed: list[str] = []
        with self._connect() as conn:
            expired = [
                row["session_id"]
                for row in conn.execute(
                    """SELECT session_id FROM sessions
                       WHERE state != 'deleting' AND raw_media_expires_at <= ?
                       ORDER BY raw_media_expires_at, session_id""",
                    (boundary_text,),
                )
            ]
            pending = [row["session_id"] for row in conn.execute("SELECT session_id FROM pending_deletions")]
        for session_id in pending:
            try:
                self._finish_pending_deletion(session_id)
                deleted.append(session_id)
            except ApiError:
                failed.append(session_id)
        for session_id in expired:
            if session_id in deleted or session_id in failed:
                continue
            try:
                with self._connect() as conn:
                    session = conn.execute(
                        "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
                    ).fetchone()
                    if session is None:
                        continue
                    request = self._internal_deletion_request(
                        conn, session, "retention_expired", boundary
                    )
                self._begin_deletion(
                    request,
                    bearer_secret=None,
                    internal=True,
                    accepted_at_override=boundary,
                )
                deleted.append(session_id)
            except ApiError:
                failed.append(session_id)
        with self._connect() as conn:
            purged_tombstones = conn.execute(
                "DELETE FROM tombstones WHERE expires_at <= ?", (boundary_text,)
            ).rowcount
            purged_grants = conn.execute(
                "DELETE FROM launch_grants WHERE consumed_at IS NULL AND expires_at <= ?", (boundary_text,)
            ).rowcount
        if purged_tombstones:
            self._checkpoint_wal()
        result = {
            "swept_at": boundary_text,
            "deleted_session_ids": deleted,
            "failed_session_ids": failed,
            "purged_tombstones": purged_tombstones,
            "purged_launch_grants": purged_grants,
        }
        self._last_retention_sweep = result
        return result

    @property
    def retention_worker_running(self) -> bool:
        return self._retention_thread is not None and self._retention_thread.is_alive()

    @property
    def last_retention_sweep(self) -> dict[str, Any] | None:
        return dict(self._last_retention_sweep) if self._last_retention_sweep else None

    def start_retention_enforcement(self) -> dict[str, Any]:
        with self._retention_worker_lock:
            if self.retention_worker_running:
                return self.last_retention_sweep or self.sweep_expired_sessions()
            startup = self.sweep_expired_sessions()
            self._retention_stop.clear()
            self._retention_thread = threading.Thread(
                target=self._retention_worker_loop,
                name="tacua-retention",
                daemon=True,
            )
            self._retention_thread.start()
            return startup

    def _retention_worker_loop(self) -> None:
        interval = float(self.config.retention_sweep_interval_seconds)
        while True:
            try:
                stopped = self._retention_wait(self._retention_stop, interval)
            except Exception:
                stopped = False
            if stopped or self._retention_stop.is_set():
                return
            try:
                self.sweep_expired_sessions()
            except Exception:
                # The next bounded interval retries. No request data or secret is logged.
                continue

    def stop_retention_enforcement(self, timeout_seconds: float = 5.0) -> bool:
        with self._retention_worker_lock:
            thread = self._retention_thread
            if thread is None:
                return True
            self._retention_stop.set()
        thread.join(timeout_seconds)
        stopped = not thread.is_alive()
        if stopped:
            with self._retention_worker_lock:
                if self._retention_thread is thread:
                    self._retention_thread = None
        return stopped

    def health(self) -> dict[str, Any]:
        with self._connect() as conn:
            conn.execute("SELECT 1").fetchone()
            sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            tombstones = conn.execute("SELECT COUNT(*) FROM tombstones").fetchone()[0]
            pending = conn.execute("SELECT COUNT(*) FROM pending_deletions").fetchone()[0]
        last_sweep = self.last_retention_sweep
        sweep_age_seconds = (
            None
            if last_sweep is None
            else (self._now() - _parse_timestamp(last_sweep["swept_at"])).total_seconds()
        )
        retention_healthy = (
            self.retention_worker_running
            and last_sweep is not None
            and not last_sweep["failed_session_ids"]
            and sweep_age_seconds is not None
            and -300 <= sweep_age_seconds
            <= 2 * self.config.retention_sweep_interval_seconds + 60
        )
        return {
            "status": "ok" if pending == 0 and retention_healthy else "degraded",
            "service": "tacua-backend",
            "version": __version__,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "sessions": sessions,
            "tombstones": tombstones,
            "pending_deletions": pending,
            "retention_worker_running": self.retention_worker_running,
            "retention_last_swept_at": (
                None if last_sweep is None else last_sweep["swept_at"]
            ),
            "retention_last_deleted_sessions": (
                0 if last_sweep is None else len(last_sweep["deleted_session_ids"])
            ),
            "retention_last_failed_sessions": (
                0 if last_sweep is None else len(last_sweep["failed_session_ids"])
            ),
        }

    def list_builds(self) -> list[dict[str, Any]]:
        """Return the non-sensitive reviewer bootstrap projection."""

        build = self._registered_build_identity
        return [
            {
                "build_id": build["build_id"],
                "application_id": self.config.application_id,
                "bundle_identifier": build["bundle_identifier"],
                "native_version": build["native_version"],
                "native_build": build["native_build"],
                "distribution": build["distribution"],
                "build_identity_digest": build["build_identity_digest"],
            }
        ]

    @staticmethod
    def _raise_candidate_error(error: CandidateStoreError) -> None:
        raise ApiError(
            error.status,
            error.code,
            error.message,
            details=error.details,
        ) from error

    @staticmethod
    def _raise_evidence_error(error: EvidenceDomainError) -> None:
        if error.code in {
            "EVIDENCE_BINDING_NOT_FOUND",
            "EVIDENCE_ITEM_NOT_FOUND",
            "PREVIEW_NOT_FOUND",
        }:
            status = 404
            code = "CANDIDATE_EVIDENCE_NOT_FOUND"
        elif error.code in {
            "PREVIEW_UNAVAILABLE",
            "APPROVAL_KEYFRAME_INVALID",
            "APPROVAL_KEYFRAMES_INVALID",
        }:
            status = 409
            code = "CANDIDATE_EVIDENCE_UNAVAILABLE"
        elif error.code in {
            "PREVIEW_FILE_MISSING",
            "PREVIEW_PATH_ESCAPE",
            "PREVIEW_PATH_INVALID",
            "PREVIEW_PATH_SYMLINK",
            "PREVIEW_READ_FAILED",
        } or "TAMPER" in error.code or "DIGEST" in error.code:
            status = 500
            code = "CANDIDATE_EVIDENCE_CORRUPT"
        elif "SCOPE" in error.code or "BINDING" in error.code:
            status = 403
            code = "CANDIDATE_EVIDENCE_SCOPE_MISMATCH"
        else:
            status = 409
            code = "CANDIDATE_EVIDENCE_INVALID"
        raise ApiError(status, code, "candidate evidence could not be verified") from error

    def _require_review_session(
        self,
        connection: sqlite3.Connection,
        session_id: str,
        *,
        require_completed: bool = False,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            if connection.execute(
                "SELECT 1 FROM tombstones WHERE session_id = ?", (session_id,)
            ).fetchone():
                raise ApiError(410, "SESSION_DELETED", "session was deleted")
            raise ApiError(404, "SESSION_NOT_FOUND", "session was not found")
        if row["state"] == "deleting":
            raise ApiError(410, "SESSION_DELETED", "session deletion is in progress")
        if _parse_timestamp(row["raw_media_expires_at"]) <= self._now():
            raise ApiError(
                410,
                "SESSION_RETENTION_EXPIRED",
                "session retention has expired",
            )
        if require_completed and row["state"] != "completed":
            raise ApiError(409, "SESSION_NOT_COMPLETED", "session is not ready for processing")
        return row

    def _sweep_before_review_access(self) -> datetime:
        """Erase due sessions before an admin/reviewer read and fail closed on errors."""

        boundary = self._now()
        self.sweep_expired_sessions(now=boundary)
        return boundary

    @staticmethod
    def _candidate_binding(candidate: dict[str, Any]) -> dict[str, Any]:
        return {
            "organization_id": candidate["organization_id"],
            "project_id": candidate["project_id"],
            "session_id": candidate["session_id"],
            "candidate_id": candidate["candidate_id"],
            "candidate_version": candidate["candidate_version"],
            "candidate_digest": candidate["candidate_digest"],
            "manifest_digest": candidate["evidence_manifest"]["manifest_digest"],
        }

    @staticmethod
    def _load_candidate_document(raw: Any) -> dict[str, Any]:
        """Load one exact canonical candidate without opening another handle."""

        try:
            document = strict_json_loads(raw)
            canonical = canonical_json(document)
            stored = raw.decode("utf-8") if isinstance(raw, bytes) else raw
            if not isinstance(document, dict) or not isinstance(stored, str) or canonical != stored:
                raise ValueError("candidate JSON is not canonical")
            TICKET_CONTRACT.validate(document)
            return document
        except (UnicodeError, ValueError, CandidateContractError) as error:
            raise ApiError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate failed validation",
            ) from error

    def _candidate_from_connection(
        self,
        connection: sqlite3.Connection,
        candidate_id: str,
        version: int | None = None,
    ) -> dict[str, Any]:
        """Resolve and verify a complete immutable chain on one transaction."""

        rows = connection.execute(
            """SELECT candidate_version,organization_id,project_id,session_id,state,
                      candidate_digest,candidate_content_digest,
                      evidence_manifest_digest,canonical_json,version_created_at
                 FROM candidate_versions
                WHERE candidate_id = ? AND organization_id = ? AND project_id = ?
                ORDER BY candidate_version""",
            (candidate_id, self.config.organization_id, self.config.project_id),
        ).fetchall()
        if not rows:
            raise ApiError(404, "CANDIDATE_NOT_FOUND", "candidate was not found")
        chain = [self._load_candidate_document(row["canonical_json"]) for row in rows]
        try:
            TICKET_CONTRACT.validate_chain(chain)
        except CandidateContractError as error:
            raise ApiError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate chain failed validation",
            ) from error
        for row, candidate in zip(rows, chain, strict=True):
            projection = (
                candidate["candidate_version"],
                candidate["organization_id"],
                candidate["project_id"],
                candidate["session_id"],
                candidate["state"],
                candidate["candidate_digest"],
                candidate["candidate_content_digest"],
                candidate["evidence_manifest"]["manifest_digest"],
                candidate["version_created_at"],
            )
            if tuple(row[field] for field in (
                "candidate_version",
                "organization_id",
                "project_id",
                "session_id",
                "state",
                "candidate_digest",
                "candidate_content_digest",
                "evidence_manifest_digest",
                "version_created_at",
            )) != projection:
                raise ApiError(
                    500,
                    "CANDIDATE_STORAGE_CORRUPT",
                    "stored candidate projection changed",
                )
        head = connection.execute(
            """SELECT candidate_version,candidate_digest,organization_id,project_id,
                      session_id,state
                 FROM candidate_heads
                WHERE candidate_id = ? AND organization_id = ? AND project_id = ?""",
            (candidate_id, self.config.organization_id, self.config.project_id),
        ).fetchone()
        current = chain[-1]
        if head is None or tuple(head) != (
            current["candidate_version"],
            current["candidate_digest"],
            current["organization_id"],
            current["project_id"],
            current["session_id"],
            current["state"],
        ):
            raise ApiError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate head changed",
            )
        if version is None:
            return current
        for candidate in chain:
            if candidate["candidate_version"] == version:
                return candidate
        raise ApiError(404, "CANDIDATE_NOT_FOUND", "candidate version was not found")

    def persist_candidate_bundle(
        self,
        *,
        candidate: dict[str, Any],
        evidence_manifest: dict[str, Any],
        previews: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Reject the retired single-candidate processing publication path.

        Generated candidates become visible only through
        :meth:`publish_processing_result`, whose final SQLite transaction also
        seals the successful processing job and drops its lease. Keeping this
        named boundary closed prevents older integrations from accidentally
        exposing a partial terminal result.
        """

        _ = (candidate, evidence_manifest, previews)
        raise ApiError(
            409,
            "PROCESSING_PUBLICATION_REQUIRED",
            "generated candidates require atomic terminal publication",
        )

    def _persist_candidate_bundle_locked(
        self,
        *,
        candidate: dict[str, Any],
        evidence_manifest: dict[str, Any],
        previews: list[dict[str, Any]],
        publish_candidate: bool = True,
    ) -> dict[str, Any]:
        """Implementation covered end-to-end by ``self._lock``."""

        self._sweep_before_review_access()
        try:
            TICKET_CONTRACT.validate_chain([candidate])
        except CandidateContractError as error:
            raise ApiError(422, "INVALID_CANDIDATE", "processed candidate is invalid") from error
        if (
            candidate["organization_id"] != self.config.organization_id
            or candidate["project_id"] != self.config.project_id
        ):
            raise ApiError(403, "CANDIDATE_SCOPE_MISMATCH", "candidate is outside this deployment")
        if not isinstance(previews, list) or len(previews) > 100:
            raise ApiError(422, "INVALID_CANDIDATE_PREVIEWS", "candidate previews are invalid")
        candidate_ids = candidate["evidence_manifest"]["evidence_ids"]
        manifest_items = evidence_manifest.get("items") if isinstance(evidence_manifest, dict) else None
        if not isinstance(manifest_items, list):
            raise ApiError(422, "INVALID_EVIDENCE_MANIFEST", "candidate evidence manifest is invalid")
        manifest_ids = [item.get("evidence_id") for item in manifest_items if isinstance(item, dict)]
        if (
            len(manifest_ids) != len(manifest_items)
            or len(set(manifest_ids)) != len(manifest_ids)
            or sorted(manifest_ids) != sorted(candidate_ids)
            or evidence_manifest.get("manifest_id") != candidate["evidence_manifest"]["manifest_id"]
            or evidence_manifest.get("manifest_digest")
            != candidate["evidence_manifest"]["manifest_digest"]
        ):
            raise ApiError(
                422,
                "CANDIDATE_EVIDENCE_MISMATCH",
                "candidate and evidence manifest identify different evidence",
            )

        required_keyframes = {
            item["evidence_id"]
            for item in manifest_items
            if item.get("evidence_type") == "media.keyframe"
            and item.get("availability") == "available"
        }
        preview_ids = {
            item.get("evidence_id") for item in previews if isinstance(item, dict)
        }
        if not required_keyframes or not required_keyframes <= preview_ids:
            raise ApiError(
                422,
                "CANDIDATE_SCREENSHOT_REQUIRED",
                "candidate publication requires every available keyframe preview",
            )

        binding = self._candidate_binding(candidate)
        binding_without_digest = dict(binding)
        binding_without_digest.pop("manifest_digest")
        with self._connect() as connection:
            session = self._require_review_session(
                connection, candidate["session_id"], require_completed=True
            )
            processing = connection.execute(
                "SELECT status FROM jobs WHERE session_id = ?",
                (candidate["session_id"],),
            ).fetchone()
            if processing is None or processing["status"] == "succeeded":
                raise ApiError(
                    409,
                    "PROCESSING_PUBLICATION_CLOSED",
                    "processing output candidate publication is closed",
                )
            if (
                candidate["build_id"] != self.config.build_id
                or candidate["build_identity_digest"] != session["build_identity_digest"]
            ):
                raise ApiError(
                    403,
                    "CANDIDATE_BUILD_MISMATCH",
                    "candidate does not identify the captured build",
                )
            evidence = self._evidence_store(connection)
            try:
                evidence.put_manifest(
                    manifest=evidence_manifest,
                    **binding_without_digest,
                )
                preview_transaction_guard = self._candidate_preview_transaction_guard(
                    candidate
                )
                for preview in previews:
                    if not isinstance(preview, dict) or set(preview) != {
                        "evidence_id",
                        "preview_revision_id",
                        "content_type",
                        "size_bytes",
                        "content_digest",
                        "body",
                    }:
                        raise ApiError(
                            422,
                            "INVALID_CANDIDATE_PREVIEWS",
                            "candidate preview fields are invalid",
                        )
                    evidence.put_preview(
                        evidence_id=preview["evidence_id"],
                        preview_revision_id=preview["preview_revision_id"],
                        content_type=preview["content_type"],
                        size_bytes=preview["size_bytes"],
                        content_digest=preview["content_digest"],
                        body=preview["body"],
                        transaction_guard=preview_transaction_guard,
                        **binding,
                    )
            except EvidenceDomainError as error:
                self._raise_evidence_error(error)
        if not publish_candidate:
            return copy.deepcopy(candidate)
        try:
            return self._candidate_store().insert_generated(candidate)
        except CandidateStoreError as error:
            self._raise_candidate_error(error)

    @staticmethod
    def _candidate_summary(row: sqlite3.Row) -> dict[str, Any]:
        raw = row["canonical_json"]
        if not isinstance(raw, (bytes, str)):
            raise ApiError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate failed validation",
            )
        candidate = PilotBackend._load_candidate_document(raw)
        head_projection = (
            row["head_candidate_id"],
            row["head_candidate_version"],
            row["head_candidate_digest"],
            row["head_organization_id"],
            row["head_project_id"],
            row["head_session_id"],
            row["head_state"],
        )
        expected_head_projection = (
            candidate["candidate_id"],
            candidate["candidate_version"],
            candidate["candidate_digest"],
            candidate["organization_id"],
            candidate["project_id"],
            candidate["session_id"],
            candidate["state"],
        )
        version_projection = (
            row["version_candidate_id"],
            row["version_candidate_version"],
            row["version_organization_id"],
            row["version_project_id"],
            row["version_session_id"],
            row["version_state"],
            row["version_candidate_digest"],
            row["version_candidate_content_digest"],
            row["version_evidence_manifest_digest"],
            row["version_created_at"],
        )
        expected_version_projection = (
            candidate["candidate_id"],
            candidate["candidate_version"],
            candidate["organization_id"],
            candidate["project_id"],
            candidate["session_id"],
            candidate["state"],
            candidate["candidate_digest"],
            candidate["candidate_content_digest"],
            candidate["evidence_manifest"]["manifest_digest"],
            candidate["version_created_at"],
        )
        if (
            head_projection != expected_head_projection
            or version_projection != expected_version_projection
        ):
            raise ApiError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate projection changed",
            )
        return {
            "candidate_id": candidate["candidate_id"],
            "candidate_version": candidate["candidate_version"],
            "candidate_digest": candidate["candidate_digest"],
            "state": candidate["state"],
            "priority": candidate["content"]["priority"],
            "title": candidate["content"]["title"],
            "summary": candidate["content"]["summary"]["text"],
            "version_created_at": candidate["version_created_at"],
        }

    def list_candidates(
        self,
        session_id: str,
        page_cursor: str | None = None,
    ) -> dict[str, Any]:
        _require_id(session_id, "session_id")
        cursor = _decode_page_cursor(
            page_cursor,
            kind="candidates",
            session_id=session_id,
        )
        with self._lock:
            self._sweep_before_review_access()
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._require_review_session(connection, session_id)
                cursor_candidate_id = None if cursor is None else cursor["candidate_id"]
                rows = connection.execute(
                    """SELECT heads.candidate_id AS head_candidate_id,
                              heads.candidate_version AS head_candidate_version,
                              heads.candidate_digest AS head_candidate_digest,
                              heads.organization_id AS head_organization_id,
                              heads.project_id AS head_project_id,
                              heads.session_id AS head_session_id,
                              heads.state AS head_state,
                              versions.candidate_id AS version_candidate_id,
                              versions.candidate_version AS version_candidate_version,
                              versions.organization_id AS version_organization_id,
                              versions.project_id AS version_project_id,
                              versions.session_id AS version_session_id,
                              versions.state AS version_state,
                              versions.candidate_digest AS version_candidate_digest,
                              versions.candidate_content_digest AS version_candidate_content_digest,
                              versions.evidence_manifest_digest AS version_evidence_manifest_digest,
                              versions.canonical_json AS canonical_json,
                              versions.version_created_at AS version_created_at
                         FROM candidate_heads AS heads
                         LEFT JOIN candidate_versions AS versions
                           ON versions.candidate_id = heads.candidate_id
                          AND versions.candidate_version = heads.candidate_version
                        WHERE heads.organization_id = ?
                          AND heads.project_id = ?
                          AND heads.session_id = ?
                          AND NOT EXISTS (
                              SELECT 1 FROM candidate_supersessions AS superseded
                               WHERE superseded.source_candidate_id = heads.candidate_id
                          )
                          AND (? IS NULL OR heads.candidate_id > ?)
                        ORDER BY heads.candidate_id ASC
                        LIMIT 51""",
                    (
                        self.config.organization_id,
                        self.config.project_id,
                        session_id,
                        cursor_candidate_id,
                        cursor_candidate_id,
                    ),
                ).fetchall()
                summaries = [self._candidate_summary(row) for row in rows]
                page = summaries[:LIST_PAGE_SIZE]
                next_cursor = None
                if len(summaries) > LIST_PAGE_SIZE:
                    next_cursor = _encode_page_cursor(
                        {
                            "version": PAGE_CURSOR_VERSION,
                            "kind": "candidates",
                            "session_id": session_id,
                            "candidate_id": page[-1]["candidate_id"],
                        }
                    )
                return {"candidates": page, "next_cursor": next_cursor}

    def get_candidate(self, candidate_id: str, version: int | None = None) -> dict[str, Any]:
        _require_id(candidate_id, "candidate_id")
        if version is not None and (
            isinstance(version, bool) or not isinstance(version, int) or version < 1
        ):
            raise ApiError(400, "INVALID_CANDIDATE_VERSION", "candidate version is invalid")
        with self._lock:
            self._sweep_before_review_access()
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                candidate = self._candidate_from_connection(connection, candidate_id, version)
                self._require_review_session(connection, candidate["session_id"])
                return candidate

    def get_candidate_supersession(self, candidate_id: str) -> dict[str, Any]:
        _require_id(candidate_id, "candidate_id")
        with self._lock:
            self._sweep_before_review_access()
            try:
                supersession = self._candidate_store().get_supersession(candidate_id)
            except CandidateStoreError as error:
                self._raise_candidate_error(error)
            source = next(
                binding
                for binding in supersession["operation"]["sources"]
                if binding["candidate_id"] == candidate_id
            )
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                candidate = self._candidate_from_connection(
                    connection, candidate_id, source["candidate_version"]
                )
                self._require_review_session(connection, candidate["session_id"])
                exact = {
                    "candidate_id": candidate["candidate_id"],
                    "candidate_version": candidate["candidate_version"],
                    "candidate_digest": candidate["candidate_digest"],
                    "candidate_content_digest": candidate["candidate_content_digest"],
                    "evidence_manifest_digest": candidate["evidence_manifest"][
                        "manifest_digest"
                    ],
                }
                if exact != source:
                    raise ApiError(
                        500,
                        "CANDIDATE_STORAGE_CORRUPT",
                        "stored candidate supersession source changed",
                    )
            return supersession

    def replace_candidates(
        self,
        *,
        idempotency_key: str,
        body: Any,
    ) -> CandidateReplacementResponse:
        with self._lock:
            self._sweep_before_review_access()
            try:
                return self._candidate_store().replace(
                    idempotency_key=idempotency_key,
                    body=body,
                )
            except CandidateStoreError as error:
                self._raise_candidate_error(error)

    def get_candidate_handoff(
        self,
        candidate_id: str,
        version: int | None = None,
    ) -> StoredHandoff:
        _require_id(candidate_id, "candidate_id")
        if version is not None and (
            isinstance(version, bool) or not isinstance(version, int) or version < 1
        ):
            raise ApiError(400, "INVALID_CANDIDATE_VERSION", "candidate version is invalid")
        with self._lock:
            self._sweep_before_review_access()
            try:
                self._candidate_store().require_not_superseded(candidate_id)
            except CandidateStoreError as error:
                self._raise_candidate_error(error)
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    handoff = self._handoff_store(connection).get(
                        candidate_id, version
                    )
                except HandoffStoreError as error:
                    if error.code == "HANDOFF_NOT_FOUND":
                        raise ApiError(
                            404,
                            "HANDOFF_NOT_FOUND",
                            "approved handoff was not found",
                        ) from error
                    raise ApiError(
                        500,
                        "HANDOFF_STORAGE_CORRUPT",
                        "stored approved handoff failed validation",
                    ) from error
                candidate = self._candidate_from_connection(
                    connection,
                    candidate_id,
                    handoff.candidate_version,
                )
                self._require_review_session(connection, candidate["session_id"])
                if (
                    candidate["state"] != "approved"
                    or candidate["candidate_digest"] != handoff.candidate_digest
                    or len(handoff.json_bytes) > MAX_HANDOFF_ARTIFACT_BYTES
                    or len(handoff.markdown_bytes) > MAX_HANDOFF_ARTIFACT_BYTES
                ):
                    raise ApiError(
                        500,
                        "HANDOFF_STORAGE_CORRUPT",
                        "stored approved handoff differs from its candidate",
                    )
                return handoff

    def _candidate_diagnostic_events(
        self,
        connection: sqlite3.Connection,
        *,
        session_id: str,
        manifest: dict[str, Any],
    ) -> list[dict[str, Any]]:
        allowed = {item["evidence_id"] for item in manifest["items"]}
        windows = [
            (item["time_range"]["start_ms"], item["time_range"]["end_ms"])
            for item in manifest["items"]
            if item["time_range"] is not None
        ]
        selected: dict[str, dict[str, Any]] = {}
        session = self._require_review_session(connection, session_id)
        try:
            scope = self._decode_protocol_object(session["scope_json"])
            build = self._decode_protocol_object(session["build_identity_json"])
            validate(scope)
            validate(build)
        except (ValueError, ContractError) as error:
            raise ApiError(
                500,
                "DIAGNOSTIC_STORAGE_CORRUPT",
                "stored diagnostic session binding failed validation",
            ) from error
        rows = connection.execute(
            "SELECT * FROM diagnostics WHERE session_id = ? ORDER BY accepted_at, upload_id",
            (session_id,),
        )
        for row in rows:
            try:
                raw_request = row["request_json"]
                request = self._decode_protocol_object(row["request_json"])
                if not isinstance(raw_request, str) or canonical_json(request) != raw_request:
                    raise ValueError("stored diagnostic request is not canonical")
                validate(request)
                if request.get("message_type") != "diagnostic_upload_request":
                    raise ValueError("stored request is not a diagnostic upload")
                envelope = request["envelope"]
                runtime_validate(envelope)
                raw_response = bytes(row["response_bytes"])
                response = self._decode_protocol_object(raw_response)
                if _canonical_bytes(response) != raw_response:
                    raise ValueError("stored diagnostic response is not canonical")
                validate_operation_pair(request, response)
            except (KeyError, TypeError, ValueError, ContractError) as error:
                raise ApiError(
                    500,
                    "DIAGNOSTIC_STORAGE_CORRUPT",
                    "stored diagnostic evidence failed validation",
                ) from error

            envelope_bytes = _canonical_bytes(envelope)
            envelope_size = len(envelope_bytes)
            envelope_digest = digest(envelope_bytes)
            transport = request["transport"]
            if (
                request["session_id"] != session_id
                or request["session_id"] != row["session_id"]
                or request["upload_id"] != row["upload_id"]
                or request["credential_id"] != row["source_credential_id"]
                or request["scope_digest"] != session["scope_digest"]
                or request["request_digest"] != row["request_digest"]
                or envelope["envelope_id"] != row["envelope_id"]
                or row["relative_path"]
                != self._relative_object_path(
                    session_id, "diagnostics", row["object_id"], "json"
                )
                or transport["content_type"]
                != "application/vnd.tacua.diagnostic-envelope+json;version=1.0.0"
                or transport["size_bytes"] != envelope_size
                or transport["content_digest"] != envelope_digest
                or row["size_bytes"] != envelope_size
                or row["content_digest"] != envelope_digest
                or response["object_id"] != row["object_id"]
                or response["size_bytes"] != envelope_size
                or response["transport_digest"] != envelope_digest
                or response["envelope_id"] != envelope["envelope_id"]
                or response["envelope_digest"] != envelope["envelope_digest"]
            ):
                raise ApiError(
                    500,
                    "DIAGNOSTIC_STORAGE_CORRUPT",
                    "stored diagnostic transport bindings changed",
                )
            self._verify_row_object(row)
            if (
                envelope["organization_id"] != self.config.organization_id
                or envelope["project_id"] != self.config.project_id
                or envelope["session_id"] != session_id
                or envelope["build_id"] != self.config.build_id
                or envelope["build_identity_digest"]
                != self.config.build_identity_digest
                or envelope["organization_id"] != scope["organization_id"]
                or envelope["project_id"] != scope["project_id"]
                or envelope["build_id"] != scope["build_id"]
                or envelope["build_identity_digest"]
                != scope["build_identity_digest"]
                or envelope["build_id"] != build["build_id"]
                or envelope["build_identity_digest"]
                != build["build_identity_digest"]
            ):
                raise ApiError(
                    500,
                    "DIAGNOSTIC_STORAGE_CORRUPT",
                    "stored diagnostic evidence escaped its session",
                )
            for event in envelope["events"]:
                refs = set(event["evidence_refs"])
                if not refs <= allowed:
                    continue
                inside_window = any(
                    start <= event["elapsed_ms"] <= end for start, end in windows
                )
                if not refs and not inside_window:
                    continue
                prior = selected.get(event["event_id"])
                if prior is not None and canonical_json(prior) != canonical_json(event):
                    raise ApiError(
                        500,
                        "DIAGNOSTIC_STORAGE_CORRUPT",
                        "stored diagnostic event identities conflict",
                    )
                selected[event["event_id"]] = event
        return sorted(
            selected.values(),
            key=lambda event: (event["elapsed_ms"], event["sequence"], event["event_id"]),
        )[:512]

    def _bounded_candidate_evidence_view(
        self,
        evidence: EvidenceStore,
        *,
        diagnostic_events: list[dict[str, Any]],
        binding: dict[str, Any],
    ) -> dict[str, Any]:
        """Return the deterministic sorted event prefix that fits the HTTP cap."""

        view = evidence.get_candidate_evidence_view(
            diagnostic_events=[],
            **binding,
        )
        if len(_canonical_bytes(view)) > MAX_CANDIDATE_EVIDENCE_VIEW_BYTES:
            raise ApiError(
                500,
                "CANDIDATE_EVIDENCE_VIEW_TOO_LARGE",
                "candidate evidence metadata exceeds the reviewer response limit",
            )
        for event in diagnostic_events[:512]:
            view["diagnostic_events"].append(event)
            if len(_canonical_bytes(view)) > MAX_CANDIDATE_EVIDENCE_VIEW_BYTES:
                view["diagnostic_events"].pop()
                break
        return view

    def get_candidate_evidence(
        self,
        candidate_id: str,
        candidate_version: int,
        *,
        candidate_digest: str,
        manifest_digest: str,
    ) -> dict[str, Any]:
        _require_id(candidate_id, "candidate_id")
        _require_digest(candidate_digest, "candidate_digest")
        _require_digest(manifest_digest, "manifest_digest")
        if (
            isinstance(candidate_version, bool)
            or not isinstance(candidate_version, int)
            or candidate_version < 1
        ):
            raise ApiError(400, "INVALID_CANDIDATE_VERSION", "candidate version is invalid")
        with self._lock:
            self._sweep_before_review_access()
            with self._connect() as connection:
                # A write-intent transaction makes the read/delete exclusion
                # true even if another V1 process is accidentally started.
                connection.execute("BEGIN IMMEDIATE")
                candidate = self._candidate_from_connection(
                    connection, candidate_id, candidate_version
                )
                self._require_review_session(connection, candidate["session_id"])
                if (
                    candidate["candidate_digest"] != candidate_digest
                    or candidate["evidence_manifest"]["manifest_digest"]
                    != manifest_digest
                ):
                    raise ApiError(
                        412,
                        "CANDIDATE_PRECONDITION_FAILED",
                        "candidate version changed; reload before viewing evidence",
                    )
                binding = self._candidate_binding(candidate)
                evidence = self._evidence_store(connection)
                try:
                    manifest = evidence.get_manifest(**binding)
                    events = self._candidate_diagnostic_events(
                        connection,
                        session_id=candidate["session_id"],
                        manifest=manifest,
                    )
                    return self._bounded_candidate_evidence_view(
                        evidence,
                        diagnostic_events=events,
                        binding=binding,
                    )
                except EvidenceDomainError as error:
                    self._raise_evidence_error(error)

    def get_candidate_preview(
        self,
        candidate_id: str,
        candidate_version: int,
        evidence_id: str,
        *,
        candidate_digest: str,
        manifest_digest: str,
    ) -> dict[str, Any]:
        _require_id(candidate_id, "candidate_id")
        _require_id(evidence_id, "evidence_id")
        _require_digest(candidate_digest, "candidate_digest")
        _require_digest(manifest_digest, "manifest_digest")
        if (
            isinstance(candidate_version, bool)
            or not isinstance(candidate_version, int)
            or candidate_version < 1
        ):
            raise ApiError(400, "INVALID_CANDIDATE_VERSION", "candidate version is invalid")
        with self._lock:
            self._sweep_before_review_access()
            try:
                with self._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    candidate = self._candidate_from_connection(
                        connection, candidate_id, candidate_version
                    )
                    self._require_review_session(connection, candidate["session_id"])
                    if (
                        candidate["candidate_digest"] != candidate_digest
                        or candidate["evidence_manifest"]["manifest_digest"]
                        != manifest_digest
                    ):
                        raise ApiError(
                            412,
                            "CANDIDATE_PRECONDITION_FAILED",
                            "candidate version changed; reload before viewing evidence",
                        )
                    return self._evidence_store(connection).get_preview(
                        evidence_id=evidence_id,
                        **self._candidate_binding(candidate),
                    )
            except EvidenceDomainError as error:
                self._raise_evidence_error(error)

    def transition_candidate(
        self,
        candidate_id: str,
        *,
        if_match: str,
        idempotency_key: str,
        body: Any,
    ) -> CandidateTransitionResponse:
        # Resolve scope before entering the append transaction; the version
        # hook checks it again under the same SQLite write lock as the append.
        self.get_candidate(candidate_id)
        try:
            return self._candidate_store().transition(
                candidate_id,
                if_match=if_match,
                idempotency_key=idempotency_key,
                body=body,
            )
        except CandidateStoreError as error:
            self._raise_candidate_error(error)

    def _session_summary(
        self,
        row: sqlite3.Row,
        completion: sqlite3.Row | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            scope_raw = row["scope_json"]
            build_raw = row["build_identity_json"]
            scope_text = (
                scope_raw.decode("utf-8") if isinstance(scope_raw, bytes) else scope_raw
            )
            build_text = (
                build_raw.decode("utf-8") if isinstance(build_raw, bytes) else build_raw
            )
            scope = self._decode_protocol_object(scope_raw)
            build = self._decode_protocol_object(build_raw)
            validate(scope)
            validate(build)
            created_at = timestamp(_parse_timestamp(row["created_at"]))
            raw_media_expires_at = timestamp(
                _parse_timestamp(row["raw_media_expires_at"])
            )
            derived_data_expires_at = timestamp(
                _parse_timestamp(row["derived_data_expires_at"])
            )
            if (
                not isinstance(scope_text, str)
                or not isinstance(build_text, str)
                or canonical_json(scope) != scope_text
                or canonical_json(build) != build_text
                or scope.get("message_type") != "capture_scope"
                or build.get("message_type") != "build_identity"
                or scope["scope_digest"] != row["scope_digest"]
                or build["build_identity_digest"] != row["build_identity_digest"]
                or scope["build_identity_digest"] != build["build_identity_digest"]
                or canonical_json(build) != self._registered_build_identity_json
                or scope["organization_id"] != self.config.organization_id
                or scope["project_id"] != self.config.project_id
                or scope["application_id"] != self.config.application_id
                or scope["build_id"] != self.config.build_id
                or scope["consent"]["policy_version"] != self.config.consent_contract
                or scope["retention"]["policy_version"] != RETENTION_POLICY_VERSION
                or scope["retention"]["raw_media_days"]
                != self.config.raw_retention_days
                or scope["retention"]["derived_data_days"]
                != self.config.derived_retention_days
                or created_at != row["created_at"]
                or raw_media_expires_at != row["raw_media_expires_at"]
                or derived_data_expires_at != row["derived_data_expires_at"]
                or timestamp(
                    _parse_timestamp(row["created_at"])
                    + timedelta(days=scope["retention"]["raw_media_days"])
                )
                != row["raw_media_expires_at"]
                or timestamp(
                    _parse_timestamp(row["created_at"])
                    + timedelta(days=scope["retention"]["derived_data_days"])
                )
                != row["derived_data_expires_at"]
            ):
                raise ValueError("session scope or build projection changed")

            state = row["state"]
            completed_projection = (
                row["completed_at"] is not None or row["completion_id"] is not None
            )
            has_completion = completion is not None
            if (
                state not in {"receiving", "completed", "deleting"}
                or (state == "receiving" and (completed_projection or has_completion))
                or (state == "completed" and (not completed_projection or not has_completion))
                or (state == "deleting" and completed_projection != has_completion)
            ):
                raise ValueError("session completion projection changed")

            manifest_digest = None
            if has_completion:
                if row["completed_at"] is None or row["completion_id"] is None:
                    raise ValueError("completion row has no session projection")
                completed_at = timestamp(_parse_timestamp(row["completed_at"]))
                completion_raw = completion["request_json"]
                completion_text = (
                    completion_raw.decode("utf-8")
                    if isinstance(completion_raw, bytes)
                    else completion_raw
                )
                completion_request = self._decode_protocol_object(completion_raw)
                validate(completion_request)
                manifest = completion_request["capture_manifest"]
                expected_manifest_retention = {
                    "policy_version": MANIFEST_RETENTION_POLICY_VERSION,
                    "raw_media_expires_at": row["raw_media_expires_at"],
                    "derived_data_expires_at": row["derived_data_expires_at"],
                    "deletion_status": "active",
                }
                if (
                    not isinstance(completion_text, str)
                    or canonical_json(completion_request) != completion_text
                    or completion_request.get("message_type") != "completion_request"
                    or completion["session_id"] != row["session_id"]
                    or completion["completion_id"] != row["completion_id"]
                    or completion["request_digest"]
                    != completion_request["request_digest"]
                    or completion["accepted_at"] != row["completed_at"]
                    or completed_at != row["completed_at"]
                    or completion_request["session_id"] != row["session_id"]
                    or completion_request["completion_id"] != row["completion_id"]
                    or completion_request["scope_digest"] != row["scope_digest"]
                    or manifest["organization_id"] != scope["organization_id"]
                    or manifest["project_id"] != scope["project_id"]
                    or manifest["session_id"] != row["session_id"]
                    or manifest["build_id"] != scope["build_id"]
                    or manifest["build_identity_digest"]
                    != scope["build_identity_digest"]
                    or canonical_json(manifest["retention"])
                    != canonical_json(expected_manifest_retention)
                ):
                    raise ValueError("stored completion projection changed")
                manifest_digest = manifest["manifest_digest"]
        except (
            KeyError,
            TypeError,
            UnicodeError,
            ValueError,
            ContractError,
            DuplicateJSONKey,
            InvalidJSONValue,
            json.JSONDecodeError,
        ) as error:
            raise ApiError(
                500,
                "SESSION_STORAGE_CORRUPT",
                "stored session failed validation",
            ) from error
        return {
            "session_id": row["session_id"],
            "organization_id": scope["organization_id"],
            "project_id": scope["project_id"],
            "application_id": scope["application_id"],
            "build_id": build["build_id"],
            "consent_contract": scope["consent"]["policy_version"],
            "state": row["state"],
            "scope_digest": row["scope_digest"],
            "build_identity_digest": row["build_identity_digest"],
            "created_at": row["created_at"],
            "completed_at": row["completed_at"],
            "completion_id": row["completion_id"],
            "manifest_digest": manifest_digest,
            "retention": {
                "policy_version": scope["retention"]["policy_version"],
                "raw_media_expires_at": row["raw_media_expires_at"],
                "derived_data_expires_at": row["derived_data_expires_at"],
                "deletion_status": "deleting"
                if row["state"] == "deleting"
                else "active",
            },
        }

    def list_sessions(self, page_cursor: str | None = None) -> dict[str, Any]:
        cursor = _decode_page_cursor(page_cursor, kind="sessions")
        with self._lock:
            boundary = self._sweep_before_review_access()
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                cursor_created_at = None if cursor is None else cursor["created_at"]
                cursor_session_id = None if cursor is None else cursor["session_id"]
                rows = conn.execute(
                    """SELECT sessions.session_id AS session_id,
                              sessions.state AS state,
                              sessions.scope_digest AS scope_digest,
                              sessions.scope_json AS scope_json,
                              sessions.build_identity_digest AS build_identity_digest,
                              sessions.build_identity_json AS build_identity_json,
                              sessions.created_at AS created_at,
                              sessions.completed_at AS completed_at,
                              sessions.raw_media_expires_at AS raw_media_expires_at,
                              sessions.derived_data_expires_at AS derived_data_expires_at,
                              sessions.completion_id AS completion_id,
                              completions.session_id AS joined_completion_session_id,
                              completions.completion_id AS joined_completion_id,
                              completions.request_digest AS joined_completion_request_digest,
                              completions.request_json AS joined_completion_request_json,
                              completions.accepted_at AS joined_completion_accepted_at
                         FROM sessions AS sessions
                         LEFT JOIN completions AS completions
                           ON completions.session_id = sessions.session_id
                        WHERE sessions.state != 'deleting'
                          AND sessions.raw_media_expires_at > ?
                          AND (
                               ? IS NULL
                               OR sessions.created_at < ?
                               OR (
                                    sessions.created_at = ?
                                    AND sessions.session_id < ?
                               )
                          )
                        ORDER BY sessions.created_at DESC, sessions.session_id DESC
                        LIMIT 51""",
                    (
                        timestamp(boundary),
                        cursor_created_at,
                        cursor_created_at,
                        cursor_created_at,
                        cursor_session_id,
                    ),
                ).fetchall()
                page_rows = rows[:LIST_PAGE_SIZE]
                sessions = [
                    self._session_summary(
                        row,
                        None
                        if row["joined_completion_session_id"] is None
                        else {
                            "session_id": row["joined_completion_session_id"],
                            "completion_id": row["joined_completion_id"],
                            "request_digest": row[
                                "joined_completion_request_digest"
                            ],
                            "request_json": row["joined_completion_request_json"],
                            "accepted_at": row["joined_completion_accepted_at"],
                        },
                    )
                    for row in page_rows
                ]
                next_cursor = None
                if len(rows) > LIST_PAGE_SIZE:
                    last = page_rows[-1]
                    next_cursor = _encode_page_cursor(
                        {
                            "version": PAGE_CURSOR_VERSION,
                            "kind": "sessions",
                            "created_at": last["created_at"],
                            "session_id": last["session_id"],
                        }
                    )
                return {"sessions": sessions, "next_cursor": next_cursor}

    def get_session(self, session_id: str) -> dict[str, Any]:
        _require_id(session_id, "session_id")
        with self._lock:
            return self._get_session_locked(session_id)

    def _get_session_locked(self, session_id: str) -> dict[str, Any]:
        """Resolve one session while deletion acceptance is excluded."""

        self._sweep_before_review_access()
        with self._connect() as conn:
            conn.execute("BEGIN")
            row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            if row is None:
                tombstone = conn.execute(
                    "SELECT * FROM tombstones WHERE session_id = ?", (session_id,)
                ).fetchone()
                if tombstone is None:
                    raise ApiError(404, "SESSION_NOT_FOUND", "session was not found")
                raise ApiError(410, "SESSION_DELETED", "session was deleted")
            self._require_review_session(conn, session_id)
            completion = conn.execute(
                """SELECT session_id,completion_id,request_digest,request_json,
                          accepted_at,response_bytes
                     FROM completions WHERE session_id = ?""",
                (session_id,),
            ).fetchone()
            result = self._session_summary(row, completion)
            result["build_identity"] = self._decode_protocol_object(row["build_identity_json"])
            result["scope"] = self._decode_protocol_object(row["scope_json"])
            result["credentials"] = [
                {
                    "credential_id": item["credential_id"],
                    "ordinal": item["ordinal"],
                    "issued_at": item["issued_at"],
                    "expires_at": item["expires_at"],
                    "revoked_at": item["revoked_at"],
                    "issued_state": item["issued_state"],
                    "current_state": item["current_state"],
                    "replay_completion_id": item["replay_completion_id"],
                }
                for item in conn.execute(
                    "SELECT * FROM credentials WHERE session_id = ? ORDER BY ordinal", (session_id,)
                )
            ]
            protocol_segments = [
                self._decode_protocol_object(bytes(item["response_bytes"]))
                for item in conn.execute(
                    "SELECT response_bytes FROM segments WHERE session_id = ? ORDER BY sequence",
                    (session_id,),
                )
            ]
            result["segment_receipts"] = protocol_segments
            result["segments"] = [item["runtime_receipt"] for item in protocol_segments]
            protocol_diagnostics = [
                self._decode_protocol_object(bytes(item["response_bytes"]))
                for item in conn.execute(
                    "SELECT response_bytes FROM diagnostics WHERE session_id = ? ORDER BY upload_id",
                    (session_id,),
                )
            ]
            result["diagnostic_receipts"] = protocol_diagnostics
            result["diagnostics"] = [
                {
                    "envelope_id": item["envelope_id"],
                    "size_bytes": item["size_bytes"],
                    "content_digest": item["transport_digest"],
                    "envelope_digest": item["envelope_digest"],
                    "received_at": item["received_at"],
                }
                for item in protocol_diagnostics
            ]
            result["completion_receipt"] = (
                self._decode_protocol_object(bytes(completion["response_bytes"])) if completion else None
            )
            try:
                full_jobs = self._processing_job_store(conn).list(session_id=session_id)
            except ProcessingJobStoreError as error:
                self._raise_processing_job_error(error)
            result["jobs"] = [
                {
                    "job_id": job["job_id"],
                    "job_type": "process_session",
                    "status": job["status"],
                    "requested_at": job["requested_at"],
                    "started_at": job["started_at"],
                    "completed_at": job["completed_at"],
                    "failure_code": job["failure"]["code"] if job["failure"] else None,
                }
                for job in full_jobs
            ]
            return result

    @staticmethod
    def _normalize_processing_result(
        result: ProcessingResult,
    ) -> tuple[str, str, list[PublicationCandidate]]:
        if not isinstance(result, ProcessingResult):
            raise ApiError(
                422,
                "PROCESSING_RESULT_INVALID",
                "processor returned an invalid terminal result",
            )
        if (
            result.disposition not in {"candidates_created", "no_issue_detected"}
            or not isinstance(result.summary, str)
            or not 1 <= len(result.summary) <= 4096
            or unicodedata.normalize("NFC", result.summary) != result.summary
            or "\x00" in result.summary
            or not isinstance(result.candidates, tuple)
            or len(result.candidates) > 256
        ):
            raise ApiError(
                422,
                "PROCESSING_RESULT_INVALID",
                "processor returned an invalid terminal result",
            )
        if (result.disposition == "candidates_created") != bool(result.candidates):
            raise ApiError(
                422,
                "PROCESSING_RESULT_INVALID",
                "processing disposition differs from its candidate set",
            )
        bundles: list[PublicationCandidate] = []
        candidate_ids: set[str] = set()
        candidate_digests: set[str] = set()
        for bundle in result.candidates:
            if (
                not isinstance(bundle, PublicationCandidate)
                or not isinstance(bundle.candidate, dict)
                or not isinstance(bundle.evidence_manifest, dict)
                or not isinstance(bundle.previews, tuple)
                or len(bundle.previews) > 100
                or any(not isinstance(preview, dict) for preview in bundle.previews)
            ):
                raise ApiError(
                    422,
                    "PROCESSING_RESULT_INVALID",
                    "processor returned an invalid candidate bundle",
                )
            candidate = copy.deepcopy(bundle.candidate)
            try:
                TICKET_CONTRACT.validate_chain([candidate])
            except CandidateContractError as error:
                raise ApiError(
                    422, "INVALID_CANDIDATE", "processed candidate is invalid"
                ) from error
            if (
                candidate["candidate_id"] in candidate_ids
                or candidate["candidate_digest"] in candidate_digests
            ):
                raise ApiError(
                    409,
                    "DUPLICATE_GENERATED_CANDIDATE",
                    "processing result contains duplicate candidates",
                )
            candidate_ids.add(candidate["candidate_id"])
            candidate_digests.add(candidate["candidate_digest"])
            bundles.append(
                PublicationCandidate(
                    candidate=candidate,
                    evidence_manifest=copy.deepcopy(bundle.evidence_manifest),
                    previews=tuple(copy.deepcopy(bundle.previews)),
                )
            )
        evidence_ids = {
            evidence_id
            for bundle in bundles
            for evidence_id in bundle.candidate["evidence_manifest"]["evidence_ids"]
        }
        if len(evidence_ids) > 10_000:
            raise ApiError(
                422,
                "PROCESSING_RESULT_INVALID",
                "processing result contains too many evidence references",
            )
        return result.disposition, result.summary, bundles

    def publish_processing_result(
        self,
        job_id: str,
        lease_token: str,
        result: ProcessingResult,
    ) -> dict[str, Any]:
        """Stage processor artifacts, then reveal all outputs in one commit.

        Evidence manifests and preview files use their existing crash journal
        before this transaction. Reviewer routes cannot resolve those staged
        rows without a candidate head. The final transaction inserts every
        candidate version/head, appends the successful job snapshot, validates
        all cross-links, and removes the lease together.
        """

        _require_id(job_id, "job_id")
        disposition, summary, bundles = self._normalize_processing_result(result)
        with self._lock:
            publication_time = self._now()
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    job, publication_worker_id = self._processing_job_store(
                        connection
                    ).validate_publication_lease(job_id, lease_token)
                except ProcessingJobStoreError as error:
                    self._raise_processing_job_error(error)
                existing_candidate = connection.execute(
                    """SELECT candidate_id FROM candidate_versions
                        WHERE organization_id = ? AND project_id = ?
                          AND session_id = ? AND candidate_version = 1
                        LIMIT 1""",
                    (
                        job["organization_id"],
                        job["project_id"],
                        job["session_id"],
                    ),
                ).fetchone()
                if existing_candidate is not None:
                    raise ApiError(
                        409,
                        "PROCESSING_PUBLICATION_CONFLICT",
                        "processing session already has generated candidates",
                    )

            for bundle in bundles:
                candidate = bundle.candidate
                if (
                    candidate["organization_id"] != job["organization_id"]
                    or candidate["project_id"] != job["project_id"]
                    or candidate["session_id"] != job["session_id"]
                    or candidate["build_id"] != job["build_id"]
                    or candidate["build_identity_digest"]
                    != job["build_identity_digest"]
                    or candidate["candidate_version"] != 1
                    or candidate["previous_candidate_digest"] is not None
                    or candidate["lineage"]
                    != {"operation": "generated", "parents": []}
                    or candidate["state"] != "draft"
                    or candidate["transition"]["actor"]["actor_type"] != "system"
                    or candidate["transition"]["actor"]["actor_id"]
                    != publication_worker_id
                    or any(
                        not (
                            _parse_timestamp(job["requested_at"])
                            <= _parse_timestamp(candidate_timestamp)
                            <= publication_time
                        )
                        for candidate_timestamp in (
                            candidate["candidate_created_at"],
                            candidate["transition"]["occurred_at"],
                            candidate["version_created_at"],
                        )
                    )
                ):
                    raise ApiError(
                        422,
                        "PROCESSING_RESULT_BINDING_MISMATCH",
                        "processed candidate differs from its leased job",
                    )
                self._persist_candidate_bundle_locked(
                    candidate=candidate,
                    evidence_manifest=bundle.evidence_manifest,
                    previews=list(bundle.previews),
                    publish_candidate=False,
                )

            candidate_documents = [bundle.candidate for bundle in bundles]
            candidate_refs = sorted(
                (
                    {
                        "candidate_id": candidate["candidate_id"],
                        "candidate_version": candidate["candidate_version"],
                    }
                    for candidate in candidate_documents
                ),
                key=lambda item: item["candidate_id"],
            )
            evidence_refs = sorted(
                {
                    evidence_id
                    for candidate in candidate_documents
                    for evidence_id in candidate["evidence_manifest"]["evidence_ids"]
                }
            )
            outputs = {
                "disposition": disposition,
                "candidate_refs": candidate_refs,
                "derived_evidence_refs": evidence_refs,
                "summary": summary,
            }

            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    if candidate_documents:
                        self._candidate_store().insert_generated_many_in_transaction(
                            connection, candidate_documents
                        )
                    succeeded = self._processing_job_store(connection).succeed(
                        job_id,
                        JOB_STAGES[-1],
                        lease_token,
                        outputs=outputs,
                    )
                    try:
                        self._validate_processing_result_publication(
                            connection, succeeded
                        )
                    except ValueError as error:
                        raise ApiError(
                            500,
                            "PROCESSING_PUBLICATION_INVALID",
                            "processing result failed publication validation",
                        ) from error
                    return succeeded
                except CandidateStoreError as error:
                    self._raise_candidate_error(error)
                except ProcessingJobStoreError as error:
                    self._raise_processing_job_error(error)
                except EvidenceDomainError as error:
                    self._raise_evidence_error(error)

    def run_processing_once(self, worker_id: str) -> dict[str, Any] | None:
        """Run one lease-owned stage through the explicitly injected engine."""

        engine = self._processing_engine
        if engine is None:
            raise ApiError(
                503,
                "PROCESSING_ENGINE_DISABLED",
                "no internal processing engine is configured",
            )
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                claimed = self._processing_job_store(connection).claim(worker_id)
            except ProcessingJobStoreError as error:
                self._raise_processing_job_error(error)
            if claimed.retry_required:
                raise ApiError(
                    409,
                    "PROCESSING_CLAIM_RETRY",
                    "bounded processing cleanup made progress; retry the claim",
                )
            claim = claimed.claim
        if claim is None:
            return None

        try:
            stage_result = engine.process_stage(claim)
        except Exception as error:
            worker_code = vars(error).get("code")
            try:
                self.fail_processing_job(
                    claim.job["job_id"],
                    claim.stage_name,
                    claim.lease_token,
                    code="PROCESSING_ENGINE_FAILED",
                    detail="The configured processing engine failed.",
                    retryable=True,
                )
            except ApiError:
                pass
            raise _ProcessingEngineFailure(worker_code) from None

        final_stage = claim.stage_name == JOB_STAGES[-1]
        if final_stage and isinstance(stage_result, ProcessingResult):
            return self.publish_processing_result(
                claim.job["job_id"], claim.lease_token, stage_result
            )
        if not final_stage and type(stage_result) is ProcessingCheckpoint:
            return self.publish_processing_checkpoint(
                claim.job["job_id"],
                claim.stage_name,
                claim.lease_token,
                stage_result,
            )
        if not final_stage and stage_result is None:
            return self.checkpoint_processing_stage(
                claim.job["job_id"],
                claim.stage_name,
                claim.lease_token,
                detail="The configured processor completed this stage.",
            )

        try:
            self.fail_processing_job(
                claim.job["job_id"],
                claim.stage_name,
                claim.lease_token,
                code="PROCESSING_ENGINE_RESULT_INVALID",
                detail="The configured processing engine returned an invalid stage result.",
                retryable=False,
            )
        finally:
            raise ApiError(
                500,
                "PROCESSING_ENGINE_RESULT_INVALID",
                "configured processing engine returned an invalid stage result",
            )

    @staticmethod
    def _processing_job_summary(job: dict[str, Any]) -> dict[str, Any]:
        failure = job["failure"]
        return {
            "job_id": job["job_id"],
            "job_type": "process_session",
            "status": job["status"],
            "requested_at": job["requested_at"],
            "started_at": job["started_at"],
            "completed_at": job["completed_at"],
            "failure_code": failure["code"] if failure else None,
        }

    def list_jobs(self, page_cursor: str | None = None) -> dict[str, Any]:
        cursor = _decode_page_cursor(page_cursor, kind="jobs")
        boundary = self._sweep_before_review_access()
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN")
            store = self._processing_job_store(conn)
            try:
                store.validate_population()
            except ProcessingJobStoreError as error:
                self._raise_processing_job_error(error)
            cursor_requested_at = None if cursor is None else cursor["requested_at"]
            cursor_job_id = None if cursor is None else cursor["job_id"]
            rows = conn.execute(
                """SELECT jobs.job_id,jobs.requested_at FROM jobs
                   JOIN sessions ON sessions.session_id = jobs.session_id
                   WHERE jobs.organization_id = ? AND jobs.project_id = ?
                     AND sessions.state != 'deleting'
                     AND sessions.raw_media_expires_at > ?
                     AND (
                          ? IS NULL
                          OR jobs.requested_at < ?
                          OR (jobs.requested_at = ? AND jobs.job_id < ?)
                     )
                   ORDER BY jobs.requested_at DESC, jobs.job_id DESC
                   LIMIT 51""",
                (
                    self.config.organization_id,
                    self.config.project_id,
                    timestamp(boundary),
                    cursor_requested_at,
                    cursor_requested_at,
                    cursor_requested_at,
                    cursor_job_id,
                ),
            ).fetchall()
            try:
                page_rows = rows[:LIST_PAGE_SIZE]
                jobs = [
                    self._processing_job_summary(store.get(row["job_id"]))
                    for row in page_rows
                ]
            except ProcessingJobStoreError as error:
                self._raise_processing_job_error(error)
            next_cursor = None
            if len(rows) > LIST_PAGE_SIZE:
                last = page_rows[-1]
                next_cursor = _encode_page_cursor(
                    {
                        "version": PAGE_CURSOR_VERSION,
                        "kind": "jobs",
                        "requested_at": last["requested_at"],
                        "job_id": last["job_id"],
                    }
                )
            return {"jobs": jobs, "next_cursor": next_cursor}

    def get_job(self, job_id: str) -> dict[str, Any]:
        _require_id(job_id, "job_id")
        boundary = self._sweep_before_review_access()
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN")
            store = self._processing_job_store(conn)
            try:
                store.validate_population()
            except ProcessingJobStoreError as error:
                self._raise_processing_job_error(error)
            row = conn.execute(
                """SELECT jobs.job_id FROM jobs
                   JOIN sessions ON sessions.session_id = jobs.session_id
                   WHERE jobs.job_id = ? AND jobs.organization_id = ?
                     AND jobs.project_id = ? AND sessions.state != 'deleting'
                     AND sessions.raw_media_expires_at > ?""",
                (
                    job_id,
                    self.config.organization_id,
                    self.config.project_id,
                    timestamp(boundary),
                ),
            ).fetchone()
            if row is None:
                raise ApiError(404, "JOB_NOT_FOUND", "job was not found")
            try:
                return store.get(row["job_id"])
            except ProcessingJobStoreError as error:
                self._raise_processing_job_error(error)

    def claim_processing_job(self, worker_id: str) -> dict[str, Any] | None:
        """Atomically lease the oldest queued or expired-running job.

        This is an internal single-process boundary.  Startup never calls it,
        so merely starting Tacua cannot process data or authorize egress.
        """

        retry_required = False
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                result = self._processing_job_store(conn).claim(worker_id)
            except ProcessingJobStoreError as error:
                self._raise_processing_job_error(error)
            claim = result.claim
            retry_required = result.retry_required
        if retry_required:
            raise ApiError(
                409,
                "PROCESSING_CLAIM_RETRY",
                "bounded processing cleanup made progress; retry the claim",
            )
        return None if claim is None else claim.as_dict()

    def checkpoint_processing_stage(
        self,
        job_id: str,
        stage_name: str,
        lease_token: str,
        *,
        detail: str | None = None,
    ) -> dict[str, Any]:
        """Commit one exact non-final stage checkpoint and release its lease."""

        _require_id(job_id, "job_id")
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                return self._processing_job_store(conn).checkpoint(
                    job_id, stage_name, lease_token, detail=detail
                )
            except ProcessingJobStoreError as error:
                self._raise_processing_job_error(error)

    def publish_processing_checkpoint(
        self,
        job_id: str,
        stage_name: str,
        lease_token: str,
        checkpoint: ProcessingCheckpoint,
    ) -> dict[str, Any]:
        """Atomically publish one internal checkpoint and its inline artifacts.

        This is intentionally a Python-only engine boundary.  It is not
        exposed over HTTP and does not alter the frozen local-adapter result
        contract.  Artifact identities and lifecycle fields are derived by
        the store while the live stage lease is revalidated.
        """

        _require_id(job_id, "job_id")
        if type(checkpoint) is not ProcessingCheckpoint:
            raise ApiError(
                422,
                "PROCESSING_CHECKPOINT_INVALID",
                "processing checkpoint is invalid",
            )
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                return self._processing_job_store(conn).checkpoint(
                    job_id,
                    stage_name,
                    lease_token,
                    detail="The configured processor completed this stage.",
                    artifacts=checkpoint.artifacts,
                    consumed_artifacts=checkpoint.consumed_artifacts,
                )
            except ProcessingJobStoreError as error:
                self._raise_processing_job_error(error)

    def renew_processing_lease(
        self,
        job_id: str,
        stage_name: str,
        lease_token: str,
    ) -> dict[str, Any]:
        """Heartbeat one live lease by one fixed, bounded interval."""

        _require_id(job_id, "job_id")
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                return self._processing_job_store(conn).renew(
                    job_id, stage_name, lease_token
                )
            except ProcessingJobStoreError as error:
                self._raise_processing_job_error(error)

    def fail_processing_job(
        self,
        job_id: str,
        stage_name: str,
        lease_token: str,
        *,
        code: str,
        detail: str,
        retryable: bool,
    ) -> dict[str, Any]:
        """Record a retry boundary or a terminal processing failure."""

        _require_id(job_id, "job_id")
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                return self._processing_job_store(conn).fail(
                    job_id,
                    stage_name,
                    lease_token,
                    code=code,
                    detail=detail,
                    retryable=retryable,
                )
            except ProcessingJobStoreError as error:
                self._raise_processing_job_error(error)

    def list_audit_events(self, page_cursor: str | None = None) -> dict[str, Any]:
        cursor = _decode_page_cursor(page_cursor, kind="audit_events")
        boundary = self._sweep_before_review_access()
        with self._lock, self._connect() as conn:
            cursor_occurred_at = None if cursor is None else cursor["occurred_at"]
            cursor_event_id = None if cursor is None else cursor["event_id"]
            rows = conn.execute(
                """SELECT audit_events.event_id,audit_events.event_type,
                          audit_events.actor_kind,audit_events.organization_id,
                          audit_events.project_id,audit_events.session_id,
                          audit_events.outcome,audit_events.occurred_at
                   FROM audit_events
                   LEFT JOIN sessions ON sessions.session_id = audit_events.session_id
                   WHERE audit_events.organization_id = ?
                     AND audit_events.project_id = ?
                     AND (
                         audit_events.session_id IS NULL
                         OR (
                             sessions.session_id IS NOT NULL
                             AND sessions.state != 'deleting'
                             AND sessions.raw_media_expires_at > ?
                         )
                     )
                     AND (
                          ? IS NULL
                          OR audit_events.occurred_at < ?
                          OR (
                              audit_events.occurred_at = ?
                              AND audit_events.event_id < ?
                          )
                     )
                   ORDER BY audit_events.occurred_at DESC,audit_events.event_id DESC
                   LIMIT 51""",
                (
                    self.config.organization_id,
                    self.config.project_id,
                    timestamp(boundary),
                    cursor_occurred_at,
                    cursor_occurred_at,
                    cursor_occurred_at,
                    cursor_event_id,
                ),
            ).fetchall()
        page_rows = rows[:LIST_PAGE_SIZE]
        events = [dict(row) for row in page_rows]
        next_cursor = None
        if len(rows) > LIST_PAGE_SIZE:
            last = page_rows[-1]
            next_cursor = _encode_page_cursor(
                {
                    "version": PAGE_CURSOR_VERSION,
                    "kind": "audit_events",
                    "occurred_at": last["occurred_at"],
                    "event_id": last["event_id"],
                }
            )
        return {"events": events, "next_cursor": next_cursor}


class LimitedReader(io.RawIOBase):
    """Prevent the service from reading beyond one HTTP request body."""

    def __init__(self, source: BinaryIO, length: int):
        self.source = source
        self.remaining = length

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if self.remaining <= 0:
            return b""
        if size < 0 or size > self.remaining:
            size = self.remaining
        data = self.source.read(size)
        self.remaining -= len(data)
        return data
