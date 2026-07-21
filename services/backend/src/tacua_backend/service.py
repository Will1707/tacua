"""Durable SDK/backend protocol service for one self-hosted Tacua deployment."""

from __future__ import annotations

import base64
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
from typing import Any, BinaryIO, Callable

from . import PROCESSING_JOB_CONTRACT, __version__
from .config import (
    BUNDLE_ID_PATTERN,
    DIGEST_PATTERN,
    ID_PATTERN,
    TRANSPORT_POLICY_VERSION,
    PilotConfig,
    normalize_backend_origin,
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


MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_SEGMENTS = 2048
SCHEMA_VERSION = 2
INTERNAL_DELETION_RESOURCE = "tacua.internal-deletion-job@1.0.0"
SCOPE_POLICY_CONTRACT = "tacua.capture-scope-policy@1.0.0"
RETENTION_POLICY_VERSION = "tacua.retention-v1"


class ClosingConnection(sqlite3.Connection):
    """Commit or roll back a context, then close its SQLite handle."""

    def __exit__(self, exc_type, exc_value, traceback):  # type: ignore[no-untyped-def]
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class ApiError(Exception):
    """A content-free error safe to serialize to an API client."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


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


def strict_json_loads(value: bytes | str) -> Any:
    """Decode duplicate-free, integer-only, NFC, interoperable JSON."""

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if unicodedata.normalize("NFC", key) != key:
                raise InvalidJSONValue("JSON object keys must be NFC-normalized")
            if key in result:
                raise DuplicateJSONKey("JSON object contains a duplicate key")
            result[key] = item
        return result

    def reject_float(_value: str) -> float:
        raise InvalidJSONValue("floating-point JSON values are forbidden")

    def checked_int(raw: str) -> int:
        parsed = int(raw)
        if abs(parsed) > MAX_SAFE_INTEGER:
            raise InvalidJSONValue("JSON integer exceeds the interoperable range")
        return parsed

    def reject_constant(_value: str) -> None:
        raise InvalidJSONValue("non-finite JSON values are forbidden")

    if isinstance(value, bytes):
        value = value.decode("utf-8")
    result = json.loads(
        value,
        object_pairs_hook=reject_duplicates,
        parse_float=reject_float,
        parse_int=checked_int,
        parse_constant=reject_constant,
    )
    for path, child in PROTOCOL.runtime.walk(result):
        if isinstance(child, str) and unicodedata.normalize("NFC", child) != child:
            raise InvalidJSONValue(f"non-NFC string at {path}")
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
    ):
        if not 32 <= len(admin_secret) <= 4096:
            raise ValueError("admin secret must contain from 32 through 4096 bytes")
        for name in ("organization_id", "project_id", "application_id"):
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
        if not all(
            1 <= value <= 30
            for value in (
                config.raw_retention_days,
                config.derived_retention_days,
                config.tombstone_retention_days,
            )
        ):
            raise ValueError("retention periods must be from 1 through 30 days")
        if not 300 <= config.credential_ttl_seconds <= 2_592_000:
            raise ValueError("credential_ttl_seconds is outside the V1 bound")
        if not 30 <= config.retention_sweep_interval_seconds <= 3600:
            raise ValueError("retention_sweep_interval_seconds is outside the V1 bound")
        if not callable(clock):
            raise ValueError("clock must be callable")
        self.config = config
        self._registered_build_identity = strict_json_loads(canonical_json(config.build_identity))
        self._registered_build_identity_json = canonical_json(self._registered_build_identity)
        self._admin_secret = bytes(admin_secret)
        self._verifier_key = hmac.new(
            self._admin_secret,
            b"tacua sdk credential verifier root v1",
            hashlib.sha256,
        ).digest()
        self._clock = clock
        self._retention_wait = retention_wait or self._wait_for_retention_interval
        self.state_dir = config.state_directory
        if not self.state_dir.is_absolute() or self.state_dir == Path(self.state_dir.anchor):
            raise ValueError("state_directory must be an absolute non-root path")
        self.objects_dir = self.state_dir / "objects"
        self.temp_dir = self.state_dir / "tmp"
        self.db_path = self.state_dir / "tacua.sqlite3"
        self._lock = threading.RLock()
        self._retention_worker_lock = threading.Lock()
        self._retention_stop = threading.Event()
        self._retention_thread: threading.Thread | None = None
        self._last_retention_sweep: dict[str, Any] | None = None
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.objects_dir.mkdir(exist_ok=True, mode=0o700)
        self.temp_dir.mkdir(exist_ok=True, mode=0o700)
        for directory in (self.state_dir, self.objects_dir, self.temp_dir):
            metadata = directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"backend state path is not a real directory: {directory}")
            directory.chmod(0o700)
        self._initialize_database()
        self._recover_pending_deletions()
        self._reconcile_storage()

    @staticmethod
    def _wait_for_retention_interval(stop_event: threading.Event, seconds: float) -> bool:
        return stop_event.wait(seconds)

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc).replace(microsecond=0)

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
            if version not in {0, SCHEMA_VERSION}:
                raise ValueError(
                    "persisted backend schema is incompatible with the frozen SDK protocol; "
                    "back up and start with an empty state directory"
                )
            if version == 0 and tables:
                raise ValueError("unversioned backend state is not safe to adopt")

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
            ordinal INTEGER NOT NULL,
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
        CREATE INDEX IF NOT EXISTS audit_session_idx ON audit_events(session_id, occurred_at);
        CREATE INDEX IF NOT EXISTS jobs_status_idx ON jobs(status, requested_at);
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

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _regular_file_size(path: Path) -> int | None:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"state path is not a regular file: {path}")
        return metadata.st_size

    @staticmethod
    def _file_digest(path: Path) -> tuple[int, str]:
        hasher = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                hasher.update(chunk)
                size += len(chunk)
        return size, "sha256:" + hasher.hexdigest()

    def _object_path(self, relative_path: str) -> Path:
        candidate = (self.state_dir / relative_path).resolve()
        root = self.objects_dir.resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError("persisted object path escaped backend storage") from exc
        return candidate

    def _reconcile_storage(self) -> None:
        """Remove crash orphans and fail closed if committed bytes disappeared."""

        changed = False
        for entry in self.temp_dir.iterdir():
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
            for table in ("segments", "diagnostics", "completions"):
                expected_rows.extend(
                    (row["relative_path"], row["size_bytes"], row["content_digest"])
                    for row in conn.execute(f"SELECT relative_path, size_bytes, content_digest FROM {table}")
                )
        expected = {relative for relative, _, _ in expected_rows}
        for relative, size, content_digest in expected_rows:
            path = self._object_path(relative)
            if self._regular_file_size(path) != size or self._file_digest(path) != (size, content_digest):
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
                current = conn.execute(
                    "SELECT * FROM credentials WHERE session_id = ? AND revoked_at IS NULL",
                    (session_id,),
                ).fetchone()
                if current is None:
                    raise ApiError(500, "STORAGE_INCONSISTENT", "session has no current credential")
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

    def preauthorize_sdk_route(self, session_id: str, bearer_secret: str | None) -> str:
        """Authenticate a route before the HTTP adapter reads a request body."""

        with self._connect() as conn:
            _session, credential = self._authenticate_current(conn, session_id, bearer_secret, self._now())
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
        try:
            validate_new_upload_authentication(
                request,
                current["credential_id"],
                timestamp(accepted_at),
                self._credential_history(conn, session["session_id"]),
                session["state"],
            )
        except ContractError as exc:
            raise ApiError(403, "OPERATION_NOT_AUTHORIZED", "new upload requires the current active credential") from exc

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

    def _publish(self, temporary: Path, relative_path: str) -> Path:
        final = self._object_path(relative_path)
        final.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.replace(temporary, final)
        self._fsync_directory(final.parent)
        self._fsync_directory(self.objects_dir)
        self._fsync_directory(self.temp_dir)
        return final

    def _checkpoint_wal(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()

    def _verify_row_object(self, row: sqlite3.Row) -> None:
        path = self._object_path(row["relative_path"])
        if self._regular_file_size(path) != row["size_bytes"]:
            raise ApiError(500, "STORAGE_INCONSISTENT", "durable object size changed")
        if self._file_digest(path) != (row["size_bytes"], row["content_digest"]):
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
                    return StoredResponse(200, bytes(existing["response_bytes"]))
                if (
                    session["state"] != "receiving"
                    or current["current_state"] != "active"
                    or request["credential_id"] != current["credential_id"]
                ):
                    raise ApiError(403, "OPERATION_NOT_AUTHORIZED", "first completion requires the current active credential")
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
                conn.execute(
                    """UPDATE credentials SET current_state = 'completion_replay_or_delete_only',
                       replay_completion_id = ? WHERE credential_id = ?""",
                    (completion_id, current["credential_id"]),
                )
                conn.execute(
                    "UPDATE sessions SET state = 'completed', completed_at = ?, completion_id = ? WHERE session_id = ?",
                    (accepted_text, completion_id, session_id),
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
                       (SELECT COUNT(*) FROM jobs WHERE session_id = ?)""",
                    (session_id, session_id, session_id, session_id),
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
            self._object_path(row["relative_path"])
            for table in ("segments", "diagnostics", "completions")
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
                try:
                    self._erase_session_objects(conn, session_id)
                except OSError as exc:
                    raise ApiError(500, "STORAGE_DELETE_FAILED", "session objects could not be erased") from exc

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
        return {
            "status": "ok" if pending == 0 else "degraded",
            "service": "tacua-backend",
            "version": __version__,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "sessions": sessions,
            "tombstones": tombstones,
            "pending_deletions": pending,
            "retention_worker_running": self.retention_worker_running,
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
    def _session_summary(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "session_id": row["session_id"],
            "state": row["state"],
            "scope_digest": row["scope_digest"],
            "build_identity_digest": row["build_identity_digest"],
            "created_at": row["created_at"],
            "completed_at": row["completed_at"],
            "completion_id": row["completion_id"],
            "retention": {
                "raw_media_expires_at": row["raw_media_expires_at"],
                "derived_data_expires_at": row["derived_data_expires_at"],
            },
        }

    def list_sessions(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            active = [
                self._session_summary(row)
                for row in conn.execute("SELECT * FROM sessions ORDER BY created_at DESC")
            ]
            deleted = [
                {
                    "session_id": row["session_id"],
                    "state": "deleted",
                    "scope_digest": row["scope_digest"],
                    "deleted_at": row["deleted_at"],
                    "tombstone_expires_at": row["expires_at"],
                }
                for row in conn.execute("SELECT * FROM tombstones ORDER BY deleted_at DESC")
            ]
        return active + deleted

    def get_session(self, session_id: str) -> dict[str, Any]:
        _require_id(session_id, "session_id")
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            if row is None:
                tombstone = conn.execute(
                    "SELECT * FROM tombstones WHERE session_id = ?", (session_id,)
                ).fetchone()
                if tombstone is None:
                    raise ApiError(404, "SESSION_NOT_FOUND", "session was not found")
                return {
                    "session_id": session_id,
                    "state": "deleted",
                    "tombstone": self._decode_protocol_object(bytes(tombstone["response_bytes"])),
                }
            result = self._session_summary(row)
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
            result["segment_receipts"] = [
                self._decode_protocol_object(bytes(item["response_bytes"]))
                for item in conn.execute(
                    "SELECT response_bytes FROM segments WHERE session_id = ? ORDER BY sequence",
                    (session_id,),
                )
            ]
            result["diagnostic_receipts"] = [
                self._decode_protocol_object(bytes(item["response_bytes"]))
                for item in conn.execute(
                    "SELECT response_bytes FROM diagnostics WHERE session_id = ? ORDER BY upload_id",
                    (session_id,),
                )
            ]
            completion = conn.execute(
                "SELECT response_bytes FROM completions WHERE session_id = ?", (session_id,)
            ).fetchone()
            result["completion_receipt"] = (
                self._decode_protocol_object(bytes(completion["response_bytes"])) if completion else None
            )
            result["jobs"] = [
                self._decode_protocol_object(item["job_json"])
                for item in conn.execute(
                    "SELECT job_json FROM jobs WHERE session_id = ? ORDER BY requested_at", (session_id,)
                )
            ]
            return result

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT job_json FROM jobs WHERE organization_id = ? AND project_id = ? ORDER BY requested_at DESC",
                (self.config.organization_id, self.config.project_id),
            ).fetchall()
        return [self._decode_protocol_object(row["job_json"]) for row in rows]

    def get_job(self, job_id: str) -> dict[str, Any]:
        _require_id(job_id, "job_id")
        with self._connect() as conn:
            row = conn.execute(
                """SELECT job_json FROM jobs WHERE job_id = ?
                   AND organization_id = ? AND project_id = ?""",
                (job_id, self.config.organization_id, self.config.project_id),
            ).fetchone()
        if row is None:
            raise ApiError(404, "JOB_NOT_FOUND", "job was not found")
        return self._decode_protocol_object(row["job_json"])

    def list_audit_events(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT event_id,event_type,actor_kind,organization_id,project_id,
                          session_id,outcome,occurred_at
                   FROM audit_events WHERE organization_id = ? AND project_id = ?
                   ORDER BY occurred_at,event_id""",
                (self.config.organization_id, self.config.project_id),
            ).fetchall()
        return [dict(row) for row in rows]


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
