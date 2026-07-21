"""Persistent trust-boundary service for the Tacua pilot backend."""

from __future__ import annotations

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
from typing import Any, BinaryIO

from . import CAPTURE_CONTRACT, DIAGNOSTIC_CONTRACT, PROCESSING_JOB_CONTRACT, __version__
from .config import BUNDLE_ID_PATTERN, ID_PATTERN, PilotConfig
from .contracts import ContractError, seal as seal_contract, validate as validate_contract


DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
MAX_SEGMENTS = 2048
INTERNAL_DELETION_RESOURCE = "tacua.internal-deletion-job@1.0.0"


class ClosingConnection(sqlite3.Connection):
    """Commit or roll back a context, then actually close its SQLite handle."""

    def __exit__(self, exc_type, exc_value, traceback):  # type: ignore[no-untyped-def]
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class ApiError(Exception):
    """A safe error that may be returned to an API client."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


def _new_credential(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def _credential_hash(value: str) -> str:
    return sha256_digest(value.encode("utf-8"))


class DuplicateJSONKey(ValueError):
    pass


def strict_json_loads(value: bytes | str) -> Any:
    """Decode JSON while rejecting ambiguous duplicate object members."""

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise DuplicateJSONKey("JSON object contains a duplicate key")
            result[key] = item
        return result

    return json.loads(value, object_pairs_hook=reject_duplicates)


def _require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        raise ApiError(400, "INVALID_IDENTIFIER", f"{field} is invalid")
    return value


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not DIGEST_PATTERN.fullmatch(value):
        raise ApiError(400, "INVALID_DIGEST", f"{field} must be a lowercase SHA-256 digest")
    return value


class PilotBackend:
    """SQLite and filesystem implementation of the V1 pilot boundary."""

    def __init__(self, config: PilotConfig, admin_secret: bytes):
        if len(admin_secret) < 32:
            raise ValueError("admin secret must be at least 32 bytes")
        for name in ("organization_id", "project_id", "application_id", "build_id"):
            if not ID_PATTERN.fullmatch(getattr(config, name)):
                raise ValueError(f"{name} is invalid")
        if not BUNDLE_ID_PATTERN.fullmatch(config.bundle_identifier):
            raise ValueError("bundle_identifier must be a reverse-DNS application identifier")
        if not DIGEST_PATTERN.fullmatch(config.build_identity_digest):
            raise ValueError("build_identity_digest must be a lowercase SHA-256 digest")
        if not 1 <= config.raw_retention_days <= 30:
            raise ValueError("raw_retention_days must be from 1 through 30")
        self.config = config
        self._admin_secret = bytes(admin_secret)
        self.state_dir = config.state_directory
        if not self.state_dir.is_absolute() or self.state_dir == Path(self.state_dir.anchor):
            raise ValueError("state_directory must be an absolute non-root path")
        self.media_dir = self.state_dir / "media"
        self.temp_dir = self.state_dir / "tmp"
        self.db_path = self.state_dir / "tacua.sqlite3"
        self._lock = threading.RLock()
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.media_dir.mkdir(exist_ok=True, mode=0o700)
        self.temp_dir.mkdir(exist_ok=True, mode=0o700)
        for directory in (self.state_dir, self.media_dir, self.temp_dir):
            metadata = directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"backend state path is not a real directory: {directory}")
            directory.chmod(0o700)
        self._initialize_database()
        self._reconcile_storage()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, factory=ClosingConnection)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        return conn

    def _initialize_database(self) -> None:
        deployment_scope_json = canonical_json(self.config.scope)
        schema = """
        CREATE TABLE IF NOT EXISTS deployment_scope (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            scope_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS launch_codes (
            launch_id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            application_id TEXT NOT NULL,
            bundle_identifier TEXT NOT NULL,
            build_id TEXT NOT NULL,
            build_identity_digest TEXT NOT NULL,
            consent_contract TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            session_id TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            application_id TEXT NOT NULL,
            bundle_identifier TEXT NOT NULL,
            build_id TEXT NOT NULL,
            build_identity_digest TEXT NOT NULL,
            consent_contract TEXT NOT NULL,
            state TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            raw_media_expires_at TEXT NOT NULL,
            retention_policy TEXT NOT NULL,
            deletion_status TEXT NOT NULL,
            manifest_digest TEXT,
            completion_digest TEXT,
            manifest_size_bytes INTEGER,
            manifest_content_digest TEXT,
            manifest_relative_path TEXT
        );
        CREATE TABLE IF NOT EXISTS upload_tokens (
            token_hash TEXT PRIMARY KEY,
            session_id TEXT NOT NULL UNIQUE REFERENCES sessions(session_id),
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT
        );
        CREATE TABLE IF NOT EXISTS segments (
            session_id TEXT NOT NULL REFERENCES sessions(session_id),
            sequence INTEGER NOT NULL,
            segment_id TEXT NOT NULL,
            object_id TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            content_type TEXT NOT NULL,
            content_digest TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            received_at TEXT NOT NULL,
            receipt_digest TEXT NOT NULL,
            PRIMARY KEY (session_id, sequence),
            UNIQUE (session_id, segment_id)
        );
        CREATE TABLE IF NOT EXISTS diagnostics (
            session_id TEXT NOT NULL REFERENCES sessions(session_id),
            envelope_id TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            content_digest TEXT NOT NULL,
            envelope_digest TEXT NOT NULL,
            build_identity_digest TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            received_at TEXT NOT NULL,
            PRIMARY KEY (session_id, envelope_id)
        );
        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            contract_version TEXT NOT NULL,
            job_type TEXT NOT NULL,
            session_id TEXT NOT NULL REFERENCES sessions(session_id),
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            status TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            input_json TEXT,
            job_json TEXT,
            failure_code TEXT
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
        CREATE INDEX IF NOT EXISTS jobs_status_idx ON jobs(status, requested_at);
        CREATE INDEX IF NOT EXISTS audit_session_idx ON audit_events(session_id, occurred_at);
        """
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(schema)
            pinned = conn.execute(
                "SELECT scope_json FROM deployment_scope WHERE singleton = 1"
            ).fetchone()
            if pinned is None:
                conn.execute(
                    "INSERT INTO deployment_scope (singleton, scope_json) VALUES (1, ?)",
                    (deployment_scope_json,),
                )
            elif pinned["scope_json"] != deployment_scope_json:
                raise ValueError("configured deployment scope differs from the persisted scope")
            conn.execute("PRAGMA user_version = 1")

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
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"state path is not a regular file: {path}")
        return metadata.st_size

    def _reconcile_storage(self) -> None:
        """Remove recognized crash orphans and fail closed on lost committed files."""

        with self._lock, self._connect() as conn:
            sessions = {row["session_id"]: row for row in conn.execute("SELECT * FROM sessions")}
            segments = {
                (row["session_id"], row["sequence"]): row
                for row in conn.execute("SELECT * FROM segments")
            }
            diagnostics = {
                (row["session_id"], row["envelope_id"]): row
                for row in conn.execute("SELECT * FROM diagnostics")
            }

        temp_changed = False
        for entry in self.temp_dir.iterdir():
            if not any(entry.name.startswith(prefix) for prefix in ("upload-", "diagnostic-", "manifest-")):
                raise ValueError(f"unrecognized file in backend temp state: {entry.name}")
            self._regular_file_size(entry)
            entry.unlink()
            temp_changed = True
        if temp_changed:
            self._fsync_directory(self.temp_dir)

        for session_dir in self.media_dir.iterdir():
            if session_dir.is_symlink() or not session_dir.is_dir() or not ID_PATTERN.fullmatch(session_dir.name):
                raise ValueError(f"unrecognized backend media directory: {session_dir.name}")
            session_id = session_dir.name
            session = sessions.get(session_id)
            if session is None:
                raise ValueError(f"media directory has no durable session: {session_id}")
            deletion_in_progress = session["deletion_status"] == "deletion_requested"
            changed = False
            for entry in session_dir.iterdir():
                segment_match = re.fullmatch(r"([0-9]{4})\.segment", entry.name)
                if segment_match:
                    sequence = int(segment_match.group(1))
                    row = segments.get((session_id, sequence))
                    size = self._regular_file_size(entry)
                    if row is None:
                        entry.unlink()
                        changed = True
                    elif not deletion_in_progress and size != row["size_bytes"]:
                        raise ValueError(f"committed segment is missing or truncated: {session_id}/{sequence}")
                    continue
                if entry.name == "capture-manifest.json":
                    size = self._regular_file_size(entry)
                    if session["manifest_relative_path"] is None:
                        entry.unlink()
                        changed = True
                    elif not deletion_in_progress and size != session["manifest_size_bytes"]:
                        raise ValueError(f"committed manifest is missing or truncated: {session_id}")
                    continue
                if entry.name == "diagnostics" and not entry.is_symlink() and entry.is_dir():
                    diagnostic_changed = False
                    for document in entry.iterdir():
                        match = re.fullmatch(r"([a-z][a-z0-9_-]{2,63})\.json", document.name)
                        if not match:
                            raise ValueError(f"unrecognized diagnostic state: {document.name}")
                        envelope_id = match.group(1)
                        row = diagnostics.get((session_id, envelope_id))
                        size = self._regular_file_size(document)
                        if row is None:
                            document.unlink()
                            diagnostic_changed = True
                        elif not deletion_in_progress and size != row["size_bytes"]:
                            raise ValueError(
                                f"committed diagnostic is missing or truncated: {session_id}/{envelope_id}"
                            )
                    if diagnostic_changed:
                        self._fsync_directory(entry)
                    if not any(entry.iterdir()):
                        entry.rmdir()
                        changed = True
                    continue
                raise ValueError(f"unrecognized backend session state: {entry.name}")
            if not deletion_in_progress:
                for (stored_session, sequence), row in segments.items():
                    if stored_session == session_id and self._regular_file_size(
                        self._segment_path(session_id, sequence)
                    ) != row["size_bytes"]:
                        raise ValueError(f"committed segment is missing: {session_id}/{sequence}")
                for (stored_session, envelope_id), row in diagnostics.items():
                    if stored_session == session_id and self._regular_file_size(
                        self._diagnostic_path(session_id, envelope_id)
                    ) != row["size_bytes"]:
                        raise ValueError(f"committed diagnostic is missing: {session_id}/{envelope_id}")
                if session["manifest_relative_path"] is not None and self._regular_file_size(
                    self._manifest_path(session_id)
                ) != session["manifest_size_bytes"]:
                    raise ValueError(f"committed manifest is missing: {session_id}")
            if changed:
                self._fsync_directory(session_dir)
            if not any(session_dir.iterdir()):
                session_dir.rmdir()
                self._fsync_directory(self.media_dir)

        # This pass is intentionally independent of directory discovery: a
        # whole missing session directory must not make committed rows invisible.
        for (session_id, sequence), row in segments.items():
            session = sessions[session_id]
            if session["deletion_status"] != "deletion_requested" and self._regular_file_size(
                self._segment_path(session_id, sequence)
            ) != row["size_bytes"]:
                raise ValueError(f"committed segment is missing: {session_id}/{sequence}")
        for (session_id, envelope_id), row in diagnostics.items():
            session = sessions[session_id]
            if session["deletion_status"] != "deletion_requested" and self._regular_file_size(
                self._diagnostic_path(session_id, envelope_id)
            ) != row["size_bytes"]:
                raise ValueError(f"committed diagnostic is missing: {session_id}/{envelope_id}")
        for session_id, session in sessions.items():
            if (
                session["deletion_status"] != "deletion_requested"
                and session["manifest_relative_path"] is not None
                and self._regular_file_size(self._manifest_path(session_id))
                != session["manifest_size_bytes"]
            ):
                raise ValueError(f"committed manifest is missing: {session_id}")

    @property
    def retention_policy(self) -> str:
        return f"raw-{self.config.raw_retention_days}d-v1"

    def health(self) -> dict[str, Any]:
        with self._connect() as conn:
            conn.execute("SELECT 1").fetchone()
        return {
            "status": "ok",
            "service": "tacua-pilot-backend",
            "version": __version__,
            "production_ready": False,
            "contracts": {
                "capture": CAPTURE_CONTRACT,
                "diagnostics": DIAGNOSTIC_CONTRACT,
                "processing_job": PROCESSING_JOB_CONTRACT,
            },
        }

    def authenticate_admin(self, credential: str | None) -> None:
        if not isinstance(credential, str) or not hmac.compare_digest(
            credential.encode("utf-8"), self._admin_secret
        ):
            raise ApiError(401, "ADMIN_AUTH_REQUIRED", "valid administrator authentication is required")

    def _audit(
        self,
        conn: sqlite3.Connection,
        event_type: str,
        actor_kind: str,
        outcome: str,
        session_id: str | None = None,
    ) -> None:
        # This fixed-column event intentionally has no arbitrary payload field.
        conn.execute(
            """INSERT INTO audit_events
               (event_id, event_type, actor_kind, organization_id, project_id,
                session_id, outcome, occurred_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                _new_id("aud"),
                event_type,
                actor_kind,
                self.config.organization_id,
                self.config.project_id,
                session_id,
                outcome,
                timestamp(utc_now()),
            ),
        )

    def create_launch_code(self, requested_scope: Any) -> dict[str, Any]:
        if not isinstance(requested_scope, dict) or requested_scope != self.config.scope:
            raise ApiError(403, "SCOPE_NOT_ALLOWED", "requested launch scope is not configured")
        now = utc_now()
        expires_at = now + timedelta(seconds=self.config.launch_code_ttl_seconds)
        launch_code = _new_credential("lc")
        launch_id = _new_id("lch")
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO launch_codes
                   (launch_id, token_hash, organization_id, project_id, application_id,
                    bundle_identifier, build_id, build_identity_digest, consent_contract,
                    created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    launch_id,
                    _credential_hash(launch_code),
                    self.config.organization_id,
                    self.config.project_id,
                    self.config.application_id,
                    self.config.bundle_identifier,
                    self.config.build_id,
                    self.config.build_identity_digest,
                    self.config.consent_contract,
                    timestamp(now),
                    timestamp(expires_at),
                ),
            )
            self._audit(conn, "launch_code_created", "admin", "succeeded")
        return {
            "launch_code": launch_code,
            "expires_at": timestamp(expires_at),
            "scope": self.config.scope,
        }

    def exchange_launch_code(self, body: Any) -> dict[str, Any]:
        if not isinstance(body, dict) or set(body) != {"launch_code", "scope"}:
            raise ApiError(400, "INVALID_REQUEST", "exchange fields are invalid")
        code = body.get("launch_code")
        scope = body.get("scope")
        if not isinstance(code, str) or not 40 <= len(code) <= 256:
            raise ApiError(400, "INVALID_LAUNCH_CODE", "launch code is invalid")
        if not isinstance(scope, dict) or scope != self.config.scope:
            raise ApiError(403, "SCOPE_MISMATCH", "SDK scope does not match the launch scope")

        now = utc_now()
        now_text = timestamp(now)
        upload_expires_at = now + timedelta(seconds=self.config.upload_token_ttl_seconds)
        raw_expires_at = now + timedelta(days=self.config.raw_retention_days)
        session_id = _new_id("ses")
        upload_token = _new_credential("ut")

        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM launch_codes WHERE token_hash = ?", (_credential_hash(code),)
            ).fetchone()
            if row is None:
                raise ApiError(401, "INVALID_LAUNCH_CODE", "launch code is invalid")
            if row["consumed_at"] is not None:
                raise ApiError(409, "LAUNCH_CODE_CONSUMED", "launch code has already been consumed")
            if row["expires_at"] <= now_text:
                raise ApiError(401, "LAUNCH_CODE_EXPIRED", "launch code has expired")
            stored_scope = {key: row[key] for key in self.config.scope}
            if stored_scope != scope:
                raise ApiError(403, "SCOPE_MISMATCH", "SDK scope does not match the launch scope")

            conn.execute(
                """INSERT INTO sessions
                   (session_id, organization_id, project_id, application_id, bundle_identifier, build_id,
                    build_identity_digest, consent_contract, state, created_at, raw_media_expires_at,
                    retention_policy, deletion_status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'receiving', ?, ?, ?, 'active')""",
                (
                    session_id,
                    self.config.organization_id,
                    self.config.project_id,
                    self.config.application_id,
                    self.config.bundle_identifier,
                    self.config.build_id,
                    self.config.build_identity_digest,
                    self.config.consent_contract,
                    now_text,
                    timestamp(raw_expires_at),
                    self.retention_policy,
                ),
            )
            conn.execute(
                """INSERT INTO upload_tokens
                   (token_hash, session_id, created_at, expires_at)
                   VALUES (?, ?, ?, ?)""",
                (_credential_hash(upload_token), session_id, now_text, timestamp(upload_expires_at)),
            )
            conn.execute(
                "UPDATE launch_codes SET consumed_at = ?, session_id = ? WHERE launch_id = ?",
                (now_text, session_id, row["launch_id"]),
            )
            self._audit(conn, "launch_code_exchanged", "sdk", "succeeded", session_id)

        return {
            "session_id": session_id,
            "upload_token": upload_token,
            "upload_token_expires_at": timestamp(upload_expires_at),
            "scope": self.config.scope,
            "raw_media_expires_at": timestamp(raw_expires_at),
            "retention_policy": self.retention_policy,
        }

    def _authorize_upload(
        self, conn: sqlite3.Connection, session_id: str, upload_token: str | None
    ) -> sqlite3.Row:
        _require_id(session_id, "session_id")
        if not isinstance(upload_token, str) or not 40 <= len(upload_token) <= 256:
            raise ApiError(401, "UPLOAD_AUTH_REQUIRED", "valid SDK upload authentication is required")
        row = conn.execute(
            """SELECT s.*, t.expires_at AS token_expires_at, t.revoked_at
               FROM upload_tokens t JOIN sessions s ON s.session_id = t.session_id
               WHERE t.token_hash = ?""",
            (_credential_hash(upload_token),),
        ).fetchone()
        if row is None or row["session_id"] != session_id:
            raise ApiError(403, "UPLOAD_SCOPE_MISMATCH", "upload credential is not scoped to this session")
        persisted_scope = {
            "organization_id": row["organization_id"],
            "project_id": row["project_id"],
            "application_id": row["application_id"],
            "bundle_identifier": row["bundle_identifier"],
            "build_id": row["build_id"],
            "build_identity_digest": row["build_identity_digest"],
            "consent_contract": row["consent_contract"],
        }
        if persisted_scope != self.config.scope:
            raise ApiError(403, "UPLOAD_SCOPE_MISMATCH", "session is outside this deployment scope")
        if row["revoked_at"] is not None or row["token_expires_at"] <= timestamp(utc_now()):
            raise ApiError(401, "UPLOAD_TOKEN_EXPIRED", "upload credential is expired or revoked")
        if row["state"] != "receiving" or row["deletion_status"] != "active":
            raise ApiError(409, "SESSION_NOT_RECEIVING", "session no longer accepts uploads")
        return row

    def check_upload_authorization(self, session_id: str, upload_token: str | None) -> None:
        """Fail before a request body is read, while commit paths re-check later."""

        with self._connect() as conn:
            self._authorize_upload(conn, session_id, upload_token)

    def check_completion_authorization(self, session_id: str, upload_token: str | None) -> None:
        """Authenticate a new completion or an exact completed-manifest replay."""

        _require_id(session_id, "session_id")
        if not isinstance(upload_token, str) or not 40 <= len(upload_token) <= 256:
            raise ApiError(401, "UPLOAD_AUTH_REQUIRED", "valid SDK upload authentication is required")
        with self._connect() as conn:
            row = conn.execute(
                """SELECT s.*, t.expires_at AS token_expires_at, t.revoked_at
                   FROM upload_tokens t JOIN sessions s ON s.session_id = t.session_id
                   WHERE t.token_hash = ?""",
                (_credential_hash(upload_token),),
            ).fetchone()
            if row is None or row["session_id"] != session_id:
                raise ApiError(403, "UPLOAD_SCOPE_MISMATCH", "upload credential is not scoped to this session")
            if {key: row[key] for key in self.config.scope} != self.config.scope:
                raise ApiError(403, "UPLOAD_SCOPE_MISMATCH", "session is outside this deployment scope")
            if row["deletion_status"] != "active" or row["state"] not in ("receiving", "completed"):
                raise ApiError(409, "SESSION_NOT_RECEIVING", "session cannot be completed")
            if row["token_expires_at"] <= timestamp(utc_now()):
                raise ApiError(401, "UPLOAD_TOKEN_EXPIRED", "upload credential is expired or revoked")
            if row["state"] == "receiving" and row["revoked_at"] is not None:
                raise ApiError(401, "UPLOAD_TOKEN_EXPIRED", "upload credential is expired or revoked")

    def _segment_path(self, session_id: str, sequence: int) -> Path:
        _require_id(session_id, "session_id")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence < MAX_SEGMENTS:
            raise ApiError(400, "INVALID_SEGMENT_INDEX", "segment index is outside the supported range")
        return self.media_dir / session_id / f"{sequence:04d}.segment"

    def _diagnostic_path(self, session_id: str, envelope_id: str) -> Path:
        _require_id(session_id, "session_id")
        _require_id(envelope_id, "envelope_id")
        return self.media_dir / session_id / "diagnostics" / f"{envelope_id}.json"

    def _manifest_path(self, session_id: str) -> Path:
        _require_id(session_id, "session_id")
        return self.media_dir / session_id / "capture-manifest.json"

    def _write_verified_stream(
        self,
        stream: BinaryIO,
        declared_length: int,
        expected_digest: str,
        maximum: int,
    ) -> tuple[Path, str]:
        if isinstance(declared_length, bool) or not isinstance(declared_length, int):
            raise ApiError(411, "CONTENT_LENGTH_REQUIRED", "a valid Content-Length is required")
        if declared_length < 1 or declared_length > maximum:
            raise ApiError(413, "CONTENT_SIZE_NOT_ALLOWED", "content size is outside the configured limit")
        _require_digest(expected_digest, "content_digest")
        hasher = hashlib.sha256()
        count = 0
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.temp_dir, prefix="upload-", delete=False) as handle:
                temporary = Path(handle.name)
                while True:
                    chunk = stream.read(min(65_536, declared_length - count + 1))
                    if not chunk:
                        break
                    if not isinstance(chunk, bytes):
                        raise ApiError(400, "INVALID_BODY", "request body must be bytes")
                    count += len(chunk)
                    if count > declared_length or count > maximum:
                        raise ApiError(400, "CONTENT_LENGTH_MISMATCH", "request body length does not match Content-Length")
                    hasher.update(chunk)
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            if count != declared_length:
                raise ApiError(400, "CONTENT_LENGTH_MISMATCH", "request body length does not match Content-Length")
            actual = "sha256:" + hasher.hexdigest()
            if not hmac.compare_digest(actual, expected_digest):
                raise ApiError(422, "CONTENT_DIGEST_MISMATCH", "request body does not match its SHA-256 digest")
            return temporary, actual
        except Exception:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            raise

    @staticmethod
    def _receipt_from_row(row: sqlite3.Row, idempotent: bool) -> dict[str, Any]:
        return {
            "segment_id": row["segment_id"],
            "object_id": row["object_id"],
            "size_bytes": row["size_bytes"],
            "content_digest": row["content_digest"],
            "received_at": row["received_at"],
            "receipt_digest": row["receipt_digest"],
            "idempotent_retry": idempotent,
        }

    @staticmethod
    def _verify_stored_segment(path: Path, expected_size: int, expected_digest: str) -> bool:
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected_size:
                return False
            hasher = hashlib.sha256()
            with path.open("rb") as handle:
                while chunk := handle.read(65_536):
                    hasher.update(chunk)
            return hmac.compare_digest("sha256:" + hasher.hexdigest(), expected_digest)
        except OSError:
            return False

    def upload_segment(
        self,
        session_id: str,
        sequence: int,
        segment_id: str,
        upload_token: str | None,
        stream: BinaryIO,
        declared_length: int,
        expected_digest: str,
        content_type: str = "video/quicktime",
    ) -> dict[str, Any]:
        _require_id(segment_id, "segment_id")
        if content_type not in ("video/quicktime", "video/mp4"):
            raise ApiError(415, "CONTENT_TYPE_NOT_ALLOWED", "segment content type is not supported")
        self.check_upload_authorization(session_id, upload_token)
        final_path = self._segment_path(session_id, sequence)
        temporary, actual_digest = self._write_verified_stream(
            stream, declared_length, expected_digest, self.config.max_segment_bytes
        )
        publication_needs_cleanup = False
        try:
            with self._lock, self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                self._authorize_upload(conn, session_id, upload_token)
                existing = conn.execute(
                    "SELECT * FROM segments WHERE session_id = ? AND sequence = ?",
                    (session_id, sequence),
                ).fetchone()
                same_id = conn.execute(
                    "SELECT sequence FROM segments WHERE session_id = ? AND segment_id = ?",
                    (session_id, segment_id),
                ).fetchone()
                if same_id is not None and same_id["sequence"] != sequence:
                    raise ApiError(409, "SEGMENT_ID_CONFLICT", "segment id is already bound to another index")
                if existing is not None:
                    if (
                        existing["segment_id"] == segment_id
                        and existing["size_bytes"] == declared_length
                        and existing["content_type"] == content_type
                        and hmac.compare_digest(existing["content_digest"], actual_digest)
                    ):
                        if not self._verify_stored_segment(
                            final_path, existing["size_bytes"], existing["content_digest"]
                        ):
                            raise ApiError(500, "STORAGE_INCONSISTENT", "stored segment is unavailable")
                        self._audit(conn, "segment_retried", "sdk", "succeeded", session_id)
                        result = self._receipt_from_row(existing, True)
                        return result
                    self._audit(conn, "segment_conflict", "sdk", "rejected", session_id)
                    raise ApiError(409, "SEGMENT_CONFLICT", "segment index already contains different content")

                final_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.replace(temporary, final_path)
                temporary = None
                publication_needs_cleanup = True
                self._fsync_directory(final_path.parent)
                self._fsync_directory(self.media_dir)
                self._fsync_directory(self.temp_dir)
                now_text = timestamp(utc_now())
                receipt = {
                    "segment_id": segment_id,
                    "object_id": _new_id("obj"),
                    "size_bytes": declared_length,
                    "content_digest": actual_digest,
                    "received_at": now_text,
                }
                receipt["receipt_digest"] = sha256_digest(canonical_json(receipt).encode("utf-8"))
                relative_path = str(final_path.relative_to(self.state_dir))
                conn.execute(
                    """INSERT INTO segments
                       (session_id, sequence, segment_id, object_id, size_bytes, content_type,
                        content_digest, relative_path, received_at, receipt_digest)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        session_id,
                        sequence,
                        receipt["segment_id"],
                        receipt["object_id"],
                        declared_length,
                        content_type,
                        actual_digest,
                        relative_path,
                        now_text,
                        receipt["receipt_digest"],
                    ),
                )
                self._audit(conn, "segment_stored", "sdk", "succeeded", session_id)
                result = {**receipt, "idempotent_retry": False}
            publication_needs_cleanup = False
            return result
        except Exception:
            if publication_needs_cleanup:
                final_path.unlink(missing_ok=True)
                self._fsync_directory(final_path.parent)
            raise
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def upload_diagnostic(
        self,
        session_id: str,
        envelope_id: str,
        upload_token: str | None,
        raw_document: bytes,
        expected_digest: str,
    ) -> dict[str, Any]:
        _require_id(session_id, "session_id")
        _require_id(envelope_id, "envelope_id")
        self.check_upload_authorization(session_id, upload_token)
        if not isinstance(raw_document, bytes) or not 1 <= len(raw_document) <= self.config.max_diagnostic_bytes:
            raise ApiError(413, "DIAGNOSTIC_SIZE_NOT_ALLOWED", "diagnostic size is outside the configured limit")
        _require_digest(expected_digest, "content_digest")
        actual_digest = sha256_digest(raw_document)
        if not hmac.compare_digest(actual_digest, expected_digest):
            raise ApiError(422, "CONTENT_DIGEST_MISMATCH", "diagnostic does not match its SHA-256 digest")
        try:
            document = strict_json_loads(raw_document)
        except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJSONKey) as exc:
            raise ApiError(400, "INVALID_DIAGNOSTIC_JSON", "diagnostic body must be valid UTF-8 JSON") from exc
        if not isinstance(document, dict):
            raise ApiError(400, "INVALID_DIAGNOSTIC_JSON", "diagnostic document must be an object")
        expected_fields = {
            "contract_version": DIAGNOSTIC_CONTRACT,
            "organization_id": self.config.organization_id,
            "project_id": self.config.project_id,
            "build_id": self.config.build_id,
            "build_identity_digest": self.config.build_identity_digest,
            "session_id": session_id,
            "envelope_id": envelope_id,
        }
        for key, expected in expected_fields.items():
            if document.get(key) != expected:
                raise ApiError(403, "DIAGNOSTIC_SCOPE_MISMATCH", f"diagnostic {key} does not match the session")
        try:
            validate_contract(document)
        except ContractError as exc:
            raise ApiError(
                422,
                "DIAGNOSTIC_CONTRACT_INVALID",
                f"diagnostic contract validation failed ({exc.code})",
            ) from exc
        envelope_digest = document["envelope_digest"]
        now_text = timestamp(utc_now())
        final_path = self._diagnostic_path(session_id, envelope_id)
        temporary: Path | None = None
        publication_needs_cleanup = False
        try:
            with tempfile.NamedTemporaryFile(dir=self.temp_dir, prefix="diagnostic-", delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(raw_document)
                handle.flush()
                os.fsync(handle.fileno())
            with self._lock, self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                self._authorize_upload(conn, session_id, upload_token)
                existing = conn.execute(
                    "SELECT * FROM diagnostics WHERE session_id = ? AND envelope_id = ?",
                    (session_id, envelope_id),
                ).fetchone()
                if existing is not None:
                    if (
                        hmac.compare_digest(existing["content_digest"], actual_digest)
                        and hmac.compare_digest(existing["envelope_digest"], envelope_digest)
                        and self._verify_stored_segment(
                            final_path, existing["size_bytes"], existing["content_digest"]
                        )
                    ):
                        return {
                            "envelope_id": envelope_id,
                            "content_digest": actual_digest,
                            "envelope_digest": envelope_digest,
                            "size_bytes": existing["size_bytes"],
                            "received_at": existing["received_at"],
                            "idempotent_retry": True,
                        }
                    raise ApiError(409, "DIAGNOSTIC_CONFLICT", "envelope id already contains different content")
                final_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.replace(temporary, final_path)
                temporary = None
                publication_needs_cleanup = True
                self._fsync_directory(final_path.parent)
                self._fsync_directory(final_path.parent.parent)
                self._fsync_directory(self.media_dir)
                self._fsync_directory(self.temp_dir)
                relative_path = str(final_path.relative_to(self.state_dir))
                conn.execute(
                    """INSERT INTO diagnostics
                       (session_id, envelope_id, size_bytes, content_digest, envelope_digest,
                        build_identity_digest, relative_path, received_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        session_id,
                        envelope_id,
                        len(raw_document),
                        actual_digest,
                        envelope_digest,
                        document["build_identity_digest"],
                        relative_path,
                        now_text,
                    ),
                )
                self._audit(conn, "diagnostic_stored", "sdk", "succeeded", session_id)
                result = {
                    "envelope_id": envelope_id,
                    "content_digest": actual_digest,
                    "envelope_digest": envelope_digest,
                    "size_bytes": len(raw_document),
                    "received_at": now_text,
                    "idempotent_retry": False,
                }
            publication_needs_cleanup = False
            return result
        except Exception:
            if publication_needs_cleanup:
                final_path.unlink(missing_ok=True)
                self._fsync_directory(final_path.parent)
            raise
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _queued_job_snapshot(
        self,
        job_id: str,
        session_id: str,
        build_identity_digest: str,
        requested_at: str,
        manifest_digest: str,
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
        snapshot = {
            "contract_version": PROCESSING_JOB_CONTRACT,
            "media_type": "application/vnd.tacua.processing-job+json;version=1.0.0",
            "organization_id": self.config.organization_id,
            "project_id": self.config.project_id,
            "build_id": self.config.build_id,
            "build_identity_digest": build_identity_digest,
            "session_id": session_id,
            "job_id": job_id,
            "job_version": 1,
            "previous_job_digest": None,
            "status": "queued",
            "requested_at": requested_at,
            "started_at": None,
            "completed_at": None,
            "inputs": {
                "capture_manifest_digest": manifest_digest,
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
        snapshot = seal_contract(snapshot)
        validate_contract(snapshot)
        return snapshot

    def complete_session(self, session_id: str, upload_token: str | None, body: Any) -> dict[str, Any]:
        _require_id(session_id, "session_id")
        self.check_completion_authorization(session_id, upload_token)
        if not isinstance(body, dict) or set(body) != {"capture_manifest", "diagnostic_envelope_ids"}:
            raise ApiError(400, "INVALID_COMPLETION", "completion fields are invalid")
        manifest = body.get("capture_manifest")
        diagnostic_ids = body.get("diagnostic_envelope_ids")
        if not isinstance(manifest, dict):
            raise ApiError(400, "INVALID_COMPLETION", "capture_manifest must be an object")
        if not isinstance(diagnostic_ids, list) or not 1 <= len(diagnostic_ids) <= MAX_SEGMENTS:
            raise ApiError(400, "INVALID_COMPLETION", "at least one diagnostic envelope is required")
        if len(diagnostic_ids) != len(set(diagnostic_ids)):
            raise ApiError(400, "INVALID_COMPLETION", "diagnostic envelope ids must be unique")
        for envelope_id in diagnostic_ids:
            _require_id(envelope_id, "diagnostic_envelope_id")
        try:
            validate_contract(manifest)
        except ContractError as exc:
            raise ApiError(
                422,
                "CAPTURE_CONTRACT_INVALID",
                f"capture contract validation failed ({exc.code})",
            ) from exc

        expected_scope = {
            "contract_version": CAPTURE_CONTRACT,
            "organization_id": self.config.organization_id,
            "project_id": self.config.project_id,
            "build_id": self.config.build_id,
            "build_identity_digest": self.config.build_identity_digest,
            "session_id": session_id,
        }
        for key, expected in expected_scope.items():
            if manifest.get(key) != expected:
                raise ApiError(403, "MANIFEST_SCOPE_MISMATCH", f"capture manifest {key} does not match the session")
        if manifest["capture_state"] != "complete" or manifest["upload"]["state"] != "complete":
            raise ApiError(409, "CAPTURE_NOT_COMPLETE", "sealed capture and upload states must both be complete")
        if manifest["upload"]["remote_session_id"] != session_id:
            raise ApiError(403, "MANIFEST_SCOPE_MISMATCH", "remote session id does not match the session")

        manifest_digest = manifest["manifest_digest"]
        completion_digest = sha256_digest(
            canonical_json(
                {
                    "manifest_digest": manifest_digest,
                    "diagnostic_envelope_ids": diagnostic_ids,
                }
            ).encode("utf-8")
        )
        manifest_bytes = canonical_json(manifest).encode("utf-8")
        manifest_path = self._manifest_path(session_id)
        temporary: Path | None = None
        publication_needs_cleanup = False
        try:
            with tempfile.NamedTemporaryFile(dir=self.temp_dir, prefix="manifest-", delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(manifest_bytes)
                handle.flush()
                os.fsync(handle.fileno())

            now_text = timestamp(utc_now())
            job_id = _new_id("job")
            with self._lock, self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                if not isinstance(upload_token, str) or not 40 <= len(upload_token) <= 256:
                    raise ApiError(401, "UPLOAD_AUTH_REQUIRED", "valid SDK upload authentication is required")
                session = conn.execute(
                    """SELECT s.*, t.expires_at AS token_expires_at, t.revoked_at
                       FROM upload_tokens t JOIN sessions s ON s.session_id = t.session_id
                       WHERE t.token_hash = ?""",
                    (_credential_hash(upload_token),),
                ).fetchone()
                if session is None or session["session_id"] != session_id:
                    raise ApiError(403, "UPLOAD_SCOPE_MISMATCH", "upload credential is not scoped to this session")
                persisted_scope = {key: session[key] for key in self.config.scope}
                if persisted_scope != self.config.scope:
                    raise ApiError(403, "UPLOAD_SCOPE_MISMATCH", "session is outside this deployment scope")
                if session["token_expires_at"] <= now_text:
                    raise ApiError(401, "UPLOAD_TOKEN_EXPIRED", "upload credential is expired or revoked")
                if session["state"] == "completed":
                    if hmac.compare_digest(
                        session["manifest_digest"] or "", manifest_digest
                    ) and hmac.compare_digest(
                        session["completion_digest"] or "", completion_digest
                    ):
                        existing_job = conn.execute(
                            """SELECT * FROM jobs
                               WHERE session_id = ? AND job_type = 'process_session'
                               ORDER BY requested_at LIMIT 1""",
                            (session_id,),
                        ).fetchone()
                        if existing_job is None:
                            raise ApiError(500, "STORAGE_INCONSISTENT", "completed session job is unavailable")
                        if not self._verify_stored_segment(
                            manifest_path,
                            session["manifest_size_bytes"],
                            session["manifest_content_digest"],
                        ):
                            raise ApiError(500, "STORAGE_INCONSISTENT", "stored manifest is unavailable")
                        return self._job_from_row(existing_job)
                    raise ApiError(409, "COMPLETION_CONFLICT", "session was completed with different sealed inputs")
                self._authorize_upload(conn, session_id, upload_token)
                if manifest["retention"]["raw_media_expires_at"] != session["raw_media_expires_at"]:
                    raise ApiError(409, "RETENTION_MISMATCH", "manifest retention does not match server metadata")
                if manifest["retention"]["deletion_status"] != "active":
                    raise ApiError(409, "RETENTION_MISMATCH", "active completion cannot be deletion-marked")

                uploaded_rows = list(conn.execute("SELECT * FROM segments WHERE session_id = ?", (session_id,)))
                uploaded = {row["sequence"]: row for row in uploaded_rows}
                available = {
                    item["sequence"]: item
                    for item in manifest["segments"]
                    if item["availability"] == "available"
                }
                if set(uploaded) != set(available):
                    raise ApiError(409, "SEGMENT_SET_MISMATCH", "available declarations do not match uploaded segments")
                receipts = {item["segment_id"]: item for item in manifest["upload"]["receipts"]}
                for sequence, declaration in available.items():
                    stored = uploaded[sequence]
                    content = declaration["content"]
                    receipt = receipts.get(declaration["segment_id"])
                    expected_receipt = {
                        "segment_id": stored["segment_id"],
                        "object_id": stored["object_id"],
                        "size_bytes": stored["size_bytes"],
                        "content_digest": stored["content_digest"],
                        "received_at": stored["received_at"],
                        "receipt_digest": stored["receipt_digest"],
                    }
                    if (
                        declaration["segment_id"] != stored["segment_id"]
                        or content["size_bytes"] != stored["size_bytes"]
                        or content["content_type"] != stored["content_type"]
                        or content["content_digest"] != stored["content_digest"]
                        or receipt != expected_receipt
                    ):
                        raise ApiError(409, "SEGMENT_METADATA_MISMATCH", "manifest segment or receipt differs from server state")
                    if not self._verify_stored_segment(
                        self._segment_path(session_id, sequence), stored["size_bytes"], stored["content_digest"]
                    ):
                        raise ApiError(500, "STORAGE_INCONSISTENT", "stored segment is unavailable")

                diagnostic_rows = list(
                    conn.execute(
                        "SELECT * FROM diagnostics WHERE session_id = ?",
                        (session_id,),
                    )
                )
                diagnostics = {row["envelope_id"]: row for row in diagnostic_rows}
                if set(diagnostics) != set(diagnostic_ids):
                    raise ApiError(
                        409,
                        "DIAGNOSTIC_SET_MISMATCH",
                        "declared diagnostics do not match the complete stored set",
                    )
                for envelope_id, row in diagnostics.items():
                    if not self._verify_stored_segment(
                        self._diagnostic_path(session_id, envelope_id),
                        row["size_bytes"],
                        row["content_digest"],
                    ):
                        raise ApiError(500, "STORAGE_INCONSISTENT", "stored diagnostic is unavailable")
                diagnostic_digests = [diagnostics[value]["envelope_digest"] for value in diagnostic_ids]
                if len(set(diagnostic_digests)) != len(diagnostic_digests):
                    raise ApiError(409, "DIAGNOSTIC_DIGEST_CONFLICT", "diagnostic semantic digests must be unique")
                if any(
                    row["build_identity_digest"] != manifest["build_identity_digest"]
                    for row in diagnostic_rows
                ):
                    raise ApiError(409, "BUILD_IDENTITY_MISMATCH", "diagnostic and capture builds differ")

                job = self._queued_job_snapshot(
                    job_id,
                    session_id,
                    manifest["build_identity_digest"],
                    now_text,
                    manifest_digest,
                    diagnostic_digests,
                )
                manifest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.replace(temporary, manifest_path)
                temporary = None
                publication_needs_cleanup = True
                self._fsync_directory(manifest_path.parent)
                self._fsync_directory(self.media_dir)
                self._fsync_directory(self.temp_dir)
                relative_path = str(manifest_path.relative_to(self.state_dir))
                conn.execute(
                    """UPDATE sessions
                       SET state = 'completed', completed_at = ?, manifest_digest = ?,
                           completion_digest = ?, manifest_size_bytes = ?,
                           manifest_content_digest = ?, manifest_relative_path = ?
                       WHERE session_id = ?""",
                    (
                        now_text,
                        manifest_digest,
                        completion_digest,
                        len(manifest_bytes),
                        sha256_digest(manifest_bytes),
                        relative_path,
                        session_id,
                    ),
                )
                conn.execute("UPDATE upload_tokens SET revoked_at = ? WHERE session_id = ?", (now_text, session_id))
                conn.execute(
                    """INSERT INTO jobs
                       (job_id, contract_version, job_type, session_id, organization_id,
                        project_id, status, requested_at, input_json, job_json)
                       VALUES (?, ?, 'process_session', ?, ?, ?, 'queued', ?, ?, ?)""",
                    (
                        job_id,
                        PROCESSING_JOB_CONTRACT,
                        session_id,
                        self.config.organization_id,
                        self.config.project_id,
                        now_text,
                        canonical_json(job["inputs"]),
                        canonical_json(job),
                    ),
                )
                self._audit(conn, "session_completed", "sdk", "succeeded", session_id)
            publication_needs_cleanup = False
            return job
        except Exception:
            if publication_needs_cleanup:
                manifest_path.unlink(missing_ok=True)
                self._fsync_directory(manifest_path.parent)
            raise
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def list_sessions(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT * FROM sessions
                   WHERE organization_id = ? AND project_id = ? AND application_id = ?
                     AND bundle_identifier = ? AND build_id = ? AND build_identity_digest = ?
                     AND consent_contract = ?
                   ORDER BY created_at DESC""",
                tuple(self.config.scope.values()),
            ).fetchall()
        return [self._session_summary(row) for row in rows]

    @staticmethod
    def _session_summary(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "session_id": row["session_id"],
            "organization_id": row["organization_id"],
            "project_id": row["project_id"],
            "application_id": row["application_id"],
            "bundle_identifier": row["bundle_identifier"],
            "build_id": row["build_id"],
            "build_identity_digest": row["build_identity_digest"],
            "consent_contract": row["consent_contract"],
            "state": row["state"],
            "created_at": row["created_at"],
            "completed_at": row["completed_at"],
            "retention": {
                "policy_version": row["retention_policy"],
                "raw_media_expires_at": row["raw_media_expires_at"],
                "deletion_status": row["deletion_status"],
            },
            "manifest_digest": row["manifest_digest"],
        }

    def get_session(self, session_id: str) -> dict[str, Any]:
        _require_id(session_id, "session_id")
        with self._connect() as conn:
            row = conn.execute(
                """SELECT * FROM sessions WHERE session_id = ? AND organization_id = ?
                   AND project_id = ? AND application_id = ? AND bundle_identifier = ? AND build_id = ?
                   AND build_identity_digest = ? AND consent_contract = ?""",
                (session_id, *self.config.scope.values()),
            ).fetchone()
            if row is None:
                raise ApiError(404, "SESSION_NOT_FOUND", "session was not found")
            result = self._session_summary(row)
            result["segments"] = [
                self._receipt_from_row(segment, False)
                for segment in conn.execute(
                    "SELECT * FROM segments WHERE session_id = ? ORDER BY sequence", (session_id,)
                )
            ]
            result["diagnostics"] = [
                {
                    "envelope_id": diagnostic["envelope_id"],
                    "size_bytes": diagnostic["size_bytes"],
                    "content_digest": diagnostic["content_digest"],
                    "envelope_digest": diagnostic["envelope_digest"],
                    "received_at": diagnostic["received_at"],
                }
                for diagnostic in conn.execute(
                    "SELECT * FROM diagnostics WHERE session_id = ? ORDER BY envelope_id", (session_id,)
                )
            ]
            result["jobs"] = [
                self._job_from_row(job)
                for job in conn.execute(
                    "SELECT * FROM jobs WHERE session_id = ? ORDER BY requested_at", (session_id,)
                )
            ]
            return result

    @staticmethod
    def _job_from_row(row: sqlite3.Row) -> dict[str, Any]:
        if row["job_type"] == "process_session" and row["job_json"]:
            return strict_json_loads(row["job_json"])
        return {
            "job_id": row["job_id"],
            "resource_version": row["contract_version"],
            "job_type": row["job_type"],
            "session_id": row["session_id"],
            "organization_id": row["organization_id"],
            "project_id": row["project_id"],
            "status": row["status"],
            "requested_at": row["requested_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "failure_code": row["failure_code"],
        }

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT * FROM jobs WHERE organization_id = ? AND project_id = ?
                   ORDER BY requested_at DESC""",
                (self.config.organization_id, self.config.project_id),
            ).fetchall()
        return [self._job_from_row(row) for row in rows]

    def get_job(self, job_id: str) -> dict[str, Any]:
        _require_id(job_id, "job_id")
        with self._connect() as conn:
            row = conn.execute(
                """SELECT * FROM jobs WHERE job_id = ? AND organization_id = ? AND project_id = ?""",
                (job_id, self.config.organization_id, self.config.project_id),
            ).fetchone()
        if row is None:
            raise ApiError(404, "JOB_NOT_FOUND", "job was not found")
        return self._job_from_row(row)

    def list_audit_events(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT event_id, event_type, actor_kind, organization_id, project_id,
                          session_id, outcome, occurred_at
                   FROM audit_events WHERE organization_id = ? AND project_id = ?
                   ORDER BY occurred_at, event_id""",
                (self.config.organization_id, self.config.project_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def _cancel_processing_jobs(
        self, conn: sqlite3.Connection, session_id: str, cancelled_at: str
    ) -> None:
        rows = conn.execute(
            """SELECT * FROM jobs WHERE session_id = ? AND job_type = 'process_session'
               AND status IN ('queued', 'running', 'waiting_for_clarification')""",
            (session_id,),
        ).fetchall()
        for row in rows:
            if not row["job_json"]:
                raise ApiError(500, "STORAGE_INCONSISTENT", "processing job snapshot is unavailable")
            snapshot = strict_json_loads(row["job_json"])
            snapshot["previous_job_digest"] = snapshot["job_digest"]
            snapshot["job_version"] += 1
            snapshot["status"] = "cancelled"
            snapshot["completed_at"] = cancelled_at
            snapshot["outputs"] = None
            snapshot["failure"] = None
            snapshot = seal_contract(snapshot)
            validate_contract(snapshot)
            conn.execute(
                """UPDATE jobs SET status = 'cancelled', completed_at = ?, job_json = ?
                   WHERE job_id = ?""",
                (cancelled_at, canonical_json(snapshot), row["job_id"]),
            )

    def _delete_session_files(
        self, session_id: str, sequences: list[int], envelope_ids: list[str]
    ) -> None:
        session_dir = self.media_dir / session_id
        diagnostics_dir = session_dir / "diagnostics"
        for sequence in sequences:
            self._segment_path(session_id, sequence).unlink(missing_ok=True)
        for envelope_id in envelope_ids:
            self._diagnostic_path(session_id, envelope_id).unlink(missing_ok=True)
        self._manifest_path(session_id).unlink(missing_ok=True)
        if diagnostics_dir.exists():
            self._fsync_directory(diagnostics_dir)
            diagnostics_dir.rmdir()
        if session_dir.exists():
            self._fsync_directory(session_dir)
            session_dir.rmdir()
            self._fsync_directory(self.media_dir)

    def delete_session(self, session_id: str) -> dict[str, Any]:
        """Durably request, perform, then tombstone one in-scope session."""

        _require_id(session_id, "session_id")
        with self._lock:
            now_text = timestamp(utc_now())
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                session = conn.execute(
                    """SELECT * FROM sessions WHERE session_id = ? AND organization_id = ?
                       AND project_id = ? AND application_id = ? AND bundle_identifier = ? AND build_id = ?
                       AND build_identity_digest = ? AND consent_contract = ?""",
                    (session_id, *self.config.scope.values()),
                ).fetchone()
                if session is None:
                    raise ApiError(404, "SESSION_NOT_FOUND", "session was not found")
                latest = conn.execute(
                    """SELECT * FROM jobs WHERE session_id = ? AND job_type = 'delete_session'
                       ORDER BY requested_at DESC LIMIT 1""",
                    (session_id,),
                ).fetchone()
                if session["deletion_status"] == "deleted":
                    if latest is None:
                        raise ApiError(500, "STORAGE_INCONSISTENT", "deletion tombstone job is unavailable")
                    return self._job_from_row(latest)

                self._cancel_processing_jobs(conn, session_id, now_text)

                if session["deletion_status"] == "deletion_requested" and latest is not None:
                    job_id = latest["job_id"]
                    conn.execute(
                        """UPDATE jobs SET status = 'running', started_at = ?, completed_at = NULL,
                           failure_code = NULL WHERE job_id = ?""",
                        (now_text, job_id),
                    )
                else:
                    job_id = _new_id("job")
                    conn.execute(
                        """INSERT INTO jobs
                           (job_id, contract_version, job_type, session_id, organization_id,
                            project_id, status, requested_at, started_at)
                           VALUES (?, ?, 'delete_session', ?, ?, ?, 'running', ?, ?)""",
                        (
                            job_id,
                            INTERNAL_DELETION_RESOURCE,
                            session_id,
                            self.config.organization_id,
                            self.config.project_id,
                            now_text,
                            now_text,
                        ),
                    )
                conn.execute(
                    "UPDATE sessions SET deletion_status = 'deletion_requested' WHERE session_id = ?",
                    (session_id,),
                )
                conn.execute(
                    "UPDATE upload_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE session_id = ?",
                    (now_text, session_id),
                )
                self._audit(conn, "session_deletion_requested", "admin", "succeeded", session_id)

            with self._connect() as conn:
                sequences = [
                    row["sequence"]
                    for row in conn.execute(
                        "SELECT sequence FROM segments WHERE session_id = ?", (session_id,)
                    )
                ]
                envelope_ids = [
                    row["envelope_id"]
                    for row in conn.execute(
                        "SELECT envelope_id FROM diagnostics WHERE session_id = ?", (session_id,)
                    )
                ]
            try:
                self._delete_session_files(session_id, sequences, envelope_ids)
            except OSError as exc:
                failed_at = timestamp(utc_now())
                with self._connect() as conn:
                    conn.execute(
                        """UPDATE jobs SET status = 'failed', completed_at = ?,
                           failure_code = 'STORAGE_DELETE_FAILED' WHERE job_id = ?""",
                        (failed_at, job_id),
                    )
                    self._audit(conn, "session_deleted", "backend", "failed", session_id)
                raise ApiError(500, "STORAGE_DELETE_FAILED", "session media could not be deleted") from exc

            completed_at = timestamp(utc_now())
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("DELETE FROM segments WHERE session_id = ?", (session_id,))
                conn.execute("DELETE FROM diagnostics WHERE session_id = ?", (session_id,))
                conn.execute(
                    """UPDATE sessions SET state = 'deleted', deletion_status = 'deleted',
                       manifest_digest = NULL, completion_digest = NULL, manifest_size_bytes = NULL,
                       manifest_content_digest = NULL, manifest_relative_path = NULL
                       WHERE session_id = ?""",
                    (session_id,),
                )
                conn.execute(
                    "UPDATE jobs SET status = 'succeeded', completed_at = ? WHERE job_id = ?",
                    (completed_at, job_id),
                )
                self._audit(conn, "session_deleted", "backend", "succeeded", session_id)
            return self.get_job(job_id)


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
