# SPDX-License-Identifier: Apache-2.0

"""Durable, scoped reviewer pairing and session authentication.

The store deliberately owns no HTTP policy and no database location.  The
backend supplies both a connection factory and a deployment-local verifier
key.  Pairing and session bearer secrets are returned exactly once; SQLite
contains only domain-separated HMAC verifiers.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from typing import Callable, Iterable
import unicodedata


PAIRING_TTL = timedelta(minutes=10)
SESSION_TTL = timedelta(days=30)
DEFAULT_PENDING_PAIRING_LIMIT = 16
DEFAULT_ACTIVE_SESSION_LIMIT = 64
REVIEWER_SCOPES = (
    "reviewer.launch",
    "reviewer.read",
    "reviewer.write",
)

_SCHEMA_VERSION = 1
_MAX_DEVICE_LABEL_CHARACTERS = 64
_MAX_DEVICE_LABEL_BYTES = 128
_MAX_SCOPE_COUNT = len(REVIEWER_SCOPES)
_TOKEN_SECRET_BYTES = 32
_TOKEN_SECRET_LENGTH = 43
_HUMAN_CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
_HUMAN_CODE_CHARACTERS = 8
_PAIRING_ID_PATTERN = re.compile(r"^rpair_[a-f0-9]{32}$")
_SESSION_ID_PATTERN = re.compile(r"^rsess_[a-f0-9]{32}$")
_REVIEWER_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_TOKEN_SECRET_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_HUMAN_CODE_PATTERN = re.compile(
    r"^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-"
    r"[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}$"
)
_CLIENT_KINDS = frozenset({"native", "web"})
_PAIRING_TOKEN_DOMAIN = b"tacua reviewer pairing token verifier v1\x00"
_PAIRING_CODE_DOMAIN = b"tacua reviewer pairing human code verifier v1\x00"
_SESSION_TOKEN_DOMAIN = b"tacua reviewer session token verifier v1\x00"

_SCHEMA_TABLE_SQL = {
    "tacua_reviewer_auth_schema": """
        CREATE TABLE tacua_reviewer_auth_schema (
            schema_version INTEGER PRIMARY KEY CHECK (schema_version = 1)
        )
    """,
    "tacua_reviewer_auth_time_floor": """
        CREATE TABLE tacua_reviewer_auth_time_floor (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            observed_at TEXT NOT NULL
        )
    """,
    "reviewer_pairing_requests": """
        CREATE TABLE reviewer_pairing_requests (
            pairing_id TEXT PRIMARY KEY,
            pairing_verifier BLOB NOT NULL UNIQUE CHECK (length(pairing_verifier) = 32),
            human_code_verifier BLOB NOT NULL UNIQUE CHECK (length(human_code_verifier) = 32),
            device_label TEXT NOT NULL,
            client_kind TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            approved_at TEXT,
            approved_scopes_json TEXT,
            consumed_at TEXT,
            session_id TEXT UNIQUE,
            CHECK ((approved_at IS NULL) = (approved_scopes_json IS NULL)),
            CHECK ((consumed_at IS NULL) = (session_id IS NULL)),
            CHECK (consumed_at IS NULL OR approved_at IS NOT NULL),
            CHECK (created_at < expires_at)
        )
    """,
    "reviewer_sessions": """
        CREATE TABLE reviewer_sessions (
            session_id TEXT PRIMARY KEY,
            session_verifier BLOB NOT NULL UNIQUE CHECK (length(session_verifier) = 32),
            reviewer_id TEXT NOT NULL,
            device_label TEXT NOT NULL,
            client_kind TEXT NOT NULL,
            scopes_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            originating_pairing_id TEXT NOT NULL UNIQUE,
            CHECK (created_at < expires_at),
            CHECK (revoked_at IS NULL OR revoked_at >= created_at),
            FOREIGN KEY (originating_pairing_id)
              REFERENCES reviewer_pairing_requests(pairing_id)
              ON DELETE RESTRICT
        )
    """,
}
_SCHEMA_INDEX_SQL = {
    "reviewer_pairings_pending_idx": """
        CREATE INDEX reviewer_pairings_pending_idx
          ON reviewer_pairing_requests(expires_at, approved_at, consumed_at)
    """,
    "reviewer_sessions_reviewer_idx": """
        CREATE INDEX reviewer_sessions_reviewer_idx
          ON reviewer_sessions(reviewer_id, created_at DESC, session_id)
    """,
}


class ReviewerAuthStoreError(Exception):
    """Stable, content-free failure suitable for an API adapter."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclass(frozen=True)
class PairingRequest:
    pairing_id: str
    pairing_token: str = field(repr=False)
    human_code: str = field(repr=False)
    device_label: str
    client_kind: str
    created_at: str
    expires_at: str


@dataclass(frozen=True)
class ApprovedPairing:
    pairing_id: str
    device_label: str
    client_kind: str
    scopes: tuple[str, ...]
    created_at: str
    approved_at: str
    expires_at: str


@dataclass(frozen=True)
class ReviewerSession:
    session_id: str
    reviewer_id: str
    device_label: str
    client_kind: str
    scopes: tuple[str, ...]
    created_at: str
    expires_at: str
    revoked_at: str | None


@dataclass(frozen=True)
class IssuedReviewerSession:
    session_token: str = field(repr=False)
    session: ReviewerSession


@dataclass(frozen=True)
class ReviewerPrincipal:
    reviewer_id: str
    session_id: str
    device_label: str
    client_kind: str
    scopes: tuple[str, ...]
    expires_at: str


class ReviewerAuthStore:
    """SQLite-backed one-use pairing and revocable reviewer sessions."""

    def __init__(
        self,
        connect: Callable[[], sqlite3.Connection],
        *,
        verifier_key: bytes,
        reviewer_id: str,
        clock: Callable[[], datetime] | None = None,
        pending_pairing_limit: int = DEFAULT_PENDING_PAIRING_LIMIT,
        active_session_limit: int = DEFAULT_ACTIVE_SESSION_LIMIT,
    ):
        if not callable(connect):
            raise ValueError("connect must be callable")
        if not isinstance(verifier_key, bytes) or len(verifier_key) < 32:
            raise ValueError("verifier_key must contain at least 32 bytes")
        if (
            not isinstance(reviewer_id, str)
            or _REVIEWER_ID_PATTERN.fullmatch(reviewer_id) is None
        ):
            raise ValueError("reviewer_id is invalid")
        if clock is None:
            clock = lambda: datetime.now(timezone.utc)
        if not callable(clock):
            raise ValueError("clock must be callable")
        if (
            not isinstance(pending_pairing_limit, int)
            or isinstance(pending_pairing_limit, bool)
            or not 1 <= pending_pairing_limit <= 64
        ):
            raise ValueError("pending_pairing_limit must be between 1 and 64")
        if (
            not isinstance(active_session_limit, int)
            or isinstance(active_session_limit, bool)
            or not 1 <= active_session_limit <= DEFAULT_ACTIVE_SESSION_LIMIT
        ):
            raise ValueError("active_session_limit must be between 1 and 64")
        self._connect = connect
        self._verifier_key = bytes(verifier_key)
        self.reviewer_id = reviewer_id
        self._clock = clock
        self.pending_pairing_limit = pending_pairing_limit
        self.active_session_limit = active_session_limit

    def initialize_schema(self) -> None:
        with closing(self._connection()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' "
                    f"AND name IN ({','.join('?' for _ in _SCHEMA_TABLE_SQL)})",
                    tuple(_SCHEMA_TABLE_SQL),
                ).fetchone()[0]
                if existing == 0:
                    for statement in _SCHEMA_TABLE_SQL.values():
                        connection.execute(statement)
                    connection.execute(
                        "INSERT INTO tacua_reviewer_auth_schema(schema_version) VALUES (?)",
                        (_SCHEMA_VERSION,),
                    )
                    for statement in _SCHEMA_INDEX_SQL.values():
                        connection.execute(statement)
                self._validate_schema(connection)
                connection.commit()
            except ReviewerAuthStoreError:
                connection.rollback()
                raise
            except sqlite3.DatabaseError as error:
                connection.rollback()
                raise ReviewerAuthStoreError(
                    500,
                    "REVIEWER_AUTH_SCHEMA_INVALID",
                    "reviewer authentication schema is incompatible",
                ) from error

    def create_pairing(self, *, device_label: str, client_kind: str) -> PairingRequest:
        label = self._validate_device_label(device_label)
        kind = self._validate_client_kind(client_kind)
        now = self._now()
        created_at = self._format_time(now)
        expires_at = self._format_time(now + PAIRING_TTL)

        with closing(self._connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self._prune_inactive_state(connection, created_at)
            active_count = connection.execute(
                """SELECT COUNT(*) AS active_count
                     FROM reviewer_pairing_requests
                     WHERE consumed_at IS NULL""",
            ).fetchone()["active_count"]
            if active_count < self.pending_pairing_limit:
                for _ in range(16):
                    pairing_id = "rpair_" + secrets.token_hex(16)
                    pairing_secret = secrets.token_urlsafe(_TOKEN_SECRET_BYTES)
                    pairing_token = f"{pairing_id}.{pairing_secret}"
                    human_code = self._new_human_code()
                    try:
                        connection.execute(
                            """INSERT INTO reviewer_pairing_requests
                               (pairing_id, pairing_verifier, human_code_verifier,
                                device_label, client_kind, created_at, expires_at,
                                approved_at, approved_scopes_json, consumed_at, session_id)
                               VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)""",
                            (
                                pairing_id,
                                self._verifier(_PAIRING_TOKEN_DOMAIN, pairing_token),
                                self._verifier(_PAIRING_CODE_DOMAIN, human_code),
                                label,
                                kind,
                                created_at,
                                expires_at,
                            ),
                        )
                    except sqlite3.IntegrityError:
                        continue
                    return PairingRequest(
                        pairing_id=pairing_id,
                        pairing_token=pairing_token,
                        human_code=human_code,
                        device_label=label,
                        client_kind=kind,
                        created_at=created_at,
                        expires_at=expires_at,
                    )
        if active_count >= self.pending_pairing_limit:
            raise ReviewerAuthStoreError(
                429,
                "PAIRING_CAPACITY_REACHED",
                "too many pairing requests are pending",
            )
        raise ReviewerAuthStoreError(
            500,
            "REVIEWER_AUTH_RANDOMNESS_EXHAUSTED",
            "reviewer authentication identifier generation failed",
        )

    def approve_pairing(
        self,
        human_code: str,
        *,
        scopes: Iterable[str] = REVIEWER_SCOPES,
    ) -> ApprovedPairing:
        code = self._validate_human_code_for_lookup(human_code)
        approved_scopes = self._validate_scopes(scopes)
        scopes_json = self._encode_scopes(approved_scopes)
        now = self._now()
        approved_at = self._format_time(now)
        supplied_verifier = self._verifier(_PAIRING_CODE_DOMAIN, code)

        with closing(self._connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self._prune_inactive_state(connection, approved_at)
            rows = connection.execute(
                """SELECT pairing_id, human_code_verifier, device_label,
                          client_kind, created_at, expires_at
                     FROM reviewer_pairing_requests
                     WHERE approved_at IS NULL AND consumed_at IS NULL
                       AND expires_at > ?
                     ORDER BY pairing_id""",
                (approved_at,),
            ).fetchall()
            row = next(
                (
                    candidate
                    for candidate in rows
                    if hmac.compare_digest(
                        self._stored_verifier(candidate["human_code_verifier"]),
                        supplied_verifier,
                    )
                ),
                None,
            )
            if row is None:
                raise ReviewerAuthStoreError(
                    404,
                    "PAIRING_APPROVAL_INVALID",
                    "pairing approval code is invalid or unavailable",
                )
            updated = connection.execute(
                """UPDATE reviewer_pairing_requests
                     SET approved_at = ?, approved_scopes_json = ?
                     WHERE pairing_id = ? AND approved_at IS NULL
                       AND consumed_at IS NULL AND expires_at > ?""",
                (approved_at, scopes_json, row["pairing_id"], approved_at),
            ).rowcount
            if updated != 1:
                raise ReviewerAuthStoreError(
                    404,
                    "PAIRING_APPROVAL_INVALID",
                    "pairing approval code is invalid or unavailable",
                )
            return ApprovedPairing(
                pairing_id=row["pairing_id"],
                device_label=row["device_label"],
                client_kind=row["client_kind"],
                scopes=approved_scopes,
                created_at=self._verified_time(row["created_at"]),
                approved_at=approved_at,
                expires_at=self._verified_time(row["expires_at"]),
            )

    def exchange_pairing(
        self,
        pairing_token: str,
        *,
        expected_client_kind: str | None = None,
    ) -> IssuedReviewerSession:
        if expected_client_kind is not None:
            try:
                expected_client_kind = self._validate_client_kind(
                    expected_client_kind
                )
            except ReviewerAuthStoreError:
                self._raise_pairing_exchange_invalid()
        parsed = self._parse_token(pairing_token, _PAIRING_ID_PATTERN)
        if parsed is None:
            self._raise_pairing_exchange_invalid()
        pairing_id, _ = parsed
        supplied_verifier = self._verifier(_PAIRING_TOKEN_DOMAIN, pairing_token)
        now = self._now()
        exchanged_at = self._format_time(now)

        with closing(self._connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self._prune_inactive_state(connection, exchanged_at)
            row = connection.execute(
                """SELECT pairing_id, pairing_verifier, device_label, client_kind,
                          created_at, expires_at, approved_at,
                          approved_scopes_json, consumed_at
                     FROM reviewer_pairing_requests WHERE pairing_id = ?""",
                (pairing_id,),
            ).fetchone()
            if (
                row is None
                or not hmac.compare_digest(
                    self._stored_verifier(row["pairing_verifier"]),
                    supplied_verifier,
                )
                or row["consumed_at"] is not None
                or exchanged_at >= self._verified_time(row["expires_at"])
                or (
                    expected_client_kind is not None
                    and row["client_kind"] != expected_client_kind
                )
            ):
                self._raise_pairing_exchange_invalid()
            if row["approved_at"] is None or row["approved_scopes_json"] is None:
                raise ReviewerAuthStoreError(
                    409,
                    "PAIRING_NOT_APPROVED",
                    "pairing request has not been approved",
                )
            scopes = self._decode_scopes(row["approved_scopes_json"])
            active_count = self._active_session_count(connection, exchanged_at)
            if active_count >= self.active_session_limit:
                raise ReviewerAuthStoreError(
                    429,
                    "REVIEWER_SESSION_CAPACITY_REACHED",
                    "too many reviewer sessions are active",
                )
            expires_at = self._format_time(now + SESSION_TTL)

            for _ in range(16):
                session_id = "rsess_" + secrets.token_hex(16)
                session_secret = secrets.token_urlsafe(_TOKEN_SECRET_BYTES)
                session_token = f"{session_id}.{session_secret}"
                try:
                    connection.execute(
                        """INSERT INTO reviewer_sessions
                           (session_id, session_verifier, reviewer_id, device_label,
                            client_kind, scopes_json, created_at, expires_at,
                            revoked_at, originating_pairing_id)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)""",
                        (
                            session_id,
                            self._verifier(_SESSION_TOKEN_DOMAIN, session_token),
                            self.reviewer_id,
                            row["device_label"],
                            row["client_kind"],
                            self._encode_scopes(scopes),
                            exchanged_at,
                            expires_at,
                            pairing_id,
                        ),
                    )
                except sqlite3.IntegrityError as error:
                    if "originating_pairing_id" in str(error):
                        self._raise_pairing_exchange_invalid()
                    continue
                updated = connection.execute(
                    """UPDATE reviewer_pairing_requests
                         SET consumed_at = ?, session_id = ?
                         WHERE pairing_id = ? AND consumed_at IS NULL
                           AND approved_at IS NOT NULL AND expires_at > ?""",
                    (exchanged_at, session_id, pairing_id, exchanged_at),
                ).rowcount
                if updated != 1:
                    self._raise_pairing_exchange_invalid()
                session = ReviewerSession(
                    session_id=session_id,
                    reviewer_id=self.reviewer_id,
                    device_label=row["device_label"],
                    client_kind=row["client_kind"],
                    scopes=scopes,
                    created_at=exchanged_at,
                    expires_at=expires_at,
                    revoked_at=None,
                )
                return IssuedReviewerSession(
                    session_token=session_token,
                    session=session,
                )
        raise ReviewerAuthStoreError(
            500,
            "REVIEWER_AUTH_RANDOMNESS_EXHAUSTED",
            "reviewer authentication identifier generation failed",
        )

    def cancel_pairing(
        self,
        pairing_token: str,
        *,
        expected_client_kind: str | None = None,
    ) -> None:
        """Consume one pairing capability and remove any session it issued.

        Cancellation is deliberately content-free and idempotent.  A missing,
        malformed, tampered, already-canceled, or client-kind-mismatched token
        is indistinguishable from a successful cancellation.  A caller that
        holds the real pairing token can therefore safely retry after an
        ambiguous exchange response without turning this route into a pairing
        or session oracle.
        """

        if expected_client_kind is not None:
            try:
                expected_client_kind = self._validate_client_kind(
                    expected_client_kind
                )
            except ReviewerAuthStoreError:
                return
        parsed = self._parse_token(pairing_token, _PAIRING_ID_PATTERN)
        if parsed is None:
            return
        pairing_id, _ = parsed
        supplied_verifier = self._verifier(_PAIRING_TOKEN_DOMAIN, pairing_token)
        canceled_at = self._format_time(self._now())

        with closing(self._connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self._prune_inactive_state(connection, canceled_at)
            row = connection.execute(
                """SELECT pairing_verifier, client_kind
                     FROM reviewer_pairing_requests WHERE pairing_id = ?""",
                (pairing_id,),
            ).fetchone()
            if (
                row is None
                or not hmac.compare_digest(
                    self._stored_verifier(row["pairing_verifier"]),
                    supplied_verifier,
                )
                or (
                    expected_client_kind is not None
                    and row["client_kind"] != expected_client_kind
                )
            ):
                return

            # The pairing row is the stable capability binding retained for an
            # active session.  Deleting the session verifier first and the
            # pairing row second makes cancellation atomic whether it wins the
            # database lock before or after exchange_pairing().
            connection.execute(
                """DELETE FROM reviewer_sessions
                     WHERE originating_pairing_id = ? AND reviewer_id = ?
                       AND client_kind = ?""",
                (pairing_id, self.reviewer_id, row["client_kind"]),
            )
            connection.execute(
                "DELETE FROM reviewer_pairing_requests WHERE pairing_id = ?",
                (pairing_id,),
            )

    def authenticate_session(
        self,
        session_token: str,
        *,
        required_scope: str | None = None,
    ) -> ReviewerPrincipal:
        if required_scope is not None and required_scope not in REVIEWER_SCOPES:
            raise ValueError("required_scope is unsupported")
        parsed = self._parse_token(session_token, _SESSION_ID_PATTERN)
        if parsed is None:
            self._raise_session_unauthorized()
        session_id, _ = parsed
        supplied_verifier = self._verifier(_SESSION_TOKEN_DOMAIN, session_token)
        now = self._format_time(self._now())

        with closing(self._connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self._prune_inactive_state(connection, now)
            self._require_active_session_bound(connection, now)
            row = connection.execute(
                """SELECT session_id, session_verifier, reviewer_id, device_label,
                          client_kind, scopes_json, created_at, expires_at, revoked_at
                     FROM reviewer_sessions WHERE session_id = ?""",
                (session_id,),
            ).fetchone()
        if (
            row is None
            or row["reviewer_id"] != self.reviewer_id
            or not hmac.compare_digest(
                self._stored_verifier(row["session_verifier"]),
                supplied_verifier,
            )
            or row["revoked_at"] is not None
            or now >= self._verified_time(row["expires_at"])
        ):
            self._raise_session_unauthorized()
        scopes = self._decode_scopes(row["scopes_json"])
        if required_scope is not None and required_scope not in scopes:
            raise ReviewerAuthStoreError(
                403,
                "REVIEWER_SESSION_FORBIDDEN",
                "reviewer session lacks the required scope",
            )
        return ReviewerPrincipal(
            reviewer_id=self.reviewer_id,
            session_id=row["session_id"],
            device_label=row["device_label"],
            client_kind=row["client_kind"],
            scopes=scopes,
            expires_at=self._verified_time(row["expires_at"]),
        )

    def revoke_session(self, session_id: str) -> ReviewerSession:
        if not isinstance(session_id, str) or _SESSION_ID_PATTERN.fullmatch(session_id) is None:
            self._raise_session_not_found()
        revoked_at = self._format_time(self._now())
        with closing(self._connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self._prune_inactive_state(connection, revoked_at)
            row = connection.execute(
                """SELECT session_id, reviewer_id, device_label, client_kind,
                          scopes_json, created_at, expires_at, revoked_at,
                          originating_pairing_id
                     FROM reviewer_sessions
                     WHERE session_id = ? AND reviewer_id = ?""",
                (session_id, self.reviewer_id),
            ).fetchone()
            if row is None:
                self._raise_session_not_found()
            connection.execute(
                """UPDATE reviewer_sessions SET revoked_at = ?
                     WHERE session_id = ? AND reviewer_id = ?
                       AND revoked_at IS NULL""",
                (revoked_at, session_id, self.reviewer_id),
            )
            revoked = self._session_from_row(row, revoked_at=revoked_at)
            self._prune_inactive_state(connection, revoked_at)
            return revoked

    def list_sessions(self) -> tuple[ReviewerSession, ...]:
        observed_at = self._format_time(self._now())
        with closing(self._connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self._prune_inactive_state(connection, observed_at)
            self._require_active_session_bound(connection, observed_at)
            rows = connection.execute(
                """SELECT session_id, reviewer_id, device_label, client_kind,
                          scopes_json, created_at, expires_at, revoked_at
                     FROM reviewer_sessions WHERE reviewer_id = ?
                     ORDER BY created_at DESC, session_id""",
                (self.reviewer_id,),
            ).fetchall()
        return tuple(self._session_from_row(row) for row in rows)

    def _connection(self) -> sqlite3.Connection:
        connection = self._connect()
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _prune_inactive_state(
        self,
        connection: sqlite3.Connection,
        observed_at: str,
    ) -> None:
        """Delete inactive sessions and their no-longer-needed pairing rows."""

        self._verified_time(observed_at)
        connection.execute(
            """DELETE FROM reviewer_sessions
                 WHERE reviewer_id = ?
                   AND (revoked_at IS NOT NULL OR expires_at <= ?)""",
            (self.reviewer_id, observed_at),
        )
        connection.execute(
            """DELETE FROM reviewer_pairing_requests
                 WHERE consumed_at IS NOT NULL
                   AND NOT EXISTS (
                       SELECT 1 FROM reviewer_sessions
                        WHERE reviewer_sessions.originating_pairing_id =
                              reviewer_pairing_requests.pairing_id
                   )"""
        )
        connection.execute(
            """DELETE FROM reviewer_pairing_requests
                 WHERE consumed_at IS NULL AND expires_at <= ?""",
            (observed_at,),
        )

    def _active_session_count(
        self,
        connection: sqlite3.Connection,
        observed_at: str,
    ) -> int:
        return int(
            connection.execute(
                """SELECT COUNT(*) FROM reviewer_sessions
                     WHERE reviewer_id = ? AND revoked_at IS NULL
                       AND expires_at > ?""",
                (self.reviewer_id, observed_at),
            ).fetchone()[0]
        )

    def _require_active_session_bound(
        self,
        connection: sqlite3.Connection,
        observed_at: str,
    ) -> None:
        if self._active_session_count(connection, observed_at) > self.active_session_limit:
            self._raise_storage_corrupt()

    def _now(self) -> datetime:
        """Return time at or above the durable reviewer-auth floor.

        The floor uses its own short transaction so an expected authentication
        failure cannot roll it back and make an expired credential usable after
        a process restart.
        """

        value = self._clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ValueError("clock must return a timezone-aware datetime")
        observed = value.astimezone(timezone.utc).replace(microsecond=0)
        observed_at = self._format_time(observed)
        with closing(self._connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT observed_at FROM tacua_reviewer_auth_time_floor
                     WHERE singleton = 1"""
            ).fetchone()
            if row is None:
                connection.execute(
                    """INSERT INTO tacua_reviewer_auth_time_floor
                         (singleton, observed_at) VALUES (1, ?)""",
                    (observed_at,),
                )
            else:
                persisted_at = self._verified_time(row["observed_at"])
                if persisted_at > observed_at:
                    observed_at = persisted_at
                elif persisted_at < observed_at:
                    connection.execute(
                        """UPDATE tacua_reviewer_auth_time_floor
                             SET observed_at = ? WHERE singleton = 1""",
                        (observed_at,),
                    )
        return datetime.strptime(observed_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )

    @staticmethod
    def _format_time(value: datetime) -> str:
        return value.astimezone(timezone.utc).replace(microsecond=0).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    @classmethod
    def _verified_time(cls, value: object) -> str:
        if not isinstance(value, str):
            cls._raise_storage_corrupt()
        try:
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            cls._raise_storage_corrupt()
        if cls._format_time(parsed) != value:
            cls._raise_storage_corrupt()
        return value

    def _verifier(self, domain: bytes, value: str) -> bytes:
        return hmac.new(
            self._verifier_key,
            domain + value.encode("ascii"),
            hashlib.sha256,
        ).digest()

    @staticmethod
    def _new_human_code() -> str:
        compact = "".join(
            secrets.choice(_HUMAN_CODE_ALPHABET)
            for _ in range(_HUMAN_CODE_CHARACTERS)
        )
        return compact[:4] + "-" + compact[4:]

    @staticmethod
    def _parse_token(
        token: object, identifier_pattern: re.Pattern[str]
    ) -> tuple[str, str] | None:
        if not isinstance(token, str) or len(token) > 128 or token.count(".") != 1:
            return None
        identifier, secret = token.split(".", 1)
        if (
            identifier_pattern.fullmatch(identifier) is None
            or len(secret) != _TOKEN_SECRET_LENGTH
            or _TOKEN_SECRET_PATTERN.fullmatch(secret) is None
        ):
            return None
        return identifier, secret

    @staticmethod
    def _validate_device_label(value: object) -> str:
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or value != unicodedata.normalize("NFC", value)
            or len(value) > _MAX_DEVICE_LABEL_CHARACTERS
            or len(value.encode("utf-8")) > _MAX_DEVICE_LABEL_BYTES
            or any(unicodedata.category(character).startswith("C") for character in value)
        ):
            raise ReviewerAuthStoreError(
                400,
                "INVALID_PAIRING_REQUEST",
                "pairing request metadata is invalid",
            )
        return value

    @staticmethod
    def _validate_client_kind(value: object) -> str:
        if not isinstance(value, str) or value not in _CLIENT_KINDS:
            raise ReviewerAuthStoreError(
                400,
                "INVALID_PAIRING_REQUEST",
                "pairing request metadata is invalid",
            )
        return value

    @staticmethod
    def _validate_human_code_for_lookup(value: object) -> str:
        if not isinstance(value, str) or _HUMAN_CODE_PATTERN.fullmatch(value) is None:
            raise ReviewerAuthStoreError(
                404,
                "PAIRING_APPROVAL_INVALID",
                "pairing approval code is invalid or unavailable",
            )
        return value

    @staticmethod
    def _validate_scopes(scopes: Iterable[str]) -> tuple[str, ...]:
        if isinstance(scopes, (str, bytes)):
            raise ReviewerAuthStoreError(
                400, "INVALID_REVIEWER_SCOPES", "reviewer scopes are invalid"
            )
        try:
            values = tuple(scopes)
        except TypeError as error:
            raise ReviewerAuthStoreError(
                400, "INVALID_REVIEWER_SCOPES", "reviewer scopes are invalid"
            ) from error
        canonical = (
            tuple(sorted(set(values)))
            if all(isinstance(item, str) for item in values)
            else ()
        )
        if (
            not canonical
            or len(values) != len(canonical)
            or len(canonical) > _MAX_SCOPE_COUNT
            or any(scope not in REVIEWER_SCOPES for scope in canonical)
        ):
            raise ReviewerAuthStoreError(
                400, "INVALID_REVIEWER_SCOPES", "reviewer scopes are invalid"
            )
        return canonical

    @staticmethod
    def _encode_scopes(scopes: tuple[str, ...]) -> str:
        return json.dumps(list(scopes), separators=(",", ":"), sort_keys=True)

    @classmethod
    def _decode_scopes(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, str):
            cls._raise_storage_corrupt()
        try:
            decoded = json.loads(value)
            scopes = cls._validate_scopes(decoded)
        except (json.JSONDecodeError, ReviewerAuthStoreError, TypeError):
            cls._raise_storage_corrupt()
        if cls._encode_scopes(scopes) != value:
            cls._raise_storage_corrupt()
        return scopes

    @classmethod
    def _session_from_row(
        cls, row: sqlite3.Row, *, revoked_at: str | None = None
    ) -> ReviewerSession:
        stored_revoked_at = row["revoked_at"] if revoked_at is None else revoked_at
        return ReviewerSession(
            session_id=row["session_id"],
            reviewer_id=row["reviewer_id"],
            device_label=row["device_label"],
            client_kind=row["client_kind"],
            scopes=cls._decode_scopes(row["scopes_json"]),
            created_at=cls._verified_time(row["created_at"]),
            expires_at=cls._verified_time(row["expires_at"]),
            revoked_at=(
                None
                if stored_revoked_at is None
                else cls._verified_time(stored_revoked_at)
            ),
        )

    @staticmethod
    def _normalized_schema_sql(value: object) -> str:
        if not isinstance(value, str) or not value.strip():
            ReviewerAuthStore._raise_schema_invalid()
        return " ".join(value.strip().removesuffix(";").split())

    @classmethod
    def _validate_schema(cls, connection: sqlite3.Connection) -> None:
        placeholders = ",".join("?" for _ in _SCHEMA_TABLE_SQL)
        table_rows = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'table' "
            f"AND name IN ({placeholders}) ORDER BY name",
            tuple(_SCHEMA_TABLE_SQL),
        ).fetchall()
        observed_tables = {
            row["name"]: cls._normalized_schema_sql(row["sql"])
            for row in table_rows
        }
        expected_tables = {
            name: cls._normalized_schema_sql(statement)
            for name, statement in _SCHEMA_TABLE_SQL.items()
        }
        if observed_tables != expected_tables:
            cls._raise_schema_invalid()

        all_index_rows = connection.execute(
            "SELECT name, tbl_name, sql FROM sqlite_master WHERE type = 'index' "
            f"AND tbl_name IN ({placeholders}) ORDER BY name",
            tuple(_SCHEMA_TABLE_SQL),
        ).fetchall()
        for row in all_index_rows:
            if row["sql"] is None and not row["name"].startswith(
                f"sqlite_autoindex_{row['tbl_name']}_"
            ):
                cls._raise_schema_invalid()
        observed_indexes = {
            row["name"]: (
                row["tbl_name"],
                cls._normalized_schema_sql(row["sql"]),
            )
            for row in all_index_rows
            if row["sql"] is not None
        }
        expected_indexes = {
            name: (
                "reviewer_pairing_requests"
                if name == "reviewer_pairings_pending_idx"
                else "reviewer_sessions",
                cls._normalized_schema_sql(statement),
            )
            for name, statement in _SCHEMA_INDEX_SQL.items()
        }
        if observed_indexes != expected_indexes:
            cls._raise_schema_invalid()

        triggers = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'trigger' "
            f"AND tbl_name IN ({placeholders}) LIMIT 1",
            tuple(_SCHEMA_TABLE_SQL),
        ).fetchone()
        if triggers is not None:
            cls._raise_schema_invalid()

        versions = connection.execute(
            """SELECT schema_version FROM tacua_reviewer_auth_schema
                 ORDER BY schema_version"""
        ).fetchall()
        if [tuple(row) for row in versions] != [(_SCHEMA_VERSION,)]:
            cls._raise_schema_invalid()

        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(reviewer_sessions)"
        ).fetchall()
        if len(foreign_keys) != 1:
            cls._raise_schema_invalid()
        foreign_key = foreign_keys[0]
        if (
            foreign_key["table"] != "reviewer_pairing_requests"
            or foreign_key["from"] != "originating_pairing_id"
            or foreign_key["to"] != "pairing_id"
            or foreign_key["on_update"] != "NO ACTION"
            or foreign_key["on_delete"] != "RESTRICT"
            or foreign_key["match"] != "NONE"
        ):
            cls._raise_schema_invalid()
        if connection.execute(
            "PRAGMA foreign_key_check(reviewer_sessions)"
        ).fetchone() is not None:
            cls._raise_schema_invalid()

    @classmethod
    def _stored_verifier(cls, value: object) -> bytes:
        if not isinstance(value, (bytes, bytearray, memoryview)):
            cls._raise_storage_corrupt()
        verifier = bytes(value)
        if len(verifier) != hashlib.sha256().digest_size:
            cls._raise_storage_corrupt()
        return verifier

    @staticmethod
    def _raise_schema_invalid() -> None:
        raise ReviewerAuthStoreError(
            500,
            "REVIEWER_AUTH_SCHEMA_INVALID",
            "reviewer authentication schema is incompatible",
        )

    @staticmethod
    def _raise_storage_corrupt() -> None:
        raise ReviewerAuthStoreError(
            500,
            "REVIEWER_AUTH_STORAGE_CORRUPT",
            "reviewer authentication storage failed integrity verification",
        )

    @staticmethod
    def _raise_pairing_exchange_invalid() -> None:
        raise ReviewerAuthStoreError(
            401,
            "PAIRING_EXCHANGE_INVALID",
            "pairing token is invalid or unavailable",
        )

    @staticmethod
    def _raise_session_unauthorized() -> None:
        raise ReviewerAuthStoreError(
            401,
            "REVIEWER_SESSION_UNAUTHORIZED",
            "reviewer session is invalid or unavailable",
        )

    @staticmethod
    def _raise_session_not_found() -> None:
        raise ReviewerAuthStoreError(
            404,
            "REVIEWER_SESSION_NOT_FOUND",
            "reviewer session was not found",
        )
