"""Durable immutable ticket-candidate versions and reviewer transitions."""

from __future__ import annotations

import copy
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import secrets
import sqlite3
from typing import Any, Callable
import unicodedata

from .candidate_domain import ContractError, TICKET_CONTRACT, apply_transition
from .evidence_domain import EvidenceDomainError


_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
_IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,512}$")
_EXPECTED_ERRORS = {
    "EXPECTED_CANDIDATE_ID_MISMATCH",
    "EXPECTED_CANDIDATE_VERSION_MISMATCH",
    "EXPECTED_CANDIDATE_DIGEST_MISMATCH",
    "EXPECTED_CONTENT_DIGEST_MISMATCH",
    "EXPECTED_EVIDENCE_DIGEST_MISMATCH",
}
_CONFLICT_ERRORS = {
    "ILLEGAL_TRANSITION_ACTION",
    "UNRESOLVED_BLOCKING_CLARIFICATION",
    "CLARIFICATION_ALREADY_RESOLVED",
}


class CandidateStoreError(Exception):
    """Safe API-facing failure from candidate persistence."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclass(frozen=True)
class CandidateTransitionResponse:
    status: int
    body: bytes
    body_digest: str
    candidate_digest: str


ApprovalGuard = Callable[[sqlite3.Connection, dict[str, Any]], None]
GeneratedInsertGuard = Callable[[sqlite3.Connection, dict[str, Any]], None]
VersionAppendGuard = Callable[
    [sqlite3.Connection, dict[str, Any], dict[str, Any]], None
]


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ID_PATTERN.fullmatch(value) is None:
        raise CandidateStoreError(400, "INVALID_IDENTIFIER", f"{field} is invalid")
    return value


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise CandidateStoreError(400, "INVALID_DIGEST", f"{field} is invalid")
    return value


def _response(candidate: dict[str, Any]) -> bytes:
    return _canonical_json(candidate).encode("utf-8")


class CandidateStore:
    """SQLite-backed append-only candidate chains with CAS heads.

    Connections are supplied by the owning backend so this module does not
    choose a database location or weaken its filesystem boundary. Every public
    method obtains and closes its own connection. Optional guards execute on
    that same connection while its ``BEGIN IMMEDIATE`` transaction is active.
    Approval verification runs after exact parent/request binding and before
    transition construction. Generated insertion verification runs after exact
    idempotency handling and before the first candidate/head write. Version
    append integration runs after the sealed child is constructed and before
    any candidate row or head is changed. Any guard failure rolls back its
    writes and the entire candidate mutation.
    """

    def __init__(
        self,
        connect: Callable[[], sqlite3.Connection],
        *,
        organization_id: str,
        project_id: str,
        reviewer_id: str,
        clock: Callable[[], datetime],
        approval_guard: ApprovalGuard | None = None,
        generated_insert_guard: GeneratedInsertGuard | None = None,
        version_append_guard: VersionAppendGuard | None = None,
    ):
        self._connect = connect
        self.organization_id = _require_id(organization_id, "organization_id")
        self.project_id = _require_id(project_id, "project_id")
        self.reviewer_id = _require_id(reviewer_id, "reviewer_id")
        if not callable(clock):
            raise ValueError("clock must be callable")
        if approval_guard is not None and not callable(approval_guard):
            raise ValueError("approval_guard must be callable")
        if generated_insert_guard is not None and not callable(generated_insert_guard):
            raise ValueError("generated_insert_guard must be callable")
        if version_append_guard is not None and not callable(version_append_guard):
            raise ValueError("version_append_guard must be callable")
        self._clock = clock
        self._approval_guard = approval_guard
        self._generated_insert_guard = generated_insert_guard
        self._version_append_guard = version_append_guard

    def initialize_schema(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS candidate_versions (
            candidate_id TEXT NOT NULL,
            candidate_version INTEGER NOT NULL,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            state TEXT NOT NULL,
            candidate_digest TEXT NOT NULL UNIQUE,
            candidate_content_digest TEXT NOT NULL,
            evidence_manifest_digest TEXT NOT NULL,
            canonical_json TEXT NOT NULL,
            version_created_at TEXT NOT NULL,
            PRIMARY KEY (candidate_id, candidate_version)
        );
        CREATE TABLE IF NOT EXISTS candidate_heads (
            candidate_id TEXT PRIMARY KEY,
            candidate_version INTEGER NOT NULL,
            candidate_digest TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            state TEXT NOT NULL,
            FOREIGN KEY (candidate_id, candidate_version)
              REFERENCES candidate_versions(candidate_id, candidate_version)
              ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS candidate_operations (
            reviewer_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            candidate_id TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            response_status INTEGER NOT NULL,
            response_body BLOB NOT NULL,
            response_digest TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (reviewer_id, idempotency_key)
        );
        CREATE INDEX IF NOT EXISTS candidate_heads_session_idx
          ON candidate_heads(organization_id, project_id, session_id, candidate_id);
        CREATE INDEX IF NOT EXISTS candidate_versions_session_idx
          ON candidate_versions(organization_id, project_id, session_id, candidate_id, candidate_version);
        CREATE INDEX IF NOT EXISTS candidate_operations_candidate_idx
          ON candidate_operations(candidate_id, created_at);
        """
        with closing(self._connection()) as connection, connection:
            connection.executescript(schema)

    def insert_generated(self, candidate: dict[str, Any]) -> dict[str, Any]:
        document = copy.deepcopy(candidate)
        try:
            TICKET_CONTRACT.validate_chain([document])
        except ContractError as exc:
            raise CandidateStoreError(400, "INVALID_CANDIDATE", "generated candidate is invalid") from exc
        if (
            document["organization_id"] != self.organization_id
            or document["project_id"] != self.project_id
        ):
            raise CandidateStoreError(403, "CANDIDATE_SCOPE_MISMATCH", "candidate is outside this deployment")
        if (
            document["candidate_version"] != 1
            or document["previous_candidate_digest"] is not None
            or document["lineage"]["operation"] != "generated"
            or document["lineage"]["parents"]
            or document["state"] != "draft"
        ):
            raise CandidateStoreError(409, "INVALID_GENERATED_HEAD", "candidate is not a generated first version")

        with closing(self._connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT canonical_json FROM candidate_versions WHERE candidate_id = ?",
                (document["candidate_id"],),
            ).fetchall()
            if existing:
                if len(existing) == 1 and existing[0]["canonical_json"] == _canonical_json(document):
                    return copy.deepcopy(document)
                raise CandidateStoreError(409, "CANDIDATE_ALREADY_EXISTS", "candidate ID is already in use")
            if self._generated_insert_guard is not None:
                self._invoke_guard(
                    self._generated_insert_guard,
                    connection,
                    copy.deepcopy(document),
                )
            self._insert_version(connection, document)
            connection.execute(
                """INSERT INTO candidate_heads
                   (candidate_id, candidate_version, candidate_digest, organization_id,
                    project_id, session_id, state)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    document["candidate_id"],
                    document["candidate_version"],
                    document["candidate_digest"],
                    document["organization_id"],
                    document["project_id"],
                    document["session_id"],
                    document["state"],
                ),
            )
        return copy.deepcopy(document)

    def list_current(self, session_id: str) -> list[dict[str, Any]]:
        session_id = _require_id(session_id, "session_id")
        with closing(self._connection()) as connection, connection:
            rows = connection.execute(
                """SELECT versions.canonical_json
                   FROM candidate_heads AS heads
                   JOIN candidate_versions AS versions
                     ON versions.candidate_id = heads.candidate_id
                    AND versions.candidate_version = heads.candidate_version
                   WHERE heads.organization_id = ? AND heads.project_id = ?
                     AND heads.session_id = ?
                   ORDER BY versions.version_created_at, versions.candidate_id""",
                (self.organization_id, self.project_id, session_id),
            ).fetchall()
        return [self._load_document(row["canonical_json"]) for row in rows]

    def get(self, candidate_id: str, version: int | None = None) -> dict[str, Any]:
        candidate_id = _require_id(candidate_id, "candidate_id")
        if version is not None and (
            isinstance(version, bool) or not isinstance(version, int) or version < 1
        ):
            raise CandidateStoreError(400, "INVALID_CANDIDATE_VERSION", "candidate version is invalid")
        with closing(self._connection()) as connection, connection:
            if version is None:
                row = connection.execute(
                    """SELECT versions.canonical_json
                       FROM candidate_heads AS heads
                       JOIN candidate_versions AS versions
                         ON versions.candidate_id = heads.candidate_id
                        AND versions.candidate_version = heads.candidate_version
                       WHERE heads.candidate_id = ? AND heads.organization_id = ?
                         AND heads.project_id = ?""",
                    (candidate_id, self.organization_id, self.project_id),
                ).fetchone()
            else:
                row = connection.execute(
                    """SELECT canonical_json FROM candidate_versions
                       WHERE candidate_id = ? AND candidate_version = ?
                         AND organization_id = ? AND project_id = ?""",
                    (candidate_id, version, self.organization_id, self.project_id),
                ).fetchone()
        if row is None:
            raise CandidateStoreError(404, "CANDIDATE_NOT_FOUND", "candidate was not found")
        return self._load_document(row["canonical_json"])

    def transition(
        self,
        candidate_id: str,
        *,
        if_match: str,
        idempotency_key: str,
        body: Any,
    ) -> CandidateTransitionResponse:
        candidate_id = _require_id(candidate_id, "candidate_id")
        if_match = _require_digest(if_match, "If-Match")
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY_PATTERN.fullmatch(idempotency_key) is None:
            raise CandidateStoreError(400, "INVALID_IDEMPOTENCY_KEY", "Idempotency-Key is invalid")
        public_body = self._validate_public_body(body)
        request_digest = _digest(
            {
                "candidate_id": candidate_id,
                "if_match": if_match,
                "body": public_body,
            }
        )

        with closing(self._connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                """SELECT candidate_id, request_digest, response_status, response_body,
                          response_digest
                   FROM candidate_operations
                   WHERE reviewer_id = ? AND idempotency_key = ?""",
                (self.reviewer_id, idempotency_key),
            ).fetchone()
            if prior is not None:
                if prior["candidate_id"] != candidate_id or prior["request_digest"] != request_digest:
                    raise CandidateStoreError(
                        409,
                        "IDEMPOTENCY_CONFLICT",
                        "Idempotency-Key was already used for another transition",
                    )
                response_body = bytes(prior["response_body"])
                if "sha256:" + hashlib.sha256(response_body).hexdigest() != prior["response_digest"]:
                    raise CandidateStoreError(500, "CANDIDATE_STORAGE_CORRUPT", "stored response failed integrity verification")
                prior_candidate = self._load_document(response_body)
                return CandidateTransitionResponse(
                    status=prior["response_status"],
                    body=response_body,
                    body_digest=prior["response_digest"],
                    candidate_digest=prior_candidate["candidate_digest"],
                )

            chain = self._load_chain(connection, candidate_id)
            parent = chain[-1]
            if parent["candidate_digest"] != if_match:
                raise CandidateStoreError(412, "CANDIDATE_PRECONDITION_FAILED", "candidate version changed; reload before reviewing")

            internal = self._domain_body(candidate_id, public_body)
            if internal["expected_candidate_digest"] != if_match:
                raise CandidateStoreError(412, "CANDIDATE_PRECONDITION_FAILED", "body and If-Match identify different versions")
            self._require_exact_parent_binding(parent, internal)
            if public_body["action"] == "approve" and self._approval_guard is not None:
                self._invoke_guard(
                    self._approval_guard,
                    connection,
                    copy.deepcopy(parent),
                )
            try:
                candidate = apply_transition(
                    chain,
                    self.reviewer_id,
                    internal,
                    self._now(),
                )
            except ContractError as exc:
                if exc.code in _EXPECTED_ERRORS:
                    status = 412
                elif exc.code in _CONFLICT_ERRORS:
                    status = 409
                else:
                    status = 400
                raise CandidateStoreError(status, exc.code, exc.detail) from exc

            if self._version_append_guard is not None:
                self._invoke_guard(
                    self._version_append_guard,
                    connection,
                    copy.deepcopy(parent),
                    copy.deepcopy(candidate),
                )

            self._insert_version(connection, candidate)
            updated = connection.execute(
                """UPDATE candidate_heads
                   SET candidate_version = ?, candidate_digest = ?, state = ?
                   WHERE candidate_id = ? AND candidate_version = ? AND candidate_digest = ?
                     AND organization_id = ? AND project_id = ?""",
                (
                    candidate["candidate_version"],
                    candidate["candidate_digest"],
                    candidate["state"],
                    candidate_id,
                    parent["candidate_version"],
                    parent["candidate_digest"],
                    self.organization_id,
                    self.project_id,
                ),
            )
            if updated.rowcount != 1:
                raise CandidateStoreError(412, "CANDIDATE_PRECONDITION_FAILED", "candidate version changed; reload before reviewing")
            response_body = _response(candidate)
            response_digest = "sha256:" + hashlib.sha256(response_body).hexdigest()
            connection.execute(
                """INSERT INTO candidate_operations
                   (reviewer_id, idempotency_key, candidate_id, request_digest,
                    response_status, response_body, response_digest, created_at)
                   VALUES (?, ?, ?, ?, 200, ?, ?, ?)""",
                (
                    self.reviewer_id,
                    idempotency_key,
                    candidate_id,
                    request_digest,
                    response_body,
                    response_digest,
                    candidate["version_created_at"],
                ),
            )
            return CandidateTransitionResponse(
                status=200,
                body=response_body,
                body_digest=response_digest,
                candidate_digest=candidate["candidate_digest"],
            )

    def delete_session(self, session_id: str) -> dict[str, int]:
        session_id = _require_id(session_id, "session_id")
        with closing(self._connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            operations = connection.execute(
                """DELETE FROM candidate_operations
                    WHERE candidate_id IN (
                        SELECT candidate_id FROM candidate_heads
                         WHERE organization_id = ? AND project_id = ?
                           AND session_id = ?
                    )""",
                (self.organization_id, self.project_id, session_id),
            ).rowcount
            heads = connection.execute(
                """DELETE FROM candidate_heads
                   WHERE organization_id = ? AND project_id = ? AND session_id = ?""",
                (self.organization_id, self.project_id, session_id),
            ).rowcount
            versions = connection.execute(
                """DELETE FROM candidate_versions
                   WHERE organization_id = ? AND project_id = ? AND session_id = ?""",
                (self.organization_id, self.project_id, session_id),
            ).rowcount
        return {"candidate_heads": heads, "candidate_versions": versions, "candidate_operations": operations}

    @staticmethod
    def _require_exact_parent_binding(
        parent: dict[str, Any], body: dict[str, Any]
    ) -> None:
        bindings = (
            (body["expected_candidate_id"], parent["candidate_id"]),
            (body["expected_candidate_version"], parent["candidate_version"]),
            (body["expected_candidate_digest"], parent["candidate_digest"]),
            (
                body["expected_candidate_content_digest"],
                parent["candidate_content_digest"],
            ),
            (
                body["expected_evidence_manifest_digest"],
                parent["evidence_manifest"]["manifest_digest"],
            ),
        )
        if any(
            type(actual) is not type(expected) or actual != expected
            for actual, expected in bindings
        ):
            raise CandidateStoreError(
                412,
                "CANDIDATE_PRECONDITION_FAILED",
                "transition body does not identify the exact current candidate",
            )

    @staticmethod
    def _invoke_guard(callback: Callable[..., None], *arguments: Any) -> None:
        try:
            callback(*arguments)
        except CandidateStoreError:
            raise
        except EvidenceDomainError as exc:
            raise CandidateStoreError(409, exc.code, exc.detail) from exc
        except ContractError as exc:
            if exc.code in _EXPECTED_ERRORS:
                status = 412
            elif exc.code in _CONFLICT_ERRORS:
                status = 409
            else:
                status = 400
            raise CandidateStoreError(status, exc.code, exc.detail) from exc

    def _connection(self) -> sqlite3.Connection:
        connection = self._connect()
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    def _load_document(self, raw: str | bytes) -> dict[str, Any]:
        try:
            document = json.loads(raw)
            if not isinstance(document, dict) or _canonical_json(document) != (
                raw.decode("utf-8") if isinstance(raw, bytes) else raw
            ):
                raise ValueError("candidate JSON is not canonical")
            TICKET_CONTRACT.validate(document)
            return document
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, ContractError) as exc:
            raise CandidateStoreError(500, "CANDIDATE_STORAGE_CORRUPT", "stored candidate failed validation") from exc

    def _load_chain(self, connection: sqlite3.Connection, candidate_id: str) -> list[dict[str, Any]]:
        rows = connection.execute(
            """SELECT canonical_json FROM candidate_versions
               WHERE candidate_id = ? AND organization_id = ? AND project_id = ?
               ORDER BY candidate_version""",
            (candidate_id, self.organization_id, self.project_id),
        ).fetchall()
        if not rows:
            raise CandidateStoreError(404, "CANDIDATE_NOT_FOUND", "candidate was not found")
        chain = [self._load_document(row["canonical_json"]) for row in rows]
        try:
            TICKET_CONTRACT.validate_chain(chain)
        except ContractError as exc:
            raise CandidateStoreError(500, "CANDIDATE_STORAGE_CORRUPT", "stored candidate chain failed validation") from exc
        return chain

    @staticmethod
    def _insert_version(connection: sqlite3.Connection, candidate: dict[str, Any]) -> None:
        connection.execute(
            """INSERT INTO candidate_versions
               (candidate_id, candidate_version, organization_id, project_id, session_id,
                state, candidate_digest, candidate_content_digest,
                evidence_manifest_digest, canonical_json, version_created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                candidate["candidate_id"],
                candidate["candidate_version"],
                candidate["organization_id"],
                candidate["project_id"],
                candidate["session_id"],
                candidate["state"],
                candidate["candidate_digest"],
                candidate["candidate_content_digest"],
                candidate["evidence_manifest"]["manifest_digest"],
                _canonical_json(candidate),
                candidate["version_created_at"],
            ),
        )

    def _validate_public_body(self, body: Any) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise CandidateStoreError(400, "INVALID_TRANSITION_BODY", "transition body must be an object")
        try:
            encoded = _canonical_json(body)
        except (TypeError, ValueError) as exc:
            raise CandidateStoreError(400, "INVALID_TRANSITION_BODY", "transition body is not canonical JSON data") from exc
        if len(encoded.encode("utf-8")) > 16_384:
            raise CandidateStoreError(413, "TRANSITION_BODY_TOO_LARGE", "transition body exceeds 16 KiB")
        if unicodedata.normalize("NFC", encoded) != encoded:
            raise CandidateStoreError(400, "INVALID_TRANSITION_BODY", "transition text must be NFC-normalized")

        action = body.get("action")
        common = {
            "expected_candidate_digest",
            "candidate_version",
            "candidate_content_digest",
            "evidence_manifest_digest",
            "action",
            "actor_id",
            "reason",
        }
        if action == "resolve_clarification":
            allowed = common | {"clarification_id", "selected_choice_id", "resolution_note"}
            required = common | {"clarification_id", "selected_choice_id"}
        elif action in {"mark_ready", "approve", "reject"}:
            allowed = required = common
        else:
            raise CandidateStoreError(400, "INVALID_TRANSITION_ACTION", "transition action is invalid")
        if not required <= set(body) or set(body) - allowed:
            raise CandidateStoreError(400, "INVALID_TRANSITION_FIELDS", "transition fields are invalid")
        if body["actor_id"] != self.reviewer_id:
            raise CandidateStoreError(403, "REVIEWER_MISMATCH", "transition actor does not match the authenticated reviewer")
        return copy.deepcopy(body)

    def _domain_body(self, candidate_id: str, body: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {
            "action": body["action"],
            "actor_id": body["actor_id"],
            "expected_candidate_id": candidate_id,
            "expected_candidate_version": body["candidate_version"],
            "expected_candidate_digest": body["expected_candidate_digest"],
            "expected_candidate_content_digest": body["candidate_content_digest"],
            "expected_evidence_manifest_digest": body["evidence_manifest_digest"],
            "reason": body["reason"],
        }
        if body["action"] == "resolve_clarification":
            result.update(
                {
                    "clarification_id": body["clarification_id"],
                    "choice_id": body["selected_choice_id"],
                    "resolution_note": body.get("resolution_note"),
                }
            )
        elif body["action"] == "approve":
            result["approval_id"] = "approval_" + secrets.token_hex(12)
        return result
