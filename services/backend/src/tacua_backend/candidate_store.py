# SPDX-License-Identifier: Apache-2.0

"""Durable immutable ticket-candidate versions and reviewer transitions."""

from __future__ import annotations

import copy
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import secrets
import sqlite3
from typing import Any, Callable
import unicodedata

from .candidate_domain import ContractError, TICKET_CONTRACT, apply_transition
from .evidence_domain import EvidenceDomainError, validate_manifest


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
_REPLACEMENT_OPERATIONS = {"split", "merge"}
_MAX_REPLACEMENT_BODY_BYTES = 16_777_216
_MAX_REPLACEMENT_RESPONSE_BYTES = 16_777_216


class CandidateStoreError(Exception):
    """Safe API-facing failure from candidate persistence."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = copy.deepcopy(details)


@dataclass(frozen=True)
class CandidateTransitionResponse:
    status: int
    body: bytes
    body_digest: str
    candidate_digest: str


@dataclass(frozen=True)
class CandidateReplacementResponse:
    status: int
    body: bytes
    body_digest: str


ApprovalGuard = Callable[[sqlite3.Connection, dict[str, Any]], None]
GeneratedInsertGuard = Callable[[sqlite3.Connection, dict[str, Any]], None]
VersionAppendGuard = Callable[
    [sqlite3.Connection, dict[str, Any], dict[str, Any]], None
]
ReplacementManifestFactory = Callable[
    [sqlite3.Connection, str, list[dict[str, Any]]], dict[str, Any]
]
ReplacementResultGuard = Callable[
    [
        sqlite3.Connection,
        str,
        list[dict[str, Any]],
        list[dict[str, Any]],
        dict[str, Any],
    ],
    None,
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
        replacement_manifest_factory: ReplacementManifestFactory | None = None,
        replacement_result_guard: ReplacementResultGuard | None = None,
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
        if replacement_manifest_factory is not None and not callable(
            replacement_manifest_factory
        ):
            raise ValueError("replacement_manifest_factory must be callable")
        if replacement_result_guard is not None and not callable(
            replacement_result_guard
        ):
            raise ValueError("replacement_result_guard must be callable")
        self._clock = clock
        self._approval_guard = approval_guard
        self._generated_insert_guard = generated_insert_guard
        self._version_append_guard = version_append_guard
        self._replacement_manifest_factory = replacement_manifest_factory
        self._replacement_result_guard = replacement_result_guard

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
        CREATE TABLE IF NOT EXISTS candidate_replacement_operations (
            operation_id TEXT PRIMARY KEY,
            reviewer_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            operation TEXT NOT NULL CHECK (operation IN ('split','merge')),
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            operation_json TEXT NOT NULL,
            response_status INTEGER NOT NULL CHECK (response_status = 201),
            response_body BLOB NOT NULL,
            response_digest TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            UNIQUE (reviewer_id, idempotency_key)
        );
        CREATE TABLE IF NOT EXISTS candidate_supersessions (
            source_candidate_id TEXT PRIMARY KEY,
            source_candidate_version INTEGER NOT NULL,
            source_candidate_digest TEXT NOT NULL UNIQUE,
            operation_id TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            FOREIGN KEY (operation_id)
              REFERENCES candidate_replacement_operations(operation_id)
              ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS candidate_heads_session_idx
          ON candidate_heads(organization_id, project_id, session_id, candidate_id);
        CREATE INDEX IF NOT EXISTS candidate_versions_session_idx
          ON candidate_versions(organization_id, project_id, session_id, candidate_id, candidate_version);
        CREATE INDEX IF NOT EXISTS candidate_operations_candidate_idx
          ON candidate_operations(candidate_id, created_at);
        CREATE INDEX IF NOT EXISTS candidate_replacements_session_idx
          ON candidate_supersessions(organization_id, project_id, session_id, source_candidate_id);
        CREATE INDEX IF NOT EXISTS candidate_replacement_operations_session_idx
          ON candidate_replacement_operations(organization_id, project_id, session_id, operation_id);
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

    def insert_generated_many_in_transaction(
        self,
        connection: sqlite3.Connection,
        candidates: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Publish generated heads on a caller-owned atomic commit boundary.

        The processing-result publisher stages evidence before calling this
        method, then appends the terminal job snapshot on the same connection.
        No nested connection or commit is allowed here.
        """

        if (
            not isinstance(connection, sqlite3.Connection)
            or not connection.in_transaction
        ):
            raise CandidateStoreError(
                500,
                "CANDIDATE_TRANSACTION_REQUIRED",
                "candidate publication requires one active transaction",
            )
        if not isinstance(candidates, list) or not 1 <= len(candidates) <= 256:
            raise CandidateStoreError(
                400, "INVALID_CANDIDATE_SET", "generated candidate set is invalid"
            )
        documents = [copy.deepcopy(candidate) for candidate in candidates]
        identifiers: set[str] = set()
        digests: set[str] = set()
        for document in documents:
            try:
                TICKET_CONTRACT.validate_chain([document])
            except ContractError as exc:
                raise CandidateStoreError(
                    400, "INVALID_CANDIDATE", "generated candidate is invalid"
                ) from exc
            if (
                document["organization_id"] != self.organization_id
                or document["project_id"] != self.project_id
            ):
                raise CandidateStoreError(
                    403,
                    "CANDIDATE_SCOPE_MISMATCH",
                    "candidate is outside this deployment",
                )
            if (
                document["candidate_version"] != 1
                or document["previous_candidate_digest"] is not None
                or document["lineage"]["operation"] != "generated"
                or document["lineage"]["parents"]
                or document["state"] != "draft"
            ):
                raise CandidateStoreError(
                    409,
                    "INVALID_GENERATED_HEAD",
                    "candidate is not a generated first version",
                )
            if (
                document["candidate_id"] in identifiers
                or document["candidate_digest"] in digests
            ):
                raise CandidateStoreError(
                    409,
                    "DUPLICATE_GENERATED_CANDIDATE",
                    "processing result contains duplicate candidates",
                )
            identifiers.add(document["candidate_id"])
            digests.add(document["candidate_digest"])

        placeholders = ",".join("?" for _ in identifiers)
        existing = connection.execute(
            f"""SELECT candidate_id FROM candidate_versions
                  WHERE candidate_id IN ({placeholders}) LIMIT 1""",
            sorted(identifiers),
        ).fetchone()
        if existing is not None:
            raise CandidateStoreError(
                409,
                "CANDIDATE_ALREADY_EXISTS",
                "candidate ID is already in use",
            )

        for document in documents:
            if self._generated_insert_guard is not None:
                self._invoke_guard(
                    self._generated_insert_guard,
                    connection,
                    copy.deepcopy(document),
                )
        for document in documents:
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
        return copy.deepcopy(documents)

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
                     AND NOT EXISTS (
                         SELECT 1 FROM candidate_supersessions AS superseded
                          WHERE superseded.source_candidate_id = heads.candidate_id
                     )
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

            self._raise_if_superseded(connection, candidate_id)
            chain = self._load_current_chain(connection, candidate_id)
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

    def replace(
        self,
        *,
        idempotency_key: str,
        body: Any,
    ) -> CandidateReplacementResponse:
        """Atomically replace exact candidate heads with split or merge results."""

        if (
            not isinstance(idempotency_key, str)
            or _IDEMPOTENCY_PATTERN.fullmatch(idempotency_key) is None
        ):
            raise CandidateStoreError(
                400, "INVALID_IDEMPOTENCY_KEY", "Idempotency-Key is invalid"
            )
        public_body = self._validate_replacement_body(body)
        request_digest = _digest(public_body)

        with closing(self._connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                """SELECT operation_id, reviewer_id, operation, organization_id,
                          project_id, session_id, request_digest, operation_json,
                          response_status, response_body, response_digest, occurred_at
                     FROM candidate_replacement_operations
                    WHERE reviewer_id = ? AND idempotency_key = ?""",
                (self.reviewer_id, idempotency_key),
            ).fetchone()
            if prior is not None:
                if prior["request_digest"] != request_digest:
                    raise CandidateStoreError(
                        409,
                        "IDEMPOTENCY_CONFLICT",
                        "Idempotency-Key was already used for another candidate replacement",
                    )
                response_body = bytes(prior["response_body"])
                self._verify_replacement_response(
                    connection,
                    response_body=response_body,
                    response_digest=prior["response_digest"],
                    operation_id=prior["operation_id"],
                    operation_json=prior["operation_json"],
                    stored_operation=prior["operation"],
                    stored_reviewer_id=prior["reviewer_id"],
                    stored_organization_id=prior["organization_id"],
                    stored_project_id=prior["project_id"],
                    stored_session_id=prior["session_id"],
                    stored_occurred_at=prior["occurred_at"],
                    response_status=prior["response_status"],
                )
                return CandidateReplacementResponse(
                    status=prior["response_status"],
                    body=response_body,
                    body_digest=prior["response_digest"],
                )

            sources: list[dict[str, Any]] = []
            for binding in public_body["sources"]:
                self._raise_if_superseded(connection, binding["candidate_id"])
                chain = self._load_current_chain(
                    connection, binding["candidate_id"]
                )
                source = chain[-1]
                self._require_replacement_source_binding(source, binding)
                if source["state"] in {"approved", "rejected"}:
                    raise CandidateStoreError(
                        409,
                        "CANDIDATE_NOT_REPLACEABLE",
                        "terminal candidates cannot be split or merged",
                    )
                sources.append(source)

            fixed_scope = (
                "organization_id",
                "project_id",
                "session_id",
                "build_id",
                "build_identity_digest",
            )
            first_source = sources[0]
            if any(
                any(source[field] != first_source[field] for field in fixed_scope)
                for source in sources[1:]
            ):
                raise CandidateStoreError(
                    409,
                    "CANDIDATE_REPLACEMENT_SCOPE_MISMATCH",
                    "replacement sources must belong to one exact capture and build",
                )

            if self._replacement_manifest_factory is None:
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_REPLACEMENT_UNAVAILABLE",
                    "candidate replacement evidence is unavailable",
                )
            manifest = self._invoke_manifest_factory(
                connection,
                public_body["operation"],
                copy.deepcopy(sources),
            )
            evidence_binding = self._validate_replacement_manifest(
                manifest,
                operation=public_body["operation"],
                sources=sources,
            )
            occurred_at = self._replacement_timestamp(sources)
            lineage_operation = (
                "split" if public_body["operation"] == "split" else "merged"
            )
            parents = [self._candidate_reference(source) for source in sources]
            candidates = [
                self._build_replacement_candidate(
                    first_source,
                    result,
                    evidence_binding=evidence_binding,
                    lineage_operation=lineage_operation,
                    parents=parents,
                    reason=public_body["reason"],
                    occurred_at=occurred_at,
                )
                for result in public_body["results"]
            ]
            if public_body["operation"] == "split":
                content_documents = [
                    _canonical_json(candidate["content"]) for candidate in candidates
                ]
                source_content = _canonical_json(first_source["content"])
                if (
                    source_content in content_documents
                    or len(set(content_documents)) != len(content_documents)
                ):
                    raise CandidateStoreError(
                        409,
                        "SPLIT_CONTENT_NOT_DISTINCT",
                        "split results must differ from the source and every sibling",
                    )

            identifiers = [candidate["candidate_id"] for candidate in candidates]
            placeholders = ",".join("?" for _ in identifiers)
            existing = connection.execute(
                f"""SELECT candidate_id FROM candidate_versions
                      WHERE candidate_id IN ({placeholders}) LIMIT 1""",
                identifiers,
            ).fetchone()
            if existing is not None:
                raise CandidateStoreError(
                    409,
                    "CANDIDATE_ALREADY_EXISTS",
                    "a replacement candidate ID is already in use",
                )

            if self._replacement_result_guard is None:
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_REPLACEMENT_UNAVAILABLE",
                    "candidate replacement evidence binding is unavailable",
                )
            self._invoke_replacement_result_guard(
                connection,
                public_body["operation"],
                copy.deepcopy(sources),
                copy.deepcopy(candidates),
                copy.deepcopy(manifest),
            )

            for candidate in candidates:
                self._insert_version(connection, candidate)
                connection.execute(
                    """INSERT INTO candidate_heads
                       (candidate_id, candidate_version, candidate_digest,
                        organization_id, project_id, session_id, state)
                       VALUES (?, 1, ?, ?, ?, ?, 'draft')""",
                    (
                        candidate["candidate_id"],
                        candidate["candidate_digest"],
                        candidate["organization_id"],
                        candidate["project_id"],
                        candidate["session_id"],
                    ),
                )

            operation_id = "candidate_operation_" + secrets.token_hex(12)
            source_bindings = [self._exact_binding(source) for source in sources]
            result_bindings = [self._exact_binding(candidate) for candidate in candidates]
            projection = {
                "operation_id": operation_id,
                "operation": public_body["operation"],
                "actor_id": self.reviewer_id,
                "occurred_at": occurred_at,
                "sources": source_bindings,
                "results": result_bindings,
            }
            response_document = {
                "operation": projection,
                "candidates": copy.deepcopy(candidates),
            }
            response_body = _canonical_json(response_document).encode("utf-8")
            if len(response_body) > _MAX_REPLACEMENT_RESPONSE_BYTES:
                raise CandidateStoreError(
                    413,
                    "CANDIDATE_REPLACEMENT_RESPONSE_TOO_LARGE",
                    "candidate replacement response exceeds 16 MiB",
                )
            response_digest = "sha256:" + hashlib.sha256(response_body).hexdigest()
            operation_json = _canonical_json(projection)
            connection.execute(
                """INSERT INTO candidate_replacement_operations
                   (operation_id, reviewer_id, idempotency_key, operation,
                    organization_id, project_id, session_id, request_digest,
                    operation_json, response_status,
                    response_body, response_digest, occurred_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 201, ?, ?, ?)""",
                (
                    operation_id,
                    self.reviewer_id,
                    idempotency_key,
                    public_body["operation"],
                    first_source["organization_id"],
                    first_source["project_id"],
                    first_source["session_id"],
                    request_digest,
                    operation_json,
                    response_body,
                    response_digest,
                    occurred_at,
                ),
            )
            for source in sources:
                connection.execute(
                    """INSERT INTO candidate_supersessions
                       (source_candidate_id, source_candidate_version,
                        source_candidate_digest, operation_id, organization_id,
                        project_id, session_id, recorded_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        source["candidate_id"],
                        source["candidate_version"],
                        source["candidate_digest"],
                        operation_id,
                        source["organization_id"],
                        source["project_id"],
                        source["session_id"],
                        occurred_at,
                    ),
                )
            return CandidateReplacementResponse(
                status=201,
                body=response_body,
                body_digest=response_digest,
            )

    def get_supersession(self, candidate_id: str) -> dict[str, Any]:
        """Return the immutable replacement operation for one source candidate."""

        candidate_id = _require_id(candidate_id, "candidate_id")
        with closing(self._connection()) as connection, connection:
            # Preserve candidate existence/scope semantics for guessed IDs.
            self._load_current_chain(connection, candidate_id)
            projection = self._supersession_projection(connection, candidate_id)
            if projection is None:
                raise CandidateStoreError(
                    404,
                    "SUPERSESSION_NOT_FOUND",
                    "candidate has not been superseded",
                )
            return {"operation": projection}

    def require_not_superseded(self, candidate_id: str) -> None:
        """Fail with the stable replacement projection before a forbidden action."""

        candidate_id = _require_id(candidate_id, "candidate_id")
        with closing(self._connection()) as connection, connection:
            self._raise_if_superseded(connection, candidate_id)

    def _validate_replacement_body(self, body: Any) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise CandidateStoreError(
                400,
                "INVALID_CANDIDATE_REPLACEMENT_BODY",
                "candidate replacement body must be an object",
            )
        try:
            encoded = _canonical_json(body)
        except (TypeError, ValueError) as exc:
            raise CandidateStoreError(
                400,
                "INVALID_CANDIDATE_REPLACEMENT_BODY",
                "candidate replacement body is not canonical JSON data",
            ) from exc
        if len(encoded.encode("utf-8")) > _MAX_REPLACEMENT_BODY_BYTES:
            raise CandidateStoreError(
                413,
                "CANDIDATE_REPLACEMENT_BODY_TOO_LARGE",
                "candidate replacement body exceeds 16 MiB",
            )
        if unicodedata.normalize("NFC", encoded) != encoded or "\x00" in encoded:
            raise CandidateStoreError(
                400,
                "INVALID_CANDIDATE_REPLACEMENT_BODY",
                "candidate replacement text must be NFC-normalized and contain no NUL",
            )
        if set(body) != {"operation", "actor_id", "reason", "sources", "results"}:
            raise CandidateStoreError(
                400,
                "INVALID_CANDIDATE_REPLACEMENT_FIELDS",
                "candidate replacement fields are invalid",
            )
        operation = body["operation"]
        if not isinstance(operation, str) or operation not in _REPLACEMENT_OPERATIONS:
            raise CandidateStoreError(
                400,
                "INVALID_CANDIDATE_REPLACEMENT_OPERATION",
                "candidate replacement operation is invalid",
            )
        if body["actor_id"] != self.reviewer_id:
            raise CandidateStoreError(
                403,
                "REVIEWER_MISMATCH",
                "candidate replacement actor does not match the authenticated reviewer",
            )
        if not isinstance(body["reason"], str) or not 1 <= len(body["reason"]) <= 256:
            raise CandidateStoreError(
                400,
                "INVALID_CANDIDATE_REPLACEMENT_REASON",
                "candidate replacement reason is invalid",
            )
        sources = body["sources"]
        results = body["results"]
        source_bounds = (1, 1) if operation == "split" else (2, 16)
        result_bounds = (2, 16) if operation == "split" else (1, 1)
        if not isinstance(sources, list) or not (
            source_bounds[0] <= len(sources) <= source_bounds[1]
        ):
            raise CandidateStoreError(
                400,
                "INVALID_CANDIDATE_REPLACEMENT_SOURCES",
                "candidate replacement source count is invalid",
            )
        if not isinstance(results, list) or not (
            result_bounds[0] <= len(results) <= result_bounds[1]
        ):
            raise CandidateStoreError(
                400,
                "INVALID_CANDIDATE_REPLACEMENT_RESULTS",
                "candidate replacement result count is invalid",
            )

        source_fields = {
            "candidate_id",
            "candidate_version",
            "candidate_digest",
            "candidate_content_digest",
            "evidence_manifest_digest",
        }
        source_ids: set[str] = set()
        source_digests: set[str] = set()
        for source in sources:
            if not isinstance(source, dict) or set(source) != source_fields:
                raise CandidateStoreError(
                    400,
                    "INVALID_CANDIDATE_REPLACEMENT_SOURCE",
                    "candidate replacement source binding is invalid",
                )
            candidate_id = _require_id(source["candidate_id"], "source.candidate_id")
            if candidate_id in source_ids:
                raise CandidateStoreError(
                    400,
                    "DUPLICATE_CANDIDATE_REPLACEMENT_SOURCE",
                    "candidate replacement sources must be distinct",
                )
            source_ids.add(candidate_id)
            version = source["candidate_version"]
            if (
                isinstance(version, bool)
                or not isinstance(version, int)
                or not 1 <= version <= 9_007_199_254_740_991
            ):
                raise CandidateStoreError(
                    400,
                    "INVALID_CANDIDATE_VERSION",
                    "candidate replacement source version is invalid",
                )
            for field in (
                "candidate_digest",
                "candidate_content_digest",
                "evidence_manifest_digest",
            ):
                _require_digest(source[field], f"source.{field}")
            if source["candidate_digest"] in source_digests:
                raise CandidateStoreError(
                    400,
                    "DUPLICATE_CANDIDATE_REPLACEMENT_SOURCE",
                    "candidate replacement source digests must be distinct",
                )
            source_digests.add(source["candidate_digest"])

        result_ids: set[str] = set()
        for result in results:
            if not isinstance(result, dict) or set(result) != {"candidate_id", "content"}:
                raise CandidateStoreError(
                    400,
                    "INVALID_CANDIDATE_REPLACEMENT_RESULT",
                    "candidate replacement result is invalid",
                )
            candidate_id = _require_id(result["candidate_id"], "result.candidate_id")
            if candidate_id in result_ids or candidate_id in source_ids:
                raise CandidateStoreError(
                    400,
                    "DUPLICATE_CANDIDATE_REPLACEMENT_RESULT",
                    "replacement result IDs must be unique and distinct from sources",
                )
            result_ids.add(candidate_id)
            if not isinstance(result["content"], dict):
                raise CandidateStoreError(
                    400,
                    "INVALID_CANDIDATE_REPLACEMENT_CONTENT",
                    "replacement result content must be an object",
                )
        return copy.deepcopy(body)

    @staticmethod
    def _candidate_reference(candidate: dict[str, Any]) -> dict[str, Any]:
        return {
            "candidate_id": candidate["candidate_id"],
            "candidate_version": candidate["candidate_version"],
            "candidate_digest": candidate["candidate_digest"],
        }

    @staticmethod
    def _exact_binding(candidate: dict[str, Any]) -> dict[str, Any]:
        return {
            "candidate_id": candidate["candidate_id"],
            "candidate_version": candidate["candidate_version"],
            "candidate_digest": candidate["candidate_digest"],
            "candidate_content_digest": candidate["candidate_content_digest"],
            "evidence_manifest_digest": candidate["evidence_manifest"]["manifest_digest"],
        }

    @staticmethod
    def _require_replacement_source_binding(
        source: dict[str, Any], binding: dict[str, Any]
    ) -> None:
        if CandidateStore._exact_binding(source) != binding:
            raise CandidateStoreError(
                412,
                "CANDIDATE_PRECONDITION_FAILED",
                "replacement source does not identify the exact current candidate",
            )

    def _replacement_timestamp(self, sources: list[dict[str, Any]]) -> str:
        current = self._now().replace(microsecond=0)
        source_floor = max(
            TICKET_CONTRACT.parse_time(
                source["version_created_at"], "$.source.version_created_at"
            )
            for source in sources
        ) + timedelta(seconds=1)
        occurred = max(current, source_floor)
        return occurred.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _validate_replacement_manifest(
        self,
        manifest: Any,
        *,
        operation: str,
        sources: list[dict[str, Any]],
    ) -> dict[str, Any]:
        try:
            validate_manifest(manifest)
        except EvidenceDomainError as exc:
            raise CandidateStoreError(
                409,
                exc.code,
                "candidate replacement evidence manifest is invalid",
            ) from exc
        first = sources[0]
        if any(
            manifest[field] != first[field]
            for field in ("organization_id", "project_id", "session_id")
        ):
            raise CandidateStoreError(
                409,
                "CANDIDATE_REPLACEMENT_SCOPE_MISMATCH",
                "replacement evidence escaped its source capture",
            )
        manifest_ids = [item["evidence_id"] for item in manifest["items"]]
        binding = {
            "manifest_id": manifest["manifest_id"],
            "manifest_digest": manifest["manifest_digest"],
            "evidence_ids": sorted(manifest_ids),
        }
        if operation == "split":
            if (
                binding["manifest_id"]
                != first["evidence_manifest"]["manifest_id"]
                or binding["manifest_digest"]
                != first["evidence_manifest"]["manifest_digest"]
                or set(manifest_ids)
                != set(first["evidence_manifest"]["evidence_ids"])
            ):
                raise CandidateStoreError(
                    409,
                    "SPLIT_EVIDENCE_CHANGED",
                    "split results must reuse the exact source evidence manifest",
                )
            return copy.deepcopy(first["evidence_manifest"])
        return binding

    def _build_replacement_candidate(
        self,
        source: dict[str, Any],
        result: dict[str, Any],
        *,
        evidence_binding: dict[str, Any],
        lineage_operation: str,
        parents: list[dict[str, Any]],
        reason: str,
        occurred_at: str,
    ) -> dict[str, Any]:
        candidate = {
            "contract_version": source["contract_version"],
            "media_type": source["media_type"],
            "organization_id": source["organization_id"],
            "project_id": source["project_id"],
            "build_id": source["build_id"],
            "build_identity_digest": source["build_identity_digest"],
            "session_id": source["session_id"],
            "candidate_id": result["candidate_id"],
            "candidate_version": 1,
            "candidate_created_at": occurred_at,
            "version_created_at": occurred_at,
            "previous_candidate_digest": None,
            "evidence_manifest": copy.deepcopy(evidence_binding),
            "lineage": {
                "operation": lineage_operation,
                "parents": copy.deepcopy(parents),
            },
            "state": "draft",
            "transition": {
                "from_state": None,
                "to_state": "draft",
                "actor": {"actor_type": "human", "actor_id": self.reviewer_id},
                "occurred_at": occurred_at,
                "reason": reason,
            },
            "review": {
                "status": "in_review",
                "reviewer_action_required": True,
                "last_human_actor_id": self.reviewer_id,
                "last_reviewed_at": occurred_at,
                "notes": [],
            },
            "content": copy.deepcopy(result["content"]),
            "approval": None,
            "rejection": None,
        }
        try:
            candidate = TICKET_CONTRACT.seal(candidate)
            TICKET_CONTRACT.validate_chain([candidate])
        except ContractError as exc:
            raise CandidateStoreError(
                400,
                "INVALID_CANDIDATE_REPLACEMENT_CONTENT",
                "replacement result content is not a valid ticket candidate",
            ) from exc
        return candidate

    def _invoke_manifest_factory(
        self,
        connection: sqlite3.Connection,
        operation: str,
        sources: list[dict[str, Any]],
    ) -> dict[str, Any]:
        assert self._replacement_manifest_factory is not None
        try:
            manifest = self._replacement_manifest_factory(
                connection, operation, sources
            )
        except CandidateStoreError:
            raise
        except EvidenceDomainError as exc:
            raise CandidateStoreError(409, exc.code, exc.detail) from exc
        except ContractError as exc:
            raise CandidateStoreError(400, exc.code, exc.detail) from exc
        if not isinstance(manifest, dict):
            raise CandidateStoreError(
                500,
                "CANDIDATE_REPLACEMENT_EVIDENCE_INVALID",
                "replacement evidence factory returned an invalid manifest",
            )
        return copy.deepcopy(manifest)

    def _invoke_replacement_result_guard(
        self,
        connection: sqlite3.Connection,
        operation: str,
        sources: list[dict[str, Any]],
        results: list[dict[str, Any]],
        manifest: dict[str, Any],
    ) -> None:
        assert self._replacement_result_guard is not None
        try:
            self._replacement_result_guard(
                connection, operation, sources, results, manifest
            )
        except CandidateStoreError:
            raise
        except EvidenceDomainError as exc:
            raise CandidateStoreError(409, exc.code, exc.detail) from exc
        except ContractError as exc:
            raise CandidateStoreError(400, exc.code, exc.detail) from exc

    def _load_current_chain(
        self, connection: sqlite3.Connection, candidate_id: str
    ) -> list[dict[str, Any]]:
        chain = self._load_chain(connection, candidate_id)
        current = chain[-1]
        row = connection.execute(
            """SELECT candidate_version, candidate_digest, organization_id,
                      project_id, session_id, state
                 FROM candidate_heads
                WHERE candidate_id = ?""",
            (candidate_id,),
        ).fetchone()
        if row is None or tuple(row) != (
            current["candidate_version"],
            current["candidate_digest"],
            current["organization_id"],
            current["project_id"],
            current["session_id"],
            current["state"],
        ):
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate head failed integrity verification",
            )
        return chain

    def _raise_if_superseded(
        self, connection: sqlite3.Connection, candidate_id: str
    ) -> None:
        projection = self._supersession_projection(connection, candidate_id)
        if projection is None:
            return
        raise CandidateStoreError(
            409,
            "CANDIDATE_SUPERSEDED",
            "candidate was replaced by a reviewer operation",
            details={
                "operation_id": projection["operation_id"],
                "operation": projection["operation"],
                "replacements": copy.deepcopy(projection["results"]),
            },
        )

    def _supersession_projection(
        self, connection: sqlite3.Connection, candidate_id: str
    ) -> dict[str, Any] | None:
        row = connection.execute(
            """SELECT superseded.source_candidate_version,
                      superseded.source_candidate_digest,
                      superseded.organization_id, superseded.project_id,
                      superseded.session_id, superseded.operation_id,
                      operations.organization_id AS operation_organization_id,
                      operations.project_id AS operation_project_id,
                      operations.session_id AS operation_session_id,
                      operations.reviewer_id AS operation_reviewer_id,
                      operations.operation AS stored_operation,
                      operations.occurred_at AS operation_occurred_at,
                      operations.operation_json, operations.response_status,
                      operations.response_body, operations.response_digest
                 FROM candidate_supersessions AS superseded
                 JOIN candidate_replacement_operations AS operations
                   ON operations.operation_id = superseded.operation_id
                WHERE superseded.source_candidate_id = ?""",
            (candidate_id,),
        ).fetchone()
        if row is None:
            return None
        if (
            row["organization_id"] != self.organization_id
            or row["project_id"] != self.project_id
            or row["operation_organization_id"] != row["organization_id"]
            or row["operation_project_id"] != row["project_id"]
            or row["operation_session_id"] != row["session_id"]
        ):
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate supersession scope changed",
            )
        projection = self._verify_replacement_response(
            connection,
            response_body=bytes(row["response_body"]),
            response_digest=row["response_digest"],
            operation_id=row["operation_id"],
            operation_json=row["operation_json"],
            stored_operation=row["stored_operation"],
            stored_reviewer_id=row["operation_reviewer_id"],
            stored_organization_id=row["operation_organization_id"],
            stored_project_id=row["operation_project_id"],
            stored_session_id=row["operation_session_id"],
            stored_occurred_at=row["operation_occurred_at"],
            response_status=row["response_status"],
        )
        if projection["operation_id"] != row["operation_id"]:
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate replacement identity changed",
            )
        matching_sources = [
            source
            for source in projection["sources"]
            if source["candidate_id"] == candidate_id
        ]
        if len(matching_sources) != 1 or (
            matching_sources[0]["candidate_version"],
            matching_sources[0]["candidate_digest"],
        ) != (row["source_candidate_version"], row["source_candidate_digest"]):
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate supersession binding changed",
            )
        return projection

    def _load_operation_projection(self, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, (str, bytes)):
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate replacement is invalid",
            )
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        try:
            projection = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate replacement is invalid",
            ) from exc
        if not isinstance(projection, dict) or _canonical_json(projection) != text:
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate replacement is not canonical",
            )
        fields = {
            "operation_id",
            "operation",
            "actor_id",
            "occurred_at",
            "sources",
            "results",
        }
        binding_fields = {
            "candidate_id",
            "candidate_version",
            "candidate_digest",
            "candidate_content_digest",
            "evidence_manifest_digest",
        }
        try:
            valid = (
                set(projection) == fields
                and _ID_PATTERN.fullmatch(projection["operation_id"]) is not None
                and projection["operation"] in _REPLACEMENT_OPERATIONS
                and projection["actor_id"] == self.reviewer_id
                and isinstance(projection["occurred_at"], str)
                and isinstance(projection["sources"], list)
                and isinstance(projection["results"], list)
            )
        except (KeyError, TypeError):
            valid = False
        if not valid:
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate replacement projection is invalid",
            )
        try:
            TICKET_CONTRACT.parse_time(projection["occurred_at"], "$.occurred_at")
        except ContractError as exc:
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate replacement time is invalid",
            ) from exc
        source_bounds = (1, 1) if projection["operation"] == "split" else (2, 16)
        result_bounds = (2, 16) if projection["operation"] == "split" else (1, 1)
        if not (
            source_bounds[0] <= len(projection["sources"]) <= source_bounds[1]
            and result_bounds[0] <= len(projection["results"]) <= result_bounds[1]
        ):
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate replacement cardinality is invalid",
            )
        identifiers: set[str] = set()
        for binding in [*projection["sources"], *projection["results"]]:
            if not isinstance(binding, dict) or set(binding) != binding_fields:
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_STORAGE_CORRUPT",
                    "stored candidate replacement binding is invalid",
                )
            try:
                _require_id(binding["candidate_id"], "candidate_id")
                if (
                    isinstance(binding["candidate_version"], bool)
                    or not isinstance(binding["candidate_version"], int)
                    or binding["candidate_version"] < 1
                ):
                    raise CandidateStoreError(400, "INVALID", "invalid")
                for field in (
                    "candidate_digest",
                    "candidate_content_digest",
                    "evidence_manifest_digest",
                ):
                    _require_digest(binding[field], field)
            except CandidateStoreError as exc:
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_STORAGE_CORRUPT",
                    "stored candidate replacement binding is invalid",
                ) from exc
            if binding["candidate_id"] in identifiers:
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_STORAGE_CORRUPT",
                    "stored candidate replacement identities overlap",
                )
            identifiers.add(binding["candidate_id"])
        if len(
            {binding["candidate_digest"] for binding in projection["sources"]}
        ) != len(projection["sources"]):
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate replacement source digests overlap",
            )
        return projection

    def _verify_operation_projection(
        self, connection: sqlite3.Connection, projection: dict[str, Any]
    ) -> tuple[str, str, str, str, str]:
        scope: tuple[str, str, str, str, str] | None = None
        source_documents: list[dict[str, Any]] = []
        for source in projection["sources"]:
            row = connection.execute(
                """SELECT versions.candidate_content_digest,
                          versions.evidence_manifest_digest,
                          superseded.operation_id
                     FROM candidate_versions AS versions
                     JOIN candidate_heads AS heads
                       ON heads.candidate_id = versions.candidate_id
                      AND heads.candidate_version = versions.candidate_version
                      AND heads.candidate_digest = versions.candidate_digest
                     JOIN candidate_supersessions AS superseded
                       ON superseded.source_candidate_id = versions.candidate_id
                      AND superseded.source_candidate_version = versions.candidate_version
                      AND superseded.source_candidate_digest = versions.candidate_digest
                    WHERE versions.candidate_id = ?
                      AND versions.candidate_version = ?
                      AND versions.candidate_digest = ?
                      AND versions.organization_id = ? AND versions.project_id = ?""",
                (
                    source["candidate_id"],
                    source["candidate_version"],
                    source["candidate_digest"],
                    self.organization_id,
                    self.project_id,
                ),
            ).fetchone()
            if row is None or tuple(row) != (
                source["candidate_content_digest"],
                source["evidence_manifest_digest"],
                projection["operation_id"],
            ):
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_STORAGE_CORRUPT",
                    "stored supersession source projection changed",
                )
            chain = self._load_current_chain(connection, source["candidate_id"])
            document = chain[source["candidate_version"] - 1]
            if (
                self._exact_binding(document) != source
                or document["state"] in {"approved", "rejected"}
            ):
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_STORAGE_CORRUPT",
                    "stored replacement source candidate changed",
                )
            document_scope = tuple(
                document[field]
                for field in (
                    "organization_id",
                    "project_id",
                    "session_id",
                    "build_id",
                    "build_identity_digest",
                )
            )
            if scope is not None and document_scope != scope:
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_STORAGE_CORRUPT",
                    "stored replacement source scope changed",
                )
            scope = document_scope
            source_documents.append(document)
        parent_refs = [self._candidate_reference(source) for source in source_documents]
        lineage_operation = "split" if projection["operation"] == "split" else "merged"
        for result in projection["results"]:
            row = connection.execute(
                """SELECT versions.candidate_content_digest,
                          versions.evidence_manifest_digest
                     FROM candidate_versions AS versions
                    WHERE versions.candidate_id = ?
                      AND versions.candidate_version = ?
                      AND versions.candidate_digest = ?
                      AND versions.organization_id = ? AND versions.project_id = ?""",
                (
                    result["candidate_id"],
                    result["candidate_version"],
                    result["candidate_digest"],
                    self.organization_id,
                    self.project_id,
                ),
            ).fetchone()
            if row is None or tuple(row) != (
                result["candidate_content_digest"],
                result["evidence_manifest_digest"],
            ):
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_STORAGE_CORRUPT",
                    "stored replacement result projection changed",
                )
            chain = self._load_chain(connection, result["candidate_id"])
            document = chain[result["candidate_version"] - 1]
            document_scope = tuple(
                document[field]
                for field in (
                    "organization_id",
                    "project_id",
                    "session_id",
                    "build_id",
                    "build_identity_digest",
                )
            )
            if (
                self._exact_binding(document) != result
                or result["candidate_version"] != 1
                or document_scope != scope
                or document["lineage"]
                != {"operation": lineage_operation, "parents": parent_refs}
                or document["transition"]["actor"]
                != {"actor_type": "human", "actor_id": projection["actor_id"]}
                or document["transition"]["occurred_at"]
                != projection["occurred_at"]
                or document["candidate_created_at"] != projection["occurred_at"]
                or document["version_created_at"] != projection["occurred_at"]
            ):
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_STORAGE_CORRUPT",
                    "stored replacement result candidate changed",
                )
        assert scope is not None
        return scope

    def _verify_replacement_response(
        self,
        connection: sqlite3.Connection,
        *,
        response_body: bytes,
        response_digest: str,
        operation_id: str,
        operation_json: Any,
        stored_operation: Any,
        stored_reviewer_id: Any,
        stored_organization_id: Any,
        stored_project_id: Any,
        stored_session_id: Any,
        stored_occurred_at: Any,
        response_status: Any,
    ) -> dict[str, Any]:
        if (
            len(response_body) > _MAX_REPLACEMENT_RESPONSE_BYTES
            or "sha256:" + hashlib.sha256(response_body).hexdigest()
            != response_digest
        ):
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate replacement response failed integrity verification",
            )
        try:
            document = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate replacement response is invalid",
            ) from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"operation", "candidates"}
            or not isinstance(document["candidates"], list)
            or _canonical_json(document).encode("utf-8") != response_body
        ):
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate replacement response is not canonical",
            )
        projection = self._load_operation_projection(operation_json)
        if (
            document["operation"] != projection
            or projection["operation_id"] != operation_id
            or stored_operation != projection["operation"]
            or stored_reviewer_id != projection["actor_id"]
            or stored_occurred_at != projection["occurred_at"]
            or response_status != 201
        ):
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate replacement response changed",
            )
        if len(document["candidates"]) != len(projection["results"]):
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate replacement results changed",
            )
        for candidate, binding in zip(
            document["candidates"], projection["results"], strict=True
        ):
            try:
                TICKET_CONTRACT.validate_chain([candidate])
            except ContractError as exc:
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_STORAGE_CORRUPT",
                    "stored replacement candidate failed validation",
                ) from exc
            if self._exact_binding(candidate) != binding:
                raise CandidateStoreError(
                    500,
                    "CANDIDATE_STORAGE_CORRUPT",
                    "stored replacement candidate binding changed",
                )
        scope = self._verify_operation_projection(connection, projection)
        if (
            stored_organization_id,
            stored_project_id,
            stored_session_id,
        ) != scope[:3]:
            raise CandidateStoreError(
                500,
                "CANDIDATE_STORAGE_CORRUPT",
                "stored candidate replacement scope changed",
            )
        return projection

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
            connection.execute(
                """DELETE FROM candidate_replacement_operations
                    WHERE organization_id = ? AND project_id = ?
                      AND session_id = ?""",
                (self.organization_id, self.project_id, session_id),
            )
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
        if len(encoded.encode("utf-8")) > 1_048_576:
            raise CandidateStoreError(413, "TRANSITION_BODY_TOO_LARGE", "transition body exceeds 1 MiB")
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
        if action == "edit_content":
            allowed = required = common | {"content"}
        elif action == "resolve_clarification":
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
        if body["action"] == "edit_content":
            result["content"] = body["content"]
        elif body["action"] == "resolve_clarification":
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
